package serviceaccess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/zxh326/kite/pkg/cluster"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type destination struct {
	uid  string
	pod  *corev1.Pod
	port int
}

func ready(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil || pod.Status.PodIP == "" {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func resolve(ctx context.Context, cs *cluster.ClientSet, target Target, uid string) (*destination, error) {
	client := cs.K8sClient.ClientSet.CoreV1()
	var result destination
	if target.Kind == "pods" {
		pod, err := client.Pods(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
		if err != nil {
			return nil, errors.New("unable to read the target Pod")
		}
		if !ready(pod) {
			return nil, errors.New("target Pod is not ready")
		}
		declared := false
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if int(port.ContainerPort) == target.Port && (port.Protocol == "" || port.Protocol == corev1.ProtocolTCP) {
					declared = true
				}
			}
		}
		if !declared {
			return nil, errors.New("select a declared TCP container port")
		}
		result = destination{uid: string(pod.UID), pod: pod, port: target.Port}
	} else {
		service, err := client.Services(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
		if err != nil {
			return nil, errors.New("unable to read the target Service")
		}
		if service.Spec.Type == corev1.ServiceTypeExternalName || len(service.Spec.Selector) == 0 {
			return nil, errors.New("service access requires a Service with a Pod selector")
		}
		var servicePort *corev1.ServicePort
		for i := range service.Spec.Ports {
			port := &service.Spec.Ports[i]
			if int(port.Port) == target.Port && (port.Protocol == "" || port.Protocol == corev1.ProtocolTCP) {
				servicePort = port
				break
			}
		}
		if servicePort == nil {
			return nil, errors.New("TCP Service port not found")
		}
		pods, err := client.Pods(target.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(service.Spec.Selector).String()})
		if err != nil {
			return nil, errors.New("unable to find Service Pods")
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			if !ready(pod) {
				continue
			}
			port := targetPort(pod, servicePort)
			if port > 0 && port <= 65535 {
				result = destination{uid: string(service.UID), pod: pod, port: port}
				break
			}
		}
		if result.pod == nil {
			return nil, errors.New("no ready Pod with the selected Service port")
		}
	}
	if uid != "" && result.uid != uid {
		return nil, errors.New("target was replaced; open the service again")
	}
	return &result, nil
}

func targetPort(pod *corev1.Pod, servicePort *corev1.ServicePort) int {
	if servicePort.TargetPort.Type == intstr.Int {
		if servicePort.TargetPort.IntVal == 0 {
			return int(servicePort.Port)
		}
		return int(servicePort.TargetPort.IntVal)
	}
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == servicePort.TargetPort.StrVal && (port.Protocol == "" || port.Protocol == corev1.ProtocolTCP) {
				return int(port.ContainerPort)
			}
		}
	}
	return 0
}

func (s *Server) newTransport(item *session) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	transport.MaxIdleConns = 8
	transport.MaxIdleConnsPerHost = 8
	transport.MaxConnsPerHost = 32
	transport.IdleConnTimeout = time.Minute
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		stop := context.AfterFunc(item.ctx, cancel)
		defer stop()
		cs, err := s.cm.GetClientSet(item.Cluster)
		if err != nil {
			return nil, err
		}
		resolved, err := resolve(ctx, cs, item.Target, item.uid)
		if err != nil {
			return nil, err
		}
		address := net.JoinHostPort(resolved.pod.Status.PodIP, strconv.Itoa(resolved.port))
		if dial := cs.K8sClient.Configuration.Dial; dial != nil {
			return dial(ctx, "tcp", address)
		}
		if cs.InCluster {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}
		return dialPortForward(ctx, item.ctx, cs, resolved)
	}
	return transport
}

// Each upstream TCP connection owns a port-forward connection. HTTP keep-alives
// reuse it; no local listening ports or Kubernetes bearer tokens reach the app.
func dialPortForward(ctx, lifetime context.Context, cs *cluster.ClientSet, target *destination) (net.Conn, error) {
	config := rest.CopyConfig(cs.K8sClient.Configuration)
	config.Timeout = 0
	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, err
	}
	targetURL := cs.K8sClient.ClientSet.CoreV1().RESTClient().Post().Resource("pods").Namespace(target.pod.Namespace).Name(target.pod.Name).SubResource("portforward").URL()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL.String(), nil)
	if err != nil {
		return nil, err
	}
	connection, _, err := spdy.NegotiateStreaming(upgrader, &http.Client{Transport: transport}, request, portforward.PortForwardProtocolV1Name)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, strconv.Itoa(target.port))
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	errorStream, err := connection.CreateStream(headers)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	_ = errorStream.Close()
	headers.Set(corev1.StreamType, corev1.StreamTypeData)
	dataStream, err := connection.CreateStream(headers)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	local, remote := net.Pipe()
	var once sync.Once
	cleanup := func() { once.Do(func() { _ = connection.Close(); _ = remote.Close(); _ = local.Close() }) }
	stopLifetime := context.AfterFunc(lifetime, cleanup)
	go func() { defer cleanup(); defer stopLifetime(); _, _ = io.Copy(dataStream, remote) }()
	go func() { defer cleanup(); _, _ = io.Copy(remote, dataStream) }()
	go func() {
		message, _ := io.ReadAll(io.LimitReader(errorStream, 4096))
		if len(message) > 0 {
			cleanup()
		}
	}()
	if !stop() || ctx.Err() != nil {
		cleanup()
		return nil, fmt.Errorf("port-forward connection cancelled")
	}
	return local, nil
}
