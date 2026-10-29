package serviceaccess

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zxh326/kite/pkg/cluster"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type destination struct {
	uid     string
	pod     *corev1.Pod
	port    int
	host    string
	tlsHost string
}

func (d *destination) upstreamHost(target Target) string {
	if d.tlsHost != "" {
		return d.tlsHost
	}
	return target.Name + "." + target.Namespace + ".svc.cluster.local"
}

func validExternalHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsGlobalUnicast()
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host != "" && host != "localhost" && !strings.HasSuffix(host, ".localhost") && len(validation.IsDNS1123Subdomain(host)) == 0
}

func externalDestination(cs *cluster.ClientSet, uid, host string, port int) (*destination, error) {
	if !cs.InCluster && cs.K8sClient.Configuration.Dial == nil {
		return nil, errors.New("external Services require an in-cluster Kite or a Cluster Agent; kubeconfig port-forward cannot reach external endpoints")
	}
	if !validExternalHost(host) {
		return nil, errors.New("external Service must reference a DNS name or a unicast IP address outside loopback and link-local ranges")
	}
	return &destination{uid: uid, host: host, port: port}, nil
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

func declaresTCPPort(pod *corev1.Pod, port int) bool {
	for _, container := range pod.Spec.Containers {
		for _, declared := range container.Ports {
			if int(declared.ContainerPort) == port && (declared.Protocol == "" || declared.Protocol == corev1.ProtocolTCP) {
				return true
			}
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
		if !declaresTCPPort(pod, target.Port) {
			return nil, errors.New("select a declared TCP container port")
		}
		result = destination{uid: string(pod.UID), pod: pod, port: target.Port}
	} else {
		service, err := client.Services(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
		if err != nil {
			return nil, errors.New("unable to read the target Service")
		}
		if service.DeletionTimestamp != nil {
			return nil, errors.New("target Service is being deleted")
		}
		var servicePort *corev1.ServicePort
		for i := range service.Spec.Ports {
			port := &service.Spec.Ports[i]
			if int(port.Port) == target.Port && (port.Protocol == "" || port.Protocol == corev1.ProtocolTCP) {
				servicePort = port
				break
			}
		}
		switch {
		case service.Spec.Type == corev1.ServiceTypeExternalName:
			if len(service.Spec.Ports) > 0 && servicePort == nil {
				return nil, errors.New("TCP Service port not found")
			}
			host := strings.TrimSuffix(service.Spec.ExternalName, ".")
			external, err := externalDestination(cs, string(service.UID), host, target.Port)
			if err != nil {
				return nil, err
			}
			result = *external
			result.tlsHost = host
		case servicePort == nil:
			return nil, errors.New("TCP Service port not found")
		case len(service.Spec.Selector) == 0:
			external, err := resolveServiceEndpoint(ctx, cs, service, servicePort)
			if err != nil {
				return nil, err
			}
			result = *external
		default:
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
	}
	if uid != "" && result.uid != uid {
		return nil, errors.New("target was replaced; open the service again")
	}
	return &result, nil
}

func resolveServiceEndpoint(ctx context.Context, cs *cluster.ClientSet, service *corev1.Service, port *corev1.ServicePort) (*destination, error) {
	if !cs.InCluster && cs.K8sClient.Configuration.Dial == nil {
		return nil, errors.New("external Services require an in-cluster Kite or a Cluster Agent; kubeconfig port-forward cannot reach external endpoints")
	}
	slices, err := cs.K8sClient.ClientSet.DiscoveryV1().EndpointSlices(service.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{discoveryv1.LabelServiceName: service.Name}.String(),
	})
	if err != nil {
		return nil, errors.New("unable to read Service EndpointSlices")
	}
	for _, slice := range slices.Items {
		if slice.DeletionTimestamp != nil || (slice.AddressType != discoveryv1.AddressTypeIPv4 && slice.AddressType != discoveryv1.AddressTypeIPv6) {
			continue
		}
		stale := false
		for _, owner := range slice.OwnerReferences {
			if owner.Kind == "Service" && owner.UID != service.UID {
				stale = true
			}
		}
		if stale {
			continue
		}
		for _, endpointPort := range slice.Ports {
			if endpointPort.Port == nil || *endpointPort.Port < 1 || *endpointPort.Port > 65535 ||
				(endpointPort.Protocol != nil && *endpointPort.Protocol != corev1.ProtocolTCP) {
				continue
			}
			name := ""
			if endpointPort.Name != nil {
				name = *endpointPort.Name
			}
			if name != port.Name {
				continue
			}
			for _, endpoint := range slice.Endpoints {
				if (endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready) ||
					(endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {
					continue
				}
				for _, address := range endpoint.Addresses {
					if ip := net.ParseIP(address); ip != nil && ip.IsGlobalUnicast() {
						return externalDestination(cs, string(service.UID), address, int(*endpointPort.Port))
					}
				}
			}
		}
	}
	return nil, errors.New("no ready TCP endpoint for the selected Service port")
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
	if item.Scheme == "https" {
		// Certificate verification is disabled only for this explicitly configured address.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: item.SkipTLSVerify}
	}
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
		if resolved.upstreamHost(item.Target) != item.upstreamHost {
			return nil, errors.New("external Service destination changed; open it again")
		}
		host := resolved.host
		if resolved.pod != nil {
			host = resolved.pod.Status.PodIP
		}
		address := net.JoinHostPort(host, strconv.Itoa(resolved.port))
		if dial := cs.K8sClient.Configuration.Dial; dial != nil {
			return dial(ctx, "tcp", address)
		}
		if cs.InCluster {
			if resolved.pod == nil {
				return dialExternal(ctx, host, resolved.port)
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}
		return dialPortForward(ctx, item.ctx, cs, resolved)
	}
	return transport
}

func dialExternal(ctx context.Context, host string, port int) (net.Conn, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, errors.New("unable to resolve external Service")
	}
	err = errors.New("external Service has no reachable unicast address")
	for _, address := range addresses {
		if !address.IP.IsGlobalUnicast() {
			continue
		}
		var connection net.Conn
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(address.IP.String(), strconv.Itoa(port)))
		if err == nil {
			return connection, nil
		}
	}
	return nil, err
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
