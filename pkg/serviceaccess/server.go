package serviceaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zxh326/kite/pkg/cluster"
	"github.com/zxh326/kite/pkg/common"
	"github.com/zxh326/kite/pkg/model"
	"github.com/zxh326/kite/pkg/rbac"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	cookieName      = "__Host-kite_service_session"
	exchangePath    = "/.kite/access"
	idleTimeout     = 30 * time.Minute
	sessionLifetime = 8 * time.Hour
	maxSessions     = 1024
)

type Target struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Port      int    `json:"port"`
	Scheme    string `json:"scheme"`
}

func (t Target) valid() bool {
	return (t.Kind == "services" || t.Kind == "pods") && t.Namespace != common.AllNamespaces && len(validation.IsDNS1123Label(t.Namespace)) == 0 && len(validation.IsDNS1123Subdomain(t.Name)) == 0 && t.Port > 0 && t.Port <= 65535 && (t.Scheme == "http" || t.Scheme == "https")
}

type session struct {
	ID string `json:"id"`
	Target
	Cluster       string    `json:"cluster"`
	ExpiresAt     time.Time `json:"expiresAt"`
	userID        uint
	uid           string
	secret        [32]byte
	ticket        [32]byte
	ticketExpires time.Time
	ticketPath    string
	lastUsed      time.Time
	transport     *http.Transport
	ctx           context.Context
	cancel        context.CancelFunc
}

type Server struct {
	cm       *cluster.ClusterManager
	domain   string
	origin   string
	mu       sync.Mutex
	sessions map[string]*session
}

func New(ctx context.Context, cm *cluster.ClusterManager) (*Server, error) {
	s := &Server{cm: cm, sessions: make(map[string]*session)}
	if common.ServiceAccessDomain == "" {
		return s, nil
	}
	domain := common.ServiceAccessDomain
	origin, err := url.Parse(common.Host)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, errors.New("service access requires HOST to be an HTTPS origin without a path (use KITE_BASE for a subpath)")
	}
	if len(validation.IsDNS1123Subdomain(domain)) != 0 || len(domain) > 220 || !strings.Contains(domain, ".") || origin.Hostname() == domain || strings.HasSuffix(origin.Hostname(), "."+domain) {
		return nil, errors.New("SERVICE_ACCESS_DOMAIN must be a DNS suffix separate from the Kite host, without a wildcard or port")
	}
	if common.AnonymousUserEnabled {
		return nil, errors.New("service access requires authenticated users; disable anonymous access")
	}
	s.domain, s.origin = domain, origin.Scheme+"://"+origin.Host
	go s.run(ctx)
	return s, nil
}

func (s *Server) run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			for id := range s.sessions {
				s.removeLocked(id)
			}
			s.mu.Unlock()
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for id, item := range s.sessions {
				if now.After(item.ExpiresAt) || now.Sub(item.lastUsed) > idleTimeout {
					s.removeLocked(id)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) removeLocked(id string) {
	if item := s.sessions[id]; item != nil {
		item.cancel()
		item.transport.CloseIdleConnections()
		delete(s.sessions, id)
	}
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) newSessionID(target Target) string {
	name := strings.ReplaceAll(target.Name, ".", "-")
	port := "-" + strconv.Itoa(target.Port)
	labelLimit := min(63, 253-1-len(s.domain))
	name = strings.TrimRight(name[:min(len(name), labelLimit-len(port)-1-12)], "-")
	for {
		id := name + port + "-" + randomToken()[:12]
		if _, exists := s.sessions[id]; !exists {
			return id
		}
	}
}

func allowed(user model.User, clusterName string, target Target) bool {
	return user.ID != 0 && user.Enabled &&
		rbac.CanAccessCurrent(user, target.Kind, string(common.VerbGet), clusterName, target.Namespace) &&
		rbac.CanAccessCurrent(user, target.Kind, string(common.VerbPortForward), clusterName, target.Namespace)
}

func (s *Server) Create(c *gin.Context) {
	if s.domain == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "service access is not configured"})
		return
	}
	if c.GetHeader("Origin") != s.origin {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid origin"})
		return
	}
	var request struct {
		Target
		Path string `json:"path"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service access request"})
		return
	}
	target := request.Target
	if request.Path == "" {
		request.Path = "/"
	}
	parsed, pathErr := url.ParseRequestURI(request.Path)
	if pathErr != nil || parsed.IsAbs() || !strings.HasPrefix(request.Path, "/") || strings.HasPrefix(request.Path, "//") || strings.ContainsAny(request.Path, "\\\r\n") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "start path must be a local path beginning with /"})
		return
	}
	if target.Scheme == "" {
		target.Scheme = "http"
	}
	if !target.valid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target; select a namespace, TCP port, and HTTP or HTTPS"})
		return
	}
	user := c.MustGet("user").(model.User)
	cs := c.MustGet("cluster").(*cluster.ClientSet)
	if !allowed(user, cs.Name, target) {
		c.JSON(http.StatusForbidden, gin.H{"error": "get and portforward permissions are required"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	resolved, err := resolve(ctx, cs, target, "")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var item *session
	for id, candidate := range s.sessions {
		if now.After(candidate.ExpiresAt) || now.Sub(candidate.lastUsed) > idleTimeout {
			s.removeLocked(id)
			continue
		}
		if candidate.userID == user.ID && candidate.Cluster == cs.Name && candidate.Target == target && candidate.uid == resolved.uid {
			item = candidate
		}
	}
	if item == nil {
		if len(s.sessions) >= maxSessions {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many service access sessions"})
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		item = &session{ID: s.newSessionID(target), Target: target, Cluster: cs.Name, userID: user.ID, uid: resolved.uid, ExpiresAt: now.Add(sessionLifetime), ctx: ctx, cancel: cancel}
		item.transport = s.newTransport(item)
		s.sessions[item.ID] = item
	}
	ticket := randomToken()
	item.ticket = sha256.Sum256([]byte(ticket))
	item.ticketExpires = now.Add(time.Minute)
	item.ticketPath = request.Path
	item.lastUsed = now
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, gin.H{"id": item.ID, "url": "https://" + item.ID + "." + s.domain + exchangePath + "#" + ticket, "expiresAt": item.ExpiresAt})
}

func (s *Server) List(c *gin.Context) {
	user := c.MustGet("user").(model.User)
	cs := c.MustGet("cluster").(*cluster.ClientSet)
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]session, 0)
	now := time.Now()
	for _, item := range s.sessions {
		if item.userID == user.ID && item.Cluster == cs.Name && now.Before(item.ExpiresAt) && now.Sub(item.lastUsed) <= idleTimeout && allowed(user, item.Cluster, item.Target) {
			items = append(items, session{ID: item.ID, Target: item.Target, Cluster: item.Cluster, ExpiresAt: item.ExpiresAt})
		}
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, items)
}

func (s *Server) Delete(c *gin.Context) {
	if c.GetHeader("Origin") != s.origin {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid origin"})
		return
	}
	user := c.MustGet("user").(model.User)
	cs := c.MustGet("cluster").(*cluster.ClientSet)
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.sessions[c.Param("id")]
	if item == nil || item.userID != user.ID || item.Cluster != cs.Name {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	s.removeLocked(item.ID)
	c.Status(http.StatusNoContent)
}

// Wrap dispatches before Gin so upstream paths never enter Kite's router, redirects, or gzip middleware.
func (s *Server) Wrap(next http.Handler) http.Handler {
	if s.domain == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if hostname, _, err := net.SplitHostPort(host); err == nil {
			host = hostname
		}
		host = strings.TrimSuffix(host, ".")
		if host != s.domain && !strings.HasSuffix(host, "."+s.domain) {
			next.ServeHTTP(w, r)
			return
		}
		id := strings.TrimSuffix(host, "."+s.domain)
		s.serve(w, r, id)
	})
}
