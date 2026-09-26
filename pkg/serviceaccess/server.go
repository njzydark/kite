package serviceaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
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
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	cookieName           = "__Host-kite_service_session"
	exchangePath         = "/.kite/access"
	iconPath             = "/.kite/icon.svg"
	defaultAccessMinutes = 3 * 60
	maxAccessMinutes     = 365 * 24 * 60
	maxSessions          = 1024
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
	public        bool
	userID        uint
	uid           string
	secrets       [][32]byte
	ticket        [32]byte
	ticketExpires time.Time
	ticketPath    string
	transport     *http.Transport
	ctx           context.Context
	cancel        context.CancelFunc
}

type Server struct {
	cm       *cluster.ClusterManager
	domain   string
	origin   string
	icon     []byte
	mu       sync.Mutex
	sessions map[string]*session
}

func New(ctx context.Context, cm *cluster.ClusterManager, assets fs.FS) (*Server, error) {
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
	icons, err := fs.Glob(assets, "static/assets/icon-*.svg")
	if err != nil || len(icons) != 1 {
		return nil, errors.New("service access requires the built Kite icon asset")
	}
	s.icon, err = fs.ReadFile(assets, icons[0])
	if err != nil {
		return nil, err
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
				if expired(item.ExpiresAt, now) {
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

func (s *Server) defaultAlias(target Target) string {
	name := strings.ReplaceAll(target.Name, ".", "-")
	port := "-" + strconv.Itoa(target.Port)
	labelLimit := min(63, 253-1-len(s.domain))
	name = strings.TrimRight(name[:min(len(name), labelLimit-len(port))], "-")
	return name + port
}

func (s *Server) validAlias(alias string) bool {
	return len(alias) <= min(63, 253-1-len(s.domain)) && len(validation.IsDNS1123Label(alias)) == 0
}

func allowed(user model.User, clusterName string, target Target) bool {
	return user.ID != 0 && user.Enabled &&
		rbac.CanAccessCurrent(user, target.Kind, string(common.VerbGet), clusterName, target.Namespace) &&
		rbac.CanAccessCurrent(user, target.Kind, string(common.VerbPortForward), clusterName, target.Namespace)
}

func expired(at time.Time, now time.Time) bool {
	return !at.IsZero() && !now.Before(at)
}

func accessExpiry(minutes int, now time.Time) time.Time {
	if minutes == 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(minutes) * time.Minute)
}

func publicExpired(entry model.ServiceAccess, now time.Time) bool {
	return entry.Public && entry.ExpiresInMinutes > 0 && (entry.PublicUntil == nil || !now.Before(*entry.PublicUntil))
}

func samePublicUntil(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func isAdmin(user model.User) bool {
	user.Roles = nil
	return rbac.UserHasRole(user, model.DefaultAdminRole.Name)
}

func setPublicUntil(entry *model.ServiceAccess, now time.Time) {
	entry.PublicUntil = nil
	if entry.Public && entry.ExpiresInMinutes > 0 {
		until := accessExpiry(entry.ExpiresInMinutes, now)
		entry.PublicUntil = &until
	}
}

type createRequest struct {
	Target
	Path             string `json:"path"`
	Alias            string `json:"alias"`
	ExpiresInMinutes *int   `json:"expiresInMinutes"`
	Public           *bool  `json:"public"`
}

func (s *Server) prepareCreate(c *gin.Context) (createRequest, model.User, *cluster.ClientSet, bool) {
	var request createRequest
	var user model.User
	if s.domain == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "service access is not configured"})
		return request, user, nil, false
	}
	if c.GetHeader("Origin") != s.origin {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid origin"})
		return request, user, nil, false
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service access request"})
		return request, user, nil, false
	}
	if request.Path == "" {
		request.Path = "/"
	}
	parsed, pathErr := url.ParseRequestURI(request.Path)
	if pathErr != nil || parsed.IsAbs() || !strings.HasPrefix(request.Path, "/") || strings.HasPrefix(request.Path, "//") || strings.ContainsAny(request.Path, "\\\r\n") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "start path must be a local path beginning with /"})
		return request, user, nil, false
	}
	if request.Scheme == "" {
		request.Scheme = "http"
	}
	if !request.valid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target; select a namespace, TCP port, and HTTP or HTTPS"})
		return request, user, nil, false
	}
	if request.Alias == "" {
		request.Alias = s.defaultAlias(request.Target)
	}
	if !s.validAlias(request.Alias) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hostname; use a single DNS label"})
		return request, user, nil, false
	}
	if request.ExpiresInMinutes != nil && (*request.ExpiresInMinutes < 0 || *request.ExpiresInMinutes > maxAccessMinutes) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expiration must be between 0 and 525600 minutes"})
		return request, user, nil, false
	}
	user = c.MustGet("user").(model.User)
	if request.Public != nil && *request.Public && !isAdmin(user) {
		c.JSON(http.StatusForbidden, gin.H{"error": "only administrators can publish a service"})
		return request, user, nil, false
	}
	cs := c.MustGet("cluster").(*cluster.ClientSet)
	if !allowed(user, cs.Name, request.Target) {
		c.JSON(http.StatusForbidden, gin.H{"error": "get and portforward permissions are required"})
		return request, user, nil, false
	}
	checkCtx, cancelCheck := context.WithTimeout(c.Request.Context(), 20*time.Second)
	_, checkErr := resolve(checkCtx, cs, request.Target, "")
	cancelCheck()
	if checkErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": checkErr.Error()})
		return request, user, nil, false
	}
	return request, user, cs, true
}

func (s *Server) Create(c *gin.Context) {
	request, user, cs, ok := s.prepareCreate(c)
	if !ok {
		return
	}
	target := request.Target
	s.mu.Lock()
	var entry model.ServiceAccess
	created := false
	err := model.DB.Where("user_id = ? AND cluster = ? AND namespace = ? AND kind = ? AND name = ? AND port = ?", user.ID, cs.Name, target.Namespace, target.Kind, target.Name, target.Port).First(&entry).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		minutes := defaultAccessMinutes
		if request.ExpiresInMinutes != nil {
			minutes = *request.ExpiresInMinutes
		}
		entry = model.ServiceAccess{ID: request.Alias, UserID: user.ID, Cluster: cs.Name, Namespace: target.Namespace, Kind: target.Kind, Name: target.Name, Port: target.Port, Scheme: target.Scheme, Path: request.Path, ExpiresInMinutes: minutes}
		if request.Public != nil {
			entry.Public = *request.Public
		}
		setPublicUntil(&entry, time.Now())
		if err := model.DB.Create(&entry).Error; err != nil {
			s.mu.Unlock()
			c.JSON(http.StatusConflict, gin.H{"error": "hostname already in use; choose another alias"})
			return
		}
		created = true
	} else if err != nil {
		s.mu.Unlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to load service access"})
		return
	}
	minutes := entry.ExpiresInMinutes
	if request.ExpiresInMinutes != nil {
		minutes = *request.ExpiresInMinutes
	}
	public := entry.Public
	if request.Public != nil {
		public = *request.Public
	}
	if public && !isAdmin(user) {
		s.mu.Unlock()
		c.JSON(http.StatusForbidden, gin.H{"error": "only administrators can publish a service"})
		return
	}
	if !created && (entry.Scheme != target.Scheme || entry.Path != request.Path || entry.ExpiresInMinutes != minutes || entry.Public != public || public) {
		entry.Scheme, entry.Path = target.Scheme, request.Path
		entry.ExpiresInMinutes, entry.Public = minutes, public
		setPublicUntil(&entry, time.Now())
		if err := model.DB.Save(&entry).Error; err != nil {
			s.mu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to update service access"})
			return
		}
		s.removeLocked(entry.ID)
	}
	s.mu.Unlock()
	if entry.Public {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusCreated, gin.H{"id": entry.ID, "url": s.publicURL(entry), "hostname": "https://" + entry.ID + "." + s.domain, "expiresAt": entry.PublicUntil})
		return
	}
	item, ticket, err := s.issue(c.Request.Context(), cs, user, entry)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.mu.Lock()
	expiresAt := expiryJSON(item.ExpiresAt)
	s.mu.Unlock()
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, gin.H{"id": item.ID, "url": s.ticketURL(item.ID, ticket), "hostname": "https://" + item.ID + "." + s.domain, "expiresAt": expiresAt})
}

func expiryJSON(at time.Time) *time.Time {
	if at.IsZero() {
		return nil
	}
	return &at
}

func (s *Server) ticketURL(id, ticket string) string {
	return "https://" + id + "." + s.domain + exchangePath + "#" + ticket
}

func (s *Server) publicURL(entry model.ServiceAccess) string {
	return "https://" + entry.ID + "." + s.domain + entry.Path
}

func (s *Server) issue(ctx context.Context, cs *cluster.ClientSet, user model.User, entry model.ServiceAccess) (*session, string, error) {
	target := Target{Namespace: entry.Namespace, Kind: entry.Kind, Name: entry.Name, Port: entry.Port, Scheme: entry.Scheme}
	resolveCtx, cancelResolve := context.WithTimeout(ctx, 20*time.Second)
	defer cancelResolve()
	resolved, err := resolve(resolveCtx, cs, target, "")
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var current model.ServiceAccess
	if err := model.DB.Where("id = ? AND user_id = ?", entry.ID, user.ID).First(&current).Error; err != nil || current.Cluster != entry.Cluster || current.Namespace != entry.Namespace || current.Kind != entry.Kind || current.Name != entry.Name || current.Port != entry.Port || current.Scheme != entry.Scheme || current.Path != entry.Path || current.ExpiresInMinutes != entry.ExpiresInMinutes || current.Public != entry.Public || !samePublicUntil(current.PublicUntil, entry.PublicUntil) {
		return nil, "", errors.New("service access configuration changed; open it again")
	}
	if publicExpired(current, time.Now()) {
		return nil, "", errors.New("public service access has expired")
	}
	now := time.Now()
	item := s.sessions[entry.ID]
	if item != nil && (expired(item.ExpiresAt, now) || item.uid != resolved.uid || item.public != entry.Public) {
		s.removeLocked(entry.ID)
		item = nil
	}
	if item == nil {
		if len(s.sessions) >= maxSessions {
			return nil, "", errors.New("too many service access sessions")
		}
		lifetime, cancel := context.WithCancel(context.Background())
		item = &session{ID: entry.ID, Target: target, Cluster: cs.Name, userID: user.ID, uid: resolved.uid, public: entry.Public, ctx: lifetime, cancel: cancel}
		item.transport = s.newTransport(item)
		s.sessions[item.ID] = item
	}
	if entry.Public {
		if entry.PublicUntil != nil {
			item.ExpiresAt = *entry.PublicUntil
		} else {
			item.ExpiresAt = time.Time{}
		}
		return item, "", nil
	}
	item.ExpiresAt = accessExpiry(entry.ExpiresInMinutes, now)
	ticket := randomToken()
	item.ticket = sha256.Sum256([]byte(ticket))
	item.ticketExpires = now.Add(time.Minute)
	item.ticketPath = entry.Path
	return item, ticket, nil
}

func (s *Server) List(c *gin.Context) {
	s.list(c, true)
}

func (s *Server) ListAll(c *gin.Context) {
	s.list(c, false)
}

func (s *Server) list(c *gin.Context, currentClusterOnly bool) {
	user := c.MustGet("user").(model.User)
	query := model.DB.Where("user_id = ?", user.ID)
	if currentClusterOnly {
		query = query.Where("cluster = ?", c.MustGet("cluster").(*cluster.ClientSet).Name)
	}
	var entries []model.ServiceAccess
	if err := query.Order("cluster, namespace, name, port").Find(&entries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to list service access"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]gin.H, 0, len(entries))
	now := time.Now()
	for _, entry := range entries {
		target := Target{Namespace: entry.Namespace, Kind: entry.Kind, Name: entry.Name, Port: entry.Port, Scheme: entry.Scheme}
		_, clusterErr := s.cm.GetClientSet(entry.Cluster)
		authorized := clusterErr == nil && allowed(user, entry.Cluster, target) && (!entry.Public || isAdmin(user))
		item := s.sessions[entry.ID]
		var expiresAt *time.Time
		if item != nil && !expired(item.ExpiresAt, now) {
			expiresAt = expiryJSON(item.ExpiresAt)
		}
		items = append(items, gin.H{"id": entry.ID, "cluster": entry.Cluster, "namespace": entry.Namespace, "kind": entry.Kind, "name": entry.Name, "port": entry.Port, "scheme": entry.Scheme, "path": entry.Path, "hostname": "https://" + entry.ID + "." + s.domain, "expiresAt": expiresAt, "expiresInMinutes": entry.ExpiresInMinutes, "public": entry.Public, "publicUntil": entry.PublicUntil, "authorized": authorized})
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, items)
}

func (s *Server) Delete(c *gin.Context) {
	s.delete(c, true)
}

func (s *Server) DeleteAny(c *gin.Context) {
	s.delete(c, false)
}

func (s *Server) Update(c *gin.Context) {
	if c.GetHeader("Origin") != s.origin {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid origin"})
		return
	}
	var request struct {
		ExpiresInMinutes *int  `json:"expiresInMinutes"`
		Public           *bool `json:"public"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.ExpiresInMinutes == nil || request.Public == nil || *request.ExpiresInMinutes < 0 || *request.ExpiresInMinutes > maxAccessMinutes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide public and an expiration between 0 and 525600 minutes"})
		return
	}
	user := c.MustGet("user").(model.User)
	var entry model.ServiceAccess
	if err := model.DB.Where("id = ? AND user_id = ?", c.Param("id"), user.ID).First(&entry).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service access not found"})
		return
	}
	if *request.Public {
		target := Target{Namespace: entry.Namespace, Kind: entry.Kind, Name: entry.Name, Port: entry.Port, Scheme: entry.Scheme}
		if !isAdmin(user) || !allowed(user, entry.Cluster, target) {
			c.JSON(http.StatusForbidden, gin.H{"error": "administrator and resource permissions are required to publish a service"})
			return
		}
		cs, err := s.cm.GetClientSet(entry.Cluster)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "cluster not found"})
			return
		}
		checkCtx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
		_, err = resolve(checkCtx, cs, target, "")
		cancel()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := model.DB.Where("id = ? AND user_id = ?", entry.ID, user.ID).First(&entry).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service access not found"})
		return
	}
	if entry.ExpiresInMinutes == *request.ExpiresInMinutes && entry.Public == *request.Public {
		c.Status(http.StatusNoContent)
		return
	}
	entry.ExpiresInMinutes, entry.Public = *request.ExpiresInMinutes, *request.Public
	setPublicUntil(&entry, time.Now())
	if err := model.DB.Save(&entry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to update service access"})
		return
	}
	s.removeLocked(entry.ID)
	c.Status(http.StatusNoContent)
}

func (s *Server) delete(c *gin.Context, currentClusterOnly bool) {
	if c.GetHeader("Origin") != s.origin {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid origin"})
		return
	}
	user := c.MustGet("user").(model.User)
	var entry model.ServiceAccess
	if err := model.DB.Where("id = ? AND user_id = ?", c.Param("id"), user.ID).First(&entry).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service access not found"})
		return
	}
	if currentClusterOnly && entry.Cluster != c.MustGet("cluster").(*cluster.ClientSet).Name {
		c.JSON(http.StatusNotFound, gin.H{"error": "service access not found"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := model.DB.Delete(&entry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to delete service access"})
		return
	}
	s.removeLocked(entry.ID)
	c.Status(http.StatusNoContent)
}

func (s *Server) Open(c *gin.Context) {
	if s.domain == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "service access is not configured"})
		return
	}
	user := c.MustGet("user").(model.User)
	var entry model.ServiceAccess
	if err := model.DB.Where("id = ? AND user_id = ?", c.Param("id"), user.ID).First(&entry).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service access not found"})
		return
	}
	target := Target{Namespace: entry.Namespace, Kind: entry.Kind, Name: entry.Name, Port: entry.Port, Scheme: entry.Scheme}
	if !allowed(user, entry.Cluster, target) {
		c.JSON(http.StatusForbidden, gin.H{"error": "get and portforward permissions are required"})
		return
	}
	cs, err := s.cm.GetClientSet(entry.Cluster)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "cluster not found"})
		return
	}
	if entry.Public {
		if !isAdmin(user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "only administrators can renew public access"})
			return
		}
		if publicExpired(entry, time.Now()) {
			s.mu.Lock()
			if err := model.DB.Where("id = ? AND user_id = ?", entry.ID, user.ID).First(&entry).Error; err != nil || !entry.Public {
				s.mu.Unlock()
				c.JSON(http.StatusNotFound, gin.H{"error": "public service access not found"})
				return
			}
			if !publicExpired(entry, time.Now()) {
				s.mu.Unlock()
				c.Header("Cache-Control", "no-store")
				c.Redirect(http.StatusFound, s.publicURL(entry))
				return
			}
			setPublicUntil(&entry, time.Now())
			err := model.DB.Save(&entry).Error
			s.removeLocked(entry.ID)
			s.mu.Unlock()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to renew public access"})
				return
			}
		}
		c.Header("Cache-Control", "no-store")
		c.Redirect(http.StatusFound, s.publicURL(entry))
		return
	}
	_, ticket, err := s.issue(c.Request.Context(), cs, user, entry)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, s.ticketURL(entry.ID, ticket))
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
