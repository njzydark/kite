package serviceaccess

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zxh326/kite/pkg/model"
)

const exchangeHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Kite</title></head><body><p id="status">Kite</p><script>
const ticket = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
fetch(location.pathname, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ticket})})
.then(async response => { if (!response.ok) throw new Error(await response.text()); const result = await response.json(); location.replace(result.path); })
.catch(error => { document.getElementById('status').textContent = error.message; });
</script></body></html>`

func (s *Server) serve(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "private, no-store")
	s.mu.Lock()
	item := s.sessions[id]
	now := time.Now()
	if item != nil && (now.After(item.ExpiresAt) || now.Sub(item.lastUsed) > idleTimeout) {
		s.removeLocked(id)
		item = nil
	}
	s.mu.Unlock()
	if item == nil {
		http.Error(w, "Service access expired. Open the service again from Kite.", http.StatusGone)
		return
	}
	user, err := model.GetUserByIDCached(uint64(item.userID))
	if err != nil || !allowed(*user, item.Cluster, item.Target) {
		http.Error(w, "Service access is no longer permitted.", http.StatusForbidden)
		return
	}
	if r.URL.Path == exchangePath {
		s.exchange(w, r, item)
		return
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Open this service from Kite to authenticate.", http.StatusUnauthorized)
		return
	}
	digest := sha256.Sum256([]byte(cookie.Value))
	s.mu.Lock()
	valid := item.secret != [32]byte{} && subtle.ConstantTimeCompare(digest[:], item.secret[:]) == 1 && s.sessions[id] == item
	if valid {
		item.lastUsed = now
	}
	s.mu.Unlock()
	if !valid {
		http.Error(w, "Open this service from Kite to authenticate.", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(item.ctx, cancel)
	defer stop()
	defer cancel()
	r = r.WithContext(ctx)
	target := &url.URL{Scheme: item.Scheme, Host: item.Name + "." + item.Namespace + ".svc.cluster.local:" + strconv.Itoa(item.Port)}
	proxy := &httputil.ReverseProxy{
		Transport:     item.transport,
		FlushInterval: -1,
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			p.Out.Host = p.In.Host
			p.SetXForwarded()
			p.Out.Header.Set("X-Forwarded-Proto", "https")
			p.Out.Header.Del("Forwarded")
			p.Out.Header.Del("X-Forwarded-Prefix")
			p.Out.Header.Del("Cookie")
			for _, cookie := range p.In.Cookies() {
				if cookie.Name != cookieName {
					p.Out.AddCookie(cookie)
				}
			}
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Set("Cache-Control", "private, no-store")
			cookies := response.Cookies()
			response.Header.Del("Set-Cookie")
			for _, cookie := range cookies {
				if cookie.Name == cookieName {
					continue
				}
				// Applications may not set cookies for Kite or sibling application hosts.
				cookie.Domain = ""
				response.Header.Add("Set-Cookie", cookie.String())
			}
			if location, err := url.Parse(response.Header.Get("Location")); err == nil && location.Host == target.Host {
				location.Scheme, location.Host = "https", r.Host
				response.Header.Set("Location", location.String())
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Unable to connect to the service. Check its port, protocol, and cluster connection.", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) exchange(w http.ResponseWriter, r *http.Request, item *session) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodGet {
		// The ticket stays in the fragment, never in ingress or application access logs.
		nonce := randomToken()
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, strings.Replace(exchangeHTML, "<script>", "<script nonce=\""+nonce+"\">", 1))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Origin") != "https://"+item.ID+"."+s.domain {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return
	}
	var request struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&request); err != nil || len(request.Ticket) != 64 {
		http.Error(w, "Invalid access ticket", http.StatusBadRequest)
		return
	}
	digest := sha256.Sum256([]byte(request.Ticket))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[item.ID] != item || time.Now().After(item.ticketExpires) || subtle.ConstantTimeCompare(digest[:], item.ticket[:]) != 1 {
		http.Error(w, "Access ticket expired. Open the service again from Kite.", http.StatusUnauthorized)
		return
	}
	secret := randomToken()
	item.secret = sha256.Sum256([]byte(secret))
	item.ticket = [32]byte{}
	item.ticketExpires = time.Time{}
	item.lastUsed = time.Now()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: secret, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: item.ExpiresAt})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"path": item.ticketPath}); err != nil {
		return
	}
}
