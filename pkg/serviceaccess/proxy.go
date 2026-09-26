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

const accessStyle = `
:root { color-scheme: light; --bg: oklch(1 0 0); --fg: oklch(0.141 0.005 285.823); --card: oklch(1 0 0); --muted: oklch(0.552 0.016 285.938); --border: oklch(0.92 0.004 286.32); --primary: oklch(0.55 0.22 235); }
@media (prefers-color-scheme: dark) {
  :root { color-scheme: dark; --bg: oklch(0.141 0.005 285.823); --fg: oklch(0.985 0 0); --card: oklch(0.21 0.006 285.885); --muted: oklch(0.705 0.015 286.067); --border: oklch(1 0 0 / 10%); --primary: oklch(0.65 0.18 235); }
  .brand img { filter: invert(1); }
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: var(--bg); color: var(--fg); font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
.page { width: min(100%, 448px); }
.brand { display: flex; align-items: center; justify-content: center; gap: 8px; margin-bottom: 32px; font-size: 24px; font-weight: 700; }
.brand img { width: 40px; height: 40px; }
.card { padding: 24px; border: 1px solid var(--border); border-radius: 8px; background: var(--card); text-align: center; box-shadow: 0 1px 2px #0000000d; }
h1 { margin: 0; font-size: 20px; line-height: 1.4; font-weight: 600; }
p { margin: 8px 0 0; color: var(--muted); }
.spinner { width: 48px; height: 48px; margin: 0 auto 20px; border: 2px solid transparent; border-bottom-color: var(--primary); border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
`

const exchangeHTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kite · Service access</title><link rel="icon" type="image/svg+xml" href="/.kite/icon.svg"><style nonce="{{NONCE}}">{{STYLE}}</style></head><body><div class="page"><div class="brand"><img src="/.kite/icon.svg" alt=""><span>Kite</span></div><main class="card"><div id="spinner" class="spinner"></div><h1 id="title">Connecting to service</h1><p id="status">Checking your Kite access…</p></main></div><script nonce="{{NONCE}}">
const zh = navigator.language.toLowerCase().startsWith('zh');
if (zh) { document.getElementById('title').textContent = '正在连接服务'; document.getElementById('status').textContent = '正在验证 Kite 访问权限…'; }
const ticket = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
if (!ticket) {
  document.getElementById('spinner').remove();
  document.getElementById('title').textContent = zh ? '无法访问' : 'Access unavailable';
  document.getElementById('status').textContent = zh ? '请从 Kite 中重新打开该服务。' : 'Open this service again from Kite.';
} else {
  fetch(location.pathname, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ticket})})
    .then(async response => { if (!response.ok) throw new Error(); const result = await response.json(); location.replace(result.path); })
    .catch(() => { document.getElementById('spinner').remove(); document.getElementById('title').textContent = zh ? '无法访问' : 'Access unavailable'; document.getElementById('status').textContent = zh ? '授权已失效，请从 Kite 中重新打开该服务。' : 'Access expired. Open this service again from Kite.'; });
}
</script></body></html>`

func accessDenied(w http.ResponseWriter, r *http.Request, status int) {
	if r.Method != http.MethodGet {
		http.Error(w, "Service access unavailable", status)
		return
	}
	zh := strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "zh")
	title, message := "Access unavailable", "Open this service from Kite to authorize access."
	if zh {
		title, message = "无法访问", "请从 Kite 中打开该服务并完成授权。"
	}
	nonce := randomToken()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'nonce-"+nonce+"'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	page := `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kite · Service access</title><link rel="icon" type="image/svg+xml" href="/.kite/icon.svg"><style nonce="{{NONCE}}">{{STYLE}}</style></head><body><div class="page"><div class="brand"><img src="/.kite/icon.svg" alt=""><span>Kite</span></div><main class="card"><h1>{{TITLE}}</h1><p>{{MESSAGE}}</p></main></div></body></html>`
	page = strings.NewReplacer("{{NONCE}}", nonce, "{{STYLE}}", accessStyle, "{{TITLE}}", title, "{{MESSAGE}}", message).Replace(page)
	_, _ = io.WriteString(w, page)
}

func sessionMatches(item *session, entry model.ServiceAccess, target Target, now time.Time) bool {
	return !expired(item.ExpiresAt, now) && item.userID == entry.UserID && item.Cluster == entry.Cluster && item.Target == target && item.public == entry.Public && (!entry.Public || entry.PublicUntil == nil || item.ExpiresAt.Equal(*entry.PublicUntil))
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "private, no-store")
	if r.URL.Path == iconPath {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Length", strconv.Itoa(len(s.icon)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(s.icon)
		}
		return
	}
	var entry model.ServiceAccess
	if err := model.DB.Where("id = ?", id).First(&entry).Error; err != nil {
		accessDenied(w, r, http.StatusGone)
		return
	}
	target := Target{Namespace: entry.Namespace, Kind: entry.Kind, Name: entry.Name, Port: entry.Port, Scheme: entry.Scheme}
	owner, err := model.GetUserByIDCached(uint64(entry.UserID))
	if err != nil || !allowed(*owner, entry.Cluster, target) || (entry.Public && (!isAdmin(*owner) || publicExpired(entry, time.Now()))) {
		accessDenied(w, r, http.StatusForbidden)
		return
	}
	s.mu.Lock()
	item := s.sessions[id]
	now := time.Now()
	if item != nil && !sessionMatches(item, entry, target, now) {
		s.removeLocked(id)
		item = nil
	}
	s.mu.Unlock()
	if item == nil && entry.Public {
		cs, err := s.cm.GetClientSet(entry.Cluster)
		if err == nil {
			item, _, err = s.issue(r.Context(), cs, *owner, entry)
		}
		if err != nil {
			accessDenied(w, r, http.StatusServiceUnavailable)
			return
		}
	}
	if item == nil {
		accessDenied(w, r, http.StatusGone)
		return
	}
	if r.URL.Path == exchangePath {
		if entry.Public {
			accessDenied(w, r, http.StatusNotFound)
			return
		}
		s.exchange(w, r, item)
		return
	}
	if !entry.Public {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			accessDenied(w, r, http.StatusUnauthorized)
			return
		}
		digest := sha256.Sum256([]byte(cookie.Value))
		s.mu.Lock()
		valid := false
		if s.sessions[id] == item {
			for _, secret := range item.secrets {
				valid = subtle.ConstantTimeCompare(digest[:], secret[:]) == 1 || valid
			}
		}
		s.mu.Unlock()
		if !valid {
			accessDenied(w, r, http.StatusUnauthorized)
			return
		}
	}
	s.mu.Lock()
	active := s.sessions[id] == item && !expired(item.ExpiresAt, time.Now())
	s.mu.Unlock()
	if !active {
		accessDenied(w, r, http.StatusGone)
		return
	}
	s.forward(w, r, item)
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, item *session) {
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(item.ctx, cancel)
	defer stop()
	defer cancel()
	r = r.WithContext(ctx)
	upstream := &url.URL{Scheme: item.Scheme, Host: item.Name + "." + item.Namespace + ".svc.cluster.local:" + strconv.Itoa(item.Port)}
	proxy := &httputil.ReverseProxy{
		Transport:     item.transport,
		FlushInterval: -1,
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(upstream)
			p.Out.Host = p.In.Host
			p.Out.Header["X-Forwarded-For"] = p.In.Header["X-Forwarded-For"]
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
			if location, err := url.Parse(response.Header.Get("Location")); err == nil && location.Host == upstream.Host {
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
		w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, strings.NewReplacer("{{NONCE}}", nonce, "{{STYLE}}", accessStyle).Replace(exchangeHTML))
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
	if len(item.secrets) >= 16 {
		item.secrets = item.secrets[1:]
	}
	item.secrets = append(item.secrets, sha256.Sum256([]byte(secret)))
	item.ticket = [32]byte{}
	item.ticketExpires = time.Time{}
	cookieExpiry := item.ExpiresAt
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: secret, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: cookieExpiry})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"path": item.ticketPath}); err != nil {
		return
	}
}
