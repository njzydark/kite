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
:root { color-scheme: light; --bg: #fff; --fg: #171717; --muted: #737373; --border: #e5e5e5; --surface: #fafafa; }
@media (prefers-color-scheme: dark) {
  :root { color-scheme: dark; --bg: #0a0a0a; --fg: #fafafa; --muted: #a3a3a3; --border: #262626; --surface: #171717; }
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--fg); font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 24px; }
.card { width: min(100%, 420px); border: 1px solid var(--border); border-radius: 12px; background: var(--surface); padding: 32px; text-align: center; box-shadow: 0 8px 30px #0000000a; }
.mark { display: grid; place-items: center; margin: 0 auto 20px; width: 44px; height: 44px; border-radius: 12px; background: #2563eb; color: #fff; font-weight: 700; font-size: 24px; }
h1 { font-size: 20px; line-height: 1.3; margin: 0 0 8px; }
p { color: var(--muted); margin: 0; }
.foot { font-size: 12px; margin-top: 24px; }
.spinner { width: 26px; height: 26px; margin: 0 auto 20px; border: 3px solid var(--border); border-top-color: #2563eb; border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
`

const exchangeHTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kite · Service access</title><style nonce="{{NONCE}}">{{STYLE}}</style></head><body><main class="card"><div class="mark">K</div><div id="spinner" class="spinner"></div><h1 id="title">Connecting to service</h1><p id="status">Checking your Kite access…</p><p class="foot">Kite · Service access</p></main><script nonce="{{NONCE}}">
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	page := `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kite · Service access</title><style nonce="{{NONCE}}">{{STYLE}}</style></head><body><main class="card"><div class="mark">K</div><h1>{{TITLE}}</h1><p>{{MESSAGE}}</p><p class="foot">Kite · Service access</p></main></body></html>`
	page = strings.NewReplacer("{{NONCE}}", nonce, "{{STYLE}}", accessStyle, "{{TITLE}}", title, "{{MESSAGE}}", message).Replace(page)
	_, _ = io.WriteString(w, page)
}

func sessionMatches(item *session, entry model.ServiceAccess, target Target, now time.Time) bool {
	return !expired(item.ExpiresAt, now) && item.userID == entry.UserID && item.Cluster == entry.Cluster && item.Target == target && item.public == entry.Public && (!entry.Public || entry.PublicUntil == nil || item.ExpiresAt.Equal(*entry.PublicUntil))
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "private, no-store")
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
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
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
