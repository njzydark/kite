# Service access

Kite can open HTTP services on an isolated subdomain while retaining both Kite
access control and the application's own login. This is separate from the legacy
Kubernetes Service Proxy. It does not expose unauthenticated public ports.

## Minimal configuration with an existing Traefik ingress

With one existing Kite ingress host, one replica, anonymous access disabled, and
Traefik's default TLSStore certificate, add only:

```yaml
serviceAccess:
  domain: access.example.com
```

The chart infers HTTPS `HOST` from the single ingress host and adds the wildcard
route. An explicit `host` takes precedence; multiple ingress hosts require it.
Keep the existing ingress and TLSStore configuration. Add `*.access.example.com`
to the default certificate and point its wildcard DNS at the same ingress.
A certificate for `*.example.com` does not cover this additional DNS level.

## Configuration

Use a dedicated DNS suffix that does not contain the Kite dashboard host. Point
`*.access.example.com` at the same ingress as Kite and provide a wildcard TLS
certificate. A certificate for `*.example.com` does not cover these app hosts.

```yaml
replicaCount: 1
host: https://kite.example.com
anonymousUserEnabled: false
serviceAccess:
  domain: access.example.com
ingress:
  enabled: true
  className: traefik
  hosts:
    - host: kite.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: kite-tls
      hosts: [kite.example.com]
    - secretName: service-access-tls
      hosts: ['*.access.example.com']
```

The chart adds a wildcard ingress rule. Outside Helm, set
`SERVICE_ACCESS_DOMAIN=access.example.com` and `HOST=https://kite.example.com`,
and route the wildcard host to Kite with its Host header unchanged. Proxy paths
start at `/`, even when the dashboard uses `KITE_BASE`. Allow WebSocket upgrades
and appropriate streaming timeouts in the ingress. Upstream HTTPS certificates
are verified; self-signed certificates are not silently accepted.

## Permissions and use

Grant both `get` and `portforward` on `services` and/or `pods`, scoped to the
appropriate clusters and namespaces. Existing viewers do not gain access.
Administrators with wildcard verbs already have the permission. For example:

```yaml
resources: [services, pods]
verbs: [get, portforward]
clusters: [Homelab]
namespaces: [default]
```

Click a TCP port in a Service or Pod's overview, select HTTP or HTTPS and a start
path (for example `/management.html`), then choose **Open service**. Each user and
target has an isolated hostname. Sign into the application normally. The same
dialog lists that port's access sessions and can close them, including active
connections. Reopening an active target reuses its hostname and application cookies.

Hostnames use the resource name, port, and a random 12-character suffix, for
example `cli-proxy-api-8317-a7c9e2b4d610.access.example.com`. Dots in resource names
become hyphens, and long names are shortened to fit DNS limits. The suffix keeps
sessions isolated across users, clusters, and namespaces; it is not a credential.

A short-lived, one-use ticket in the URL fragment establishes a host-only,
Secure, HttpOnly Kite proxy cookie. Tickets are not sent in request URLs. Kite
removes only its reserved `__Host-kite_service_session` cookie before forwarding;
application cookies and Authorization headers remain intact. App response cookies
are restricted to the current app host. Kite checks the user and current resource
permissions on each new HTTP request (user state may be cached for 30 seconds).
Applications remain responsible for their own authorization and CSRF protection.

## Connections and limits

- In-cluster connections use Pod IPs. Cluster Agent connections use the existing
  TCP tunnel. Kubeconfig-only remote clusters use Kubernetes SPDY Port Forward;
  their credentials need `get` on Pods/Services, `list` on Pods for Services, and
  `create` on `pods/portforward`. Network policy still applies.
- Services must have selectors and ready Pods; ExternalName and selectorless
  Services are not supported. Named target ports are resolved against the Pod.
  Pod access accepts declared TCP container ports. Kubernetes resource UIDs are
  pinned so replacing an object does not silently grant access to its replacement.
- HTTP methods, request bodies, WebSockets, and streamed responses pass through.
  Failed connections are not automatically replayed, especially write requests.
  A new connection resolves the Service's ready Pod again.
- Sessions are in memory: use one Kite replica. Restarting Kite closes access.
  Sessions close after 30 minutes without new HTTP requests, or after 8 hours,
  including long-lived streams. There is a 1,024-session server limit.
- Signing out of the dashboard does not itself revoke an issued proxy session;
  use **Close access** to revoke it immediately. Disabling the user or removing
  permissions denies subsequent requests; existing streams end on close/expiry.
- Some apps need their external URL / trusted origin configured. Cross-app CORS
  is not relaxed automatically. `/.kite/access` and the proxy cookie name are
  reserved. Share the Kite resource page rather than an app hostname: recipients
  must create their own authorized access.

This design borrows the separation of app authentication and app transport from
Coder's workspace application proxy, without depending on Coder or its network.
