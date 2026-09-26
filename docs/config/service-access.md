# Service access

Kite can open HTTP services on an isolated subdomain while retaining the
application's own login. Service addresses require Kite authorization by default;
an administrator can make an individual address public. This is separate from
the legacy Kubernetes Service Proxy.

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

Click a TCP port in a Service or Pod's overview, select HTTP or HTTPS, a start
path (for example `/management.html`), and optionally a hostname label. The
default label is the resource name and port, for example
`cli-proxy-api-8317.access.example.com`. The label must be unique among all
configured addresses; choose another if it is already in use. Dots in resource
names become hyphens, and long names are shortened to fit DNS limits.

The address belongs to the user who configured it and survives Kite restarts.
Each address has its own access duration (180 minutes by default, at most 525600
minutes). Set it to `0` for no automatic expiration. Private access starts a new
duration on each authorization from Kite. An administrator can enable public
access for an individual address; its duration starts when public access is
enabled. Visitors then need no Kite login or Kite proxy cookie, while the
application's own authentication still applies. Only the owner can configure
the address, and only an administrator can enable or renew public access.
The top-right service access manager lists the user's configured addresses
across clusters, with a count badge when any exist. It can reopen authorized
addresses or remove them. Removing an address ends active connections. To rename an address,
remove it and configure the port again. Sign into the application normally.
Opening an address without an authorized session shows a Kite-styled access
unavailable page; service hosts never redirect to the Kite login page. The
initial ticket exchange shows a matching loading and error state.

A private address uses a short-lived, one-use ticket in the URL fragment to establish a host-only,
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
  A new connection resolves the Service's ready Pod again. Kite preserves the
  ingress `X-Forwarded-For` chain and appends its own hop. Applications must
  trust their configured proxies and log that header to show the visitor IP;
  the TCP peer remains a cluster address. Do not trust client-supplied forwarding
  headers at the ingress.
- Addresses and public expiration times are stored in Kite's database;
  transport sessions remain in memory, so use one Kite replica. Restarting Kite
  requires reopening private access; public addresses reconnect on demand.
  Private sessions expire after their configured duration from the last Kite
  authorization. Public access expires after its configured duration from
  enablement and can be renewed by its administrator. `0` disables automatic
  server expiration, including idle expiration. A private address still needs
  reauthorization if the browser drops its session cookie. There is a
  1,024-session server limit.
- Signing out of the dashboard does not itself revoke an issued proxy session;
  use **Remove address** to revoke it immediately. Disabling the user or removing
  permissions denies subsequent requests; public access also requires the owner
  to remain an administrator. Existing streams end on close/expiry.
- Some apps need their external URL / trusted origin configured. Cross-app CORS
  is not relaxed automatically. `/.kite/access` and the proxy cookie name are
  reserved. Share private access through a Kite resource page so recipients
  create their own authorized address. Public addresses can be shared directly.

This design borrows the separation of app authentication and app transport from
Coder's workspace application proxy, without depending on Coder or its network.
