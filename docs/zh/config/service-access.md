# 服务访问

Kite 可以通过独立子域名打开 Service/Pod 的 HTTP 服务。服务域名默认需要 Kite 授权；管理员可以将某个域名单独设为公开访问。服务自身的登录仍然生效。该功能独立于旧版 Kubernetes Service Proxy。

## 已有 Traefik 入口的最小配置

如果已经配置了唯一的 Kite Ingress 主域名、单副本、非匿名访问，以及 Traefik 默认 TLSStore 证书，Kite values 只需新增：

```yaml
serviceAccess:
  domain: kite.njzydark.com
```

Chart 会从现有的唯一 Ingress 主域名推导 HTTPS `HOST` 并添加服务通配路由。已有 `host` 配置优先；多个主域名时需显式指定 `host`。无需重复配置 `replicaCount`、已有 Ingress 或另建 TLS Secret。将 `*.kite.njzydark.com` 加入现有默认 TLSStore 的证书，并让该通配 DNS 指向同一入口即可。`*.njzydark.com` 不能覆盖再下一层的服务域名。

## 配置

为服务分配专用后缀，将 `*.access.example.com` 指向 Kite 的入口并配置通配 TLS 证书。Kite 主站不能位于该后缀下；`*.example.com` 证书不能覆盖这些服务子域名。

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

Chart 自动添加通配 Ingress 规则。非 Helm 部署设置 `SERVICE_ACCESS_DOMAIN=access.example.com` 和 `HOST=https://kite.example.com`，将通配域名转发到 Kite 并保留 Host。即使主站设置了 `KITE_BASE`，服务仍从 `/` 访问。入口需要允许 WebSocket Upgrade，并为流式响应配置合适的超时。上游 HTTPS 会校验证书，不会自动忽略自签名证书错误。

## 权限与操作

在指定集群和命名空间为 `services` 或 `pods` 授予 `get` 和 `portforward` 权限。原有只读用户不会自动获得服务访问权限；包含通配操作权限的管理员可以使用。例如：

```yaml
resources: [services, pods]
verbs: [get, portforward]
clusters: [Homelab]
namespaces: [default]
```

点击 Service 或 Pod 概览中的 TCP 端口，选择 HTTP/HTTPS、起始路径（例如 `/management.html`）和可选的域名前缀，再点击“打开服务”。默认域名前缀是资源名和端口，例如 `cli-proxy-api-8317.kite.njzydark.com`。域名前缀在所有已配置服务中必须唯一；冲突时可以自定义。资源名中的点会转为连字符，过长名称会按 DNS 长度限制截短。

域名归配置它的用户所有，Kite 重启后仍保留。每个域名独立设置访问有效期，默认 180 分钟，最大 525600 分钟；`0` 表示不自动过期。私人访问每次从 Kite 授权后重新计时。管理员可为单个域名开启公开访问，公开有效期从开启时计时。访客无需登录 Kite，也无需 Kite 代理 Cookie；服务自己的鉴权仍然生效。仅配置者可以管理该域名，且只有管理员可以开启或续期公开访问。

右上角“管理服务访问”展示该用户跨集群配置的域名，有配置时显示数量角标；有权限的域名可重新打开，所有本人配置的域名均可移除。移除会立即结束活动连接；修改域名需先移除再重新配置。未获得有效访问会话时，服务域名只显示 Kite 风格的“无法访问”页面，不跳转到 Kite 登录页。私人访问的初次授权页面使用一致的加载和失败状态。

私人访问的一次性短时票据放在 URL fragment 中，兑换仅当前域名有效的 Secure、HttpOnly Kite 代理 Cookie；票据不会进入请求 URL。转发时只剥离保留的 `__Host-kite_service_session` Cookie，保留服务的 Cookie 和 Authorization。服务响应中的 Cookie 被限制在当前域名。每个新 HTTP 请求检查配置者和当前资源权限（用户状态最多缓存 30 秒）。服务自身仍负责业务权限和 CSRF 防护。

## 连接方式与边界

- 本集群直接连接 Pod IP；Cluster Agent 集群复用 TCP 隧道；仅 kubeconfig 接入的远程集群使用 Kubernetes SPDY Port Forward。后者的集群凭据需要 Pods/Services 的 `get`、Service 选 Pod 所需的 Pods `list`、以及 `pods/portforward` 的 `create` 权限。网络策略仍然生效。
- Service 必须有 selector 和就绪 Pod，不支持 ExternalName 或无 selector 的 Service。命名 targetPort 从 Pod 解析。Pod 仅支持已声明的 TCP 容器端口。会话绑定资源 UID，资源重建后需要重新打开。
- 支持 HTTP 方法、请求体、WebSocket 和流式响应。不会自动重放失败请求，尤其是写请求；新建连接会重新选择就绪 Pod。
- 域名配置及公开访问截止时间保存在 Kite 数据库中；传输会话仍在内存中，因此仅支持单副本。Kite 重启后私人访问需重新授权，公开访问会按需重新连接。私人访问从上次 Kite 授权起按配置时间到期；公开访问从开启时起按配置时间到期，可由管理员续期。`0` 表示服务端不自动过期（包括空闲过期）；如果浏览器清除了私人访问的会话 Cookie，仍需重新授权。全局最多 1,024 个会话。
- 退出 Kite 主站不会立即撤销已签发的代理会话，可使用“移除域名”立即撤销。禁用配置者或撤销资源权限会拒绝后续请求；公开访问还要求配置者保持管理员身份。已建立的流在移除或超时后结束。
- 部分服务仍需设置外部 URL/可信来源；不会自动放宽跨服务 CORS。`/.kite/access` 和代理 Cookie 名称为保留字段。私人访问应分享 Kite 资源页面，由接收者用自己的权限创建域名；公开域名可以直接分享。

实现参考 Coder 应用代理中认证与传输分离的设计，不依赖 Coder 或其网络组件。
