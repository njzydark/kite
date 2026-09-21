# 服务访问

Kite 可以通过独立子域名打开 Service/Pod 的 HTTP 服务，同时保留 Kite 权限校验和服务自己的登录。该功能独立于旧版 Kubernetes Service Proxy，不会开放匿名端口。

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

点击 Service 或 Pod 概览中的 TCP 端口，选择 HTTP/HTTPS 和起始路径（例如 `/management.html`），点击“打开服务”。每位用户、每个目标都有独立域名；在服务页面正常登录即可。端口弹窗会列出对应访问会话，可点击“关闭访问”立即终止连接。再次打开尚未过期的目标会复用域名及服务 Cookie。

域名采用“资源名 + 端口 + 12 位随机后缀”，例如 `cli-proxy-api-8317-a7c9e2b4d610.kite.njzydark.com`。资源名中的点会转为连字符，过长名称会按 DNS 长度限制截短。随机后缀用于隔离不同用户、集群和命名空间的会话，本身不是登录凭证。

一次性短时票据放在 URL fragment 中，兑换仅当前域名有效的 Secure、HttpOnly Kite 代理 Cookie；票据不会进入请求 URL。转发时只剥离保留的 `__Host-kite_service_session` Cookie，保留服务的 Cookie 和 Authorization。服务响应中的 Cookie 被限制在当前域名。每个新 HTTP 请求检查用户和当前资源权限（用户状态最多缓存 30 秒）。服务自身仍负责业务权限和 CSRF 防护。

## 连接方式与边界

- 本集群直接连接 Pod IP；Cluster Agent 集群复用 TCP 隧道；仅 kubeconfig 接入的远程集群使用 Kubernetes SPDY Port Forward。后者的集群凭据需要 Pods/Services 的 `get`、Service 选 Pod 所需的 Pods `list`、以及 `pods/portforward` 的 `create` 权限。网络策略仍然生效。
- Service 必须有 selector 和就绪 Pod，不支持 ExternalName 或无 selector 的 Service。命名 targetPort 从 Pod 解析。Pod 仅支持已声明的 TCP 容器端口。会话绑定资源 UID，资源重建后需要重新打开。
- 支持 HTTP 方法、请求体、WebSocket 和流式响应。不会自动重放失败请求，尤其是写请求；新建连接会重新选择就绪 Pod。
- 会话保存在内存中，仅支持单副本，Kite 重启后失效。30 分钟没有新 HTTP 请求或达到 8 小时后关闭，包括长连接。全局最多 1,024 个会话。
- 退出 Kite 主站不会立即撤销已签发的代理会话，可使用“关闭访问”立即撤销。禁用用户或撤销权限会拒绝后续请求；已建立的流在关闭或超时后结束。
- 部分服务仍需设置外部 URL/可信来源；不会自动放宽跨服务 CORS。`/.kite/access` 和代理 Cookie 名称为保留字段。分享 Kite 资源页面即可，接收者需要用自己的权限打开服务。

实现参考 Coder 应用代理中认证与传输分离的设计，不依赖 Coder 或其网络组件。
