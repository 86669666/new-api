# 公开 OAuth 部署 / Public OAuth deployment

本文件描述当前代码实际接入的栈。网关自己不签发令牌，也不是把 `/oauth2/*` 原样反代出去。

This describes the stack this tree actually runs. The gateway does not issue tokens itself, and it does not reverse-proxy every `/oauth2/*` path.

## 实际栈 / Actual stack

- 浏览器只访问 new-api 的公开 HTTPS 根地址。该地址必须等于站点 `ServerAddress`，路径为 `/`。
- new-api 只放行下面的白名单。其余 `/oauth2/*` 与 `/.well-known/*` 返回 `404` `{"error":"not_found"}`。
- 私网里的 [Ory Hydra](https://github.com/ory/hydra) `v26.2.0` 提供 Admin API 和令牌签发。示例见 `docker-compose.example.yml`。不要打开 Hydra 开发模式。
- 跳转目标只接受配置好的发行者地址或已登记的客户端回调。请求里的 `Host`、`X-Forwarded-Host`、`Forwarded` 不参与改写。

- Browsers use only the gateway's public HTTPS origin. That origin must equal `ServerAddress` and use path `/`.
- new-api allows only the whitelist below. Any other `/oauth2/*` or `/.well-known/*` path returns `404` `{"error":"not_found"}`.
- A private [Ory Hydra](https://github.com/ory/hydra) `v26.2.0` provides the admin API and token issuance. See `docker-compose.example.yml`. Do not enable Hydra development mode.
- Redirect targets must be the configured issuer or a registered client callback. `Host`, `X-Forwarded-Host`, and `Forwarded` are not used to rewrite them.

## 对外路径 / Public routes

| 方法 Method | 路径 Path | 作用 Role |
| --- | --- | --- |
| `GET` | `/oauth2/auth` | 授权码 + PKCE S256 |
| `POST` | `/oauth2/token` | `authorization_code` 与 `refresh_token` |
| `POST` | `/oauth2/revoke` | 吊销；需单独打开 revocation |
| `GET` | `/.well-known/openid-configuration` | 发现文档。探测用 GET |
| `GET` | `/.well-known/oauth-authorization-server` | 与上一行同一份投影 |
| `GET` | `/.well-known/jwks.json` | 仅 RSA `RS256` 公钥字段 |
| `GET` | `/oauth/provider/login` | 登录页，Hydra `URLS_LOGIN` |
| `GET` | `/oauth/provider/consent` | 同意页，Hydra `URLS_CONSENT` |

其它方法返回 `405` `{"error":"invalid_request"}`。发现文档不要用其它 HTTP 方法探测；`check-discovery.sh` 只发 GET。

Any other method returns `405` `{"error":"invalid_request"}`. Probe discovery with GET. `check-discovery.sh` sends GET only.

发行者错误不会原样返回。已知协议错误码会保留；其余失败是 `503` `temporarily_unavailable`。

Issuer error bodies are not copied through. Known protocol error codes are kept. Other failures are `503` `temporarily_unavailable`.

## 网关环境 / Gateway environment

全部默认关闭。公开面需要四项同时为 `true`，且拓扑校验通过后才会就绪：

All of these default off. The public surface stays unavailable until all four are `true` and topology validation succeeds:

- `OAUTH_USERINFO_ENABLED`
- `OAUTH_PROVIDER_BRIDGE_ENABLED`
- `OAUTH_PROVIDER_REVOCATION_ENABLED`
- `OAUTH_PROVIDER_PUBLIC_ENABLED`

配套地址：

- `OAUTH_USERINFO_ISSUER`：`https://auth.example.com/`（有结尾斜线，路径只能是 `/`）
- `OAUTH_PROVIDER_AUTHORIZATION_URL`：`https://auth.example.com/oauth2/auth`
- `OAUTH_PROVIDER_PUBLIC_BASE_URL`：私网 Hydra 公开端口，例如 `https://hydra-public.example:4444/`。主机名必须不同于发行者和 Admin。Private Hydra public port; that hostname must differ from the issuer and the admin origin.
- `OAUTH_PROVIDER_ADMIN_BASE_URL`：私网 Hydra Admin，例如 `https://hydra-admin.example:4445/`。不要把该端口暴露到公网。Private Hydra admin origin; do not expose that port on a public interface.
- `OAUTH_USERINFO_INTROSPECTION_URL`：`{Admin 源}/admin/oauth2/introspect`
- `OAUTH_USERINFO_AUDIENCE`：资源受众，客户端登记里必须包含它
- `OAUTH_USERINFO_CLIENT_IDS`：允许的公开客户端，逗号分隔
- `FRONTEND_BASE_URL` 必须为空
- 站点 `ServerAddress` 去掉结尾斜线后等于发行者去掉结尾斜线

证书按系统信任库校验。没有跳过校验的开关。私钥、数据库口令和 `SECRETS_SYSTEM` 只从密钥管理注入，不写入仓库。

Certificates use the process trust store. There is no switch to skip verification. Private keys, database passwords, and `SECRETS_SYSTEM` come from a secret manager and are not committed.

本树发现文档公布的范围是：`openid`、`profile`、`email`、`offline_access`、`balance:read`、`usage:read`、`tokens:read`、`tokens:write`。`profile` 必选。`offline_access` 需要 `openid`。客户端在 Hydra 上的 `scope` 只能是这个集合的子集，且 `token_endpoint_auth_method=none`、`subject_type=public`、`skip_consent=false`、授权类型为 `authorization_code` 与 `refresh_token`、响应类型为 `code`。

Discovery from this tree advertises `openid`, `profile`, `email`, `offline_access`, `balance:read`, `usage:read`, `tokens:read`, and `tokens:write`. `profile` is required. `offline_access` requires `openid`. The Hydra client `scope` must be a subset of that set, with `token_endpoint_auth_method=none`, `subject_type=public`, `skip_consent=false`, grants `authorization_code` and `refresh_token`, and response type `code`.

访问令牌按不透明令牌内省。`expires_in` 必须在 1 到 900 秒。本地授权绝对寿命不超过 7 天，并且不超过来源登录会话。桌面回调只允许已登记的环回地址（端口可变）或精确登记的 HTTPS / 已登记自定义 scheme。

Access tokens are opaque and introspected. `expires_in` must be from 1 to 900 seconds. A local grant lasts at most 7 days and no longer than its source login session. Desktop callbacks may use a registered loopback redirect (the port may vary) or an exactly registered HTTPS or custom-scheme redirect.

转发给私网发行者的 Cookie 只有 `__Host-newapi_oauth_(login|consent)_csrf_<数字>`。其它 Cookie 丢弃。

The only cookies forwarded to the private issuer match `__Host-newapi_oauth_(login|consent)_csrf_<digits>`. Every other cookie is dropped.

## 关闭时 / When the switch is off

`OAUTH_PROVIDER_PUBLIC_ENABLED` 不是 `true` 时，白名单路径仍在路由表里，但返回 `404` `not_found`，不会落到前端页面。授权表只在公开面已配置，或表已经存在时才迁移。不要指望关闭开关后路由快照与引入该路由之前的进程完全相同。

When `OAUTH_PROVIDER_PUBLIC_ENABLED` is not `true`, the whitelist routes remain registered and return `404` `not_found` instead of the frontend. Grant tables are migrated only when the public surface is configured or the table already exists. Turning the switch off does not restore the route snapshot from before those routes existed.

## 状态 / Status

匿名 `GET /api/status` 的 `oauth.enabled` 与 `client_features.oauth` 相同。只有公开路由已配置，并且进程启动时的拓扑校验连上了私网 Hydra（客户端文档和发现文档都成功），同时 `ServerAddress` 仍等于发行者、`FRONTEND_BASE_URL` 仍为空，才会是 `true`。此时 `oauth.issuer` 是发行者，`oauth.desktop_client_id` 是 `OAUTH_USERINFO_CLIENT_IDS` 里的第一个客户端。配置不完整、尚未校验、或站点地址后来对不上时，只返回 `{"enabled": false}`，不带发行者或客户端编号。每次读状态不会再探活 Hydra；发行者稍后宕机不会把这个字段打回 `false`，直到进程重启或站点地址不再匹配。`token_usage_logs` 和 `model_metadata` 仍是 `false`。

Anonymous `GET /api/status` sets `oauth.enabled` and `client_features.oauth` to the same value. They are `true` only when the public routes are configured, startup topology validation reached the private Hydra (client documents and discovery both succeeded), `ServerAddress` still equals the issuer, and `FRONTEND_BASE_URL` is still empty. Then `oauth.issuer` is that issuer and `oauth.desktop_client_id` is the first id in `OAUTH_USERINFO_CLIENT_IDS`. Incomplete configuration, a validation that has not succeeded, or a site address that no longer matches returns only `{"enabled": false}`, with no issuer and no client id. A status read does not probe Hydra again; a later issuer outage does not flip the flag until restart or until the site address stops matching. `token_usage_logs` and `model_metadata` stay `false`.

## 不在本文件里声称的事 / Not claimed here

- `VERSION` 可以被环境变量改成某个 git SHA，这不能证明该进程就是该提交的未修改构建。
- 发现文档包含 `tokens:write`，已登记该范围的客户端可以在同意时勾选它。创建密钥的 `POST /api/v1/oauth/tokens` 仍没有生产者。
- 未实现 DPoP 或 mTLS 发送者约束。刷新令牌轮换依赖 Hydra 的默认轮换，本仓库没有单独再做一次发送者约束。
- 用户界面里的已授权应用列表不在这里。

- An environment `VERSION` can be set to a git SHA; that does not prove the process is an unmodified build of that commit.
- Discovery includes `tokens:write`, and a client registered for it can select that scope at consent. `POST /api/v1/oauth/tokens` still has no key producer.
- DPoP and mTLS sender-constrained tokens are not implemented. Refresh rotation depends on Hydra's default rotation; this repository does not add another sender constraint.
- The authorized-applications screen is not part of this deployment note.

对照 OWASP ASVS 5.0.0：`10.4.1` 回调白名单、`10.4.3` 授权码最多 10 分钟、`10.4.4` 仅授权码与刷新、`10.4.6` PKCE 且拒绝 `plain`、`10.4.8` 本地授权绝对过期、`10.4.11` 只登记需要的范围。未满足因此不声称合规的项包括 `10.4.5` 与 `10.4.14`（无 DPoP/mTLS）以及 `10.4.9`（此处没有用户撤销界面）。OAuth 2.0 Cheat Sheet 的开放重定向、PKCE、授权码和受众限制按上述代码路径执行，不表示整份清单都已验收。

OWASP ASVS 5.0.0 controls exercised by this path: `10.4.1` redirect allowlist, `10.4.3` authorization code at most 10 minutes, `10.4.4` authorization code and refresh only, `10.4.6` PKCE with `plain` rejected, `10.4.8` absolute local grant expiry, `10.4.11` only required scopes registered. Not met, so not claimed: `10.4.5` and `10.4.14` (no DPoP or mTLS) and `10.4.9` (no user revoke screen here). The OAuth 2.0 Cheat Sheet items for open redirects, PKCE, the authorization code grant, and audience restriction follow the code paths above; that is not a completed audit of the whole sheet.
