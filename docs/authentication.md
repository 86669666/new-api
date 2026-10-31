# 用户鉴权与登录会话

面板鉴权采用短期 Access Token、HttpOnly Refresh Cookie 与服务端登录会话控制面的组合。面板请求不再依赖 Gin session，也不再要求 `New-Api-User` 请求头。

## 鉴权模型

- Access Token 是有效期 15 分钟的 JWT，只保存在浏览器内存中，通过 `Authorization: Bearer <token>` 发送。
- Refresh Token 是随机不透明值，有效期最长 30 天。浏览器只通过 `HttpOnly`、`SameSite=Strict` Cookie 持有它；服务端仅保存 HMAC 摘要，并在每次刷新时轮换。
- `new_api_has_session` 是 Refresh Cookie 的会话提示，值恒为 `1`，`Path=/`、非 `HttpOnly`，与 Refresh Cookie 同时写入、同时清除、同一过期时间。它只声明"曾签发过 Refresh Cookie"，不含任何凭据，也不参与任何鉴权判定；伪造它唯一的效果是自费一次注定失败的 refresh。它存在的原因是 Refresh Cookie 被 `HttpOnly` 和 `Path=/api/user/auth` 双重限制，`/` 上的页面无法判断自己是否匿名，否则每次冷启动都要发一次注定 401 的 refresh，而该请求还会占用按 IP 计数的 `CriticalRateLimit` 配额。
- `user_sessions` 是登录会话控制面，记录设备、IP、登录方式、最后活跃时间、到期时间和撤销状态。数据库中的 Session 状态是最终权威；撤销传播速度取决于下文所述的 Redis 拓扑。
- 用户的密码、状态、角色或安全因子发生安全相关变化时，`auth_version` 会递增并使旧登录会话失效。订阅带来的分组升降级只刷新授权缓存，不会退出任何登录设备。
- Redis 缓存保存用户鉴权快照和登录会话快照。版本栅栏和撤销 tombstone 防止旧缓存重新授权；Session 快照使用跟随 `SYNC_FREQUENCY` 的短 TTL，缓存未命中或未启用 Redis 时回退到数据库校验。

`SESSION_SECRET` 用于派生 Access Token、Security Proof、Refresh Token 摘要和 AuthFlow 摘要的不同用途密钥。生产环境及多节点部署必须在所有节点配置相同的高强度随机值；更换该值会使现有登录、临时鉴权流程和 Security Proof 全部失效。

## 多节点 Redis 拓扑

多节点部署必须共用同一主数据库。登录 Session、账户级活跃 Session 上限和签发窗口计数都以数据库为权威，因此这些限制在应用节点间全局生效。Redis 中的 Session Hash（包含 `revoking`/`revoked` tombstone）只是缓存，其 TTL 为 Session 剩余寿命与有效 `SYNC_FREQUENCY` 中的较小值；`SYNC_FREQUENCY` 默认及非法值回退均为 `60` 秒。读取缓存不会续期，过期后会按 SID 回源数据库。延迟完成的 active 缓存回写只能使用其数据库观察窗口尚未消耗的 TTL，不能在撤销 tombstone 到期后重新启动一个完整缓存周期。

| Redis 部署方式 | Session 状态传播 | 限流语义 |
| --- | --- | --- |
| 所有节点共享 Redis | 正常撤销和版本发布通过同一缓存即时传播 | Redis 限流额度在所有节点间共享 |
| 每个节点使用独立 Redis | 最迟在该节点 Session 缓存 TTL 到期后回源收敛，即不超过有效 `SYNC_FREQUENCY`；版本轮换期间，新 Token 在持有旧缓存的节点上可能短暂返回 401 | 每个节点独立计数，集群总额度最坏约为单节点阈值乘以节点数 |
| 不使用 Redis | 每次 Session 校验直接读取数据库 | 使用各节点的内存限流器，额度同样按节点独立 |

`SYNC_FREQUENCY` 越大，独立 Redis 部署的陈旧窗口越长；值越小，每个活跃 SID 在每个节点上回源数据库的频率越高。默认配置下，持续活跃的 Session 每个节点最多约每 60 秒增加一次数据库主键点查。共享 Redis 时，撤销 tombstone 和版本发布仍保持即时传播。

所有节点必须使用相同的 `SESSION_SECRET`。当多个节点连接同一个 Redis 时，还必须使用相同的 `CRYPTO_SECRET`，否则节点生成的缓存键摘要不一致，无法正确共享缓存。上述保证只覆盖登录 Session 鉴权的有界陈旧语义；限流额度及其他 Redis 缓存仍会受到 Redis 拓扑影响，不能据此认为整个控制面与拓扑无关。

## 浏览器接口

登录成功后，密码登录、2FA、Passkey、OAuth、WeChat 和 Telegram 登录均返回统一数据：

```json
{
  "success": true,
  "data": {
    "access_token": "...",
    "token_type": "Bearer",
    "access_expires_at": 1730000000,
    "user": {},
    "session": {
      "sid": "...",
      "current": true,
      "login_method": "password",
      "ip": "...",
      "user_agent": "...",
      "created_at": 1730000000,
      "last_active_at": 1730000000,
      "expires_at": 1732592000
    }
  }
}
```

会话相关接口：

| 接口 | 鉴权 | 用途 |
| --- | --- | --- |
| `POST /api/user/auth/refresh` | Refresh Cookie；Secure 模式附加 Origin 校验 | 轮换 Refresh Token 并签发新的 Access Token |
| `POST /api/user/auth/logout` | Refresh Cookie；Secure 模式附加 Origin 校验，可同时携带 Bearer | 撤销当前登录会话并清除 Cookie |
| `GET /api/user/sessions` | Bearer | 查看当前鉴权版本的有效登录会话，当前会话优先，最多 100 条 |
| `DELETE /api/user/sessions/:sid` | Bearer | 撤销指定登录会话，包括当前会话 |
| `POST /api/user/sessions/revoke-others` | Bearer | 保留当前会话并撤销其他会话 |

客户端内存中已有会话时，应在 refresh/logout 请求中发送 `X-Auth-Session: <sid>`。Refresh Cookie 与该 SID 不一致时，两个端点都返回 `409 AUTH_SESSION_MISMATCH`，且不会轮换、撤销或清除任何会话；客户端先通过 refresh 清除本标签页的旧 SID、恢复 Cookie 当前对应的会话，再重试 logout。冷启动尚无内存会话时可以省略该请求头。

并发使用同一个 Refresh Token 时，服务端通过确定性轮换恢复同一个后继 Token，多个浏览器标签页不会因丢失“胜者”响应而被迫退出。最近一代 Refresh Token 在短暂容错窗口结束后再次出现会撤销对应会话；无法识别的更早代或随机 Token 只会被拒绝，不会允许攻击者凭猜测踢掉会话。

前端使用 Web Locks 串行化同一浏览器配置文件中的刷新，并通过 BroadcastChannel（不支持时回退到 `storage` 事件）仅同步会话标识和登录/退出事件；Access Token 与 Refresh Token 都不会通过跨标签页消息传递或持久化到 Web Storage。

前端将冷启动状态与登录状态分开管理。网络或服务端临时故障允许后续导航重试 refresh；服务端确认 Refresh Cookie 无效时才进入已完成的匿名状态。内存 SID 与 Cookie SID 不一致时，客户端清除旧内存身份并在不携带旧 SID 的情况下重试一次。

公开页面的冷启动会先读 `new_api_has_session`：提示不存在且内存中没有任何身份时跳过 refresh，直接按匿名渲染，且**不**把这次跳过记为已完成的匿名判定——跳过只是延后，不是服务端结论。会依据鉴权结果做跳转的位置（受保护路由与登录页）不看提示，内存为空时一律回源。因此提示缺失但 Refresh Cookie 有效的用户（该 Cookie 上线前建立的会话，或只清理了 `/` 站点数据的浏览器）会在公开页显示为匿名，并在进入上述任一位置时自动恢复登录态，不需要重新输入密码。提示因服务端撤销而过期时，那次 refresh 返回 401 并在同一响应里清除提示，浪费的请求只发生一次。

## Session 签发限额与保留策略

服务端在所有登录方式的统一 Session 签发出口执行两级账户限制：

- `USER_SESSION_ACTIVE_LIMIT`（默认 `50`）：单用户未过期且状态为 active 的 Session 上限。达到上限时新登录返回 `409 AUTH_SESSION_LIMIT`。
- `USER_SESSION_ISSUANCE_LIMIT`（默认 `100`）和 `USER_SESSION_ISSUANCE_WINDOW_SECONDS`（默认 `86400`）：统计窗口内该用户创建的所有 Session，包含已撤销和旧鉴权版本的记录。达到上限时返回 `429 AUTH_SESSION_ISSUANCE_LIMIT`。
- 这两次计数与插入不加跨数据库锁；极端并发登录可能出现少量超额，但计数失败会拒绝签发，不会降级放行。

升级时已经超过活跃上限的账户不会被自动下线或挤掉旧会话；限制只作用于后续的新 Session 签发。

`USER_SESSION_REVOKED_RETENTION_DAYS`（默认 `7`）控制 revoked 行的审计保留期。签发计数依赖窗口内的行仍存在，因此签发窗口不得超过 revoked 保留期。如果配置超出，启动时会记录告警并将实际窗口钳制到保留期，避免提前删除 revoked 行导致限流计数被低估。

定时清理即使发现 `expires_at` 已过期，也不会删除 `created_at` 仍落在实际签发窗口内的行；尚未达到 revoked 保留期的撤销记录同样会继续保留。这样在扩大配置窗口时，过期清理不会静默削弱签发计数或审计保留。

活跃数量会计入状态仍为 active 但 `user_auth_version` 已过期的异常残留行，而设备列表只展示当前鉴权版本。因此遇到 `AUTH_SESSION_LIMIT` 时，应优先在仍已登录的设备上执行“撤销其他会话”，该操作会同时清理不可见的旧版本 active 行；没有可用设备时可使用密码重置撤销所有会话。密码重置不会清空签发窗口计数。

仅 master 节点每小时分批删除过期 Session 和超过保留期的 revoked Session。`USER_SESSION_HOURLY_ALERT_THRESHOLD`（默认 `5000`）只在最近一小时全局签发量异常时记录告警，不会形成可被滥用的全站登录拒绝开关。

## Refresh/Logout 的 Origin 校验

refresh/logout 的 Origin 防护与 Refresh Cookie 的 Secure 模式绑定：

- 未配置 `SESSION_COOKIE_SECURE` 或显式设为 `false` 时，Refresh Cookie 可用于本地 HTTP，refresh/logout 的 OriginGuard 关闭，并且不得配置 `SESSION_COOKIE_TRUSTED_URL`。这使 `http://localhost` 上不同端口的 Rsbuild/Vite 开发代理可以正常转发请求。该模式仅用于可信的本地开发环境，不应暴露到公网。
- `SESSION_COOKIE_SECURE=true` 时，Refresh Cookie 仅通过 HTTPS 发送，同时启用严格 OriginGuard。`POST /api/user/auth/refresh` 和 `POST /api/user/auth/logout` 会校验浏览器的 `Origin`；缺少 `Origin` 时只接受合法的单一 `Referer` 作为回退。允许来源包括请求自身的精确 Origin，以及 `SESSION_COOKIE_TRUSTED_URL` 中配置的精确 Origin。

Secure 模式的 Origin 校验不信任客户端直接发送的 `X-Forwarded-Proto`。TLS 在反向代理终止时，应将面板的公开 HTTPS Origin 明确写入 `SESSION_COOKIE_TRUSTED_URL`。

`SESSION_COOKIE_TRUSTED_URL` 现在具有明确的新语义：它是 refresh/logout Cookie 端点的可信 Origin 列表，不是 CORS 白名单。配置规则如下：

- 仅在 `SESSION_COOKIE_SECURE=true` 时配置；多个值用英文逗号分隔。
- 每项必须是精确的 HTTPS Origin，例如 `https://panel.example.com` 或 `https://panel.example.com:8443`。
- 不接受通配符、路径、查询参数、用户信息或域名后缀匹配。
- 不会修改 relay、旧 billing dashboard、`/api/usage/token` 或 `/api/log/token` 的 CORS 行为。浏览器使用 `sk-` key 直连 relay 的场景保持不变。

本地 HTTP 开发示例（OriginGuard 关闭）：

```env
SESSION_SECRET=<local-random-value>
SESSION_COOKIE_SECURE=false
# SESSION_COOKIE_TRUSTED_URL 不得设置
```

生产 HTTPS 示例（OriginGuard 开启）：

```env
SESSION_SECRET=<high-entropy-random-value>
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_TRUSTED_URL=https://panel.example.com,https://admin.example.com
```

该开关只控制面板 Refresh Cookie 和 refresh/logout 的 OriginGuard，不会修改 relay、旧 billing dashboard、`/api/usage/token` 或 `/api/log/token` 的 CORS 行为。

## 可信代理与 IP 限流

Gin 默认会信任所有代理提供的客户端 IP 请求头。本项目改为兼顾常见反代拓扑和公网直连安全的三态配置：

- 未配置、空字符串或纯空白的 `TRUSTED_PROXIES` 默认信任 `127.0.0.0/8`、`::1`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 和 `fc00::/7`，并输出启动告警。该默认值覆盖同机 Nginx、Docker Compose 和常见内网反代；公网直连地址不在列表中，其伪造的 `X-Forwarded-For` 会被忽略。
- `TRUSTED_PROXIES=none`（大小写不敏感且必须单独使用）启用严格直连模式，不信任任何代理，`ClientIP()` 只使用 TCP 直连地址。
- 其他非空值按英文逗号解析为代理 IP/CIDR，并完全替代默认列表。应填写反向代理自身的地址而不是客户端网段；非法 CIDR、空列表或将 `none` 与其他值混用都会阻止服务启动。

Gin 只在请求的直连来源属于可信代理时解析客户端 IP 请求头，并从转发链右侧向左寻找首个非可信地址。因此常见 Nginx `$proxy_add_x_forwarded_for` 链中的公网客户端地址会阻止更左侧的伪造前缀生效。默认信任私网的残余风险是：能够从同一私网直接访问应用的其他机器或容器仍可伪造这些请求头；需要消除此风险时应使用 `none` 或配置精确代理地址。

Redis 限流使用原子 Lua 固定窗口，替代旧的近似滑动窗口 List 实现。这是有意的语义变化：窗口边界两侧可分别打满一次，极短时间内通过量最高约为配置值的两倍。例如 `20 次/20 分钟` 在边界可通过约 40 次。帐户级 Session 上限和签发窗口继续控制数据库增长；如未来需要严格抑制边界突发，需单独迁移为 ZSET 滑动窗口。

用户级模型成功请求限流仍使用原有 Redis List 近似滑动窗口，但列表时间戳统一写为 UTC。滚动升级期间，旧节点写入的本地时间字符串和新节点写入的 UTC 字符串无法从格式上区分，可能在一个模型限流窗口内临时误放行或误拒绝。所有节点升级完成并经过一个完整窗口后会自然收敛；本次升级不会切换 Key 或主动删除现有列表。

开放注册仍会受 Critical IP 限流保护，但分布式 IP 多账号攻击不能仅靠 IP 限流阻止。公网开放注册的部署应同时启用 Turnstile 和邮箱验证；更强的设备或多维风控需作为独立安全项目设计。

## PAT 调用契约

面板 PAT（个人访问令牌）通过 `Authorization: Bearer <pat>` 发送，也兼容单值 `Authorization: <pat>`；不接受 URL 参数。`New-Api-User` 不参与鉴权。

- 令牌格式为 `nap_` 加 43 位 base62 随机串（约 256 bit）。明文只在创建时返回一次，数据库只保存 SHA-256 摘要，该摘要同时作为审计记录中的 `token_ref`。
- 每个用户最多 20 个令牌，存放在 `user_access_tokens` 表。创建时必须选择 scope 和过期时间：默认 30 天，最短 1 小时，也允许永不过期（界面会提示风险）。过期令牌立即失效，超过保留期后由 master 节点清理。
- scope 形如 `resource:action`。个人权限（资料、API 令牌、用量、钱包、账户安全）和部分后台权限由令牌目录定义；受 Casbin 保护的后台权限直接复用管理员权限矩阵的 resource 与 action。只能授予自己当前拥有的权限，并且每个请求都会重新读取角色和权限：撤回某项管理员权限后，携带该 scope 的令牌立即失去对应能力。
- 每条面板路由都必须声明所需 scope。未声明的路由一律拒绝（403 `ACCESS_TOKEN_ROUTE_UNDECLARED`），scope 不足返回 403 `ACCESS_TOKEN_SCOPE_DENIED`，令牌过期返回 401 `ACCESS_TOKEN_EXPIRED`。
- PAT 不能创建、改名或撤销 PAT，也不能管理登录会话；这些接口只接受浏览器登录会话。
- PAT 可以完成二次验证，Proof 绑定到该令牌，并且令牌必须持有该操作对应的 scope：`channel.key.read` 需要 `channel:secret_view`，`admin.user.*` 需要 `user:write`，本人的密码、2FA、Passkey、账号绑定和注销需要 `account_security:write`。PAT 不能使用 OAuth 验证方式。
- 通过 PAT 完成的安全变更（如修改密码、2FA、Passkey）会让该用户的所有浏览器登录会话下线，令牌本身保持可用。
- 用户被禁用期间，其令牌全部不可用，重新启用后恢复；注销或删除用户时，其令牌被删除。
- 最后使用时间和 IP 每个令牌每分钟最多更新一次；更新失败不影响请求。

## 临时鉴权流程与二次验证

OAuth state、2FA pending、Passkey ceremony、Telegram bind 等临时状态存放在 `auth_flows`。客户端只持有随机 `flow_token`，数据库仅保存 HMAC 摘要；流程具有用途、provider、intent、用户和登录会话绑定，并且只能原子消费一次。OAuth 注册的 affiliate code 也随登录 AuthFlow 保存。

标准 OAuth 绑定回调由 popup 通过同源 `postMessage` 交给 opener；只有 opener 使用自身内存中的 Bearer 调用后端绑定接口。Telegram 绑定先由已登录前端创建绑定 AuthFlow，再让 widget 回调携带路径中的 `flow_token`，回调时会重新确认原登录会话仍有效。Telegram 的已签名 widget assertion 也会登记为一次性凭据，重复回放会被拒绝。

敏感操作使用有效期 1 分钟的 `X-Security-Proof`：

- `channel.key.read`：查看渠道密钥；
- `passkey.register`：注册 Passkey；
- `passkey.delete`：删除 Passkey。

管理员对其他用户执行的高风险操作同样要求 Proof，且 scope 的 context 绑定被操作用户，签发给某个用户的 Proof 不能改用于另一个用户或另一种动作：

- `admin.user.delete`（`{"user_id"}`）：`DELETE /api/user/:id` 与 `POST /api/user/manage` 的 `delete`；
- `admin.user.manage`（`{"user_id","action"}`，action 为 `disable` / `enable` / `promote` / `demote`）：`POST /api/user/manage`；额度调整 `add_quota` 不要求 Proof；
- `admin.user.update`（`{"user_id"}`）：`PUT /api/user/` 在请求包含新密码或 `admin_permissions` 时要求；仅修改显示名、分组、备注不要求；
- `admin.user.create`（`{"role"}`）：`POST /api/user/` 创建管理员角色时要求；创建普通用户不要求；
- `admin.user.passkey.reset`（`{"user_id"}`）：`DELETE /api/user/:id/reset_passkey`；
- `admin.user.2fa.disable`（`{"user_id"}`）：`DELETE /api/user/:id/2fa`；
- `admin.user.binding.clear`（`{"user_id","binding_type"}` 或 `{"user_id","provider_id"}`）：`DELETE /api/user/:id/bindings/:binding_type` 与 `DELETE /api/user/:id/oauth/bindings/:provider_id`。

这些 `admin.user.*` scope 只对管理员及以上角色签发；已启用 2FA 或 Passkey 的管理员必须使用其中之一，未启用时回退到密码（或已绑定的 OAuth）重新认证；密码登录被关闭时不接受密码验证。通过 PAT 调用上述接口时，令牌需持有 `user:write` 并完成二次验证；旧版令牌不能调用。

Proof 同时绑定用户、登录会话、用户鉴权版本、会话版本和 scope，不能跨用户、跨会话或跨用途复用。对 PAT 而言，Proof 绑定的“登录会话”就是令牌本身。

启用了 2FA 的用户注册 Passkey 时，register begin 与 finish 都必须携带有效的 `passkey.register` Proof；finish 会在消费一次性 AuthFlow 之前重新验证 Proof。未启用 2FA 的首次 Passkey 注册不要求该请求头。

## 升级注意事项

- 旧 `session` Cookie 不再使用；升级后现有面板登录会失效，用户需要重新登录。
- 数据库迁移会新增 `user_sessions`、`auth_flows`、`external_identity_claims` 和 `users.auth_version`，并为已有用户初始化鉴权版本、回填 Telegram 账号唯一归属；若历史数据中同一 Telegram ID 已绑定多个用户，迁移会拒绝继续启动，需先消除歧义。
- 数据库迁移会为 Session 签发计数和分批清理新增索引；已有 `user_sessions` 很大时应为首次启动预留维护窗口。
- `user_sessions.previous_refresh_hash` 会从定长 `char(64)` 迁移为 `varchar(64)`。应用会兼容读取历史定长字段留下的空格填充；迁移后的目标结构必须保持幂等，连续启动不应反复执行列类型变更。
- 仅 master 节点定时清理过期登录会话、超过配置保留期的 revoked 会话和已过保留期的 AuthFlow。
- 未配置 `TRUSTED_PROXIES` 时会兼容信任回环和常见私网代理；使用公网负载均衡器、`100.64.0.0/10`、链路本地地址或自定义 CNI 网段的部署仍需显式配置。需要严格忽略所有转发头时设置为 `none`。
- Redis 限流从近似滑动窗口改为原子固定窗口，存在明确的边界双倍突发语义。
- 用户级模型成功请求限流的 UTC 时间戳在滚动升级期间存在一个窗口的混合格式过渡，期间可能临时误放行或误拒绝。
- 自建客户端应按新的 AuthBundle、`flow_token` 和 Security Proof 契约升级；PAT 客户端可直接移除 `New-Api-User`。
- 旧版 PAT 保留在 `users.access_token` 中，自新版首次启动起 30 天内照常可用，之后自动停用并返回 401 `ACCESS_TOKEN_LEGACY_RETIRED`。停用日期记录在 `options` 表的 `LegacyAccessTokenRetireAt`，由服务端写入，不能通过设置接口修改。过渡期内不能再生成旧版令牌，但可以撤销。
- 删除了 `/api/user/token*` 接口，改为 `/api/user/access_tokens`。
- 降级到旧版本后，新令牌不可用；未撤销的旧版令牌会重新可用，因为旧版本不认停用日期。

## 可选外部 OAuth Provider 部署契约

本节描述以 Hydra 为授权服务器、由 new-api 提供公开 OAuth 入口的部署要求，与上文面板 Access Token、Refresh Cookie 和 PAT 的生命周期分开。它不是可直接运行的 Hydra 配置，也不表示任何现有部署已通过生产验收。开关示例见 [`.env.example`](../.env.example)；仅填写样例不会创建客户端注册或验证 PKCE。

### 授权服务器与管理边界

- 固定 Hydra 版本及镜像摘要，不使用 `--dev`。使用独立、持久化的数据库，并为该版本另行验证迁移、备份恢复及服务启动顺序；不得用临时测试数据库代替。
- `URLS_SELF_ISSUER` 必须是对外 HTTPS 根地址，例如 `https://auth.example.com/`。`URLS_LOGIN` 和 `URLS_CONSENT` 分别使用同一 issuer 下的 `/oauth/provider/login`、`/oauth/provider/consent`，不是后台决策 API `/api/oauth/provider/*`。
- 本实现要求 `ServerAddress` 与 issuer 一致（比较时忽略末尾斜杠），`FRONTEND_BASE_URL` 为空。`OAUTH_PROVIDER_PUBLIC_BASE_URL` 指向 Hydra 公共服务的 HTTPS 根地址，其 host 必须不同于对外 issuer，且不能使用 Admin 地址。公开入口启用前还需满足已有 userinfo、provider bridge、revocation 配置及客户端注册校验；不要通过放宽校验或关闭 TLS 验证绕过启动失败。
- Hydra Admin 仅供私有管理边界访问，使用可信 TLS，不能发布到公开入口。系统密钥、数据库凭据和管理凭据由仓库外的密钥管理机制提供，限制读取权限；不得写入样例、日志、截图或版本库。
- 公开客户端必须强制 S256 PKCE：部署要求 `OAUTH2_PKCE_ENFORCED_FOR_PUBLIC_CLIENTS=true`，并验证授权码兑换拒绝缺失或错误的 verifier。客户端使用精确注册的回调地址并验证 issuer、state/nonce；不能以公开客户端身份或 discovery 中出现 S256 代替服务端强制校验。
- 部署要求 `STRATEGIES_ACCESS_TOKEN=opaque`。OAuth access token 与 OIDC ID token 用途不同；发现文档中的 ID token 签名算法不能证明 access token 是 opaque，也不能用 ID token 代替 API access token。
- 操作人员必须依据固定 Hydra 版本的配置契约，显式选择并记录 access token 与 refresh token 的 TTL、单位、生效配置及该版本的刷新/过期语义。本文不提供未经验证的数值默认值；不得借用上文面板会话或 PAT 的 TTL。需要可运行配置时，先补齐该固定版本的配置依据，再核对实际生效值。

拓扑、客户端及 discovery 校验由 [`service/oauth_public.go`](../service/oauth_public.go) 的 `NewOAuthPublic`、`ValidateTopology`、`CurrentOAuthDesktopStatus` 和 `metadata` 实现；环境变量装配见 [`service/oauth_provider.go`](../service/oauth_provider.go)。上述 Hydra 部署要求仍需部署者验证，不能从 gateway 配置校验推定全部已生效。

### 公开客户端注册与回调核对

公开客户端在 Hydra Admin 上的登记形态是：`token_endpoint_auth_method=none`、`subject_type=public`，`grant_types` 恰为 `authorization_code` 与 `refresh_token`，`response_types` 恰为 `code`，`skip_consent=false`，audience 恰为 gateway 配置的 audience。公开客户端不使用 client secret。登记 scopes 只能来自支持列表且包含 `profile`。授权与换票路径仍要求 S256 PKCE。Hydra 的 `OAUTH2_PKCE_ENFORCED_FOR_PUBLIC_CLIENTS` 仍是部署要求；Admin 客户端文档没有单独的 PKCE 字段，同步请求也不会写入 client secret。

控制台 `oauth_public_clients` 的创建、更新和删除由 [`CommitOAuthPublicClient`](../service/oauth_public_client.go) 写入。仅当进程内 provider bridge 与 public 服务同时生效（`OAuthProviderBridge.Public()` 非空，因此 revocation 也已启用）时，同一次本地事务才会在提交前调用 Hydra Admin：启用的客户端 `PUT /admin/clients/{id}`，若不存在则 `POST /admin/clients`；删除或 `enabled=false` 时 `DELETE /admin/clients/{id}`，404 视为已经删除。Hydra 回显必须与本次 client_id、名称、redirect、scope、grant、response type、audience 和 `skip_consent=false` 一致，事务才提交。Hydra 4xx 时 API 返回 HTTP 409 与 `OAUTH_PUBLIC_CLIENT_SYNC_REJECTED`；超时、连接失败或 5xx 返回 HTTP 503 与 `OAUTH_PUBLIC_CLIENT_SYNC_UNAVAILABLE`。这两种失败都回滚本地行，响应的 `success` 为 false，且不会出现 `hydra_synced: true`。任一开关未生效时不访问 Hydra，只提交本地行，成功响应里 `hydra_synced` 为 false。进程在 Hydra 已接受之后、本地提交之前退出时，Hydra 可能超前于本地行；接口不会报告成功，下一次成功的管理写入会再次对齐。同步不修改 `OAUTH_USERINFO_CLIENT_IDS`，公开代理仍只接受该允许列表中的客户端。外部身份提供商配置不是这类客户端注册入口。

预设 Boxnai Desktop 与 Cherry Studio 的 scopes 为 `openid`、`profile`、`offline_access`、`tokens:write`。`balance:read`、`usage:read`、`tokens:read` 仍可选。`NormalizePublicOAuthClient` 仍强制包含 `profile`。

下表对应 [`validOAuthProviderRedirect`](../service/oauth_provider.go) 与 [`OAuthPublic.client`](../service/oauth_public.go)。后者会用每个登记 URI 自身调用校验，因此登记值也必须满足规则。示例域名及回环端口仅说明协议，不指向真实部署。

| 回调类型 | 当前匹配规则 | 示例与边界 |
| --- | --- | --- |
| HTTPS | 解析后为 `https` 且 hostname 非空；请求 URI 与登记的原始字符串完全相等 | 如 `https://client.example.com/oauth/callback`；不做通配符展开、路径前缀匹配或大小写等价替换 |
| Boxnai | 原始请求与登记值均须恰为 `boxnai://oauth/callback` | 不接受其他 host、端口、路径、查询参数或大小写变体 |
| Cherry Studio 兼容回调 | 解析后的 scheme 为 `cherrystudio`、Host 恰为 `oauth`、Path 恰为 `/callback`，且请求与登记的原始字符串完全相等 | 基本形式为 `cherrystudio://oauth/callback`；代码没有额外禁止查询参数，但任何查询串也必须与登记值原样相同。不能套用 Boxnai 的固定字符串规则，也不承诺其他原始字符串的大小写等价 |
| HTTP 数字回环 | hostname 只能是 `127.0.0.1` 或 `::1`，请求与登记地址相同；登记和请求均需显式有效端口（1–65535）。比较时只允许替换数字回环端口，其余路径与查询保持精确登记匹配 | 例如登记 `http://127.0.0.1:49152/oauth/callback`，请求可使用同地址的 `:49153`；IPv6 示例为 `http://[::1]:49152/oauth/callback`。不接受无端口登记、`localhost`、非回环地址或地址族切换 |

所有类型都拒绝用户信息、opaque URI 和 fragment（包括空的 `#`）；任意其他自定义 scheme 不在允许范围内。不要把 URI 解析后的字段比较理解成对整个原始 URI 的规范化或大小写折叠，也不要把回环端口例外扩大为路径、查询或 host 的通配匹配。

通用登记通过不等于桌面状态 ready。`CurrentOAuthDesktopStatus` 还要求显式选择的 `OAUTH_PROVIDER_DESKTOP_CLIENT_ID` 对应有效登记、包含精确 `boxnai://oauth/callback`，以及 `openid profile offline_access tokens:write` 四个核心 scopes；公开服务和拓扑也必须有效。仅有回环或 Cherry Studio 回调的客户端不会因此满足桌面状态要求。可选 scopes 只按该已验证客户端的实际登记范围发布，不扩大同意或授权。

本表保留下文 OWASP 引用所要求的受限重定向、事务绑定和 PKCE 控制；HTTP 回环是原生客户端回调的限定规则，不是降低 issuer、管理连接或面板会话 TLS 要求的建议。它不构成新的运行验证或合规认证。

### 公开路径与关闭边界

[`SetOAuthPublicRouter`](../router/oauth_public_router.go) 只开放以下精确入口，不是对 Hydra 任意路径的透明代理：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/oauth2/auth` | 授权码授权 |
| POST | `/oauth2/token` | `authorization_code`、`refresh_token` |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/.well-known/oauth-authorization-server` | OAuth discovery |
| GET | `/.well-known/jwks.json` | 签名公钥 |
| GET | `/oauth2/error` | 本地固定错误响应，不透传上游错误页 |

公开代理默认关闭；关闭时上述入口返回 404，其他被保留的非白名单公开路径也返回 404，已启用入口的方法不匹配返回 405。`/oauth2/revoke` 由 [`SetOAuthProviderRouter`](../router/oauth_provider_router.go) 的独立 revocation 开关控制，不因本节 public 开关关闭而自动关闭。这里描述 HTTP 边界，不承诺路由注册或数据库迁移快照不变。

Discovery 和授权跳转校验使用配置的 issuer；不得根据请求 `Host` 或 `X-Forwarded-Host` 生成 issuer 或放宽跳转目标。`service/oauth_public.go` 的 `metadata`、`oauthPublicJSON` 及授权跳转校验约束公开元数据、允许的错误码和目标地址；上游原始错误内容不作为公开错误返回。

### 安全依据与验收范围

部署与客户端验收应保留以下控制（参考资料查阅于 2026-10-27）：

- [OWASP Authentication：凭据仅经 TLS 传输](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#transmit-passwords-only-over-tls-or-other-strong-transport)：登录和凭据传输保持受验证的加密通道。
- [OWASP Session Management：Transport Layer Security](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#transport-layer-security)：整个会话使用 HTTPS，保留安全 Cookie 和服务端会话失效控制，不因反向代理部署而绕过。
- [OWASP OAuth2：Essential Basics 与 PKCE](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html#oauth-20-essential-basics)：限制重定向目标，校验 issuer 与事务绑定，使用 S256 并拒绝 PKCE 降级；保留正常登录、同意和回调校验。

这些引用不是完整 OWASP 合规声明。样例、`/api/status` 的 readiness 或一次本地协议成功，都不能证明生产数据库耐久性、密钥管理、自动启动或重启恢复。`client_features.model_metadata` 表示可选元数据投影契约受支持，不表示声明非空或 OAuth/部署健康；该含义不随本节要求改变。生产持久性、有效 TTL 和 opaque 策略应分别留存不含凭据的部署验收记录。
