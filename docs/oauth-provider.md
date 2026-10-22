# OAuth public proxy

This proxy is off unless `OAUTH_PUBLIC_PROXY_ENABLED=true`. Turning it on does not change the status payload (`oauth.enabled` and `client_features.oauth` stay false) and does not create API keys. Login and consent still require a dashboard session. The browser is not sent to an upstream host taken from the request.

The example in `deploy/oauth/docker-compose.yml` is not applied by this repository. An operator runs it separately, after supplying secrets and certificates outside the git tree.

## Flags

All four flags are required, in this order, and each must be exactly `true`:

1. `OAUTH_USERINFO_ENABLED`
2. `OAUTH_PROVIDER_BRIDGE_ENABLED`
3. `OAUTH_PROVIDER_REVOCATION_ENABLED`
4. `OAUTH_PUBLIC_PROXY_ENABLED`

`OAUTH_PROVIDER_UPSTREAM_URL` is Hydra's HTTPS public origin, for example `https://hydra:4444` on the compose network. It must not be the admin origin and must not be the public issuer host. `OAUTH_PROVIDER_ADMIN_BASE_URL` is the Hydra admin origin, for example `https://hydra:4445`. `OAUTH_USERINFO_INTROSPECTION_URL` must be that admin origin plus `/admin/oauth2/introspect`.

`OAUTH_USERINFO_ISSUER` must equal Hydra `URLS_SELF_ISSUER` exactly, including a trailing slash when one is configured. The console setting `ServerAddress` must be HTTPS, must not include a path, and must use the same host and port as that issuer. `OAUTH_PROVIDER_AUTHORIZATION_URL` must be that public origin plus `/oauth2/auth`.

An empty flag means off. `TRUE`, `1`, and any other string fail startup. When the public proxy flag is off, `/oauth2/auth` and `/.well-known/*` stay on the existing frontend route. `/oauth2/revoke` stays the existing not-found response until revocation is enabled. No schema migration is added by the proxy.

## What is published

While the proxy is on, only these methods and paths are proxied:

| Method | Path |
| --- | --- |
| GET | `/oauth2/auth` |
| POST | `/oauth2/token` |
| GET | `/.well-known/openid-configuration` |
| GET | `/.well-known/oauth-authorization-server` |
| GET | `/.well-known/jwks.json` |

`POST /oauth2/revoke` remains the revocation route. Every other `/oauth2/` and `/.well-known/` path returns JSON `404`, including when a separate frontend base URL is configured. The token endpoint accepts only `authorization_code` (with PKCE S256) and `refresh_token`. `client_secret`, the resource-owner password grant, and query credentials are rejected locally.

Discovery is rebuilt from the configured issuer and `ServerAddress`. It is not Hydra's raw document. A mismatched `issuer`, a missing S256 method, or a missing authorization-code or refresh-token grant fails closed. JWKS responses that contain private key fields are dropped.

## Redirects

The replacement origin is `ServerAddress` after it matches the issuer host. The request `Host`, `Forwarded`, and `X-Forwarded-Host` are not copied to Hydra and are not the replacement origin. The proxy sends `X-Forwarded-Host` set to the configured public host only.

Locations whose host is the upstream origin are rewritten to that public origin. `http://127.0.0.1` and `http://[::1]` locations with an explicit port are passed through, as is `cherrystudio://oauth/callback`. Any other host, including an HTTPS application callback that is not the public origin, is rejected. Preserving registered HTTPS callbacks is left to client registration work.

Login and consent decisions rewrite a Hydra `redirect_to` or stored `request_url` from the upstream origin to the public authorization URL before the browser sees it. A URL on any other host is rejected.

## Boxo

The intended public client uses PKCE S256 and a loopback callback `http://127.0.0.1:{port}/oauth/callback`. The authorize query allowlist is `client_id`, `response_type=code`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`, and optional `response_mode=query`, `prompt=consent`, and `audience`. `prompt=none` is rejected.

Stock Hydra compares redirect URIs exactly. A random loopback port can be rejected by Hydra before New API's consent check, which already allows any loopback port for a registered loopback path. This proxy does not rewrite that port. Registering the client, including an RFC 8252 port rule if Hydra cannot express one, is separate work.

## Operator sequence

1. Create the database password, Hydra system secret, and cookie secret outside the repository. Do not put them in the shell history of a committed file.
2. Issue TLS certificates for the DNS name `hydra`, plus the CA install on the New API host. There is no switch that disables certificate verification.
3. Choose the public HTTPS origin, for example `https://auth.example.com`. Set Hydra `URLS_SELF_ISSUER` to `https://auth.example.com/` if the trailing slash is part of the issuer, and set `OAUTH_PUBLIC_ORIGIN` to `https://auth.example.com` (no path).
4. Start only the compose file's database and Hydra. Do not publish port 4445. Do not publish port 4444 either; New API reaches `https://hydra:4444` on the compose network.
5. Set the New API environment from the table below and set console `ServerAddress` to the same public origin. Restart New API. The flags are read at startup.
6. Fetch `https://auth.example.com/.well-known/openid-configuration` and confirm `issuer` is exactly `URLS_SELF_ISSUER` before creating a public client.
7. Create the public client through Hydra's admin API on the admin origin. Use `token_endpoint_auth_method=none`, grants `authorization_code` and `refresh_token`, response type `code`, and PKCE. Do not store the admin API credential in this repository.

New API environment when the proxy is intentionally on:

```
OAUTH_USERINFO_ENABLED=true
OAUTH_USERINFO_INTROSPECTION_URL=https://hydra:4445/admin/oauth2/introspect
OAUTH_USERINFO_ISSUER=https://auth.example.com/
OAUTH_USERINFO_AUDIENCE=newapi-userinfo
OAUTH_USERINFO_CLIENT_IDS=boxo
OAUTH_PROVIDER_BRIDGE_ENABLED=true
OAUTH_PROVIDER_ADMIN_BASE_URL=https://hydra:4445
OAUTH_PROVIDER_AUTHORIZATION_URL=https://auth.example.com/oauth2/auth
OAUTH_PROVIDER_REVOCATION_ENABLED=true
OAUTH_PUBLIC_PROXY_ENABLED=true
OAUTH_PROVIDER_UPSTREAM_URL=https://hydra:4444
```

`auth.example.com` and `hydra` are placeholders. Replace the public origin; keep the compose service name only if New API joins that network.

Access tokens are opaque and last one hour in the example. Refresh tokens last 720 hours. Login and consent challenges are capped at 30 minutes by the example. That cap was taken from the Hydra v26.2.0 schema default and the explicit setting; it was not measured on a running Hydra.

## Scopes

Consent grants only the intersection of three lists: the scopes the client requested, the scopes registered for that client, and the scopes the user left checked. The known list, in order, is `openid`, `profile`, `email`, `offline_access`, `balance:read`, `usage:read`, `tokens:read`, and `tokens:write`. `profile` is required. The browser selection is not trusted; the server recomputes the intersection before it accepts the consent.

Those names map to personal access token scopes as `profile` or `email` to `profile:read`, `balance:read` to `wallet:read`, `usage:read` to `usage:read`, `tokens:read` to `api_key:read`, and `tokens:write` to `api_key:write`. `tokens:read` does not include key reveal. `openid` and `offline_access` do not map to a resource scope. A resource request whose granted scope does not contain the endpoint's scope is rejected with `insufficient_scope`. An OAuth resource identity uses the session id prefix `oauth:` and is rejected by organization APIs, organization proof, and the login/consent decision, the same way `pat:` is rejected.

The public token response includes `refresh_token` only when its `scope` contains `offline_access` as its own token. A response with no scope drops the refresh token. Register `offline_access` on the Hydra client when the desktop client needs refresh.

## Limits

- ID token signatures are not verified. The proxy only checks that an `iss` claim matches the configured issuer before forwarding the token. Clients must validate the signature against the published JWKS.
- A revocation HTTP 200 from Hydra is not proof that the token was invalidated.
- HTTPS redirect targets other than the public origin are rejected.
- Hydra may still require an exact loopback port.
- No real Hydra process is started by the tests or by applying this repository.
