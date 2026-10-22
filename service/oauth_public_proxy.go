package service

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"
)

var ErrOAuthUnsupportedGrant = errors.New("unsupported_grant_type")

const oauthPublicBodyLimit = 65536

// oauthAdminReadyTTL bounds how often anonymous /api/status probes Hydra.
// A failed probe is cached too, so a down admin endpoint fails closed without
// a request storm. A cancelled caller does not poison the cache.
var oauthAdminReadyTTL = 15 * time.Second

var oauthTokenErrorText = map[string]string{
	"invalid_request":         "The request is invalid.",
	"invalid_client":          "The client authentication failed.",
	"invalid_grant":           "The authorization grant is invalid.",
	"unauthorized_client":     "The client is not authorized for this grant.",
	"unsupported_grant_type":  "The grant type is unsupported.",
	"invalid_scope":           "The requested scope is invalid.",
	"server_error":            "The authorization server failed.",
	"temporarily_unavailable": "The authorization server is unavailable.",
}

// OAuthPublicResult is a filtered upstream response. Location is already rewritten
// from the configured site address; caller headers are not a rewrite source.
type OAuthPublicResult struct {
	Status      int
	Location    string
	ContentType string
	Body        []byte
}

func oauthProxyOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || raw != strings.TrimSpace(raw) || (u.Path != "" && u.Path != "/") {
		return "", ErrOAuthProviderConfiguration
	}
	if port := u.Port(); port != "" {
		n, conv := strconv.Atoi(port)
		if conv != nil || n < 1 || n > 65535 {
			return "", ErrOAuthProviderConfiguration
		}
	}
	u.Path, u.RawPath = "", ""
	return u.String(), nil
}

func oauthProxyHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + oauthDefaultPort(u)
}

// PublicProxyReady reports whether Hydra's admin /health/ready returned 200.
// The result is cached for oauthAdminReadyTTL. Callers do not learn the admin URL.
func (b *OAuthProviderBridge) PublicProxyReady(ctx context.Context) bool {
	if b == nil || !b.PublicProxyEnabled() || b.admin == "" || b.resource == nil || b.resource.client == nil {
		return false
	}
	b.readyMu.Lock()
	defer b.readyMu.Unlock()
	if time.Now().Before(b.readyUntil) {
		return b.readyOK
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, b.admin+"/health/ready", nil)
	if err != nil {
		return false
	}
	resp, err := b.resource.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			b.readyOK = false
			b.readyUntil = time.Now().Add(oauthAdminReadyTTL)
		}
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	b.readyOK = resp.StatusCode == http.StatusOK
	b.readyUntil = time.Now().Add(oauthAdminReadyTTL)
	return b.readyOK
}

func (b *OAuthProviderBridge) publicOrigin() (string, error) {
	if b == nil || b.upstream == "" || b.resource == nil {
		return "", ErrOAuthResourceUnavailable
	}
	configured := strings.TrimSpace(system_setting.ServerAddress)
	server, err := url.Parse(configured)
	issuer, issuerErr := url.Parse(b.resource.issuer)
	if err != nil || issuerErr != nil || server.Scheme != "https" || server.Hostname() == "" || server.User != nil || server.RawQuery != "" || server.ForceQuery || server.Fragment != "" || server.Opaque != "" || server.RawPath != "" || (server.Path != "" && server.Path != "/") {
		return "", ErrOAuthResourceUnavailable
	}
	if !strings.EqualFold(server.Hostname(), issuer.Hostname()) || oauthDefaultPort(server) != oauthDefaultPort(issuer) {
		return "", ErrOAuthResourceUnavailable
	}
	return (&url.URL{Scheme: "https", Host: server.Host}).String(), nil
}

func (b *OAuthProviderBridge) ProxyAuthorize(ctx context.Context, rawQuery string, forbiddenHosts []string) (*OAuthPublicResult, error) {
	query, err := canonicalOAuthAuthorizeQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	status, header, body, err := b.fetchUpstream(ctx, http.MethodGet, "/oauth2/auth", query, "", nil)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	return b.filterAuthorize(status, header, body, forbiddenHosts)
}

func (b *OAuthProviderBridge) ProxyToken(ctx context.Context, form url.Values) (*OAuthPublicResult, error) {
	forward, err := oauthTokenForm(form)
	if err != nil {
		return nil, err
	}
	status, _, body, err := b.fetchUpstream(ctx, http.MethodPost, "/oauth2/token", "", "application/x-www-form-urlencoded", strings.NewReader(forward.Encode()))
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	filtered, status, err := filterOAuthTokenResponse(status, body, b.resource.issuer)
	if err != nil {
		return nil, err
	}
	return &OAuthPublicResult{Status: status, ContentType: "application/json", Body: filtered}, nil
}

func (b *OAuthProviderBridge) ProxyDiscovery(ctx context.Context, kind string) (*OAuthPublicResult, error) {
	if kind != "openid" && kind != "oauth" {
		return nil, ErrOAuthProviderRequest
	}
	status, _, body, err := b.fetchUpstream(ctx, http.MethodGet, "/.well-known/openid-configuration", "", "", nil)
	if err != nil || status != http.StatusOK {
		return nil, ErrOAuthResourceUnavailable
	}
	filtered, err := b.filterDiscovery(body)
	if err != nil {
		return nil, err
	}
	return &OAuthPublicResult{Status: http.StatusOK, ContentType: "application/json", Body: filtered}, nil
}

func (b *OAuthProviderBridge) ProxyJWKS(ctx context.Context) (*OAuthPublicResult, error) {
	status, _, body, err := b.fetchUpstream(ctx, http.MethodGet, "/.well-known/jwks.json", "", "", nil)
	if err != nil || status != http.StatusOK {
		return nil, ErrOAuthResourceUnavailable
	}
	filtered, err := filterJWKS(body)
	if err != nil {
		return nil, err
	}
	return &OAuthPublicResult{Status: http.StatusOK, ContentType: "application/json", Body: filtered}, nil
}

func (b *OAuthProviderBridge) fetchUpstream(ctx context.Context, method, path, rawQuery, contentType string, body io.Reader) (int, http.Header, []byte, error) {
	if b == nil || b.upstream == "" || b.resource == nil || b.resource.client == nil {
		return 0, nil, nil, ErrOAuthResourceUnavailable
	}
	public, err := b.publicOrigin()
	if err != nil {
		return 0, nil, nil, err
	}
	pub, err := url.Parse(public)
	if err != nil || pub.Host == "" {
		return 0, nil, nil, ErrOAuthResourceUnavailable
	}
	endpoint := b.upstream + path
	if rawQuery != "" {
		endpoint += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, nil, nil, err
	}
	// Dial the configured upstream. The caller's Host, Forwarded, and
	// X-Forwarded-Host are not copied; the forwarded host is ServerAddress.
	req.Host = req.URL.Host
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", pub.Host)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
		req.GetBody = nil
	}
	resp, err := b.resource.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, oauthPublicBodyLimit+1))
	if err != nil || len(data) > oauthPublicBodyLimit {
		return 0, nil, nil, ErrOAuthResourceUnavailable
	}
	return resp.StatusCode, resp.Header.Clone(), data, nil
}

func canonicalOAuthAuthorizeQuery(raw string) (string, error) {
	if raw == "" || len(raw) > 8192 || strings.Contains(raw, ";") {
		return "", ErrOAuthProviderRequest
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "", ErrOAuthProviderRequest
	}
	allowed := []string{"client_id", "response_type", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "response_mode", "prompt", "audience"}
	for key, values := range q {
		if !slices.Contains(allowed, key) || len(values) == 0 || key != "audience" && len(values) != 1 {
			return "", ErrOAuthProviderRequest
		}
		for _, value := range values {
			if len(value) > 2048 || strings.TrimSpace(value) != value {
				return "", ErrOAuthProviderRequest
			}
		}
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || !oauthVisibleASCII(q.Get("client_id"), 256) || canonicalOAuthCodeChallenge(q.Get("code_challenge")) != nil || !oauthPublicRedirectShape(q.Get("redirect_uri")) {
		return "", ErrOAuthProviderRequest
	}
	if state := q.Get("state"); state != "" && !validOAuthProviderCapability(state) {
		return "", ErrOAuthProviderRequest
	}
	if mode := q.Get("response_mode"); mode != "" && mode != "query" {
		return "", ErrOAuthProviderRequest
	}
	if prompt := q.Get("prompt"); prompt != "" && prompt != "consent" {
		return "", ErrOAuthProviderRequest
	}
	for _, value := range q["audience"] {
		if !oauthVisibleASCII(value, 256) {
			return "", ErrOAuthProviderRequest
		}
	}
	if scope := q.Get("scope"); scope != "" {
		if _, err := oauthProviderScopeSet(scope); err != nil {
			return "", ErrOAuthProviderRequest
		}
	}
	forward := url.Values{}
	for _, key := range allowed {
		if values, ok := q[key]; ok {
			forward[key] = slices.Clone(values)
		}
	}
	return forward.Encode(), nil
}

func canonicalOAuthCodeChallenge(value string) error {
	pkce, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(pkce) != 32 || base64.RawURLEncoding.EncodeToString(pkce) != value {
		return ErrOAuthProviderRequest
	}
	return nil
}

func validOAuthCodeVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c) {
			continue
		}
		return false
	}
	return true
}

func oauthVisibleASCII(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func oauthPublicRedirectShape(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\\") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		if u.Hostname() == "" {
			return false
		}
		if u.Port() == "" {
			return true
		}
		port, err := strconv.Atoi(u.Port())
		return err == nil && port >= 1 && port <= 65535
	case "cherrystudio":
		return u.Host == "oauth" && u.Path == "/callback" && u.RawQuery == ""
	case "http":
		host := strings.Trim(u.Hostname(), "[]")
		if host != "127.0.0.1" && host != "::1" || net.ParseIP(host) == nil {
			return false
		}
		port, err := strconv.Atoi(u.Port())
		return err == nil && port >= 1 && port <= 65535
	default:
		return false
	}
}

func oauthTokenForm(form url.Values) (url.Values, error) {
	allowed := []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier", "refresh_token", "scope"}
	for key, values := range form {
		if !slices.Contains(allowed, key) || len(values) != 1 || !oauthVisibleASCII(values[0], 4096) {
			return nil, ErrOAuthProviderRequest
		}
	}
	if !oauthVisibleASCII(form.Get("client_id"), 256) {
		return nil, ErrOAuthProviderRequest
	}
	grant := form.Get("grant_type")
	forward := url.Values{"grant_type": {grant}, "client_id": {form.Get("client_id")}}
	switch grant {
	case "authorization_code":
		if !oauthVisibleASCII(form.Get("code"), 4096) || form.Get("refresh_token") != "" || !validOAuthCodeVerifier(form.Get("code_verifier")) || !oauthPublicRedirectShape(form.Get("redirect_uri")) {
			return nil, ErrOAuthProviderRequest
		}
		forward.Set("code", form.Get("code"))
		forward.Set("redirect_uri", form.Get("redirect_uri"))
		forward.Set("code_verifier", form.Get("code_verifier"))
	case "refresh_token":
		if !oauthVisibleASCII(form.Get("refresh_token"), 4096) || form.Get("code") != "" || form.Get("code_verifier") != "" || form.Get("redirect_uri") != "" {
			return nil, ErrOAuthProviderRequest
		}
		forward.Set("refresh_token", form.Get("refresh_token"))
	default:
		if !oauthVisibleASCII(grant, 64) {
			return nil, ErrOAuthProviderRequest
		}
		return nil, ErrOAuthUnsupportedGrant
	}
	if scope := form.Get("scope"); scope != "" {
		if _, err := oauthProviderScopeSet(scope); err != nil {
			return nil, ErrOAuthProviderRequest
		}
		forward.Set("scope", scope)
	}
	return forward, nil
}

func (b *OAuthProviderBridge) filterAuthorize(status int, header http.Header, body []byte, forbiddenHosts []string) (*OAuthPublicResult, error) {
	if status == http.StatusFound || status == http.StatusSeeOther {
		location, err := b.rewriteLocation(header.Get("Location"), forbiddenHosts)
		if err != nil {
			return nil, ErrOAuthResourceUnavailable
		}
		return &OAuthPublicResult{Status: status, Location: location}, nil
	}
	if status == http.StatusBadRequest || status == http.StatusUnauthorized {
		filtered, code, err := oauthFixedError(body)
		if err != nil {
			return nil, err
		}
		httpStatus := http.StatusBadRequest
		if code == "invalid_client" {
			httpStatus = http.StatusUnauthorized
		}
		return &OAuthPublicResult{Status: httpStatus, ContentType: "application/json", Body: filtered}, nil
	}
	return nil, ErrOAuthResourceUnavailable
}

func (b *OAuthProviderBridge) rewriteLocation(raw string, forbiddenHosts []string) (string, error) {
	if raw == "" || len(raw) > 4096 || strings.ContainsAny(raw, "\r\n") {
		return "", ErrOAuthResourceUnavailable
	}
	public, err := b.publicOrigin()
	if err != nil {
		return "", err
	}
	loc, err := url.Parse(raw)
	if err != nil || loc.User != nil || loc.Fragment != "" || loc.Opaque != "" {
		return "", ErrOAuthResourceUnavailable
	}
	up, err := url.Parse(b.upstream)
	pub, pubErr := url.Parse(public)
	if err != nil || pubErr != nil {
		return "", ErrOAuthResourceUnavailable
	}
	if !loc.IsAbs() {
		loc = pub.ResolveReference(loc)
	}
	if oauthSameHost(loc, up) {
		loc.Scheme = pub.Scheme
		loc.Host = pub.Host
	}
	// A registered redirect is an exact https URL, a loopback path, or a custom
	// scheme an administrator stored. The port is not rewritten. An unregistered
	// https host is still rejected.
	registered := OAuthRedirectRegistered(loc.String())
	if !oauthLocationAllowed(loc, pub) && !registered {
		return "", ErrOAuthResourceUnavailable
	}
	// Loopback, the built-in custom callback, and a registered redirect are not
	// rewritten from the caller. Reject any other location whose host was
	// supplied by the caller.
	if !registered && !oauthLoopbackOrCustomCallback(loc) {
		for _, forbidden := range forbiddenHosts {
			if forbidden != "" && strings.EqualFold(loc.Hostname(), forbidden) && !strings.EqualFold(loc.Hostname(), pub.Hostname()) {
				return "", ErrOAuthResourceUnavailable
			}
		}
	}
	return loc.String(), nil
}

func oauthSameHost(a, b *url.URL) bool {
	return a != nil && b != nil && strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && oauthDefaultPort(a) == oauthDefaultPort(b)
}

func oauthLoopbackOrCustomCallback(loc *url.URL) bool {
	if loc == nil {
		return false
	}
	if loc.Scheme == "cherrystudio" && loc.Host == "oauth" && loc.Path == "/callback" {
		return true
	}
	if loc.Scheme != "http" {
		return false
	}
	host := strings.Trim(loc.Hostname(), "[]")
	return host == "127.0.0.1" || host == "::1"
}

func oauthSamePublicHost(loc, public *url.URL) bool {
	if loc == nil || public == nil || !strings.EqualFold(loc.Hostname(), public.Hostname()) {
		return false
	}
	return oauthDefaultPort(loc) == oauthDefaultPort(public)
}

func oauthDefaultPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	if u.Scheme == "http" {
		return "80"
	}
	return ""
}

func oauthLocationAllowed(loc, public *url.URL) bool {
	if loc.Scheme == "https" && oauthSamePublicHost(loc, public) {
		return true
	}
	if loc.Scheme == "cherrystudio" && loc.Host == "oauth" && loc.Path == "/callback" {
		return true
	}
	if loc.Scheme != "http" {
		return false
	}
	host := strings.Trim(loc.Hostname(), "[]")
	if host != "127.0.0.1" && host != "::1" {
		return false
	}
	port, err := strconv.Atoi(loc.Port())
	if err != nil || port < 1 || port > 65535 || net.ParseIP(host) == nil {
		return false
	}
	return public != nil
}

func filterOAuthTokenResponse(status int, body []byte, issuer string) ([]byte, int, error) {
	if status == http.StatusOK {
		filtered, err := oauthTokenSuccess(body, issuer)
		if err != nil {
			return nil, 0, err
		}
		return filtered, http.StatusOK, nil
	}
	if status == http.StatusBadRequest || status == http.StatusUnauthorized {
		filtered, code, err := oauthFixedError(body)
		if err != nil {
			return nil, 0, err
		}
		if code == "invalid_client" {
			return filtered, http.StatusUnauthorized, nil
		}
		return filtered, http.StatusBadRequest, nil
	}
	return nil, 0, ErrOAuthResourceUnavailable
}

func oauthTokenSuccess(body []byte, issuer string) ([]byte, error) {
	fields, err := common.DecodeRawJSONObject(body)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	var access, tokenType, scope, refresh, idToken string
	var expires int64
	if common.Unmarshal(fields["access_token"], &access) != nil || !oauthVisibleASCII(access, 4096) ||
		common.Unmarshal(fields["token_type"], &tokenType) != nil || !strings.EqualFold(tokenType, "bearer") ||
		common.Unmarshal(fields["expires_in"], &expires) != nil || expires <= 0 || expires > 86400*365 {
		return nil, ErrOAuthResourceUnavailable
	}
	out := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": expires}
	if value, ok := fields["scope"]; ok {
		if common.Unmarshal(value, &scope) != nil || scope == "" || len(scope) > 1024 {
			return nil, ErrOAuthResourceUnavailable
		}
		out["scope"] = scope
	}
	if value, ok := fields["refresh_token"]; ok {
		if common.Unmarshal(value, &refresh) != nil || !oauthVisibleASCII(refresh, 4096) {
			return nil, ErrOAuthResourceUnavailable
		}
		// A refresh token is returned only when the token response scope grants
		// offline_access. A missing scope fails closed and drops the token.
		if oauthScopeGrantsOfflineAccess(scope) {
			out["refresh_token"] = refresh
		}
	}
	if value, ok := fields["id_token"]; ok {
		if common.Unmarshal(value, &idToken) != nil || !oauthVisibleASCII(idToken, 8192) || oauthIDTokenIssuer(idToken, issuer) != nil {
			return nil, ErrOAuthResourceUnavailable
		}
		out["id_token"] = idToken
	}
	encoded, err := common.Marshal(out)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	return encoded, nil
}

func oauthIDTokenIssuer(token, issuer string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return ErrOAuthResourceUnavailable
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 8192 {
		return ErrOAuthResourceUnavailable
	}
	fields, err := common.DecodeRawJSONObject(payload)
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	var got string
	if common.Unmarshal(fields["iss"], &got) != nil || got != issuer {
		return ErrOAuthResourceUnavailable
	}
	return nil
}

func OAuthPublicFixedError(code string) ([]byte, error) {
	text, ok := oauthTokenErrorText[code]
	if !ok {
		return nil, ErrOAuthResourceUnavailable
	}
	return common.Marshal(map[string]string{"error": code, "error_description": text})
}

func oauthFixedError(body []byte) ([]byte, string, error) {
	fields, err := common.DecodeRawJSONObject(body)
	if err != nil {
		return nil, "", ErrOAuthResourceUnavailable
	}
	var code string
	if common.Unmarshal(fields["error"], &code) != nil {
		return nil, "", ErrOAuthResourceUnavailable
	}
	text, ok := oauthTokenErrorText[code]
	if !ok {
		return nil, "", ErrOAuthResourceUnavailable
	}
	encoded, err := common.Marshal(map[string]string{"error": code, "error_description": text})
	if err != nil {
		return nil, "", ErrOAuthResourceUnavailable
	}
	return encoded, code, nil
}

func (b *OAuthProviderBridge) filterDiscovery(body []byte) ([]byte, error) {
	fields, err := common.DecodeRawJSONObject(body)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	var issuer string
	var methods, grants, scopes []string
	if common.Unmarshal(fields["issuer"], &issuer) != nil || issuer != b.resource.issuer ||
		common.Unmarshal(fields["code_challenge_methods_supported"], &methods) != nil || !slices.Contains(methods, "S256") ||
		common.Unmarshal(fields["grant_types_supported"], &grants) != nil || !slices.Contains(grants, "authorization_code") || !slices.Contains(grants, "refresh_token") {
		return nil, ErrOAuthResourceUnavailable
	}
	if value, ok := fields["scopes_supported"]; ok && common.Unmarshal(value, &scopes) != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	scopes = filterOAuthScopeNames(scopes)
	if len(scopes) == 0 {
		return nil, ErrOAuthResourceUnavailable
	}
	public, err := b.publicOrigin()
	if err != nil {
		return nil, err
	}
	document := map[string]any{
		"issuer":                                b.resource.issuer,
		"authorization_endpoint":                b.authorize,
		"token_endpoint":                        public + "/oauth2/token",
		"revocation_endpoint":                   public + "/oauth2/revoke",
		"userinfo_endpoint":                     public + "/api/v1/oauth/userinfo",
		"jwks_uri":                              public + "/.well-known/jwks.json",
		"scopes_supported":                      scopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"subject_types_supported":               []string{"public"},
	}
	encoded, err := common.Marshal(document)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	return encoded, nil
}

func oauthScopeGrantsOfflineAccess(scope string) bool {
	for item := range strings.SplitSeq(scope, " ") {
		if item == "offline_access" {
			return true
		}
	}
	return false
}

func filterOAuthScopeNames(scopes []string) []string {
	out := []string{}
	for _, scope := range scopes {
		if scope == "" || len(scope) > 64 || slices.Contains(out, scope) {
			continue
		}
		safe := true
		for _, c := range scope {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				safe = false
				break
			}
		}
		if safe && slices.Contains(oauthProviderKnownScopes, scope) {
			out = append(out, scope)
		}
	}
	return out
}

func filterJWKS(body []byte) ([]byte, error) {
	fields, err := common.DecodeRawJSONObject(body)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	var keys []map[string]any
	if common.Unmarshal(fields["keys"], &keys) != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	private := []string{"d", "p", "q", "dp", "dq", "qi", "oth"}
	for _, key := range keys {
		kty, _ := key["kty"].(string)
		if kty == "" {
			return nil, ErrOAuthResourceUnavailable
		}
		for _, field := range private {
			if _, exists := key[field]; exists {
				return nil, ErrOAuthResourceUnavailable
			}
		}
	}
	encoded, err := common.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	return encoded, nil
}

// publicAuthorizeReference rewrites an authorization URL from the configured
// upstream origin to ServerAddress. Caller headers are not an input.
func (b *OAuthProviderBridge) publicAuthorizeReference(raw string) (string, error) {
	if b == nil || !b.PublicProxyEnabled() {
		return raw, nil
	}
	if raw == "" || len(raw) > 4096 || strings.ContainsAny(raw, "\r\n") {
		return "", ErrOAuthResourceUnavailable
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", ErrOAuthResourceUnavailable
	}
	up, err := url.Parse(b.upstream)
	public, pubErr := b.publicOrigin()
	pub, parseErr := url.Parse(public)
	if err != nil || pubErr != nil || parseErr != nil {
		return "", ErrOAuthResourceUnavailable
	}
	if oauthSameHost(u, up) {
		u.Scheme = pub.Scheme
		u.Host = pub.Host
	}
	if u.Scheme != "https" || !oauthSamePublicHost(u, pub) {
		return "", ErrOAuthResourceUnavailable
	}
	return u.String(), nil
}

// OAuthForbiddenHosts collects caller-supplied host names that must not become
// a redirect target. They are never used as the replacement origin.
func OAuthForbiddenHosts(host string, forwarded []string) []string {
	values := []string{}
	if host != "" {
		values = append(values, host)
	}
	for _, value := range forwarded {
		for part := range strings.SplitSeq(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "=") {
				for segment := range strings.SplitSeq(part, ";") {
					key, rest, ok := strings.Cut(segment, "=")
					if ok && strings.EqualFold(strings.TrimSpace(key), "host") {
						values = append(values, strings.Trim(strings.TrimSpace(rest), `"`))
					}
				}
				continue
			}
			values = append(values, part)
		}
	}
	out := []string{}
	for _, value := range values {
		if value == "" {
			continue
		}
		name := value
		if parsed, _, err := net.SplitHostPort(value); err == nil {
			name = parsed
		}
		name = strings.Trim(strings.ToLower(name), "[]")
		if name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}
