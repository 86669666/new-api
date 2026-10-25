package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
)

const OAuthPublicCapabilityLimit = 16384

var oauthPublicScopes = []string{"openid", "profile", "email", "offline_access", "balance:read", "usage:read", "tokens:read", "tokens:write"}
var oauthPublicCookieName = regexp.MustCompile(`^__Host-newapi_oauth_(login|consent)_csrf_[0-9]{1,10}$`)

type OAuthPublicConfig struct {
	Enabled bool
	BaseURL string
}
type OAuthPublic struct {
	bridge *OAuthProviderBridge
	base   string
	ready  atomic.Bool
}
type OAuthPublicResponse struct {
	Status   int
	Body     []byte
	Location string
	Cookies  []*http.Cookie
}
type OAuthPublicError struct {
	Status int
	Code   string
}

func (e *OAuthPublicError) Error() string { return e.Code }

func NewOAuthPublic(config OAuthPublicConfig, bridge *OAuthProviderBridge) (*OAuthPublic, error) {
	if !config.Enabled {
		return nil, nil
	}
	if bridge == nil || !bridge.RevocationEnabled() {
		return nil, ErrOAuthProviderConfiguration
	}
	upstream, err := url.Parse(config.BaseURL)
	issuer, issuerErr := url.Parse(bridge.resource.issuer)
	if err != nil || issuerErr != nil || upstream.Scheme != "https" || upstream.Hostname() == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.ForceQuery || upstream.Fragment != "" || upstream.RawPath != "" || upstream.Opaque != "" || (upstream.Path != "" && upstream.Path != "/") || config.BaseURL != upstream.String() || issuer.Scheme != "https" || issuer.Path != "/" || issuer.RawPath != "" || issuer.String() != bridge.resource.issuer || upstream.Host == issuer.Host || strings.TrimSuffix(config.BaseURL, "/") == bridge.admin {
		return nil, ErrOAuthProviderConfiguration
	}
	if port := upstream.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, ErrOAuthProviderConfiguration
		}
	}
	p := &OAuthPublic{bridge: bridge, base: strings.TrimSuffix(config.BaseURL, "/")}
	bridge.public = p
	bridge.resource.grantsRequired = true
	// Invalidate older public previews; existing grants keep their exact consented scopes.
	bridge.policy += ":public-v5:openid-profile-email-offline-balance-usage-tokens-read-write:7d"
	return p, nil
}

func (b *OAuthProviderBridge) Public() *OAuthPublic {
	if b == nil {
		return nil
	}
	return b.public
}

// Called after persisted site options have loaded, before listening.
func ValidateOAuthPublicTopology(ctx context.Context) error {
	b := CurrentOAuthProviderBridge()
	if b.Public() == nil {
		return nil
	}
	return b.Public().ValidateTopology(ctx)
}
func (p *OAuthPublic) topologyMatches() bool {
	return os.Getenv("FRONTEND_BASE_URL") == "" && strings.TrimSuffix(system_setting.ServerAddress, "/") == strings.TrimSuffix(p.bridge.resource.issuer, "/")
}
func (p *OAuthPublic) ValidateTopology(ctx context.Context) error {
	if !p.topologyMatches() {
		return fmt.Errorf("%w: site topology", ErrOAuthProviderConfiguration)
	}
	for _, id := range p.bridge.resource.clients {
		if _, err := p.client(ctx, id); err != nil {
			return fmt.Errorf("%w: client policy (%s)", ErrOAuthProviderConfiguration, err.Error())
		}
	}
	if _, err := p.metadata(ctx); err != nil {
		return fmt.Errorf("%w: issuer metadata", ErrOAuthProviderConfiguration)
	}
	p.ready.Store(true)
	return nil
}
func (p *OAuthPublic) Available() bool { return p != nil && p.ready.Load() && p.topologyMatches() }

func (p *OAuthPublic) client(ctx context.Context, id string) (*oauthProviderClient, error) {
	if !slices.Contains(p.bridge.resource.clients, id) {
		return nil, &OAuthPublicError{401, "invalid_client"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.bridge.admin+"/admin/clients/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: client document", ErrOAuthResourceUnavailable)
	}
	req.Header.Set("Accept", "application/json")
	response, err := p.bridge.resource.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: client connection", ErrOAuthResourceUnavailable)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	var client oauthProviderClient
	if err != nil || len(data) > 65536 {
		return nil, fmt.Errorf("%w: client response size", ErrOAuthResourceUnavailable)
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("%w: client status %d", ErrOAuthResourceUnavailable, response.StatusCode)
	}
	fields, err := common.DecodeRawJSONObject(data)
	if err != nil {
		return nil, fmt.Errorf("%w: client JSON", ErrOAuthResourceUnavailable)
	}
	security := map[string]common.RawMessage{}
	for _, key := range []string{"client_id", "token_endpoint_auth_method", "subject_type", "grant_types", "response_types", "scope", "audience", "redirect_uris", "skip_consent"} {
		value, exists := fields[key]
		if !exists {
			return nil, ErrOAuthResourceUnavailable
		}
		security[key] = value
	}
	encoded, err := common.Marshal(security)
	if err != nil || common.ValidateStrictJSONObject(encoded) != nil || common.Unmarshal(encoded, &client) != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	if value, exists := fields["client_name"]; exists {
		_ = common.Unmarshal(value, &client.Name)
	}

	if client.ID != id || client.Method == nil || *client.Method != "none" || client.SubjectType != "public" || client.SkipConsent || !sameOAuthProviderSet(client.Grants, []string{"authorization_code", "refresh_token"}) || !sameOAuthProviderSet(client.Responses, []string{"code"}) || client.Scope == nil || client.Audience == nil || !slices.Contains(*client.Audience, p.bridge.resource.audience) {
		return nil, fmt.Errorf("%w: client registration", ErrOAuthResourceUnavailable)
	}
	scopes, err := oauthProviderScopeSet(*client.Scope)
	if err != nil || !slices.Contains(scopes, "profile") {
		return nil, fmt.Errorf("%w: client scope", ErrOAuthResourceUnavailable)
	}
	for _, scope := range scopes {
		if !slices.Contains(oauthPublicScopes, scope) {
			return nil, fmt.Errorf("%w: client scope", ErrOAuthResourceUnavailable)
		}
	}
	if len(client.Redirects) == 0 {
		return nil, fmt.Errorf("%w: client scope", ErrOAuthResourceUnavailable)
	}
	for _, raw := range client.Redirects {
		if !validOAuthProviderRedirect(raw, raw) {
			return nil, fmt.Errorf("%w: client scope", ErrOAuthResourceUnavailable)
		}
	}
	return &client, nil
}

func (p *OAuthPublic) request(ctx context.Context, method, path, body string, cookies []*http.Cookie) (*http.Response, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, reader)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	req.GetBody = nil // Never replay a credential-bearing request after it was sent.
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	response, err := p.bridge.resource.client.Do(req)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	return response, nil
}
func oauthPublicJSON(response *http.Response) (map[string]common.RawMessage, error) {
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 {
		return nil, ErrOAuthResourceUnavailable
	}
	fields, err := common.DecodeRawJSONObject(data)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	if response.StatusCode != 200 {
		var code string
		if common.Unmarshal(fields["error"], &code) == nil && slices.Contains([]string{"invalid_request", "invalid_client", "invalid_grant", "invalid_scope", "unsupported_grant_type", "unauthorized_client"}, code) {
			status := 400
			if code == "invalid_client" {
				status = 401
			}
			return nil, &OAuthPublicError{status, code}
		}
		return nil, ErrOAuthResourceUnavailable
	}
	return fields, nil
}
func (p *OAuthPublic) metadata(ctx context.Context) ([]byte, error) {
	response, err := p.request(ctx, http.MethodGet, "/.well-known/openid-configuration", "", nil)
	if err != nil {
		return nil, err
	}
	fields, err := oauthPublicJSON(response)
	if err != nil {
		return nil, err
	}
	issuer := p.bridge.resource.issuer
	for key, want := range map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "oauth2/auth", "token_endpoint": issuer + "oauth2/token", "revocation_endpoint": issuer + "oauth2/revoke", "jwks_uri": issuer + ".well-known/jwks.json"} {
		var value string
		if common.Unmarshal(fields[key], &value) != nil || value != want {
			return nil, ErrOAuthResourceUnavailable
		}
	}
	var algorithms []string
	if common.Unmarshal(fields["id_token_signing_alg_values_supported"], &algorithms) != nil || !slices.Equal(algorithms, []string{"RS256"}) {
		return nil, ErrOAuthResourceUnavailable
	}
	return common.Marshal(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "oauth2/auth", "token_endpoint": issuer + "oauth2/token", "revocation_endpoint": issuer + "oauth2/revoke", "jwks_uri": issuer + ".well-known/jwks.json", "userinfo_endpoint": issuer + "api/v1/oauth/userinfo", "scopes_supported": oauthPublicScopes, "response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"none"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": algorithms, "code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true})
}
func (p *OAuthPublic) Document(ctx context.Context, path string) ([]byte, error) {
	if !p.Available() {
		return nil, ErrOAuthResourceUnavailable
	}
	if path != "/.well-known/jwks.json" {
		return p.metadata(ctx)
	}
	response, err := p.request(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	fields, err := oauthPublicJSON(response)
	if err != nil {
		return nil, err
	}
	var keys []map[string]common.RawMessage
	if common.Unmarshal(fields["keys"], &keys) != nil || len(keys) == 0 || len(keys) > 16 {
		return nil, ErrOAuthResourceUnavailable
	}
	for _, key := range keys {
		for name := range key {
			if !slices.Contains([]string{"kty", "kid", "use", "alg", "n", "e"}, name) {
				return nil, ErrOAuthResourceUnavailable
			}
		}
		for name, want := range map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256"} {
			var value string
			if common.Unmarshal(key[name], &value) != nil || value != want {
				return nil, ErrOAuthResourceUnavailable
			}
		}
		for _, name := range []string{"kid", "n", "e"} {
			var value string
			if common.Unmarshal(key[name], &value) != nil || value == "" {
				return nil, ErrOAuthResourceUnavailable
			}
		}
	}
	return common.Marshal(map[string]any{"keys": keys})
}

func (p *OAuthPublic) Authorize(ctx context.Context, request *http.Request) (*OAuthPublicResponse, error) {
	if !p.Available() {
		return nil, ErrOAuthResourceUnavailable
	}
	q, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(request.URL.RawQuery) > 32768 {
		return nil, ErrOAuthProviderRequest
	}
	for key, values := range q {
		if !slices.Contains([]string{"client_id", "response_type", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "response_mode", "prompt", "audience", "nonce", "login_verifier", "consent_verifier"}, key) || len(values) != 1 || values[0] == "" {
			return nil, ErrOAuthProviderRequest
		}
	}
	client, err := p.client(ctx, q.Get("client_id"))
	if err != nil {
		return nil, err
	}
	pkce, err := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	if err != nil || len(pkce) != 32 || base64.RawURLEncoding.EncodeToString(pkce) != q.Get("code_challenge") || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || !validOAuthProviderCapability(q.Get("state")) || q.Get("response_mode") != "" && q.Get("response_mode") != "query" || q.Get("prompt") != "" && q.Get("prompt") != "consent" {
		return nil, ErrOAuthProviderRequest
	}
	for _, key := range []string{"login_verifier", "consent_verifier"} {
		if q.Has(key) && !validOAuthHydraCapability(q.Get(key)) {
			return nil, ErrOAuthProviderRequest
		}
	}
	if q.Has("nonce") && !validOAuthProviderCapability(q.Get("nonce")) || q.Has("login_verifier") && q.Has("consent_verifier") {
		return nil, ErrOAuthProviderRequest
	}
	if !slices.ContainsFunc(client.Redirects, func(registered string) bool { return validOAuthProviderRedirect(q.Get("redirect_uri"), registered) }) {
		return nil, ErrOAuthProviderRequest
	}
	scopes, err := oauthProviderScopeSet(q.Get("scope"))
	if err != nil {
		return nil, &OAuthPublicError{400, "invalid_scope"}
	}
	registered, _ := oauthProviderScopeSet(*client.Scope)
	for _, scope := range scopes {
		if !slices.Contains(oauthPublicScopes, scope) || !slices.Contains(registered, scope) {
			return nil, &OAuthPublicError{400, "invalid_scope"}
		}
	}
	if !slices.Contains(scopes, "profile") || slices.Contains(scopes, "offline_access") && !slices.Contains(scopes, "openid") {
		return nil, &OAuthPublicError{400, "invalid_scope"}
	}
	if q.Get("audience") == "" {
		q.Set("audience", p.bridge.resource.audience)
	}
	if q.Get("audience") != p.bridge.resource.audience {
		return nil, ErrOAuthProviderRequest
	}
	cookies := []*http.Cookie{}
	names := map[string]bool{}
	// Bound every Cookie field before parsing, including unrelated cookies and
	// noncanonical map keys. Joining uses the same separator as a merged field.
	var cookieHeader strings.Builder
	seenCookieHeader := false
	for key, values := range request.Header {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, value := range values {
			separator := ""
			if seenCookieHeader {
				separator = "; "
			}
			if len(value) > 16384-cookieHeader.Len()-len(separator) {
				return nil, ErrOAuthProviderRequest
			}
			cookieHeader.WriteString(separator)
			cookieHeader.WriteString(value)
			seenCookieHeader = true
		}
	}
	cookieRequest := &http.Request{Header: http.Header{"Cookie": {cookieHeader.String()}}}
	for _, cookie := range cookieRequest.Cookies() {
		if !oauthPublicCookieName.MatchString(cookie.Name) {
			continue
		}
		if names[cookie.Name] || len(cookie.Value) > 4096 {
			return nil, ErrOAuthProviderRequest
		}
		names[cookie.Name] = true
		cookies = append(cookies, &http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	var operation *model.OAuthOperation
	published := false
	for _, kind := range []string{"login_verifier", "consent_verifier"} {
		if credential := q.Get(kind); credential != "" {
			artifact, origin, err := model.FindOAuthArtifact(ctx, p.bridge.resource.issuer, kind, credential)
			if err != nil {
				if errors.Is(oauthGrantError(err), ErrOAuthInvalidToken) {
					return nil, ErrOAuthProviderReplay
				}
				return nil, ErrOAuthResourceUnavailable
			}
			if origin.ClientID != client.ID || artifact.ExpiresAt <= time.Now().Unix() || artifact.PKCE != q.Get("code_challenge") || artifact.RedirectHash != model.OAuthArtifactRef(p.bridge.resource.issuer, "redirect", q.Get("redirect_uri")) {
				return nil, ErrOAuthProviderReplay
			}
			operation = &model.OAuthOperation{Issuer: origin.Issuer, UserID: origin.UserID, ClientID: origin.ClientID, OriginSID: origin.OriginSID, AuthVersion: origin.AuthVersion, SessionVersion: origin.SessionVersion, GrantRef: origin.GrantRef, Kind: kind + "_resume"}
			if err := model.ReserveOAuthOperation(ctx, operation); err != nil {
				return nil, oauthGrantError(err)
			}
			if err := model.SendOAuthOperation(ctx, operation); err != nil {
				return nil, oauthGrantError(err)
			}
			defer finishOAuthAttempt(operation, &published)
		}
	}
	response, err := p.request(ctx, http.MethodGet, "/oauth2/auth?"+q.Encode(), "", cookies)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 302 && response.StatusCode != 303 {
		return nil, ErrOAuthResourceUnavailable
	}
	location := response.Header.Get("Location")
	target, err := url.Parse(location)
	if err != nil || len(location) > 32768 || target.User != nil || target.Fragment != "" || target.RawPath != "" || target.Opaque != "" {
		return nil, ErrOAuthResourceUnavailable
	}
	base := *target
	base.RawQuery = ""
	base.ForceQuery = false
	targetQuery, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	allowed := false
	for _, phase := range []string{"login", "consent"} {
		if base.String() == p.bridge.resource.issuer+"oauth/provider/"+phase && len(targetQuery) == 1 && len(targetQuery[phase+"_challenge"]) == 1 && validOAuthHydraCapability(targetQuery.Get(phase+"_challenge")) {
			allowed = true
		}
	}
	if base.String() == p.bridge.resource.issuer+"oauth2/error" {
		return nil, ErrOAuthProviderRequest
	}
	callback, _ := url.Parse(q.Get("redirect_uri"))
	if callback != nil && target.Scheme == callback.Scheme && target.Host == callback.Host && target.Path == callback.Path {
		initial := callback.Query()
		valid := true
		for key, values := range targetQuery {
			if expected, exists := initial[key]; exists {
				if !slices.Equal(values, expected) {
					valid = false
				}
				continue
			}
			if !slices.Contains([]string{"code", "state", "iss", "scope", "error", "error_description", "error_hint", "error_debug"}, key) || len(values) != 1 {
				valid = false
			}
		}
		for key, values := range initial {
			if !slices.Equal(targetQuery[key], values) {
				valid = false
			}
		}
		if targetQuery.Get("state") != q.Get("state") || (targetQuery.Get("code") == "") == (targetQuery.Get("error") == "") {
			valid = false
		}
		if targetQuery.Get("iss") != "" && targetQuery.Get("iss") != p.bridge.resource.issuer {
			valid = false
		}
		if code := targetQuery.Get("code"); code != "" && (len(code) > 4096 || !validOAuthHydraCapability(code)) {
			valid = false
		}
		if failure := targetQuery.Get("error"); failure != "" && !slices.Contains([]string{"invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type", "invalid_scope", "server_error", "temporarily_unavailable", "login_required", "consent_required", "interaction_required"}, failure) {
			valid = false
		}
		if returned := targetQuery.Get("scope"); returned != "" {
			granted, err := oauthProviderScopeSet(returned)
			if err != nil {
				valid = false
			}
			for _, scope := range granted {
				if !slices.Contains(scopes, scope) {
					valid = false
				}
			}
		}
		if valid {
			for _, key := range []string{"error_description", "error_hint", "error_debug"} {
				if !initial.Has(key) {
					targetQuery.Del(key)
				}
			}
			targetQuery.Set("iss", p.bridge.resource.issuer)
			target.RawQuery = targetQuery.Encode()
			location = target.String()
			allowed = true
		}
	}
	if !allowed {
		return nil, ErrOAuthResourceUnavailable
	}
	if operation != nil {
		var artifacts []model.OAuthArtifact
		if code := targetQuery.Get("code"); code != "" {
			if operation.GrantRef == "" {
				return nil, ErrOAuthResourceUnavailable
			}
			artifacts = append(artifacts, model.OAuthArtifact{ArtifactRef: model.OAuthArtifactRef(operation.Issuer, "code", code), Kind: "code", PKCE: q.Get("code_challenge"), RedirectHash: model.OAuthArtifactRef(operation.Issuer, "redirect", q.Get("redirect_uri")), ExpiresAt: time.Now().Add(10 * time.Minute).Unix()})
		}
		if err := model.ObserveOAuthOperation(ctx, operation, artifacts); err != nil {
			return nil, ErrOAuthResourceUnavailable
		}
		// A late valid response is recorded, but revocation still wins publication.
		if err := model.ValidateOAuthOperationPublication(ctx, operation); err != nil {
			return nil, oauthGrantError(err)
		}
	}
	output := &OAuthPublicResponse{Status: response.StatusCode, Location: location}
	for _, cookie := range response.Cookies() {
		if !oauthPublicCookieName.MatchString(cookie.Name) {
			continue
		}
		if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" || cookie.Path != "/" || cookie.MaxAge > 1800 || len(cookie.Value) > 4096 {
			return nil, ErrOAuthResourceUnavailable
		}
		output.Cookies = append(output.Cookies, cookie)
	}
	published = true
	return output, nil
}

func (p *OAuthPublic) Exchange(ctx context.Context, form url.Values) ([]byte, error) {
	if !p.Available() {
		return nil, ErrOAuthResourceUnavailable
	}
	if !slices.Contains(p.bridge.resource.clients, form.Get("client_id")) {
		return nil, &OAuthPublicError{401, "invalid_client"}
	}
	kind := "code"
	credential := form.Get("code")
	if form.Get("grant_type") == "refresh_token" {
		kind, credential = "refresh_token", form.Get("refresh_token")
	}
	artifact, origin, lookupErr := model.FindOAuthArtifact(ctx, p.bridge.resource.issuer, kind, credential)
	if lookupErr != nil {
		if errors.Is(oauthGrantError(lookupErr), ErrOAuthInvalidToken) {
			return nil, &OAuthPublicError{400, "invalid_grant"}
		}
		return nil, ErrOAuthResourceUnavailable
	}
	if origin.ClientID != form.Get("client_id") || origin.GrantRef == "" {
		return nil, &OAuthPublicError{400, "invalid_grant"}
	}
	if kind == "code" {
		hash := sha256.Sum256([]byte(form.Get("code_verifier")))
		if artifact.PKCE != base64.RawURLEncoding.EncodeToString(hash[:]) || artifact.RedirectHash != model.OAuthArtifactRef(origin.Issuer, "redirect", form.Get("redirect_uri")) {
			return nil, &OAuthPublicError{400, "invalid_grant"}
		}
	}
	operation := &model.OAuthOperation{Issuer: origin.Issuer, UserID: origin.UserID, ClientID: origin.ClientID, OriginSID: origin.OriginSID, AuthVersion: origin.AuthVersion, SessionVersion: origin.SessionVersion, GrantRef: origin.GrantRef, Kind: kind + "_exchange"}
	var previous OAuthResourceIdentity
	var previousErr error
	if form.Get("grant_type") == "refresh_token" {
		previous, previousErr = p.bridge.resource.introspectPurpose(ctx, form.Get("refresh_token"), "refresh_token")
		if previousErr == nil {
			if previous.clientID != form.Get("client_id") {
				return nil, &OAuthPublicError{400, "invalid_grant"}
			}
			if _, err := authorizeOAuthGrant(ctx, previous, false); err != nil {
				if errors.Is(err, ErrOAuthInvalidToken) {
					return nil, &OAuthPublicError{400, "invalid_grant"}
				}
				return nil, ErrOAuthResourceUnavailable
			}
		} else if !errors.Is(previousErr, ErrOAuthInvalidToken) {
			return nil, ErrOAuthResourceUnavailable
		}
		// An inactive/replayed credential still reaches Hydra so its replay-family
		// invalidation runs. It cannot authorize a successful response locally.
	}
	if err := model.ReserveOAuthOperation(ctx, operation); err != nil {
		return nil, oauthGrantError(err)
	}
	if err := model.SendOAuthOperation(ctx, operation); err != nil {
		return nil, oauthGrantError(err)
	}
	published := false
	defer finishOAuthAttempt(operation, &published)
	response, err := p.request(ctx, http.MethodPost, "/oauth2/token", form.Encode(), nil)
	if err != nil {
		return nil, err
	}
	fields, err := oauthPublicJSON(response)
	if err != nil {
		var protocolError *OAuthPublicError
		if errors.As(err, &protocolError) && protocolError.Status < 500 {
			if observeErr := model.ObserveOAuthOperation(ctx, operation, nil); observeErr != nil {
				return nil, ErrOAuthResourceUnavailable
			}
		}
		return nil, err
	}
	var access, tokenKind, scope, refresh, idToken string
	var expires int64
	if common.Unmarshal(fields["access_token"], &access) != nil || access == "" || len(access) > 4096 || common.Unmarshal(fields["token_type"], &tokenKind) != nil || !strings.EqualFold(tokenKind, "bearer") || common.Unmarshal(fields["expires_in"], &expires) != nil || expires <= 0 || expires > 900 || common.Unmarshal(fields["scope"], &scope) != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	identity, err := p.bridge.resource.introspect(ctx, access)
	if err != nil {
		if errors.Is(err, ErrOAuthInvalidToken) {
			return nil, &OAuthPublicError{400, "invalid_grant"}
		}
		return nil, ErrOAuthResourceUnavailable
	}
	if form.Get("grant_type") == "refresh_token" && (previousErr != nil || previous.grantID != identity.grantID || previous.grantExpiresAt != identity.grantExpiresAt || previous.userID != identity.userID || previous.authVersion != identity.authVersion || previous.clientID != identity.clientID || !sameOAuthProviderSet(previous.scopes, identity.scopes)) {
		return nil, &OAuthPublicError{400, "invalid_grant"}
	}
	actual, err := oauthProviderScopeSet(scope)
	if err != nil || !sameOAuthProviderSet(actual, identity.scopes) || identity.clientID != form.Get("client_id") {
		return nil, ErrOAuthResourceUnavailable
	}
	for _, s := range actual {
		if !slices.Contains(oauthPublicScopes, s) {
			return nil, ErrOAuthResourceUnavailable
		}
	}
	out := map[string]any{"access_token": access, "token_type": "bearer", "expires_in": min(expires, identity.grantExpiresAt-time.Now().Unix()), "scope": scope}
	if slices.Contains(actual, "offline_access") {
		if common.Unmarshal(fields["refresh_token"], &refresh) != nil || refresh == "" || len(refresh) > 4096 {
			return nil, ErrOAuthResourceUnavailable
		}
		refreshed, err := p.bridge.resource.introspectPurpose(ctx, refresh, "refresh_token")
		if err != nil || refreshed.userID != identity.userID || refreshed.authVersion != identity.authVersion || refreshed.clientID != identity.clientID || refreshed.grantID != identity.grantID || refreshed.grantExpiresAt != identity.grantExpiresAt || !sameOAuthProviderSet(refreshed.scopes, identity.scopes) {
			return nil, ErrOAuthResourceUnavailable
		}
		out["refresh_token"] = refresh
	} else if _, exists := fields["refresh_token"]; exists {
		return nil, ErrOAuthResourceUnavailable
	}
	if raw, exists := fields["id_token"]; exists {
		if common.Unmarshal(raw, &idToken) != nil || idToken == "" || len(idToken) > 16384 || !slices.Contains(actual, "openid") {
			return nil, ErrOAuthResourceUnavailable
		}
		out["id_token"] = idToken
	} else if form.Get("grant_type") == "authorization_code" && slices.Contains(actual, "openid") {
		return nil, ErrOAuthResourceUnavailable
	}
	if model.OAuthGrantRef(identity.issuer, identity.grantID) != operation.GrantRef {
		return nil, ErrOAuthResourceUnavailable
	}
	artifacts := []model.OAuthArtifact{{ArtifactRef: model.OAuthArtifactRef(operation.Issuer, "access_token", access), Kind: "access_token", ExpiresAt: identity.expiresAt}}
	if refresh != "" {
		artifacts = append(artifacts, model.OAuthArtifact{ArtifactRef: model.OAuthArtifactRef(operation.Issuer, "refresh_token", refresh), Kind: "refresh_token", ExpiresAt: identity.grantExpiresAt})
	}
	if err := model.ObserveOAuthOperation(ctx, operation, artifacts); err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	// All issuer requests finish before the final local identity read. A logout,
	// disable or version rotation during refresh introspection must win.
	_, err = authorizeOAuthGrant(ctx, identity, form.Get("grant_type") == "authorization_code")
	if errors.Is(err, ErrOAuthInvalidToken) {
		return nil, &OAuthPublicError{400, "invalid_grant"}
	}
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	now := time.Now().Unix()
	out["expires_in"] = min(expires, identity.expiresAt-now, identity.grantExpiresAt-now)
	encoded, err := common.Marshal(out)
	if err != nil {
		return nil, err
	}
	published = true
	return encoded, nil
}

func validOAuthHydraCapability(value string) bool {
	if len(value) > OAuthPublicCapabilityLimit {
		return false
	}
	unpadded := strings.TrimRight(value, "=")
	if len(value)-len(unpadded) > 2 || len(value) != len(unpadded) && len(value)%4 != 0 {
		return false
	}
	value = unpadded
	// Keep ordinary state/nonce limits independent of Hydra's encrypted flows.
	if value == "" {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}

func oauthGrantExpiry(raw string) (int64, bool) {
	n, err := strconv.ParseInt(raw, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == raw
}

func (p *OAuthPublic) ProviderRequestAllowed(request *http.Request) bool {
	if !p.Available() {
		return false
	}
	origin := strings.TrimSuffix(p.bridge.resource.issuer, "/")
	if value := request.Header.Get("Origin"); value != "" && value != origin {
		return false
	}
	if value := request.Header.Get("Referer"); value != "" {
		u, err := url.Parse(value)
		if err != nil || u.User != nil || u.Scheme+"://"+u.Host != origin {
			return false
		}
	}
	return true
}
func (p *OAuthPublic) verifyRevocation(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.bridge.resource.endpoint, strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.bridge.resource.client.Do(req)
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	fields, err := oauthPublicJSON(response)
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	var active bool
	if strings.TrimSpace(string(fields["active"])) != "false" || common.Unmarshal(fields["active"], &active) != nil || active {
		return ErrOAuthResourceUnavailable
	}
	return nil
}
