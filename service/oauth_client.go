package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// OAuthClientManageContext is the step-up binding for creating, changing, or
// deleting a public OAuth client. It contains no secret.
type OAuthClientManageContext struct {
	Action      string   `json:"action"`
	ClientRowID int      `json:"client_row_id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Redirects   []string `json:"redirects,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

var oauthDeniedRedirectSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "blob": true,
	"filesystem": true, "vbscript": true, "about": true, "jar": true,
}

func oauthCustomScheme(scheme string) bool {
	if scheme == "" || len(scheme) > 32 || oauthDeniedRedirectSchemes[scheme] {
		return false
	}
	for i, c := range scheme {
		if i == 0 && (c < 'a' || c > 'z') {
			return false
		}
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func oauthRedirectPortOK(raw string) bool {
	if raw == "" {
		return true
	}
	port, err := strconv.Atoi(raw)
	return err == nil && port >= 1 && port <= 65535
}

// ValidOAuthClientRedirect accepts https, a loopback URL, or a registered
// custom scheme. http is only loopback. The stored text must already be canonical.
func ValidOAuthClientRedirect(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\\") || raw != strings.TrimSpace(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.String() != raw || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.RawQuery != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Hostname() != "" && u.Path != "" && oauthRedirectPortOK(u.Port())
	case "http":
		host := strings.Trim(u.Hostname(), "[]")
		if (host != "127.0.0.1" && host != "::1") || net.ParseIP(host) == nil || u.Path == "" {
			return false
		}
		return oauthRedirectPortOK(u.Port())
	default:
		return oauthCustomScheme(u.Scheme) && u.Host != "" && strings.HasPrefix(u.Path, "/")
	}
}

// OAuthClientPreset returns the documented public-client redirect and the full
// known scope list. The client id is not part of the preset.
func oauthGeneratedClientID(id string) bool {
	if len(id) != 35 || !strings.HasPrefix(id, "oc_") {
		return false
	}
	for _, c := range id[3:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// DesktopOAuthStatus is the anonymous /api/status oauth object and the
// client_features.oauth flag. Both stay false unless the public proxy is on,
// a preset desktop client is enabled, and the admin health check succeeds.
func DesktopOAuthStatus(ctx context.Context) (map[string]any, bool) {
	disabled := map[string]any{"enabled": false}
	bridge := CurrentOAuthProviderBridge()
	if bridge == nil || !bridge.PublicProxyEnabled() || !strings.HasPrefix(bridge.PublicIssuer(), "https://") {
		return disabled, false
	}
	clients := map[string]string{}
	for _, name := range []string{"boxo", "cherry_studio"} {
		redirects, _, ok := OAuthClientPreset(name)
		if !ok {
			continue
		}
		id := model.FirstEnabledOAuthClientID(redirects)
		if oauthGeneratedClientID(id) {
			clients[name] = id
		}
	}
	desktop := clients["boxo"]
	if desktop == "" {
		desktop = clients["cherry_studio"]
	}
	if desktop == "" || !bridge.PublicProxyReady(ctx) {
		return disabled, false
	}
	return map[string]any{
		"enabled":           true,
		"issuer":            bridge.PublicIssuer(),
		"desktop_client_id": desktop,
		"desktop_clients":   clients,
	}, true
}

func OAuthClientPreset(name string) (redirects []string, scopes []string, ok bool) {
	switch name {
	case "boxo":
		redirects = []string{"http://127.0.0.1/oauth/callback"}
	case "cherry_studio":
		redirects = []string{"http://127.0.0.1:29873/oauth/callback"}
	default:
		return nil, nil, false
	}
	return redirects, slices.Clone(oauthProviderKnownScopes), true
}

func NormalizeOAuthClientRegistration(name, preset string, redirects, scopes []string) (string, []string, []string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n") {
		return "", nil, nil, ErrOAuthProviderRequest
	}
	if preset != "" {
		fixed, presetScopes, ok := OAuthClientPreset(preset)
		if !ok {
			return "", nil, nil, ErrOAuthProviderRequest
		}
		redirects = fixed
		if len(scopes) == 0 {
			scopes = presetScopes
		}
	}
	normalizedRedirects, err := normalizeOAuthRedirects(redirects)
	if err != nil {
		return "", nil, nil, err
	}
	normalizedScopes, err := normalizeOAuthClientScopes(scopes)
	if err != nil {
		return "", nil, nil, err
	}
	return name, normalizedRedirects, normalizedScopes, nil
}

func normalizeOAuthRedirects(redirects []string) ([]string, error) {
	if len(redirects) == 0 || len(redirects) > 8 {
		return nil, ErrOAuthProviderRequest
	}
	values := slices.Clone(redirects)
	slices.Sort(values)
	for i, redirect := range values {
		if !ValidOAuthClientRedirect(redirect) || (i > 0 && values[i-1] == redirect) {
			return nil, ErrOAuthProviderRequest
		}
	}
	return values, nil
}

func normalizeOAuthClientScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > len(oauthProviderKnownScopes) {
		return nil, ErrOAuthProviderRequest
	}
	ordered := []string{}
	for _, scope := range oauthProviderKnownScopes {
		if slices.Contains(scopes, scope) {
			ordered = append(ordered, scope)
		}
	}
	if len(ordered) != len(scopes) || !slices.Contains(ordered, "profile") {
		return nil, ErrOAuthProviderRequest
	}
	return ordered, nil
}

func normalizeOAuthClientManageContext(fields map[string]common.RawMessage) (OAuthClientManageContext, error) {
	var action string
	if common.Unmarshal(fields["action"], &action) != nil {
		return OAuthClientManageContext{}, ErrVerificationContextInvalid
	}
	switch action {
	case "create":
		if len(fields) != 4 {
			return OAuthClientManageContext{}, ErrVerificationContextInvalid
		}
	case "update":
		if len(fields) != 5 {
			return OAuthClientManageContext{}, ErrVerificationContextInvalid
		}
	case "delete":
		if len(fields) != 2 {
			return OAuthClientManageContext{}, ErrVerificationContextInvalid
		}
	default:
		return OAuthClientManageContext{}, ErrVerificationContextInvalid
	}
	result := OAuthClientManageContext{Action: action}
	if action == "delete" || action == "update" {
		if common.Unmarshal(fields["client_row_id"], &result.ClientRowID) != nil || result.ClientRowID <= 0 {
			return OAuthClientManageContext{}, ErrVerificationContextInvalid
		}
	}
	if action == "delete" {
		return result, nil
	}
	var redirects, scopes []string
	if common.Unmarshal(fields["name"], &result.Name) != nil || common.Unmarshal(fields["redirects"], &redirects) != nil || common.Unmarshal(fields["scopes"], &scopes) != nil {
		return OAuthClientManageContext{}, ErrVerificationContextInvalid
	}
	name, normalizedRedirects, normalizedScopes, err := NormalizeOAuthClientRegistration(result.Name, "", redirects, scopes)
	if err != nil {
		return OAuthClientManageContext{}, ErrVerificationContextInvalid
	}
	result.Name, result.Redirects, result.Scopes = name, normalizedRedirects, normalizedScopes
	return result, nil
}

func NewOAuthClientID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "oc_" + hex.EncodeToString(buf), nil
}

func OAuthRedirectRegistered(raw string) bool {
	for _, registered := range model.EnabledOAuthRedirects() {
		if validOAuthProviderRedirect(raw, registered) {
			return true
		}
	}
	return false
}

func (b *OAuthProviderBridge) SyncPublicClient(ctx context.Context, clientID, name, scope string, redirects []string, create bool) error {
	if b == nil || b.resource == nil || b.resource.client == nil {
		return nil
	}
	method, endpoint := http.MethodPut, b.admin+"/admin/clients/"+url.PathEscape(clientID)
	if create {
		method, endpoint = http.MethodPost, b.admin+"/admin/clients"
	}
	body := map[string]any{
		"client_id": clientID, "client_name": name, "scope": scope,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"redirect_uris": redirects, "audience": []string{b.resource.audience},
		"token_endpoint_auth_method": "none", "skip_consent": false,
	}
	return b.oauthAdminJSON(ctx, method, endpoint, body, http.StatusOK, http.StatusCreated)
}

func (b *OAuthProviderBridge) DeletePublicClient(ctx context.Context, clientID string) error {
	if b == nil || b.resource == nil || b.resource.client == nil {
		return nil
	}
	return b.oauthAdminJSON(ctx, http.MethodDelete, b.admin+"/admin/clients/"+url.PathEscape(clientID), nil, http.StatusOK, http.StatusNoContent, http.StatusNotFound)
}

func (b *OAuthProviderBridge) oauthAdminJSON(ctx context.Context, method, endpoint string, body any, accepted ...int) error {
	var reader *strings.Reader
	if body != nil {
		data, err := common.Marshal(body)
		if err != nil {
			return ErrOAuthResourceUnavailable
		}
		reader = strings.NewReader(string(data))
	}
	var req *http.Request
	var err error
	if reader == nil {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, reader)
	}
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.resource.client.Do(req)
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	defer resp.Body.Close()
	if !slices.Contains(accepted, resp.StatusCode) {
		return ErrOAuthResourceUnavailable
	}
	return nil
}

func oauthJoinedScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}
