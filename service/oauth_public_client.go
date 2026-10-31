/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"gorm.io/gorm"
)

const (
	oauthPublicClientIDMin       = 8
	oauthPublicClientIDMax       = 64
	oauthPublicClientNameMax     = 128
	oauthPublicClientRedirectMax = 8
	oauthPublicClientRedirectLen = 2048
)

var (
	ErrOAuthPublicClientID       = errors.New("Invalid OAuth client ID")
	ErrOAuthPublicClientName     = errors.New("Invalid OAuth client name")
	ErrOAuthPublicClientRedirect = errors.New("Invalid OAuth redirect URI")
	ErrOAuthPublicClientScope    = errors.New("Invalid OAuth scope")
)

// OAuthPublicClientPreset is a registration template. It does not choose a
// client_id; that value is entered by the administrator and is not a secret.
type OAuthPublicClientPreset struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
}

func validOAuthPublicClientID(clientID string) bool {
	return len(clientID) >= oauthPublicClientIDMin && len(clientID) <= oauthPublicClientIDMax && validOAuthProviderCapability(clientID)
}

// validOAuthClientIDProof accepts client ids already stored on a grant, which
// may be shorter than a newly registered public client id.
func validOAuthClientIDProof(clientID string) bool {
	return clientID != "" && len(clientID) <= 128 && validOAuthProviderCapability(clientID)
}

func PublicOAuthClientPresets() []OAuthPublicClientPreset {
	grants := []string{"authorization_code", "refresh_token"}
	// Desktop readiness requires these four. balance:read, usage:read and
	// tokens:read stay optional; Normalize still requires profile.
	scopes := []string{"openid", "profile", "offline_access", "tokens:write"}
	return []OAuthPublicClientPreset{
		{
			Key: "boxnai-desktop", Name: "Boxnai Desktop", Scopes: scopes, GrantTypes: grants,
			RedirectURIs: []string{"http://127.0.0.1/oauth/callback", "http://[::1]/oauth/callback", "boxnai://oauth/callback"},
		},
		{
			Key: "cherry-studio", Name: "Cherry Studio", Scopes: scopes, GrantTypes: grants,
			RedirectURIs: []string{"http://127.0.0.1:29873/oauth/callback", "http://[::1]:29873/oauth/callback", "cherrystudio://oauth/callback"},
		},
	}
}

// NormalizePublicOAuthClient checks a public-client registration. There is no
// client secret: native apps authenticate with PKCE, and http is accepted only
// for an exact loopback callback.
func NormalizePublicOAuthClient(clientID, name string, redirects, scopes []string) (string, string, string, string, error) {
	clientID = strings.TrimSpace(clientID)
	if !validOAuthPublicClientID(clientID) {
		return "", "", "", "", ErrOAuthPublicClientID
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > oauthPublicClientNameMax || strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) }) {
		return "", "", "", "", ErrOAuthPublicClientName
	}
	if len(redirects) == 0 || len(redirects) > oauthPublicClientRedirectMax {
		return "", "", "", "", ErrOAuthPublicClientRedirect
	}
	normalizedRedirects := make([]string, 0, len(redirects))
	for _, raw := range redirects {
		raw = strings.TrimSpace(raw)
		if raw == "" || len(raw) > oauthPublicClientRedirectLen || strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsControl(r) }) || !validOAuthProviderRedirect(raw, raw) {
			return "", "", "", "", ErrOAuthPublicClientRedirect
		}
		if slices.Contains(normalizedRedirects, raw) {
			return "", "", "", "", ErrOAuthPublicClientRedirect
		}
		normalizedRedirects = append(normalizedRedirects, raw)
	}
	if len(scopes) == 0 || len(scopes) > len(oauthPublicScopes) {
		return "", "", "", "", ErrOAuthPublicClientScope
	}
	normalizedScopes := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || !slices.Contains(oauthPublicScopes, scope) || slices.Contains(normalizedScopes, scope) {
			return "", "", "", "", ErrOAuthPublicClientScope
		}
		normalizedScopes = append(normalizedScopes, scope)
	}
	if !slices.Contains(normalizedScopes, "profile") {
		return "", "", "", "", ErrOAuthPublicClientScope
	}
	slices.Sort(normalizedScopes)
	redirectJSON, err := common.Marshal(normalizedRedirects)
	if err != nil {
		return "", "", "", "", ErrOAuthPublicClientRedirect
	}
	scopeJSON, err := common.Marshal(normalizedScopes)
	if err != nil {
		return "", "", "", "", ErrOAuthPublicClientScope
	}
	return clientID, name, string(redirectJSON), string(scopeJSON), nil
}

const (
	oauthPublicClientSyncRejected    = "OAUTH_PUBLIC_CLIENT_SYNC_REJECTED"
	oauthPublicClientSyncUnavailable = "OAUTH_PUBLIC_CLIENT_SYNC_UNAVAILABLE"
)

// OAuthPublicClientSyncError is a failed Hydra Admin registration. Code is the
// API error code. Error text is the web-console message key. The upstream body
// is never included: a Hydra response can echo a generated client secret.
type OAuthPublicClientSyncError struct {
	Code       string
	HTTPStatus int
}

func (e *OAuthPublicClientSyncError) Error() string {
	if e != nil && e.Code == oauthPublicClientSyncRejected {
		return "OAuth client registration was rejected"
	}
	return "OAuth client registration is unavailable"
}

type hydraPublicClientDocument struct {
	ID          string   `json:"client_id"`
	Name        string   `json:"client_name"`
	Method      string   `json:"token_endpoint_auth_method"`
	SubjectType string   `json:"subject_type"`
	Grants      []string `json:"grant_types"`
	Responses   []string `json:"response_types"`
	Scope       string   `json:"scope"`
	Audience    []string `json:"audience"`
	Redirects   []string `json:"redirect_uris"`
	SkipConsent bool     `json:"skip_consent"`
}

// CommitOAuthPublicClient applies a console create, update, or delete.
// When the provider bridge and the public OAuth service are both active, the
// local transaction commits only after Hydra Admin accepts the same public
// client. Admin 4xx (OAUTH_PUBLIC_CLIENT_SYNC_REJECTED) and transport or 5xx
// failures (OAUTH_PUBLIC_CLIENT_SYNC_UNAVAILABLE) roll the local row back.
// With either switch off, only the local row changes and no Admin request is
// sent. A disabled client is removed from Hydra and kept locally. The returned
// bool is true only after that Hydra write has been accepted and committed.
// No client secret is sent or stored. Public clients use
// token_endpoint_auth_method=none; authorize and token routes still require
// S256 PKCE. Hydra's own PKCE enforcement stays a deployment setting.
func CommitOAuthPublicClient(ctx context.Context, client *model.OAuthPublicClient, action string) (bool, error) {
	if client == nil || (action != "create" && action != "update" && action != "delete") {
		return false, errors.New("invalid OAuth client action")
	}
	public := CurrentOAuthProviderBridge().Public()
	err := model.DB.Transaction(func(tx *gorm.DB) error {
		switch action {
		case "create":
			if err := tx.Create(client).Error; err != nil {
				return err
			}
		case "update":
			if err := tx.Save(client).Error; err != nil {
				return err
			}
		default:
			result := tx.Delete(&model.OAuthPublicClient{}, client.ID)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				return gorm.ErrRecordNotFound
			}
		}
		if public == nil {
			return nil
		}
		if action == "delete" || !client.Enabled {
			return public.removeHydraPublicClient(ctx, client.ClientID)
		}
		redirects, err := model.DecodeOAuthPublicClientList(client.RedirectURIs)
		if err != nil {
			return err
		}
		scopes, err := model.DecodeOAuthPublicClientList(client.Scopes)
		if err != nil {
			return err
		}
		return public.upsertHydraPublicClient(ctx, client.ClientID, client.Name, redirects, scopes)
	})
	if err != nil {
		return false, err
	}
	return public != nil, nil
}

func (p *OAuthPublic) upsertHydraPublicClient(ctx context.Context, id, name string, redirects, scopes []string) error {
	payload, err := common.Marshal(hydraPublicClientDocument{
		ID: id, Name: name, Method: "none", SubjectType: "public",
		Grants: []string{"authorization_code", "refresh_token"}, Responses: []string{"code"},
		Scope: strings.Join(scopes, " "), Audience: []string{p.bridge.resource.audience},
		Redirects: redirects, SkipConsent: false,
	})
	if err != nil {
		return &OAuthPublicClientSyncError{Code: oauthPublicClientSyncUnavailable, HTTPStatus: http.StatusServiceUnavailable}
	}
	path := "/admin/clients/" + url.PathEscape(id)
	status, data, err := p.hydraAdminJSON(ctx, http.MethodPut, path, payload)
	if err != nil {
		return oauthPublicClientSyncTransport(id, err)
	}
	if status == http.StatusNotFound {
		status, data, err = p.hydraAdminJSON(ctx, http.MethodPost, "/admin/clients", payload)
		if err != nil {
			return oauthPublicClientSyncTransport(id, err)
		}
		if status == http.StatusConflict {
			status, data, err = p.hydraAdminJSON(ctx, http.MethodPut, path, payload)
			if err != nil {
				return oauthPublicClientSyncTransport(id, err)
			}
		}
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return oauthPublicClientSyncHTTPStatus(id, status)
	}
	if !hydraPublicClientMatches(p, data, id, name, redirects, scopes) {
		common.SysError(common.LogText("oauth public client sync failed client_id=%s code=%s status=%d", id, oauthPublicClientSyncRejected, status))
		return &OAuthPublicClientSyncError{Code: oauthPublicClientSyncRejected, HTTPStatus: http.StatusConflict}
	}
	return nil
}

func (p *OAuthPublic) removeHydraPublicClient(ctx context.Context, id string) error {
	status, _, err := p.hydraAdminJSON(ctx, http.MethodDelete, "/admin/clients/"+url.PathEscape(id), nil)
	if err != nil {
		return oauthPublicClientSyncTransport(id, err)
	}
	if status == http.StatusOK || status == http.StatusNoContent || status == http.StatusNotFound {
		return nil
	}
	return oauthPublicClientSyncHTTPStatus(id, status)
}

func (p *OAuthPublic) hydraAdminJSON(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.bridge.admin+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.GetBody = nil
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.bridge.resource.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return 0, nil, err
	}
	if len(data) > 65536 {
		return 0, nil, errors.New("oauth admin response too large")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return resp.StatusCode, nil, nil
	}
	return resp.StatusCode, data, nil
}

func hydraPublicClientMatches(p *OAuthPublic, data []byte, id, name string, redirects, scopes []string) bool {
	fields, err := common.DecodeRawJSONObject(data)
	if err != nil {
		return false
	}
	security := map[string]common.RawMessage{}
	for _, key := range []string{"client_id", "client_name", "token_endpoint_auth_method", "subject_type", "grant_types", "response_types", "scope", "audience", "redirect_uris", "skip_consent"} {
		value, exists := fields[key]
		if !exists {
			return false
		}
		security[key] = value
	}
	encoded, err := common.Marshal(security)
	var doc hydraPublicClientDocument
	if err != nil || common.Unmarshal(encoded, &doc) != nil {
		return false
	}
	registered, scopeErr := oauthProviderScopeSet(doc.Scope)
	expected, expectedErr := oauthProviderScopeSet(strings.Join(scopes, " "))
	if scopeErr != nil || expectedErr != nil || doc.SkipConsent || doc.ID != id || doc.Name != name || doc.Method != "none" || doc.SubjectType != "public" {
		return false
	}
	return sameOAuthProviderSet(doc.Grants, []string{"authorization_code", "refresh_token"}) &&
		sameOAuthProviderSet(doc.Responses, []string{"code"}) &&
		sameOAuthProviderSet(doc.Audience, []string{p.bridge.resource.audience}) &&
		sameOAuthProviderSet(doc.Redirects, redirects) &&
		sameOAuthProviderSet(registered, expected)
}

func oauthPublicClientSyncTransport(id string, _ error) error {
	common.SysError(common.LogText("oauth public client sync failed client_id=%s code=%s status=%d", id, oauthPublicClientSyncUnavailable, 0))
	return &OAuthPublicClientSyncError{Code: oauthPublicClientSyncUnavailable, HTTPStatus: http.StatusServiceUnavailable}
}

func oauthPublicClientSyncHTTPStatus(id string, status int) error {
	code := oauthPublicClientSyncUnavailable
	httpStatus := http.StatusServiceUnavailable
	if status >= 400 && status < 500 {
		code = oauthPublicClientSyncRejected
		httpStatus = http.StatusConflict
	}
	common.SysError(common.LogText("oauth public client sync failed client_id=%s code=%s status=%d", id, code, status))
	return &OAuthPublicClientSyncError{Code: code, HTTPStatus: httpStatus}
}
