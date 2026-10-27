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
	"errors"
	"slices"
	"strings"
	"unicode"

	"github.com/QuantumNous/new-api/common"
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
	scopes := []string{"openid", "profile", "offline_access"}
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
