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
package model

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// AuthorizedOAuthApp is the user-visible summary of live grants for one client.
// It omits issuer, session, and grant identifiers.
type AuthorizedOAuthApp struct {
	ClientID   string   `json:"client_id"`
	Scopes     []string `json:"scopes"`
	GrantCount int      `json:"grant_count"`
	ApprovedAt int64    `json:"approved_at"`
	ExpiresAt  int64    `json:"expires_at"`
}

func ListAuthorizedOAuthApps(userID int, now int64) ([]AuthorizedOAuthApp, error) {
	if userID <= 0 {
		return nil, ErrOAuthGrantInvalid
	}
	if DB == nil {
		return nil, ErrOAuthGrantInvalid
	}
	if !DB.Migrator().HasTable(&OAuthGrant{}) {
		return []AuthorizedOAuthApp{}, nil
	}
	var grants []OAuthGrant
	err := DB.Where("user_id = ? AND revoked_at = 0 AND expires_at > ? AND state IN ?", userID, now, []string{"approved", "active"}).
		Order("client_id asc, approved_at asc, grant_ref asc").Find(&grants).Error
	if err != nil {
		return nil, err
	}
	byClient := map[string]*AuthorizedOAuthApp{}
	order := []string{}
	for _, grant := range grants {
		app, ok := byClient[grant.ClientID]
		if !ok {
			app = &AuthorizedOAuthApp{ClientID: grant.ClientID, Scopes: []string{}}
			byClient[grant.ClientID] = app
			order = append(order, grant.ClientID)
		}
		app.GrantCount++
		if grant.ApprovedAt > app.ApprovedAt {
			app.ApprovedAt = grant.ApprovedAt
		}
		if grant.ExpiresAt > app.ExpiresAt {
			app.ExpiresAt = grant.ExpiresAt
		}
		for _, scope := range oauthGrantScopes(grant.Scopes) {
			if scope != "" && !slices.Contains(app.Scopes, scope) {
				app.Scopes = append(app.Scopes, scope)
			}
		}
	}
	apps := make([]AuthorizedOAuthApp, 0, len(order))
	for _, clientID := range order {
		slices.Sort(byClient[clientID].Scopes)
		apps = append(apps, *byClient[clientID])
	}
	return apps, nil
}

func oauthGrantScopes(raw string) []string {
	var scopes []string
	if common.UnmarshalJsonStr(raw, &scopes) == nil && scopes != nil {
		return scopes
	}
	scopes = []string{}
	for scope := range strings.SplitSeq(raw, " ") {
		if scope != "" && !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

// RevokeAuthorizedOAuthApp revokes the caller's live grants for one client.
// When issuer cleanup is enabled, the existing cleanup job is queued. Otherwise
// only the local grant rows change.
func RevokeAuthorizedOAuthApp(ctx context.Context, userID int, clientID string) error {
	if userID <= 0 || clientID == "" || DB == nil || !DB.Migrator().HasTable(&OAuthGrant{}) {
		return ErrOAuthGrantInvalid
	}
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, userID); err != nil {
			return err
		}
		now := time.Now().Unix()
		var count int64
		if err := tx.Model(&OAuthGrant{}).Where("user_id = ? AND client_id = ? AND revoked_at = 0 AND expires_at > ? AND state IN ?", userID, clientID, now, []string{"approved", "active"}).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return ErrOAuthGrantInvalid
		}
		if OAuthCleanupReady() {
			return RevokeOAuthWithTx(tx, userID, "client", clientID, "explicit")
		}
		result := tx.Model(&OAuthGrant{}).Where("user_id = ? AND client_id = ? AND revoked_at = 0", userID, clientID).
			Updates(map[string]any{"state": "revoked", "revoked_at": now, "revoked_reason": "explicit", "revision": gorm.Expr("revision + 1")})
		return result.Error
	})
}
