package service

import (
	"context"
	"math"
	"reflect"
	"slices"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// RequireDerivedTokenReadScope does not add this scope to the public catalogue.
// Its producer and registration remain a separate, default-off integration gate.
func (a *OAuthUserInfoAccess) RequireDerivedTokenReadScope() error {
	if a == nil || a.resource == nil || !a.resource.grantsRequired || a.credential == "" || a.identity.userID <= 0 || a.identity.grantID == "" {
		return ErrOAuthInvalidToken
	}
	if !slices.Contains(a.identity.scopes, "tokens:read") {
		return ErrOAuthInsufficientScope
	}
	return nil
}

// PrepareDerivedTokenMetadata is not registered by K1a. It reuses the actual
// introspection/current-grant implementation, including its public scope gate.
// No test-only identity constructor or alternate authentication path is provided.
func (a *OAuthUserInfoAccess) PrepareDerivedTokenMetadata(ctx context.Context) ([]byte, error) {
	if a == nil || a.resource == nil {
		return nil, ErrOAuthInvalidToken
	}
	if _, _, err := a.resource.readCurrentIdentity(ctx, a.credential); err != nil {
		return nil, err
	}
	if err := a.RequireDerivedTokenReadScope(); err != nil {
		return nil, err
	}
	ref := model.OAuthGrantRef(a.identity.issuer, a.identity.grantID)
	snapshot, err := model.ReadOAuthDerivedTokenMetadata(ctx, ref, a.identity.userID)
	if err != nil {
		return nil, oauthGrantError(err)
	}
	unit := common.QuotaPerUnit
	if unit <= 0 || math.IsNaN(unit) || math.IsInf(unit, 0) {
		return nil, ErrOAuthResourceUnavailable
	}
	data, err := common.Marshal(struct {
		Success      bool                              `json:"success"`
		Message      string                            `json:"message"`
		Data         []model.OAuthDerivedTokenMetadata `json:"data"`
		QuotaPerUnit float64                           `json:"quota_per_unit"`
	}{Success: true, Data: snapshot.Items, QuotaPerUnit: unit})
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	// Authentication remains in the existing resource server. Only comparison of
	// this resource's bound identity and source projection is performed here.
	identity, _, err := a.resource.readCurrentIdentity(ctx, a.credential)
	if err != nil {
		return nil, err
	}
	if identity.userID != a.identity.userID || identity.authVersion != a.identity.authVersion || identity.issuer != a.identity.issuer ||
		identity.clientID != a.identity.clientID || identity.grantID != a.identity.grantID || identity.grantExpiresAt != a.identity.grantExpiresAt ||
		identity.grantRevision != a.identity.grantRevision || identity.expiresAt != a.identity.expiresAt || identity.notBefore != a.identity.notBefore ||
		!sameOAuthProviderSet(identity.scopes, a.identity.scopes) {
		return nil, ErrOAuthInvalidToken
	}
	current, err := model.ReadOAuthDerivedTokenMetadata(ctx, ref, identity.userID)
	if err != nil {
		return nil, oauthGrantError(err)
	}
	if !reflect.DeepEqual(snapshot, current) || common.QuotaPerUnit != unit {
		return nil, ErrOAuthResourceUnavailable
	}
	now := time.Now().Unix()
	for _, item := range current.Items {
		if (item.Status == "active" || item.Status == "exhausted") && item.ExpiresAt <= now {
			return nil, ErrOAuthResourceUnavailable
		}
	}
	if identity.expiresAt <= now || identity.grantExpiresAt <= now || identity.notBefore > now {
		return nil, ErrOAuthInvalidToken
	}
	if ctx.Err() != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	return data, nil
}
