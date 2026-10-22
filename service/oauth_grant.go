package service

import (
	"context"
	"errors"
	"strconv"

	"github.com/QuantumNous/new-api/model"
	"gorm.io/gorm"
)

// InitOAuthGrantStore runs only after host DB and options are ready, before the
// public topology becomes available. Public-disabled legacy userinfo needs no DB
// grant schema because it rejects tokens bearing either public grant marker.
func InitOAuthGrantStore() error {
	bridge := CurrentOAuthProviderBridge()
	enabled := bridge != nil && bridge.public != nil
	if model.DB != nil && model.DB.Migrator().HasTable(&model.OAuthGrant{}) {
		enabled = true
	}
	return model.InitOAuthGrantStore(enabled)
}

func oauthGrantError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, model.ErrOAuthGrantInvalid) || errors.Is(err, model.ErrUserSessionInactive) || errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrOAuthInvalidToken
	}
	return ErrOAuthResourceUnavailable
}

func authorizeOAuthGrant(ctx context.Context, identity OAuthResourceIdentity, activate bool) (*model.OAuthGrantSnapshot, error) {
	user, err := model.AuthorizeOAuthGrant(ctx, model.OAuthGrantAuthorization{
		Issuer: identity.issuer, GrantID: identity.grantID, ClientID: identity.clientID,
		Subject: strconv.Itoa(identity.userID), UserID: identity.userID, AuthVersion: identity.authVersion,
		GrantExpiresAt: identity.grantExpiresAt, TokenExpiresAt: identity.expiresAt, NotBefore: identity.notBefore,
		Scopes: identity.scopes, Activate: activate,
	})
	return user, oauthGrantError(err)
}
