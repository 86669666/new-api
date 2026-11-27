package model

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

var (
	ErrOAuthIssueConflict = errors.New("OAuth key issuance request conflicts with an existing key")
	ErrOAuthIssueClosed   = errors.New("OAuth key issuance is not available for this grant")
	ErrOAuthIssueLimit    = errors.New("OAuth derived-key issuance limit reached")
)

// OAuthFirstKeyIssuer owns the separate database session for the entire write
// transaction. The ordinary gateway pool cannot complete the source.
type OAuthFirstKeyIssuer struct {
	db *gorm.DB
}

func OpenOAuthFirstKeyIssuer(ctx context.Context, serviceDSN, issuerDSN string) (*OAuthFirstKeyIssuer, error) {
	db, err := openOAuthIssuePrincipal(ctx, serviceDSN, issuerDSN, oauthFirstKeyIssuerRestricted)
	if err != nil {
		return nil, err
	}
	return &OAuthFirstKeyIssuer{db: db}, nil
}

type OAuthIssuedKey struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Key        string `json:"key,omitempty"`
	QuotaLimit int64  `json:"quota_limit,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
	Derived    bool   `json:"derived,omitempty"`
}

func lockOAuthIssueGrant(tx *gorm.DB, grantRef string, userID int) error {
	if !protectedOAuthSources(tx) || !oauthSourceTransaction(tx) {
		return ErrOAuthIssueClosed
	}
	query := "CALL newapi_oauth_lock_issue_grant(?, ?)"
	if tx.Dialector.Name() == "postgres" {
		query = "SELECT newapi_oauth_source.lock_issue_grant(CAST(? AS bigint), CAST(? AS text))"
	}
	if err := tx.Exec(query, userID, grantRef).Error; err != nil {
		return ErrOAuthIssueClosed
	}
	return nil
}

func (i *OAuthFirstKeyIssuer) Issue(ctx context.Context, claims OAuthGrantAuthorization, revision int64, name, idempotencyKey string) (*OAuthIssuedKey, error) {
	if i == nil || claims.Activate || !slices.Contains(claims.Scopes, "tokens:write") {
		return nil, ErrOAuthIssueClosed
	}
	ref := OAuthGrantRef(claims.Issuer, claims.GrantID)
	idemHash := fmt.Sprintf("%x", sha256.Sum256([]byte("newapi.oauth.derived.idempotency.v1\x00"+ref+"\x00"+idempotencyKey)))
	requestHash := fmt.Sprintf("%x", sha256.Sum256([]byte("newapi.oauth.derived.request.v1\x00"+ref+"\x00"+name)))
	var result *OAuthIssuedKey
	var authorizedUntil int64
	err := withCurrentOAuthGrantOn(ctx, i.db, ref, claims.UserID, true, func(tx *gorm.DB, _ *User, session *UserSession, grant *OAuthGrant) error {
		now := time.Now().Unix()
		if grant.State != "active" || grant.Revision != revision || !oauthGrantMatchesClaims(grant, claims, now) {
			return ErrOAuthGrantInvalid
		}
		authorizedUntil = min(claims.TokenExpiresAt, grant.ExpiresAt, session.ExpiresAt)
		if err := validateOAuthDerivedTokenStore(tx, now); err != nil {
			return err
		}
		source, err := lockOAuthSource(tx, grant.UserID, ref)
		if err != nil || source.Validate(now) != nil || source.GrantRef != ref || source.UserID != grant.UserID ||
			source.PolicyHash != grant.PolicyHash || grant.CreatedAt < source.VerifiedAt || grant.ExpiresAt < source.ExpiresAt {
			return ErrOAuthDerivedTokenUnknown
		}
		if source.TokenID != nil {
			if *source.IdemHash != idemHash || *source.RequestHash != requestHash {
				return ErrOAuthIssueConflict
			}
			// The committed source is the issuance receipt, including after the
			// reveal window ends or the owner deletes the Token.
			result = &OAuthIssuedKey{ID: *source.TokenID, Name: name, Derived: true,
				QuotaLimit: source.QuotaLimit, ExpiresAt: source.ExpiresAt}
			return nil
		}
		now = time.Now().Unix()
		if source.TerminalAt != nil || now >= min(source.PermitDeadline, source.ExpiresAt, claims.TokenExpiresAt) {
			return ErrOAuthIssueClosed
		}
		if err := checkOAuthDerivedIssueLimits(tx, grant.UserID, now); err != nil {
			return err
		}
		key, err := common.GenerateKey()
		if err != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		now = time.Now().Unix()
		token := &Token{UserId: grant.UserID, Key: key, Name: name, Status: common.TokenStatusEnabled,
			CreatedTime: now, AccessedTime: now, ExpiredTime: source.ExpiresAt, RemainQuota: int(source.QuotaLimit)}
		if err := insertUserToken(tx, token); err != nil {
			return err
		}
		query := "CALL newapi_oauth_complete_issue(?, ?, ?, ?, ?, ?, ?)"
		if tx.Dialector.Name() == "postgres" {
			query = "SELECT newapi_oauth_source.complete_issue(CAST(? AS bigint), CAST(? AS text), CAST(? AS bigint), CAST(? AS text), CAST(? AS text), CAST(? AS text), CAST(? AS bigint))"
		}
		if err := tx.Exec(query, grant.UserID, ref, token.Id, OAuthDerivedTokenKeyRef(key), idemHash, requestHash, claims.TokenExpiresAt).Error; err != nil {
			return ErrOAuthDerivedTokenUnknown
		}
		result = &OAuthIssuedKey{ID: token.Id, Name: name, Key: key, Derived: true,
			QuotaLimit: source.QuotaLimit, ExpiresAt: source.ExpiresAt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if time.Now().Unix() >= authorizedUntil {
		return nil, ErrOAuthGrantInvalid
	}
	return result, nil
}

func checkOAuthDerivedIssueLimits(tx *gorm.DB, userID int, now int64) error {
	var counts struct{ Active, Recent int64 }
	table := "oauth_derived_token_sources"
	if tx.Dialector.Name() == "postgres" {
		table = "public." + table
	}
	if err := tx.Table(table).Select(`
		COUNT(CASE WHEN terminal_at IS NULL AND expires_at > ? THEN 1 END) AS active,
		COUNT(CASE WHEN created_at > ? THEN 1 END) AS recent`, now, now-86400).
		Where("user_id = ? AND token_id IS NOT NULL", userID).Scan(&counts).Error; err != nil {
		return ErrOAuthDerivedTokenUnknown
	}
	if counts.Active >= 3 || counts.Recent >= 3 {
		return ErrOAuthIssueLimit
	}
	return nil
}
