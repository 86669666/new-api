package model

import (
	"context"
	"database/sql"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

func protectedOAuthSources(tx *gorm.DB) bool {
	return tx.Dialector.Name() != "sqlite" && common.GetEnvOrDefaultBool("OAUTH_PROTECTED_SOURCE_OPS", false)
}

func oauthSourceTransaction(tx *gorm.DB) bool {
	pool := tx.Statement.ConnPool
	if prepared, ok := pool.(*gorm.PreparedStmtTX); ok && prepared != nil {
		pool = prepared.Tx
	}
	sqlTx, ok := pool.(*sql.Tx)
	return ok && sqlTx != nil
}

// The User lock precedes this operation. The privileged reader acquires the
// source row locks in the same transaction without granting table writes.
func lockOAuthSources(tx *gorm.DB, userID int, grantRef string) ([]OAuthDerivedTokenSource, error) {
	var sources []OAuthDerivedTokenSource
	if !protectedOAuthSources(tx) {
		query := lockForUpdate(tx).Where("user_id = ?", userID)
		if grantRef != "" {
			query = query.Where("grant_ref = ?", grantRef)
		}
		err := query.Order("grant_ref").Find(&sources).Error
		return sources, err
	}
	if !oauthSourceTransaction(tx) {
		return nil, ErrOAuthDerivedTokenUnknown
	}
	switch tx.Dialector.Name() {
	case "postgres":
		if err := tx.Raw("SELECT * FROM newapi_oauth_source.lock_sources(CAST(? AS bigint), CAST(? AS text))", userID, grantRef).Scan(&sources).Error; err != nil {
			return nil, ErrOAuthDerivedTokenUnknown
		}
	case "mysql":
		if err := tx.Raw("CALL newapi_oauth_lock_sources(?, ?)", userID, grantRef).Scan(&sources).Error; err != nil {
			return nil, ErrOAuthDerivedTokenUnknown
		}
	default:
		return nil, ErrOAuthDerivedTokenUnknown
	}
	return sources, nil
}

func lockOAuthSource(tx *gorm.DB, userID int, grantRef string) (*OAuthDerivedTokenSource, error) {
	sources, err := lockOAuthSources(tx, userID, grantRef)
	if err != nil || len(sources) != 1 {
		return nil, ErrOAuthDerivedTokenUnknown
	}
	return &sources[0], nil
}

func applyProtectedOAuthTerminal(tx *gorm.DB, source *OAuthDerivedTokenSource, reason string, now int64) error {
	if !oauthSourceTransaction(tx) || !oauthDerivedDigest(source.GrantRef) || source.UserID <= 0 ||
		(reason != "disabled" && reason != "deleted" && reason != "revoked") || now > time.Now().Unix() {
		return ErrOAuthDerivedTokenUnknown
	}
	var query string
	switch tx.Dialector.Name() {
	case "postgres":
		query = "SELECT newapi_oauth_source.terminal_source(CAST(? AS bigint), CAST(? AS text), CAST(? AS text), CAST(? AS bigint))"
	case "mysql":
		query = "CALL newapi_oauth_terminal_source(?, ?, ?, ?)"
	default:
		return ErrOAuthDerivedTokenUnknown
	}
	if err := tx.Exec(query, source.UserID, source.GrantRef, reason, now).Error; err != nil {
		return ErrOAuthDerivedTokenUnknown
	}
	return nil
}

func reserveAttestedOAuthSource(tx *gorm.DB, grant *OAuthGrant) error {
	if !protectedOAuthSources(tx) || !oauthSourceTransaction(tx) {
		return ErrOAuthDerivedTokenUnknown
	}
	var query string
	switch tx.Dialector.Name() {
	case "postgres":
		query = "SELECT newapi_oauth_source.reserve_attested_source(CAST(? AS bigint), CAST(? AS text))"
	case "mysql":
		query = "CALL newapi_oauth_reserve_attested_source(?, ?)"
	default:
		return ErrOAuthDerivedTokenUnknown
	}
	if err := tx.Exec(query, grant.UserID, grant.GrantRef).Error; err != nil {
		return ErrOAuthDerivedTokenUnknown
	}
	return nil
}

func OAuthGrantHasIssueReservation(ctx context.Context, grantRef string) (bool, error) {
	table := "oauth_derived_token_sources"
	if DB.Dialector.Name() == "postgres" {
		table = "public." + table
	}
	var count int64
	err := DB.WithContext(ctx).Table(table).Where("grant_ref = ?", grantRef).Count(&count).Error
	return count != 0, err
}
