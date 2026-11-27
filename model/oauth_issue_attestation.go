package model

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

const oauthIssueAttestationTable = "oauth_derived_issue_attestations"

// Only the consent verifier's database principal may append attestations.
// The ordinary gateway principal cannot read or write this table.
type OAuthIssueAttestation struct {
	GrantRef        string `gorm:"type:char(64);primaryKey;not null"`
	ConsentRef      string `gorm:"type:char(64);not null;uniqueIndex:uq_oauth_attest_consent"`
	ProofDigest     string `gorm:"type:char(64);not null;uniqueIndex:uq_oauth_attest_proof"`
	ProofFlowID     int64  `gorm:"not null;uniqueIndex:uq_oauth_attest_flow"`
	UserID          int    `gorm:"not null"`
	OriginSID       string `gorm:"column:origin_sid;type:varchar(64);not null"`
	SessionVersion  int64  `gorm:"not null"`
	UserAuthVersion int64  `gorm:"not null"`
	Issuer          string `gorm:"type:text;not null"`
	ClientID        string `gorm:"type:text;not null"`
	Scopes          string `gorm:"type:text;not null"`
	PolicyHash      string `gorm:"type:char(64);not null"`
	BindingHash     string `gorm:"type:char(64);not null"`
	VerifiedMethod  string `gorm:"type:varchar(16);not null"`
	VerifiedAt      int64  `gorm:"not null"`
	ProofExpiresAt  int64  `gorm:"not null"`
	QuotaLimit      int64  `gorm:"not null"`
	ExpiresAt       int64  `gorm:"not null"`
}

func (OAuthIssueAttestation) TableName() string { return oauthIssueAttestationTable }

// OAuthConsentRef is the stable identity before a grant identifier is allocated.
func OAuthConsentRef(issuer, requestID string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("newapi.oauth.consent.v1\x00"+issuer+"\x00"+requestID)))
}

type OAuthIssueAttestationWriter struct {
	db *gorm.DB
}

// OpenOAuthIssueAttestationWriter pins both principals to the same local SQL
// socket and target. The writer credential is supplied only when explicitly enabled.
func OpenOAuthIssueAttestationWriter(ctx context.Context, serviceDSN, writerDSN string) (*OAuthIssueAttestationWriter, error) {
	db, err := openOAuthIssuePrincipal(ctx, serviceDSN, writerDSN, oauthIssueWriterRestricted)
	if err != nil {
		return nil, err
	}
	return &OAuthIssueAttestationWriter{db: db}, nil
}

func openOAuthIssuePrincipal(ctx context.Context, serviceDSN, writerDSN string, restricted func(*gorm.DB, string) bool) (*gorm.DB, error) {
	if DB == nil || serviceDSN == "" || writerDSN == "" || serviceDSN == writerDSN {
		return nil, ErrOAuthDerivedTokenUnknown
	}
	engine := DB.Dialector.Name()
	query := "SELECT current_database(), current_user::text"
	if engine == "mysql" {
		query = "SELECT DATABASE(), CURRENT_USER()"
	} else if engine != "postgres" {
		return nil, ErrOAuthDerivedTokenUnknown
	}
	var target, servicePrincipal string
	if DB.WithContext(ctx).Raw(query).Row().Scan(&target, &servicePrincipal) != nil || !bootstrapName.MatchString(target) {
		return nil, ErrOAuthDerivedTokenUnknown
	}
	_, serviceEndpoint, err := oauthBootstrapDSN(engine, serviceDSN, target)
	if err != nil {
		return nil, ErrOAuthDerivedTokenUnknown
	}
	dsn, writerEndpoint, err := oauthBootstrapDSN(engine, writerDSN, target)
	if err != nil || serviceEndpoint != writerEndpoint {
		return nil, ErrOAuthDerivedTokenUnknown
	}
	if engine == "mysql" {
		// Disable interpolation and multiple statements for this narrow writer.
		parsed, err := mysqldriver.ParseDSN(dsn)
		if err != nil {
			return nil, ErrOAuthDerivedTokenUnknown
		}
		parsed.InterpolateParams, parsed.MultiStatements = false, false
		dsn = parsed.FormatDSN()
	}
	db, err := openOAuthBootstrapDB(engine, dsn)
	if err != nil {
		return nil, ErrOAuthDerivedTokenUnknown
	}
	var writerTarget, writerPrincipal string
	writerDB := db.WithContext(ctx)
	if writerDB.Raw(query).Row().Scan(&writerTarget, &writerPrincipal) != nil ||
		writerTarget != target || writerPrincipal == "" || writerPrincipal == servicePrincipal ||
		!restricted(writerDB, target) {
		if pool, err := db.DB(); err == nil {
			pool.Close()
		}
		return nil, ErrOAuthDerivedTokenUnknown
	}
	return db, nil
}

func (w *OAuthIssueAttestationWriter) Append(ctx context.Context, a OAuthIssueAttestation) error {
	now := time.Now().Unix()
	source := OAuthDerivedTokenSource{GrantRef: a.GrantRef, UserID: a.UserID, SchemaVersion: 1,
		QuotaLimit: a.QuotaLimit, ExpiresAt: a.ExpiresAt, PolicyHash: a.PolicyHash, BindingHash: a.BindingHash,
		VerifiedAt: a.VerifiedAt, ProofExpiresAt: a.ProofExpiresAt, PermitDeadline: min(a.ProofExpiresAt, a.VerifiedAt+60),
		VerifiedMethod: a.VerifiedMethod, ProofFlowID: a.ProofFlowID}
	if w == nil || source.Validate(now) != nil || !oauthDerivedDigest(a.ConsentRef) || !oauthDerivedDigest(a.ProofDigest) ||
		a.OriginSID == "" || a.SessionVersion <= 0 || a.UserAuthVersion <= 0 || a.Issuer == "" || a.ClientID == "" ||
		source.PermitDeadline <= now || a.ExpiresAt <= now {
		return ErrOAuthDerivedTokenUnknown
	}
	// Use bound parameters and no RETURNING: the writer has INSERT only.
	table := oauthIssueAttestationTable
	if w.db.Dialector.Name() == "postgres" {
		table = "public." + table
	}
	if err := w.db.WithContext(ctx).Exec("INSERT INTO "+table+`
		(grant_ref, consent_ref, proof_digest, proof_flow_id, user_id, origin_sid, session_version, user_auth_version,
		 issuer, client_id, scopes, policy_hash, binding_hash, verified_method, verified_at, proof_expires_at, quota_limit, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.GrantRef, a.ConsentRef, a.ProofDigest, a.ProofFlowID, a.UserID, a.OriginSID, a.SessionVersion, a.UserAuthVersion,
		a.Issuer, a.ClientID, a.Scopes, a.PolicyHash, a.BindingHash, a.VerifiedMethod, a.VerifiedAt, a.ProofExpiresAt,
		a.QuotaLimit, a.ExpiresAt).Error; err != nil {
		return ErrOAuthDerivedTokenUnknown
	}
	return nil
}
