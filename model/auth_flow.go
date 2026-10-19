package model

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	AuthFlowPurposeOAuth             = "oauth"
	AuthFlowPurposeTwoFALogin        = "2fa_login"
	AuthFlowPurposeLoginVerification = "login_verification"
	AuthFlowPurposeLoginPasskey      = "login_passkey"
	AuthFlowPurposePasskeyLogin      = "passkey_login"
	AuthFlowPurposePasskeyRegister   = "passkey_register"
	AuthFlowPurposePasskeyStepUp     = "passkey_step_up"
	AuthFlowPurposeTelegramBind      = "telegram_bind"
	AuthFlowPurposeTelegramAssertion = "telegram_assertion"
	AuthFlowIntentLogin              = "login"
	AuthFlowIntentBind               = "bind"
	AuthFlowIntentVerify             = "verify"
	AuthFlowPurposeTwoFASetup        = "2fa_setup"
	AuthFlowPurposeSecurityProof     = "security_proof"
	AuthFlowPurposeEmailBinding      = "email_binding"
	AuthFlowTokenBytes               = 32
	AuthFlowDefaultCleanupRetention  = 24 * time.Hour
)

var (
	ErrAuthFlowInvalid  = errors.New("auth flow is invalid")
	ErrAuthFlowExpired  = errors.New("auth flow has expired")
	ErrAuthFlowConsumed = errors.New("auth flow has already been consumed")
)

// AuthFlow stores one-time, short-lived state for authentication ceremonies.
// TokenHash is an HMAC of the opaque token; the token itself is never persisted.
type AuthFlow struct {
	Id         int64      `json:"id" gorm:"primaryKey"`
	TokenHash  string     `json:"-" gorm:"type:char(64);not null;uniqueIndex"`
	Purpose    string     `json:"purpose" gorm:"type:varchar(32);not null;index:idx_auth_flow_purpose_expiry"`
	Provider   string     `json:"provider,omitempty" gorm:"type:varchar(64)"`
	Intent     string     `json:"intent,omitempty" gorm:"type:varchar(16)"`
	UserId     int        `json:"user_id,omitempty" gorm:"index"`
	SessionId  string     `json:"session_id,omitempty" gorm:"type:varchar(64);index"`
	Payload    string     `json:"-" gorm:"type:text"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at" gorm:"not null;index:idx_auth_flow_purpose_expiry"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty" gorm:"index"`
}

func (AuthFlow) TableName() string {
	return "auth_flows"
}

type AuthFlowCreate struct {
	CreatedAt time.Time
	Purpose   string
	Provider  string
	Intent    string
	UserId    int
	SessionId string
	Payload   string
	ExpiresAt time.Time
}

type AuthFlowMatch struct {
	Purpose   string
	Provider  string
	Intent    string
	UserId    int
	SessionId string
}

// AuthSessionIdentity binds an authentication flow to a specific session version.
type AuthSessionIdentity struct {
	UserID          int    `json:"user_id"`
	SessionID       string `json:"session_id"`
	UserAuthVersion int64  `json:"auth_version"`
	SessionVersion  int64  `json:"session_version"`
}

// AuthFlowAuthorization is server-owned state carried into a configuration flow
// after a proof has been consumed. ProofID is a database ID, never the proof token.
type AuthFlowAuthorization struct {
	AuthSessionIdentity
	ProofID     int64  `json:"proof_id"`
	Scope       string `json:"scope"`
	ContextHash string `json:"context_hash"`
	Method      string `json:"method"`
}

// ValidateAuthSessionWithTx rechecks the authoritative identity while holding the
// user/session locks until the caller's credential change or flow consumption commits.
// Token-bound identities (pat:<id>) are checked against user_access_tokens instead.
func ValidateAuthSessionWithTx(tx *gorm.DB, identity AuthSessionIdentity) error {
	if tokenID, ok := ParseAccessTokenSessionID(identity.SessionID); ok {
		return validateAccessTokenIdentityWithTx(tx, tokenID, identity)
	}
	if identity.UserID <= 0 || identity.SessionID == "" || identity.UserAuthVersion <= 0 || identity.SessionVersion <= 0 {
		return ErrUserSessionInactive
	}
	var user User
	if err := lockForUpdate(tx).First(&user, identity.UserID).Error; err != nil {
		return err
	}
	if user.Status != common.UserStatusEnabled || user.AuthVersion != identity.UserAuthVersion {
		return ErrUserSessionInactive
	}
	var session UserSession
	if err := lockForUpdate(tx).Where("sid = ? AND user_id = ?", identity.SessionID, identity.UserID).First(&session).Error; err != nil {
		return err
	}
	if session.Status != UserSessionStatusActive || session.RevokedAt != 0 || session.ExpiresAt <= time.Now().Unix() || session.UserAuthVersion != identity.UserAuthVersion || session.Version != identity.SessionVersion {
		return ErrUserSessionInactive
	}
	return nil
}

func applyAuthFlowMatch(query *gorm.DB, token string, match AuthFlowMatch) *gorm.DB {
	query = query.Where("token_hash = ? AND purpose = ?", authFlowTokenHash(token), match.Purpose)
	if match.Provider != "" {
		query = query.Where("provider = ?", match.Provider)
	}
	if match.Intent != "" {
		query = query.Where("intent = ?", match.Intent)
	}
	if match.UserId != 0 {
		query = query.Where("user_id = ?", match.UserId)
	}
	if match.SessionId != "" {
		query = query.Where("session_id = ?", match.SessionId)
	}
	return query
}

func authFlowTokenHash(token string) string {
	return common.GenerateHMACWithKey([]byte("auth-flow-v1:"+common.SessionSecret), token)
}

func CreateAuthFlow(input AuthFlowCreate) (string, *AuthFlow, error) {
	return CreateAuthFlowWithContext(context.Background(), input)
}

func CreateAuthFlowWithContext(ctx context.Context, input AuthFlowCreate) (string, *AuthFlow, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return createAuthFlowWithTx(DB.WithContext(ctx), input)
}

func createAuthFlowWithTx(tx *gorm.DB, input AuthFlowCreate) (string, *AuthFlow, error) {
	if strings.TrimSpace(input.Purpose) == "" || input.ExpiresAt.IsZero() || !input.ExpiresAt.After(time.Now()) {
		return "", nil, ErrAuthFlowInvalid
	}
	random := make([]byte, AuthFlowTokenBytes)
	if _, err := rand.Read(random); err != nil {
		return "", nil, fmt.Errorf("generate auth flow token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	flow := &AuthFlow{
		TokenHash: authFlowTokenHash(token),
		CreatedAt: input.CreatedAt,
		Purpose:   input.Purpose,
		Provider:  input.Provider,
		Intent:    input.Intent,
		UserId:    input.UserId,
		SessionId: input.SessionId,
		Payload:   input.Payload,
		ExpiresAt: input.ExpiresAt,
	}
	if err := tx.Create(flow).Error; err != nil {
		return "", nil, err
	}
	return token, flow, nil
}

// ClaimExternalAuthAssertion records a signed provider assertion as consumed.
// The assertion is HMACed before storage and the unique token_hash index makes
// replay rejection atomic on SQLite, MySQL and PostgreSQL.
func ClaimExternalAuthAssertion(purpose, assertion string, expiresAt time.Time) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalAuthAssertionWithTx(tx, purpose, assertion, expiresAt)
	})
}

// ClaimExternalAuthAssertionWithTx records a provider assertion in the
// caller's transaction so replay protection can commit atomically with the
// authentication flow and its resulting state change.
func ClaimExternalAuthAssertionWithTx(tx *gorm.DB, purpose, assertion string, expiresAt time.Time) error {
	purpose = strings.TrimSpace(purpose)
	assertion = strings.TrimSpace(assertion)
	now := time.Now()
	if tx == nil || purpose == "" || assertion == "" || !expiresAt.After(now) {
		return ErrAuthFlowInvalid
	}
	flow := AuthFlow{
		TokenHash:  authFlowTokenHash("external:" + purpose + ":" + assertion),
		Purpose:    purpose,
		ExpiresAt:  expiresAt,
		ConsumedAt: &now,
	}
	result := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "token_hash"}},
		DoNothing: true,
	}).Create(&flow)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrAuthFlowConsumed
	}
	return nil
}

// GetAuthFlow validates a flow without consuming it. Callers must still use
// ConsumeAuthFlow with all identity-bound fields before performing the action.
func GetAuthFlow(token string, match AuthFlowMatch) (*AuthFlow, error) {
	if token == "" || match.Purpose == "" {
		return nil, ErrAuthFlowInvalid
	}
	var flow AuthFlow
	if err := applyAuthFlowMatch(DB, token, match).First(&flow).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAuthFlowInvalid
		}
		return nil, err
	}
	if flow.ConsumedAt != nil {
		return nil, ErrAuthFlowConsumed
	}
	if !flow.ExpiresAt.After(time.Now()) {
		return nil, ErrAuthFlowExpired
	}
	return &flow, nil
}

// ConsumeAuthFlow atomically validates and consumes a flow. Optional match
// fields are enforced when non-zero so tokens cannot cross purposes or users.
func ConsumeAuthFlow(token string, match AuthFlowMatch) (*AuthFlow, error) {
	return ConsumeAuthFlowWithAction(token, match, nil)
}

// ConsumeAuthFlowWithAction consumes a flow and runs action in the same
// database transaction. An action failure rolls the consumption back.
func ConsumeAuthFlowWithAction(token string, match AuthFlowMatch, action func(tx *gorm.DB, flow *AuthFlow) error) (*AuthFlow, error) {
	return ConsumeAuthFlowWithActionWithContext(context.Background(), token, match, action)
}

func ConsumeAuthFlowWithActionWithContext(ctx context.Context, token string, match AuthFlowMatch, action func(tx *gorm.DB, flow *AuthFlow) error) (*AuthFlow, error) {
	if token == "" || match.Purpose == "" {
		return nil, ErrAuthFlowInvalid
	}
	var consumed AuthFlow
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Claim with the first write, rather than upgrading a prior read lock.
		// SQLite cannot reliably upgrade two concurrent deferred read transactions.
		now := time.Now()
		result := applyAuthFlowMatch(tx.Model(&AuthFlow{}), token, match).
			Where("consumed_at IS NULL AND expires_at > ?", now).
			Update("consumed_at", now)
		if result.Error != nil {
			return result.Error
		}
		query := applyAuthFlowMatch(tx, token, match)
		if err := query.First(&consumed).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAuthFlowInvalid
			}
			return err
		}
		if result.RowsAffected != 1 && consumed.ConsumedAt != nil {
			return ErrAuthFlowConsumed
		}
		if !consumed.ExpiresAt.After(time.Now()) {
			return ErrAuthFlowExpired
		}
		if result.RowsAffected != 1 {
			return ErrAuthFlowInvalid
		}
		if action != nil {
			if err := action(tx, &consumed); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &consumed, nil
}

func DeleteExpiredAuthFlows(now time.Time) error {
	cutoff := now.Add(-AuthFlowDefaultCleanupRetention)
	return DB.Where("expires_at < ? OR (consumed_at IS NOT NULL AND consumed_at < ?)", cutoff, cutoff).
		Delete(&AuthFlow{}).Error
}

// OrganizationVerificationBudgetError is a durable per-account rolling limit.
type OrganizationVerificationBudgetError struct{ RetryAfter int }

func (e *OrganizationVerificationBudgetError) Error() string {
	return "Security verification rate limit exceeded."
}

// OrganizationVerificationStateWithTx shares the caller's existing locks and
// transaction; no cache or nested transaction participates in factor policy.
func OrganizationVerificationStateWithTx(tx *gorm.DB, identity AuthSessionIdentity) (*UserVerificationState, *UserSession, error) {
	if identity.UserID <= 0 || identity.SessionID == "" || strings.HasPrefix(identity.SessionID, "pat:") || strings.HasPrefix(identity.SessionID, "legacy") {
		return nil, nil, ErrUserSessionInactive
	}
	if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
		return nil, nil, err
	}
	state, err := getUserVerificationState(tx, identity.UserID, false)
	if err != nil {
		return nil, nil, err
	}
	var session UserSession
	if err := tx.Where("sid = ? AND user_id = ?", identity.SessionID, identity.UserID).First(&session).Error; err != nil {
		return nil, nil, err
	}
	return state, &session, nil
}

func ReserveOrganizationVerificationAttempt(identity AuthSessionIdentity) (*AuthFlow, error) {
	return ReserveOrganizationVerificationAttemptWithContext(context.Background(), identity)
}

func ReserveOrganizationVerificationAttemptWithContext(ctx context.Context, identity AuthSessionIdentity) (*AuthFlow, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var result *AuthFlow
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).Where("id = ?", identity.UserID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
			return err
		}
		_, session, err := OrganizationVerificationStateWithTx(tx, identity)
		if err != nil {
			return err
		}
		now := time.Now()
		var attempts []AuthFlow
		if err := tx.Select("id", "created_at").Where("purpose = ? AND user_id = ? AND created_at > ?", "org_verify_attempt", identity.UserID, now.Add(-300*time.Second)).Order("created_at,id").Find(&attempts).Error; err != nil {
			return err
		}
		if len(attempts) >= 5 {
			return &OrganizationVerificationBudgetError{RetryAfter: max(1, int(math.Ceil(attempts[0].CreatedAt.Add(300*time.Second).Sub(now).Seconds())))}
		}
		_, result, err = createAuthFlowWithTx(tx, AuthFlowCreate{Purpose: "org_verify_attempt", UserId: identity.UserID, SessionId: identity.SessionID, CreatedAt: now, ExpiresAt: now.Add(300 * time.Second)})
		if err != nil {
			return err
		}
		if session.ExpiresAt <= time.Now().Unix() {
			return ErrUserSessionInactive
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func ValidateOrganizationAttemptWithTx(tx *gorm.DB, identity AuthSessionIdentity, id int64) error {
	if id <= 0 {
		return ErrAuthFlowInvalid
	}
	var attempt AuthFlow
	if err := tx.Where("id = ? AND purpose = ? AND user_id = ? AND session_id = ?", id, "org_verify_attempt", identity.UserID, identity.SessionID).First(&attempt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAuthFlowInvalid
		}
		return err
	}
	if !time.Now().Before(attempt.ExpiresAt) {
		return ErrAuthFlowExpired
	}
	return nil
}

func CreateOrganizationProofFlow(identity AuthSessionIdentity, payload string, expiresAt time.Time, validate func(*gorm.DB, *UserVerificationState) error) (string, error) {
	return CreateOrganizationProofFlowWithContext(context.Background(), identity, payload, expiresAt, validate)
}

func CreateOrganizationProofFlowWithContext(ctx context.Context, identity AuthSessionIdentity, payload string, expiresAt time.Time, validate func(*gorm.DB, *UserVerificationState) error) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var token string
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).Where("id = ?", identity.UserID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
			return err
		}
		state, session, err := OrganizationVerificationStateWithTx(tx, identity)
		if err != nil {
			return err
		}
		if err := validate(tx, state); err != nil {
			return err
		}
		if expiresAt.Unix() > session.ExpiresAt || !time.Now().Before(expiresAt) {
			return ErrAuthFlowExpired
		}
		token, _, err = createAuthFlowWithTx(tx, AuthFlowCreate{Purpose: AuthFlowPurposeSecurityProof, UserId: identity.UserID, SessionId: identity.SessionID, Payload: payload, ExpiresAt: expiresAt})
		return err
	})
	return token, err
}

// InspectAuthFlowRoute selects a protocol branch from a stored, identity-bound
// flow, including resolved/expired flows. It grants nothing: consumption must
// still enforce status, expiry and identity with ConsumeAuthFlowWithAction.
func InspectAuthFlowRoute(token string, match AuthFlowMatch) (*AuthFlow, error) {
	return InspectAuthFlowRouteWithContext(context.Background(), token, match)
}

func InspectAuthFlowRouteWithContext(ctx context.Context, token string, match AuthFlowMatch) (*AuthFlow, error) {
	if token == "" || match.Purpose == "" || match.UserId <= 0 || match.SessionId == "" {
		return nil, ErrAuthFlowInvalid
	}
	var flow AuthFlow
	if err := applyAuthFlowMatch(DB.WithContext(ctx), token, match).First(&flow).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, ErrAuthFlowInvalid
	}
	return &flow, nil
}
