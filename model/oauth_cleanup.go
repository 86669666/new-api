package model

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

var ErrOAuthCleanupHeld = errors.New("OAuth authorization held for cleanup")
var oauthCleanupDB atomic.Pointer[gorm.DB]

// OAuthOperation records permission to send, not merely a request receipt.
// A sent request remains uncertain until its own response is durably observed.
// No timer or worker lease can turn an unknown issuer operation into completion.
type OAuthOperation struct {
	OperationRef   string `gorm:"type:char(64);primaryKey"`
	Issuer         string `gorm:"type:text;not null"`
	UserID         int    `gorm:"not null;index:idx_oauth_operations_user"`
	ClientID       string `gorm:"type:text;not null"`
	OriginSID      string `gorm:"column:origin_sid;type:varchar(64);not null"`
	GrantRef       string `gorm:"type:varchar(64);not null;index:idx_oauth_operations_grant"`
	AuthVersion    int64  `gorm:"not null"`
	SessionVersion int64  `gorm:"not null"`
	GrantRevision  int64  `gorm:"not null"`
	Kind           string `gorm:"type:varchar(32);not null"`
	State          string `gorm:"type:varchar(16);not null"`
	CreatedAt      int64  `gorm:"autoCreateTime:false;not null"`
	ObservedAt     int64  `gorm:"not null"`
}

// OAuthArtifact stores only domain-separated credential digests and trusted
// attribution. In particular it never stores a PKCE verifier or token body.
type OAuthArtifact struct {
	ArtifactRef  string `gorm:"type:char(64);primaryKey"`
	OperationRef string `gorm:"type:char(64);not null;index:idx_oauth_artifacts_operation"`
	Kind         string `gorm:"type:varchar(32);not null"`
	PKCE         string `gorm:"type:varchar(43);not null"`
	RedirectHash string `gorm:"type:char(64);not null"`
	ExpiresAt    int64  `gorm:"not null"`
}

type OAuthCleanupTarget struct {
	ConsentID string `json:"consent_id"`
	LoginSID  string `json:"login_sid"`
}

// Each event has its own immutable scope and targets. New revocations cannot
// be swallowed by an old worker completing a reused user/client queue row.
type OAuthCleanupJob struct {
	// Nullable provenance for legacy rows; never an authorization capability.
	SourceSessionEventRef *string `gorm:"type:varchar(64)"`
	JobRef                string  `gorm:"type:char(64);primaryKey"`
	Issuer                string  `gorm:"type:text;not null"`
	UserID                int     `gorm:"not null;index:idx_oauth_cleanup_user"`
	Subject               string  `gorm:"type:varchar(32);not null"`
	Scope                 string  `gorm:"type:varchar(16);not null"`
	Value                 string  `gorm:"type:text;not null"`
	Targets               string  `gorm:"type:text;not null"`
	Reason                string  `gorm:"type:varchar(32);not null"`
	State                 string  `gorm:"type:varchar(16);not null;index:idx_oauth_cleanup_due,priority:1"`
	NextAttemptAt         int64   `gorm:"not null;index:idx_oauth_cleanup_due,priority:2"`
	Attempt               int     `gorm:"not null"`
	Generation            int64   `gorm:"not null"`
	LeaseOwner            string  `gorm:"type:varchar(64);not null"`
	LeaseUntil            int64   `gorm:"not null"`
	CreatedAt             int64   `gorm:"autoCreateTime:false;not null"`
	CompletedAt           int64   `gorm:"not null"`
	ErrorCode             string  `gorm:"type:varchar(32);not null"`
}

func OAuthCleanupReady() bool { return DB != nil && oauthCleanupDB.Load() == DB }

func InitOAuthCleanupStore(enabled bool) error {
	oauthCleanupDB.Store(nil)
	if !enabled {
		return nil
	}
	if DB == nil {
		return errors.New("OAuth cleanup database unavailable")
	}
	models := []any{&OAuthOperation{}, &OAuthArtifact{}, &OAuthCleanupJob{}}
	if common.IsMasterNode {
		if err := DB.AutoMigrate(models...); err != nil {
			return err
		}
	}
	for _, value := range models {
		statement := &gorm.Statement{DB: DB}
		if err := statement.Parse(value); err != nil {
			return err
		}
		if err := DB.Model(value).Select(statement.Schema.DBNames).Limit(1).Find(value).Error; err != nil {
			return err
		}
		columns, err := DB.Migrator().ColumnTypes(value)
		if err != nil {
			return err
		}
		primary := false
		for _, column := range columns {
			yes, _ := column.PrimaryKey()
			if yes && column.Name() == statement.Schema.PrioritizedPrimaryField.DBName {
				primary = true
			}
		}
		if !primary {
			return errors.New("OAuth cleanup primary key unavailable")
		}
		for _, index := range statement.Schema.ParseIndexes() {
			if !DB.Migrator().HasIndex(value, index.Name) {
				return errors.New("OAuth cleanup index unavailable")
			}
		}
	}
	oauthCleanupDB.Store(DB)
	return nil
}

func OAuthArtifactRef(issuer, kind, credential string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("newapi.oauth.artifact.v1\x00"+issuer+"\x00"+kind+"\x00"+credential)))
}

// LockOAuthUser must precede session/grant/operation/job locks. Unscoped lets
// cleanup survive soft deletion; a missing hard-deleted user is not an error.
func LockOAuthUser(tx *gorm.DB, userID int) error {
	if userID <= 0 {
		return ErrOAuthGrantInvalid
	}
	if common.UsingMainDatabase(common.DatabaseTypeSQLite) {
		if err := tx.Unscoped().Model(&User{}).Where("id = ?", userID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error; err != nil {
			return err
		}
	}
	var users []User
	return lockForUpdate(tx.Unscoped()).Select("id").Where("id = ?", userID).Find(&users).Error
}

func (job OAuthCleanupJob) matches(client, sid, grant string) bool {
	switch job.Scope {
	case "user":
		return true
	case "client":
		return job.Value == client
	case "sid":
		return job.Value == sid
	case "others":
		return job.Value != sid
	case "grant":
		return job.Value == grant
	}
	return false
}

// CheckOAuthCleanupWithTx is always called under the same user lock as events
// and sending permission. It also fences re-use of a login SID during cleanup.
func CheckOAuthCleanupWithTx(tx *gorm.DB, issuer string, userID int, client, sid, grant, hydraSID string) error {
	if !OAuthCleanupReady() {
		return ErrOAuthCleanupHeld
	}
	if err := CheckSessionRevocationWithTx(tx, userID, sid); err != nil {
		return err
	}
	var local []OAuthOperation
	if err := tx.Where("user_id = ? AND state = ?", userID, "local_pending").Find(&local).Error; err != nil {
		return err
	}
	for _, op := range local {
		if op.Kind == "sessions_all" || op.Kind == "sessions_others" && op.OriginSID != sid {
			return ErrOAuthCleanupHeld
		}
	}
	var unresolved int64
	query := tx.Model(&OAuthOperation{}).Where("user_id = ? AND issuer = ? AND state IN ?", userID, issuer, []string{"sent", "unknown"})
	if grant != "" {
		query = query.Where("grant_ref = ? OR (grant_ref = ? AND client_id = ? AND origin_sid = ?)", grant, "", client, sid)
	} else {
		query = query.Where("grant_ref = ? AND client_id = ? AND origin_sid = ?", "", client, sid)
	}
	if err := query.Count(&unresolved).Error; err != nil {
		return err
	}
	if unresolved != 0 {
		return ErrOAuthCleanupHeld
	}
	var jobs []OAuthCleanupJob
	if err := tx.Where("user_id = ? AND issuer = ? AND state <> ?", userID, issuer, "complete").Find(&jobs).Error; err != nil {
		return err
	}
	for _, job := range jobs {
		if job.matches(client, sid, grant) {
			return ErrOAuthCleanupHeld
		}
		if hydraSID != "" {
			var targets []OAuthCleanupTarget
			if err := common.UnmarshalJsonStr(job.Targets, &targets); err != nil {
				return err
			}
			for _, target := range targets {
				if target.LoginSID == hydraSID {
					return ErrOAuthCleanupHeld
				}
			}
		}
	}
	return nil
}

// RevokeOAuthWithTx joins an existing security transaction. The caller holds
// the user lock and must use a fixed reason, never a token or caller error.
// Scope values are trusted local IDs; they do not authenticate a caller.
func RevokeOAuthWithTx(tx *gorm.DB, userID int, scope, value, reason string, sessionEventRef ...string) error {
	if len(sessionEventRef) > 1 {
		return ErrOAuthGrantInvalid
	}
	if err := validateOAuthDerivedTokenStore(tx, time.Now().Unix()); err != nil {
		return err
	}
	if !OAuthCleanupReady() {
		if len(sessionEventRef) != 0 {
			return ErrSessionRevocationStore
		}
		var sources int64
		if err := tx.Model(&OAuthDerivedTokenSource{}).Where("user_id = ?", userID).Count(&sources).Error; err != nil || sources != 0 {
			return ErrOAuthDerivedTokenUnknown
		}
		return nil
	}
	if !slices.Contains([]string{"user", "client", "sid", "others", "grant"}, scope) || scope != "user" && value == "" {
		return ErrOAuthGrantInvalid
	}
	if !slices.Contains([]string{"security_changed", "session_revoked", "expired", "explicit", "issuer_unknown"}, reason) {
		return ErrOAuthGrantInvalid
	}
	var grants []OAuthGrant
	if err := lockForUpdate(tx).Where("user_id = ?", userID).Order("grant_ref").Find(&grants).Error; err != nil {
		return err
	}
	var operations []OAuthOperation
	if err := lockForUpdate(tx).Where("user_id = ?", userID).Order("operation_ref").Find(&operations).Error; err != nil {
		return err
	}
	match := OAuthCleanupJob{Scope: scope, Value: value}
	issuers := make(map[string][]OAuthCleanupTarget)
	now := time.Now().Unix()
	for _, grant := range grants {
		if !match.matches(grant.ClientID, grant.OriginSID, grant.GrantRef) {
			continue
		}
		issuers[grant.Issuer] = append(issuers[grant.Issuer], OAuthCleanupTarget{ConsentID: grant.ConsentRequestID, LoginSID: grant.HydraLoginSessionID})
		if grant.RevokedAt == 0 {
			if err := tx.Model(&OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).Updates(map[string]any{"state": "revoked", "revoked_at": now, "revoked_reason": reason, "revision": gorm.Expr("revision + 1")}).Error; err != nil {
				return err
			}
		}
	}
	for _, op := range operations {
		if op.Issuer == "" {
			continue
		}
		if match.matches(op.ClientID, op.OriginSID, op.GrantRef) {
			if op.State == "reserved" {
				if err := tx.Model(&op).Update("state", "cancelled").Error; err != nil {
					return err
				}
			}
			if _, ok := issuers[op.Issuer]; !ok {
				issuers[op.Issuer] = nil
			}
		}
	}
	for issuer, targets := range issuers {
		// Keep a shared login session if any unaffected grant still uses it.
		for i := range targets {
			for _, grant := range grants {
				if grant.Issuer == issuer && grant.HydraLoginSessionID == targets[i].LoginSID && grant.RevokedAt == 0 && grant.ExpiresAt > now && !match.matches(grant.ClientID, grant.OriginSID, grant.GrantRef) {
					targets[i].LoginSID = ""
					break
				}
			}
		}
		encoded, err := common.Marshal(targets)
		if err != nil {
			return err
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		job := OAuthCleanupJob{JobRef: fmt.Sprintf("%x", nonce), Issuer: issuer, UserID: userID, Subject: strconv.Itoa(userID), Scope: scope, Value: value, Targets: string(encoded), Reason: reason, State: "pending", CreatedAt: now, NextAttemptAt: now}
		if len(sessionEventRef) == 1 {
			job.SourceSessionEventRef = &sessionEventRef[0]
		}
		if err := tx.Create(&job).Error; err != nil {
			return err
		}
	}
	return revokeOAuthDerivedTokens(tx, userID, grants, match, now)
}

func RevokeOAuth(ctx context.Context, userID int, scope, value string) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, userID); err != nil {
			return err
		}
		return RevokeOAuthWithTx(tx, userID, scope, value, "explicit")
	})
}

// ReserveOAuthOperation uses trusted actor/grant attribution obtained from the
// preview or an existing credential digest, never a client-supplied subject.
func ReserveOAuthOperation(ctx context.Context, op *OAuthOperation) error {
	if !OAuthCleanupReady() {
		return ErrOAuthCleanupHeld
	}
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, op.UserID); err != nil {
			return err
		}
		if err := ValidateAuthSessionWithTx(tx, AuthSessionIdentity{UserID: op.UserID, SessionID: op.OriginSID, UserAuthVersion: op.AuthVersion, SessionVersion: op.SessionVersion}); err != nil {
			return err
		}
		if op.GrantRef != "" {
			var grant OAuthGrant
			if err := lockForUpdate(tx).Where("grant_ref = ?", op.GrantRef).First(&grant).Error; err != nil {
				return err
			}
			if grant.UserID != op.UserID || grant.Issuer != op.Issuer || grant.ClientID != op.ClientID || grant.OriginSID != op.OriginSID || grant.RevokedAt != 0 || grant.ExpiresAt <= time.Now().Unix() {
				return ErrOAuthGrantInvalid
			}
			op.GrantRevision = grant.Revision
		}
		if err := CheckOAuthCleanupWithTx(tx, op.Issuer, op.UserID, op.ClientID, op.OriginSID, op.GrantRef, ""); err != nil {
			return err
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		op.OperationRef, op.State, op.CreatedAt = fmt.Sprintf("%x", nonce), "reserved", time.Now().Unix()
		return tx.Create(op).Error
	})
}

func SendOAuthOperation(ctx context.Context, op *OAuthOperation) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, op.UserID); err != nil {
			return err
		}
		if err := ValidateAuthSessionWithTx(tx, AuthSessionIdentity{UserID: op.UserID, SessionID: op.OriginSID, UserAuthVersion: op.AuthVersion, SessionVersion: op.SessionVersion}); err != nil {
			return err
		}
		if op.GrantRef != "" {
			var grant OAuthGrant
			if err := lockForUpdate(tx).Where("grant_ref = ?", op.GrantRef).First(&grant).Error; err != nil {
				return err
			}
			if grant.Revision != op.GrantRevision || grant.RevokedAt != 0 || grant.ExpiresAt <= time.Now().Unix() {
				return ErrOAuthGrantInvalid
			}
		}
		if err := CheckOAuthCleanupWithTx(tx, op.Issuer, op.UserID, op.ClientID, op.OriginSID, op.GrantRef, ""); err != nil {
			return err
		}
		result := tx.Model(&OAuthOperation{}).Where("operation_ref = ? AND state = ?", op.OperationRef, "reserved").Update("state", "sent")
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrOAuthCleanupHeld
		}
		return nil
	})
}

// ObserveOAuthOperation can reconcile a late response after revocation, even
// after hard deletion. It cannot restore a grant or authorize publication.
func ObserveOAuthOperation(ctx context.Context, op *OAuthOperation, artifacts []OAuthArtifact) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, op.UserID); err != nil {
			return err
		}
		var current OAuthOperation
		if err := lockForUpdate(tx).Where("operation_ref = ?", op.OperationRef).First(&current).Error; err != nil {
			return err
		}
		if current.State != "sent" && current.State != "unknown" {
			return ErrOAuthCleanupHeld
		}
		for _, artifact := range artifacts {
			artifact.OperationRef = current.OperationRef
			if err := tx.Create(&artifact).Error; err != nil {
				return err
			}
		}
		return tx.Model(&current).Updates(map[string]any{"state": "observed", "observed_at": time.Now().Unix()}).Error
	})
}

func HoldOAuthOperation(op *OAuthOperation, sentBefore int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, op.UserID); err != nil {
			return err
		}
		if sentBefore > 0 {
			var count int64
			if err := tx.Model(&OAuthOperation{}).Where("operation_ref = ? AND state = ? AND created_at < ?", op.OperationRef, "sent", sentBefore).Count(&count).Error; err != nil {
				return err
			}
			if count == 0 {
				return nil
			}
		}
		// Revoke locks grants before operations, just like the successful path.
		scope, value := "sid", op.OriginSID
		if op.GrantRef != "" {
			scope, value = "grant", op.GrantRef
		}
		if err := RevokeOAuthWithTx(tx, op.UserID, scope, value, "issuer_unknown"); err != nil {
			return err
		}
		return tx.Model(&OAuthOperation{}).Where("operation_ref = ? AND state = ?", op.OperationRef, "sent").Update("state", "unknown").Error
	})
}

func FindOAuthArtifact(ctx context.Context, issuer, kind, credential string) (*OAuthArtifact, *OAuthOperation, error) {
	var artifact OAuthArtifact
	if err := DB.WithContext(ctx).Where("artifact_ref = ?", OAuthArtifactRef(issuer, kind, credential)).First(&artifact).Error; err != nil {
		return nil, nil, err
	}
	var op OAuthOperation
	if err := DB.WithContext(ctx).Where("operation_ref = ?", artifact.OperationRef).First(&op).Error; err != nil {
		return nil, nil, err
	}
	if op.Issuer != issuer || artifact.Kind != kind || op.State != "observed" {
		return nil, nil, ErrOAuthGrantInvalid
	}
	return &artifact, &op, nil
}

// ClaimOAuthCleanup freezes both sending permission and the job generation.
// A missing user is allowed: the job/operation records retain all attribution.
func ClaimOAuthCleanup(ctx context.Context, ref, owner string, now int64) (*OAuthCleanupJob, error) {
	var seed OAuthCleanupJob
	if err := DB.WithContext(ctx).Where("job_ref = ?", ref).First(&seed).Error; err != nil {
		return nil, err
	}
	var claimed *OAuthCleanupJob
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, seed.UserID); err != nil {
			return err
		}
		localErr := CheckSessionRevocationWithTx(tx, seed.UserID, "")
		if localErr != nil && !errors.Is(localErr, ErrSessionRevocationPending) {
			return localErr
		}
		var operations []OAuthOperation
		if err := lockForUpdate(tx).Where("user_id = ? AND (issuer = ? OR state = ?)", seed.UserID, seed.Issuer, "local_pending").Order("operation_ref").Find(&operations).Error; err != nil {
			return err
		}
		var job OAuthCleanupJob
		if err := lockForUpdate(tx).Where("job_ref = ?", ref).First(&job).Error; err != nil {
			return err
		}
		if job.State == "complete" || job.NextAttemptAt > now || job.State == "leased" && job.LeaseUntil > now {
			return nil
		}
		if localErr != nil {
			return tx.Model(&job).Updates(map[string]any{"state": "blocked", "error_code": "local_pending", "next_attempt_at": now + 60}).Error
		}
		for _, op := range operations {
			if op.State == "local_pending" {
				return tx.Model(&job).Updates(map[string]any{"state": "blocked", "error_code": "local_pending", "next_attempt_at": now + 60}).Error
			}
			if !job.matches(op.ClientID, op.OriginSID, op.GrantRef) {
				continue
			}
			if op.State == "sent" || op.State == "unknown" {
				return tx.Model(&job).Updates(map[string]any{"state": "blocked", "error_code": "issuer_unknown", "next_attempt_at": now + 60}).Error
			}
			// A reserved operation has no send permission. Keeping its row is safe:
			// Send rechecks the scope fence and revoked identity before CAS.
		}
		job.State, job.LeaseOwner, job.LeaseUntil = "leased", owner, now+60
		job.Generation++
		job.Attempt++
		if err := tx.Save(&job).Error; err != nil {
			return err
		}
		claimed = &job
		return nil
	})
	return claimed, err
}

// FinishOAuthCleanup must not complete another worker's lease or a new event.
func FinishOAuthCleanup(ctx context.Context, job *OAuthCleanupJob, code string, retryAfter int64) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, job.UserID); err != nil {
			return err
		}
		now := time.Now().Unix()
		values := map[string]any{"lease_owner": "", "lease_until": 0, "error_code": code}
		switch code {
		case "":
			values["state"], values["completed_at"] = "complete", now
		case "unavailable", "rate_limited":
			values["state"], values["next_attempt_at"] = "pending", now+max(min(retryAfter, 3600), int64(min(1<<min(job.Attempt, 10), 900)))
		case "configuration", "issuer_unknown":
			values["state"], values["next_attempt_at"] = "blocked", now+60
		default:
			return ErrOAuthGrantInvalid
		}
		result := tx.Model(&OAuthCleanupJob{}).Where("job_ref = ? AND state = ? AND generation = ? AND lease_owner = ? AND lease_until > ?", job.JobRef, "leased", job.Generation, job.LeaseOwner, now).Updates(values)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrOAuthCleanupHeld
		}
		return nil
	})
}

func ReconcileExpiredOAuthGrants(ctx context.Context) error {
	if !OAuthCleanupReady() {
		return nil
	}
	after := ""
	for {
		var grants []OAuthGrant
		if err := DB.WithContext(ctx).Where("revoked_at = ? AND grant_ref > ?", 0, after).Order("grant_ref").Limit(100).Find(&grants).Error; err != nil {
			return err
		}
		for _, seed := range grants {
			if err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				if err := LockOAuthUser(tx, seed.UserID); err != nil {
					return err
				}
				var user User
				uerr := tx.First(&user, seed.UserID).Error
				if uerr != nil && !errors.Is(uerr, gorm.ErrRecordNotFound) {
					return uerr
				}
				var session UserSession
				serr := lockForUpdate(tx).Where("sid = ?", seed.OriginSID).First(&session).Error
				if serr != nil && !errors.Is(serr, gorm.ErrRecordNotFound) {
					return serr
				}
				if uerr == nil && serr == nil && user.Status == common.UserStatusEnabled && user.AuthVersion == seed.UserAuthVersion && session.Status == UserSessionStatusActive && session.RevokedAt == 0 && session.Version == seed.SessionVersion && session.UserAuthVersion == seed.UserAuthVersion && session.UserID == seed.UserID && session.ExpiresAt > time.Now().Unix() && seed.ExpiresAt > time.Now().Unix() {
					return nil
				}
				return RevokeOAuthWithTx(tx, seed.UserID, "grant", seed.GrantRef, "expired")
			}); err != nil {
				return err
			}
		}
		if len(grants) < 100 {
			break
		}
		after = grants[len(grants)-1].GrantRef
	}

	return nil
}

func ValidateOAuthOperationPublication(ctx context.Context, op *OAuthOperation) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, op.UserID); err != nil {
			return err
		}
		if err := ValidateAuthSessionWithTx(tx, AuthSessionIdentity{UserID: op.UserID, SessionID: op.OriginSID, UserAuthVersion: op.AuthVersion, SessionVersion: op.SessionVersion}); err != nil {
			return err
		}
		if op.GrantRef != "" {
			var grant OAuthGrant
			if err := lockForUpdate(tx).Where("grant_ref = ?", op.GrantRef).First(&grant).Error; err != nil {
				return err
			}
			if grant.RevokedAt != 0 || grant.Revision != op.GrantRevision || grant.ExpiresAt <= time.Now().Unix() {
				return ErrOAuthGrantInvalid
			}
		}
		return CheckOAuthCleanupWithTx(tx, op.Issuer, op.UserID, op.ClientID, op.OriginSID, op.GrantRef, "")
	})
}

// BeginOAuthSessionRevocation fences the entire range before the existing
// independently committed session batches start. A failed/crashed batch leaves
// this durable fence in place; a successful retry completes the same range.
func BeginOAuthSessionRevocation(userID int, excludedSID string) error    { return ErrOAuthCleanupHeld }
func CompleteOAuthSessionRevocation(userID int, excludedSID string) error { return ErrOAuthCleanupHeld }

// DeleteExpiredOAuthSessions retains issuer targets in the same transaction as
// the bounded source-session deletion. The final predicate is rechecked by SQL.
func DeleteExpiredOAuthSessions(sids []string, expiredBefore, issuanceCutoff, revokedBefore int64) error {
	var seeds []UserSession
	if err := DB.Where("sid IN ?", sids).Find(&seeds).Error; err != nil {
		return err
	}
	userIDs := make([]int, 0, len(seeds))
	for _, seed := range seeds {
		userIDs = append(userIDs, seed.UserID)
	}
	slices.Sort(userIDs)
	userIDs = slices.Compact(userIDs)
	return DB.Transaction(func(tx *gorm.DB) error {
		for _, id := range userIDs {
			if err := LockOAuthUser(tx, id); err != nil {
				return err
			}
		}
		var current []UserSession
		if err := lockForUpdate(tx).Where("sid IN ? AND expires_at < ? AND created_at <= ? AND (status <> ? OR revoked_at <= 0 OR revoked_at < ?)", sids, expiredBefore, issuanceCutoff, UserSessionStatusRevoked, revokedBefore).Order("sid").Find(&current).Error; err != nil {
			return err
		}
		for _, session := range current {
			if !slices.Contains(userIDs, session.UserID) {
				return ErrOAuthCleanupHeld
			}
			if err := RevokeOAuthWithTx(tx, session.UserID, "sid", session.SID, "expired"); err != nil {
				return err
			}
		}
		return tx.Where("sid IN ? AND expires_at < ? AND created_at <= ? AND (status <> ? OR revoked_at <= 0 OR revoked_at < ?)", sids, expiredBefore, issuanceCutoff, UserSessionStatusRevoked, revokedBefore).Delete(&UserSession{}).Error
	})
}
