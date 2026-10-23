package model

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

const sessionRevocationProtocol = 1

var (
	ErrSessionRevocationPending = errors.New("session revocation is pending")
	ErrSessionRevocationStale   = errors.New("session revocation revision changed")
	ErrSessionRevocationStore   = errors.New("session revocation store is unavailable")
	ErrSessionDeletionBlocked   = errors.New("session revocation must finish before hard deletion")
)

// SessionRevocationEvent is a local security intent, not an OAuth operation.
// All attribution fields are immutable. CreatedAt never defines membership.
type SessionRevocationEvent struct {
	// Persisted evidence prevents lost historical OAuth tables being treated as a fresh install.
	OAuthAttributionRequired bool   `gorm:"column:o_auth_attribution_required;not null"`
	EventRef                 string `gorm:"type:char(64);primaryKey;index:idx_session_revocation_due,priority:3;index:idx_session_revocation_user,priority:3"`
	ProtocolVersion          int    `gorm:"not null"`
	UserID                   int    `gorm:"not null;index:idx_session_revocation_user,priority:1"`
	Scope                    string `gorm:"type:varchar(16);not null"`
	ExcludedSID              string `gorm:"type:varchar(64);not null"`
	Reason                   string `gorm:"type:varchar(32);not null"`
	CreatedAt                int64  `gorm:"autoCreateTime:false;not null"`
	State                    string `gorm:"type:varchar(16);not null;index:idx_session_revocation_due,priority:1;index:idx_session_revocation_user,priority:2"`
	Revision                 int64  `gorm:"not null"`
	AffectedCount            int64  `gorm:"not null"`
	NextAttemptAt            int64  `gorm:"not null;index:idx_session_revocation_due,priority:2"`
	LastProgressAt           int64  `gorm:"not null"`
	CompletedAt              int64  `gorm:"not null"`
	ErrorCode                string `gorm:"type:varchar(32);not null"`
}

func (SessionRevocationEvent) TableName() string { return "session_revocation_events" }

// No EventRef or underlying driver/Redis error is exposed by the HTTP mapper.
type SessionRevocationPendingError struct {
	EventRef                  string
	UserID                    int
	Revision                  int64
	AffectedCount             int64
	CredentialChangeCommitted bool
	ProgressKnown             bool
}

func (*SessionRevocationPendingError) Error() string { return ErrSessionRevocationPending.Error() }
func (*SessionRevocationPendingError) Unwrap() error { return ErrSessionRevocationPending }

func (e SessionRevocationEvent) valid() bool {
	if len(e.EventRef) != 64 || e.UserID <= 0 || e.ProtocolVersion != sessionRevocationProtocol ||
		e.Revision <= 0 || e.Revision == math.MaxInt64 || e.AffectedCount < 0 ||
		e.Reason == "" || len(e.Reason) > 32 || e.CreatedAt <= 0 ||
		!slices.Contains([]string{"pending", "local_complete"}, e.State) {
		return false
	}
	if e.State == "pending" && e.CompletedAt != 0 || e.State == "local_complete" && (e.CompletedAt < e.CreatedAt || e.Revision < 2) {
		return false
	}
	for _, c := range e.EventRef {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return e.Scope == "all" && e.ExcludedSID == "" || e.Scope == "others" && e.ExcludedSID != "" && len(e.ExcludedSID) <= 64
}

func (e SessionRevocationEvent) sameIntent(other SessionRevocationEvent) bool {
	return e.EventRef == other.EventRef && e.ProtocolVersion == other.ProtocolVersion && e.OAuthAttributionRequired == other.OAuthAttributionRequired &&
		e.UserID == other.UserID && e.Scope == other.Scope && e.ExcludedSID == other.ExcludedSID &&
		e.Reason == other.Reason && e.CreatedAt == other.CreatedAt
}

// ValidateSessionRevocationStore runs independently of OAuth flags, after the
// host migration and before any authentication writers/listeners start.
func ValidateSessionRevocationStore() error {
	if DB == nil {
		return ErrSessionRevocationStore
	}
	statement := &gorm.Statement{DB: DB}
	if err := statement.Parse(&SessionRevocationEvent{}); err != nil {
		return err
	}
	var rows []SessionRevocationEvent
	if err := DB.Select(statement.Schema.DBNames).Limit(1).Find(&rows).Error; err != nil {
		return err
	}
	columns, err := DB.Migrator().ColumnTypes(&SessionRevocationEvent{})
	if err != nil {
		return err
	}
	var primary []string
	for _, column := range columns {
		yes, _ := column.PrimaryKey()
		if yes {
			primary = append(primary, column.Name())
		}
	}
	if !slices.Equal(primary, []string{"event_ref"}) {
		return ErrSessionRevocationStore
	}
	indexColumns := map[string][]string{}
	if common.UsingMainDatabase(common.DatabaseTypePostgreSQL) {
		// The pinned driver's GetIndexes aggregates columns by table attnum,
		// not index position. indkey ordinality preserves the actual key order.
		// WITH ORDINALITY is supported by the minimum PostgreSQL 9.6 baseline.
		var keys []struct {
			Name   string
			Column string
		}
		err := DB.Raw(`SELECT i.relname AS name, a.attname AS column
   FROM pg_catalog.pg_index x
   JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid
   CROSS JOIN LATERAL unnest(x.indkey) WITH ORDINALITY AS k(attnum, position)
   JOIN pg_catalog.pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = k.attnum
   WHERE x.indrelid = pg_catalog.to_regclass(?) AND x.indisvalid AND x.indisready
     AND x.indpred IS NULL AND x.indexprs IS NULL
   ORDER BY i.relname, k.position`, "session_revocation_events").Scan(&keys).Error
		if err != nil {
			return err
		}
		for _, key := range keys {
			indexColumns[key.Name] = append(indexColumns[key.Name], key.Column)
		}
	} else {
		indexes, err := DB.Migrator().GetIndexes(&SessionRevocationEvent{})
		if err != nil {
			return err
		}
		for _, index := range indexes {
			indexColumns[index.Name()] = index.Columns()
		}
	}
	for name, want := range map[string][]string{
		"idx_session_revocation_due":  {"state", "next_attempt_at", "event_ref"},
		"idx_session_revocation_user": {"user_id", "state", "event_ref"},
	} {
		if !slices.Equal(indexColumns[name], want) {
			return ErrSessionRevocationStore
		}
	}
	var unknown int64
	if err := DB.Model(&SessionRevocationEvent{}).Where("protocol_version <> ? OR state NOT IN ?", sessionRevocationProtocol, []string{"pending", "local_complete"}).Count(&unknown).Error; err != nil {
		return err
	}
	if unknown != 0 {
		return ErrSessionRevocationStore
	}
	_, err = sessionOAuthAttributionRequiredWithTx(DB)
	return err
}

// CheckSessionRevocationWithTx requires the user lock. Empty sid means any
// pending range (cleanup claim); a concrete sid checks its immutable membership.
// An unreadable/missing table or unknown version never means "no pending work".
func CheckSessionRevocationWithTx(tx *gorm.DB, userID int, sid string) error {
	var events []SessionRevocationEvent
	if err := tx.Where("user_id = ? AND (state <> ? OR protocol_version <> ?)", userID, "local_complete", sessionRevocationProtocol).Find(&events).Error; err != nil {
		return err
	}
	for _, e := range events {
		if !e.valid() {
			return ErrSessionRevocationStore
		}
		if e.State == "pending" && (sid == "" || e.Scope == "all" || e.ExcludedSID != sid) {
			return ErrSessionRevocationPending
		}
	}
	return nil
}

// sessionOAuthTables proves the namespace/catalog used for OAuth attribution.
// Empty information_schema results alone do not prove absence for a restricted
// role. Unsupported shadow/search-path topologies fail closed before mutation.
func sessionOAuthTables(tx *gorm.DB) ([]string, error) {
	var names []string
	for _, value := range []any{&OAuthGrant{}, &OAuthOperation{}, &OAuthArtifact{}, &OAuthCleanupJob{}} {
		statement := &gorm.Statement{DB: tx}
		if err := statement.Parse(value); err != nil {
			return nil, err
		}
		names = append(names, statement.Schema.Table)
	}
	var tables []string
	switch common.MainDatabaseType() {
	case common.DatabaseTypePostgreSQL:
		var namespace struct {
			Schema         string
			Count          int
			CatalogVisible bool
		}
		if err := tx.Raw(`SELECT current_schema() AS schema,
   cardinality(current_schemas(false)) AS count,
   pg_catalog.has_table_privilege('pg_catalog.pg_class','SELECT') AND
   pg_catalog.has_table_privilege('pg_catalog.pg_namespace','SELECT') AS catalog_visible`).Scan(&namespace).Error; err != nil {
			return nil, err
		}
		if namespace.Schema == "" || namespace.Count != 1 || !namespace.CatalogVisible {
			return nil, ErrSessionRevocationStore
		}
		var owned int64
		if err := tx.Raw(`SELECT count(*) FROM pg_catalog.pg_class c
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE c.oid IN (pg_catalog.to_regclass('users'),pg_catalog.to_regclass('session_revocation_events'))
    AND n.nspname=? AND c.relkind='r' AND pg_catalog.pg_table_is_visible(c.oid)
    AND pg_catalog.has_table_privilege(c.oid,'SELECT')`, namespace.Schema).Scan(&owned).Error; err != nil {
			return nil, err
		}
		if owned != 2 {
			return nil, ErrSessionRevocationStore
		}
		// pg_catalog is not filtered by object privileges. This observes hidden
		// history too, unlike information_schema and CURRENT_SCHEMA-only GetTables.
		var relations []struct {
			Schema  string
			Name    string
			Kind    string
			Visible bool
		}
		if err := tx.Raw(`SELECT n.nspname AS schema,c.relname AS name,c.relkind AS kind,
   pg_catalog.pg_table_is_visible(c.oid) AS visible
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE c.relname IN ?`, names).Scan(&relations).Error; err != nil {
			return nil, err
		}
		for _, relation := range relations {
			if relation.Schema != namespace.Schema || relation.Kind != "r" || !relation.Visible {
				return nil, ErrSessionRevocationStore
			}
			tables = append(tables, relation.Name)
		}
	case common.DatabaseTypeMySQL:
		// Require database-wide or global SELECT visibility before treating missing
		// catalog entries as absent. Table/column-only grants cannot prove this.
		var catalogVisible bool
		if err := tx.Raw(`SELECT EXISTS(SELECT 1 FROM information_schema.user_privileges
    WHERE GRANTEE=CONCAT(QUOTE(SUBSTRING_INDEX(CURRENT_USER(),'@',1)),'@',QUOTE(SUBSTRING_INDEX(CURRENT_USER(),'@',-1))) AND PRIVILEGE_TYPE='SELECT')
   OR EXISTS(SELECT 1 FROM information_schema.schema_privileges
    WHERE GRANTEE=CONCAT(QUOTE(SUBSTRING_INDEX(CURRENT_USER(),'@',1)),'@',QUOTE(SUBSTRING_INDEX(CURRENT_USER(),'@',-1)))
    AND TABLE_SCHEMA=DATABASE() AND PRIVILEGE_TYPE='SELECT')`).Scan(&catalogVisible).Error; err != nil {
			return nil, err
		}
		if !catalogVisible {
			return nil, ErrSessionRevocationStore
		}
		if err := tx.Raw("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ?", names).Scan(&tables).Error; err != nil {
			return nil, err
		}
	case common.DatabaseTypeSQLite:
		var databases []struct{ Name string }
		if err := tx.Raw("PRAGMA database_list").Scan(&databases).Error; err != nil {
			return nil, err
		}
		for _, database := range databases {
			if database.Name != "main" && database.Name != "temp" {
				return nil, ErrSessionRevocationStore
			}
		}
		var shadows int64
		if err := tx.Raw("SELECT count(*) FROM sqlite_temp_master WHERE name IN ?", names).Scan(&shadows).Error; err != nil {
			return nil, err
		}
		if shadows != 0 {
			return nil, ErrSessionRevocationStore
		}
		if err := tx.Raw("SELECT name FROM sqlite_master WHERE name IN ?", names).Scan(&tables).Error; err != nil {
			return nil, err
		}
	default:
		return nil, ErrSessionRevocationStore
	}
	return tables, nil
}

// revokeSessionOAuthWithTx either uses the initialized historical store or
// proves every OAuth attribution table absent using an error-returning catalog
// query. Flags and HasTable(false), which may hide errors, are not absence proof.
func sessionOAuthAttributionRequiredWithTx(tx *gorm.DB) (bool, error) {
	if OAuthCleanupReady() {
		for _, row := range []any{&OAuthGrant{}, &OAuthOperation{}, &OAuthArtifact{}, &OAuthCleanupJob{}} {
			stmt := &gorm.Statement{DB: tx}
			if err := stmt.Parse(row); err != nil {
				return false, err
			}
			if err := tx.Model(row).Select(stmt.Schema.DBNames).Limit(1).Find(row).Error; err != nil {
				return false, err
			}
		}
		return true, nil
	}
	tables, err := sessionOAuthTables(tx)
	if err != nil {
		return false, err
	}
	if len(tables) != 0 {
		return false, ErrSessionRevocationStore
	}
	var historical int64
	if err := tx.Model(&SessionRevocationEvent{}).Where("o_auth_attribution_required = ?", true).Count(&historical).Error; err != nil {
		return false, err
	}
	if historical != 0 {
		return false, ErrSessionRevocationStore
	}
	return false, nil
}

func revokeSessionOAuthWithTx(tx *gorm.DB, userID int, scope, value, reason, eventRef string) error {
	required, err := sessionOAuthAttributionRequiredWithTx(tx)
	if err != nil {
		return err
	}
	if !required {
		return nil
	}
	if eventRef == "" {
		return RevokeOAuthWithTx(tx, userID, scope, value, reason)
	}
	return RevokeOAuthWithTx(tx, userID, scope, value, reason, eventRef)
}

// StartSessionRevocationWithTx must join the business transaction that promises
// revocation. Only server-owned user/scope/reason values may call this API.
// The fresh event is invisible to other executors until this transaction commits.
func StartSessionRevocationWithTx(tx *gorm.DB, userID int, excludedSID, reason string) (*SessionRevocationEvent, error) {
	if err := LockOAuthUser(tx, userID); err != nil {
		return nil, err
	}
	oauthRequired, err := sessionOAuthAttributionRequiredWithTx(tx)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	event := &SessionRevocationEvent{OAuthAttributionRequired: oauthRequired, EventRef: fmt.Sprintf("%x", nonce), ProtocolVersion: sessionRevocationProtocol,
		UserID: userID, Scope: "all", ExcludedSID: excludedSID, Reason: reason, CreatedAt: now,
		State: "pending", Revision: 1, NextAttemptAt: now}
	if excludedSID != "" {
		event.Scope = "others"
	}
	if !event.valid() {
		return nil, ErrUserSessionInvalid
	}
	if err := tx.Create(event).Error; err != nil {
		return nil, err
	}
	scope := "user"
	// Credential changes invalidate every OAuth source, including a retained
	// browser's grants, regardless of their compatible visible session reason.
	if excludedSID != "" && !slices.Contains([]string{"security_changed", "password_reset", "admin_demote"}, reason) {
		scope = "others"
	}
	value := ""
	if scope == "others" {
		value = excludedSID
	}
	if err := revokeSessionOAuthWithTx(tx, userID, scope, value, "session_revoked", event.EventRef); err != nil {
		return nil, err
	}
	return event, nil
}

// RunSessionRevocationBatch revalidates the exact hint before the first Redis or
// DB effect. There is no local lease or cross-batch SID cursor. Holding the user
// lock serializes all creators and completion, including SQLite first-write.
func RunSessionRevocationBatch(ctx context.Context, hint SessionRevocationEvent) (*SessionRevocationEvent, error) {
	if !hint.valid() {
		return nil, ErrSessionRevocationStore
	}
	if hint.State != "pending" {
		return nil, ErrSessionRevocationStale
	}
	var event SessionRevocationEvent
	var revoked []UserSession
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := LockOAuthUser(tx, hint.UserID); err != nil {
			return err
		}
		if err := lockForUpdate(tx).Where("event_ref = ?", hint.EventRef).First(&event).Error; err != nil {
			return err
		}
		if !event.valid() {
			return ErrSessionRevocationStore
		}
		if !event.sameIntent(hint) || event.Revision != hint.Revision || event.State != "pending" {
			return ErrSessionRevocationStale
		}
		oauthRequired, err := sessionOAuthAttributionRequiredWithTx(tx)
		if err != nil {
			return err
		}
		if event.OAuthAttributionRequired && !oauthRequired {
			return ErrSessionRevocationStore
		}
		var owner User
		ownerErr := tx.Unscoped().Where("id = ?", event.UserID).First(&owner).Error
		if ownerErr != nil && !errors.Is(ownerErr, gorm.ErrRecordNotFound) {
			return ownerErr
		}
		if ownerErr == nil && slices.Contains([]string{"security_changed", "password_reset", "admin_demote"}, event.Reason) {
			if err := publishCommittedUserAuthVersion(owner.Id, owner.AuthVersion); err != nil {
				return err
			}
		}
		now := time.Now().Unix()
		query := tx.Where("user_id = ? AND status = ? AND revoked_at = ? AND expires_at > ?", event.UserID, UserSessionStatusActive, 0, now)
		if event.Scope == "others" {
			query = query.Where("sid <> ?", event.ExcludedSID)
		}
		if err := lockForUpdate(query).Order("sid").Limit(userSessionRevokeBatchSize).Find(&revoked).Error; err != nil {
			return err
		}
		var owners int64
		if err := tx.Unscoped().Model(&User{}).Where("id = ?", event.UserID).Count(&owners).Error; err != nil {
			return err
		}
		if owners == 0 && len(revoked) != 0 {
			return ErrSessionRevocationStore
		}
		for i := range revoked {
			session := &revoked[i]
			if err := writeUserSessionDenyFenceWithContext(ctx, session, UserSessionStatusRevoking, now, event.Reason); err != nil {
				return err
			}
			result := tx.Model(&UserSession{}).Where("sid = ? AND user_id = ? AND status = ? AND version = ? AND revoked_at = ?", session.SID, event.UserID, UserSessionStatusActive, session.Version, 0).
				Updates(map[string]any{"status": UserSessionStatusRevoked, "revoked_at": now, "revoked_reason": event.Reason})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrSessionRevocationStale
			}
			if oauthRequired {
				if err := RevokeOAuthWithTx(tx, event.UserID, "sid", session.SID, "session_revoked", event.EventRef); err != nil {
					return err
				}
			}
			session.Status, session.RevokedAt, session.RevokedReason = UserSessionStatusRevoked, now, event.Reason
		}
		if event.AffectedCount > math.MaxInt64-int64(len(revoked)) {
			return ErrSessionRevocationStore
		}
		event.AffectedCount += int64(len(revoked))
		event.Revision++
		event.LastProgressAt, event.NextAttemptAt, event.ErrorCode = now, now+1, ""
		remaining := tx.Model(&UserSession{}).Where("user_id = ? AND status = ? AND revoked_at = ? AND expires_at > ?", event.UserID, UserSessionStatusActive, 0, time.Now().Unix())
		if event.Scope == "others" {
			remaining = remaining.Where("sid <> ?", event.ExcludedSID)
		}
		var count int64
		if err := remaining.Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			event.State, event.CompletedAt = "local_complete", time.Now().Unix()
		}
		result := tx.Model(&SessionRevocationEvent{}).Where("event_ref = ? AND revision = ? AND state = ?", event.EventRef, hint.Revision, "pending").
			Updates(map[string]any{"state": event.State, "revision": event.Revision, "affected_count": event.AffectedCount,
				"last_progress_at": event.LastProgressAt, "next_attempt_at": event.NextAttemptAt, "completed_at": event.CompletedAt, "error_code": ""})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrSessionRevocationStale
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Only confirmed revoked, immutable SIDs are published after commit. A failed
	// transaction never compensates its conservative Redis deny with active data.
	for i := range revoked {
		if err := writeUserSessionCacheWithContext(ctx, revoked[i].cacheEntry(), time.Time{}); err != nil {
			common.SysLog(common.LogText("failed to finalize bulk user session revoke tombstone"))
		}
	}
	return &event, nil
}

// CompleteSessionSecurityChange attempts one batch, then reads only this exact
// event after an ambiguous commit/stale result. It never resumes by range guess.
func CompleteSessionSecurityChange(event *SessionRevocationEvent, credentialCommitted bool) error {
	if event == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := RunSessionRevocationBatch(ctx, *event)
	if err != nil {
		var current SessionRevocationEvent
		if readErr := DB.WithContext(ctx).Where("event_ref = ?", event.EventRef).First(&current).Error; readErr == nil && current.valid() && current.sameIntent(*event) {
			result = &current
		}
	}
	if result != nil {
		*event = *result
		if result.State == "local_complete" {
			return nil
		}
	}
	return &SessionRevocationPendingError{EventRef: event.EventRef, UserID: event.UserID, Revision: event.Revision,
		AffectedCount: event.AffectedCount, CredentialChangeCommitted: credentialCommitted, ProgressKnown: result != nil}
}

// RunDueSessionRevocations does bounded work; hints are never execution rights.
// Failed exact events are durably requeued under the same user/event locks.
func RunDueSessionRevocations(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var events []SessionRevocationEvent
	if err := DB.WithContext(ctx).Where("state = ? AND next_attempt_at <= ?", "pending", time.Now().Unix()).Order("next_attempt_at, event_ref").Limit(20).Find(&events).Error; err != nil {
		return 0, err
	}
	done := 0
	for _, hint := range events {
		if err := ctx.Err(); err != nil {
			return done, err
		}
		_, err := RunSessionRevocationBatch(ctx, hint)
		if errors.Is(err, ErrSessionRevocationStale) {
			continue
		}
		if err != nil {
			if !hint.valid() {
				return done, ErrSessionRevocationStore
			}
			deferCtx, deferCancel := context.WithTimeout(context.Background(), time.Second)
			deferErr := DB.WithContext(deferCtx).Transaction(func(tx *gorm.DB) error {
				if err := LockOAuthUser(tx, hint.UserID); err != nil {
					return err
				}
				var current SessionRevocationEvent
				if err := lockForUpdate(tx).Where("event_ref = ?", hint.EventRef).First(&current).Error; err != nil {
					return err
				}
				if !current.valid() {
					return ErrSessionRevocationStore
				}
				if !current.sameIntent(hint) || current.Revision != hint.Revision || current.State != "pending" {
					return nil
				}
				return tx.Model(&current).Updates(map[string]any{"revision": current.Revision + 1, "next_attempt_at": time.Now().Unix() + 5, "error_code": "local_unavailable"}).Error
			})
			deferCancel()
			if deferErr != nil {
				return done, deferErr
			}
		}
		done++
	}
	return done, nil
}

// CompleteDeletedUserSessionEventsWithTx is called only after hard deletion has
// removed all source sessions under the user lock. Exact completion prevents an
// orphan event ever binding to a later database reuse of the integer user ID.
func CompleteDeletedUserSessionEventsWithTx(tx *gorm.DB, userID int) error {
	var remaining int64
	if err := tx.Model(&UserSession{}).Where("user_id = ?", userID).Count(&remaining).Error; err != nil {
		return err
	}
	if remaining != 0 {
		return ErrSessionRevocationStore
	}
	var events []SessionRevocationEvent
	if err := lockForUpdate(tx).Where("user_id = ? AND state = ?", userID, "pending").Order("event_ref").Find(&events).Error; err != nil {
		return err
	}
	for _, event := range events {
		if !event.valid() {
			return ErrSessionRevocationStore
		}
		result := tx.Model(&SessionRevocationEvent{}).Where("event_ref = ? AND revision = ? AND state = ?", event.EventRef, event.Revision, "pending").
			Updates(map[string]any{"state": "local_complete", "revision": event.Revision + 1, "completed_at": time.Now().Unix(), "last_progress_at": time.Now().Unix()})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrSessionRevocationStale
		}
	}
	return nil
}

// RevokeSessionsForUserDeletionWithTx is the terminal business transaction,
// distinct from a resumable background batch: hard deletion must not remove
// source sessions before their deny and per-SID attribution are durable.
// A legacy account above one batch is rejected before any session effects;
// an authorized revocation must finish first. No unbounded loop is permitted.
func RevokeSessionsForUserDeletionWithTx(tx *gorm.DB, event *SessionRevocationEvent) ([]UserSession, error) {
	if event == nil || !event.valid() || event.Scope != "all" || event.State != "pending" || event.Revision != 1 {
		return nil, ErrSessionRevocationStore
	}
	if err := LockOAuthUser(tx, event.UserID); err != nil {
		return nil, err
	}
	var current SessionRevocationEvent
	if err := lockForUpdate(tx).Where("event_ref = ?", event.EventRef).First(&current).Error; err != nil {
		return nil, err
	}
	if !current.sameIntent(*event) || current.Revision != event.Revision || current.State != "pending" {
		return nil, ErrSessionRevocationStale
	}
	now := time.Now().Unix()
	query := tx.Model(&UserSession{}).Where("user_id = ? AND status = ? AND revoked_at = ? AND expires_at > ?", event.UserID, UserSessionStatusActive, 0, now)
	var active int64
	if err := query.Count(&active).Error; err != nil {
		return nil, err
	}
	if active > int64(userSessionRevokeBatchSize) {
		return nil, ErrSessionDeletionBlocked
	}
	oauthRequired, err := sessionOAuthAttributionRequiredWithTx(tx)
	if err != nil {
		return nil, err
	}
	if event.OAuthAttributionRequired && !oauthRequired {
		return nil, ErrSessionRevocationStore
	}
	var sessions []UserSession
	if err := lockForUpdate(query).Order("sid").Limit(userSessionRevokeBatchSize).Find(&sessions).Error; err != nil {
		return nil, err
	}
	for i := range sessions {
		session := &sessions[i]
		if err := writeUserSessionDenyFenceWithContext(tx.Statement.Context, session, UserSessionStatusRevoking, now, event.Reason); err != nil {
			return nil, err
		}
		result := tx.Model(&UserSession{}).Where("sid = ? AND user_id = ? AND status = ? AND version = ? AND revoked_at = ?", session.SID, event.UserID, UserSessionStatusActive, session.Version, 0).
			Updates(map[string]any{"status": UserSessionStatusRevoked, "revoked_at": now, "revoked_reason": event.Reason})
		if result.Error != nil {
			return nil, result.Error
		}
		if result.RowsAffected != 1 {
			return nil, ErrSessionRevocationStale
		}
		if oauthRequired {
			if err := RevokeOAuthWithTx(tx, event.UserID, "sid", session.SID, "session_revoked", event.EventRef); err != nil {
				return nil, err
			}
		}
		session.Status, session.RevokedAt, session.RevokedReason = UserSessionStatusRevoked, now, event.Reason
	}
	var remaining int64
	if err := tx.Model(&UserSession{}).Where("user_id = ? AND status = ? AND revoked_at = ? AND expires_at > ?", event.UserID, UserSessionStatusActive, 0, time.Now().Unix()).Count(&remaining).Error; err != nil {
		return nil, err
	}
	if remaining != 0 {
		return nil, ErrSessionDeletionBlocked
	}
	result := tx.Model(&SessionRevocationEvent{}).Where("event_ref = ? AND revision = ? AND state = ?", event.EventRef, event.Revision, "pending").
		Updates(map[string]any{"state": "local_complete", "revision": event.Revision + 1, "affected_count": int64(len(sessions)), "completed_at": now, "last_progress_at": now})
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected != 1 {
		return nil, ErrSessionRevocationStale
	}
	event.State, event.Revision, event.AffectedCount = "local_complete", event.Revision+1, int64(len(sessions))
	event.CompletedAt, event.LastProgressAt = now, now
	return sessions, nil
}

// ValidateSessionOAuthHistoryBeforeMigration rejects damage to a previously
// present attribution store before the OAuth initializer can recreate tables.
func ValidateSessionOAuthHistoryBeforeMigration() error {
	if DB == nil {
		return ErrSessionRevocationStore
	}
	var historical int64
	if err := DB.Model(&SessionRevocationEvent{}).Where("o_auth_attribution_required = ?", true).Count(&historical).Error; err != nil {
		return err
	}
	tables, err := sessionOAuthTables(DB)
	if err != nil {
		return err
	}
	count := len(tables)
	if count != 0 && count != 4 || historical != 0 && count != 4 {
		return ErrSessionRevocationStore
	}
	return nil
}
