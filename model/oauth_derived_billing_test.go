package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	mysqlconfig "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func newOAuthTextFixture(t *testing.T) (*gorm.DB, OAuthTextFacts) {
	t.Helper()
	return newOAuthTextDatabaseFixture(t, common.DatabaseTypeSQLite, sqlite.Open(filepath.Join(t.TempDir(), "charge.sqlite")))
}

func newOAuthTextDatabaseFixture(t *testing.T, database common.DatabaseType, driver gorm.Dialector) (*gorm.DB, OAuthTextFacts) {
	t.Helper()
	db, _ := oauthBirthFixture(t)
	database = common.DatabaseType(db.Dialector.Name())
	sql, err := db.DB()
	require.NoError(t, err)
	sql.SetMaxOpenConns(1)
	old, kind, cleanup := DB, common.MainDatabaseType(), oauthCleanupDB.Load()
	DB = db
	common.SetMainDatabaseType(database)
	t.Cleanup(func() {
		DB = old
		common.SetMainDatabaseType(kind)
		oauthCleanupDB.Store(cleanup)
		require.NoError(t, sql.Close())
	})
	tables := []any{&User{}, &Token{}, &UserSession{}, &SessionRevocationEvent{}, &OAuthGrant{}, &OAuthOperation{}, &OAuthArtifact{}, &OAuthCleanupJob{}, &OAuthDerivedTokenSource{}, &OAuthDerivedTokenHistory{}, &OAuthDerivedTextCharge{}}
	require.NoError(t, db.AutoMigrate(tables...))
	require.NoError(t, InitOAuthCleanupStore(true))
	now := time.Now().Unix()
	h := strings.Repeat("a", 64)
	u := User{Username: "charge", AffCode: "charge", Quota: 100, Status: common.UserStatusEnabled, AuthVersion: 1}
	require.NoError(t, db.Create(&u).Error)
	token := Token{UserId: u.Id, Key: "synthetic-unit-key", Status: common.TokenStatusEnabled, RemainQuota: 100, ExpiredTime: now + 100}
	require.NoError(t, db.Create(&token).Error)
	session := UserSession{SID: "unit-session", UserID: u.Id, Version: 1, UserAuthVersion: 1, Status: UserSessionStatusActive, ExpiresAt: now + 200}
	require.NoError(t, db.Create(&session).Error)
	g := OAuthGrant{GrantID: strings.Repeat("g", 43), Issuer: "https://unit.invalid", ClientID: "unit", Subject: strconv.Itoa(u.Id), UserID: u.Id, OriginSID: session.SID, SessionVersion: 1, UserAuthVersion: 1, State: "active", Scopes: `["tokens:write"]`, CreatedAt: now - 15, ExpiresAt: now + 150, ConsentRef: h}
	g.GrantRef = OAuthGrantRef(g.Issuer, g.GrantID)
	require.NoError(t, db.Create(&g).Error)
	key := OAuthDerivedTokenKeyRef(token.Key)
	created := now - 10
	source := OAuthDerivedTokenSource{GrantRef: g.GrantRef, UserID: u.Id, SchemaVersion: 1, QuotaLimit: 100, ExpiresAt: now + 100, PolicyHash: h, BindingHash: h, VerifiedAt: now - 20, ProofExpiresAt: now + 100, PermitDeadline: now + 40, VerifiedMethod: "password", ProofFlowID: 1, TokenID: &token.Id, KeyRef: &key, IdemHash: &h, RequestHash: &h, CreatedAt: &created}
	require.NoError(t, db.Create(&source).Error)
	var birthHistory OAuthDerivedTokenHistory
	require.NoError(t, db.First(&birthHistory).Error)
	var version string
	query := "SELECT version()"
	if database == common.DatabaseTypeSQLite {
		query = "SELECT sqlite_version()"
	}
	require.NoError(t, db.Raw(query).Scan(&version).Error)
	t.Log(database, version)
	return db, OAuthTextFacts{GrantRef: g.GrantRef, UserID: u.Id, TokenID: token.Id, Model: "unit-text", ChannelID: 1, RouteHash: h, BodyHash: h, PolicyHash: h, ModelRatio: 1, CompletionRatio: 1, GroupRatio: 1, PromptEstimate: 20, MaxCompletion: 60}
}
func TestOAuthDerivedTextContract(t *testing.T) {
	ctx := context.Background()
	ref := strings.Repeat("b", 64)
	for _, tc := range []struct {
		name    string
		actual  int
		wallet  int
		state   string
		balance int
	}{{"refund", 60, 20, "settled", 40}, {"delta_held", 110, 20, "held", 20}, {"refund_capacity", 60, common.MaxWalletQuota, "held", common.MaxWalletQuota}, {"zero", 0, 20, "refunded", 100}} {
		t.Run(tc.name, func(t *testing.T) {
			db, f := newOAuthTextFixture(t)
			c, err := ReserveOAuthDerivedText(ctx, ref, f, 80)
			require.NoError(t, err)
			assert.Equal(t, "reserved", c.State)
			_, err = ReserveOAuthDerivedText(ctx, ref, f, 80)
			require.NoError(t, err)
			altered := f
			altered.BodyHash = strings.Repeat("c", 64)
			_, err = ReserveOAuthDerivedText(ctx, ref, altered, 80)
			require.Error(t, err)
			results := make(chan bool, 2)
			errs := make(chan error, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() { won, e := ClaimOAuthDerivedText(ctx, ref, f, 80); results <- won != nil; errs <- e })
			}
			wg.Wait()
			close(results)
			close(errs)
			wins := 0
			for v := range results {
				if v {
					wins++
				}
			}
			for e := range errs {
				require.NoError(t, e)
			}
			assert.Equal(t, 1, wins)
			require.NoError(t, db.Model(&OAuthGrant{}).Where("grant_ref = ?", f.GrantRef).Update("state", "revoked").Error)
			require.NoError(t, db.Model(&User{}).Where("id = ?", f.UserID).Update("quota", tc.wallet).Error)
			c, err = FinalizeOAuthDerivedText(ctx, ref, tc.actual, OAuthTextUsage{Prompt: 20, Completion: 40, Total: 60})
			require.NoError(t, err)
			assert.Equal(t, tc.state, c.State)
			_, err = FinalizeOAuthDerivedText(ctx, ref, tc.actual, OAuthTextUsage{Prompt: 20, Completion: 40, Total: 60})
			require.NoError(t, err)
			_, err = FinalizeOAuthDerivedText(ctx, ref, tc.actual+1, OAuthTextUsage{Prompt: 20, Completion: 40, Total: 60})
			require.Error(t, err)
			var u User
			require.NoError(t, db.First(&u, f.UserID).Error)
			assert.Equal(t, tc.balance, u.Quota)
			var token Token
			require.NoError(t, db.First(&token, f.TokenID).Error)
			expected := tc.actual
			if tc.state == "held" {
				expected = 80
			}
			assert.Equal(t, 100-expected, token.RemainQuota)
			assert.Equal(t, expected, token.UsedQuota)
		})
	}
	t.Run("rollback_and_unknown", func(t *testing.T) {
		db, f := newOAuthTextFixture(t)
		_, err := ReserveOAuthDerivedText(ctx, ref, f, 101)
		require.Error(t, err)
		require.NoError(t, db.Callback().Create().Before("gorm:create").Register("charge_fail", func(tx *gorm.DB) {
			if tx.Statement.Table == "oauth_derived_text_charges" {
				tx.AddError(errors.New("unit failure"))
			}
		}))
		_, err = ReserveOAuthDerivedText(ctx, ref, f, 80)
		require.Error(t, err)
		require.NoError(t, db.Callback().Create().Remove("charge_fail"))
		var u User
		require.NoError(t, db.First(&u, f.UserID).Error)
		assert.Equal(t, 100, u.Quota)
		_, err = ReserveOAuthDerivedText(ctx, ref, f, 0)
		require.NoError(t, err)
		won, err := ClaimOAuthDerivedText(ctx, ref, f, 0)
		require.NoError(t, err)
		assert.NotNil(t, won)
		_, err = FinalizeOAuthDerivedText(ctx, ref, 0, OAuthTextUsage{})
		require.Error(t, err)
		_, err = ReserveOAuthDerivedText(ctx, strings.Repeat("d", 64), f, 1)
		require.Error(t, err)
		var c OAuthDerivedTextCharge
		require.NoError(t, db.First(&c, "ref = ?", ref).Error)
		assert.Nil(t, c.Actual)
		assert.Equal(t, "send_claimed", c.State)
	})
}

func TestOAuthDerivedTextHistoricalBinding(t *testing.T) {
	for _, kind := range []string{"missing_token", "changed_key", "unlimited", "rollback_finalize", "cross_grant_held"} {
		t.Run(kind, func(t *testing.T) {
			db, f := newOAuthTextFixture(t)
			ctx := context.Background()
			ref := strings.Repeat("e", 64)
			_, err := ReserveOAuthDerivedText(ctx, ref, f, 80)
			require.NoError(t, err)
			if kind == "cross_grant_held" {
				require.NoError(t, db.Create(&OAuthDerivedTextCharge{Ref: strings.Repeat("f", 64), UserID: f.UserID, GrantRef: strings.Repeat("d", 64), State: "held"}).Error)
				won, e := ClaimOAuthDerivedText(ctx, ref, f, 80)
				require.Error(t, e)
				assert.Nil(t, won)
				return
			}
			won, err := ClaimOAuthDerivedText(ctx, ref, f, 80)
			require.NoError(t, err)
			require.NotNil(t, won)
			switch kind {
			case "missing_token":
				require.NoError(t, db.Unscoped().Delete(&Token{}, f.TokenID).Error)
			case "changed_key":
				require.NoError(t, db.Model(&Token{}).Where("id = ?", f.TokenID).Update("key", "different-unit-key").Error)
			case "unlimited":
				require.NoError(t, db.Model(&Token{}).Where("id = ?", f.TokenID).Update("unlimited_quota", true).Error)
			case "rollback_finalize":
				require.NoError(t, db.Callback().Update().Before("gorm:update").Register("charge_settle_fail", func(tx *gorm.DB) {
					if tx.Statement.Table == "oauth_derived_text_charges" {
						tx.AddError(errors.New("unit settle failure"))
					}
				}))
			}
			c, err := FinalizeOAuthDerivedText(ctx, ref, 60, OAuthTextUsage{Prompt: 20, Completion: 40, Total: 60})
			if kind == "rollback_finalize" {
				require.Error(t, err)
				require.NoError(t, db.Callback().Update().Remove("charge_settle_fail"))
				var stored OAuthDerivedTextCharge
				require.NoError(t, db.First(&stored, "ref = ?", ref).Error)
				assert.Nil(t, stored.Actual)
				assert.Equal(t, "send_claimed", stored.State)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "held", c.State)
				require.NotNil(t, c.Actual)
				assert.Equal(t, 60, *c.Actual)
			}
			var u User
			require.NoError(t, db.First(&u, f.UserID).Error)
			assert.Equal(t, 20, u.Quota)
		})
	}
}

func TestOAuthDerivedTextAdmissionSnapshot(t *testing.T) {
	for _, kind := range []string{"source_binding", "token_key", "cap", "payer", "attempt", "cache_price"} {
		t.Run(kind, func(t *testing.T) {
			db, f := newOAuthTextFixture(t)
			ctx := context.Background()
			ref := strings.Repeat("b", 64)
			original, err := ReserveOAuthDerivedText(ctx, ref, f, 80)
			require.NoError(t, err)
			var source OAuthDerivedTokenSource
			require.NoError(t, db.First(&source, "grant_ref = ?", f.GrantRef).Error)
			switch kind {
			case "source_binding":
				source.BindingHash = strings.Repeat("c", 64)
			case "token_key":
				key := "replacement-synthetic-key"
				keyRef := OAuthDerivedTokenKeyRef(key)
				source.KeyRef = &keyRef
				require.NoError(t, db.Model(&Token{}).Where("id = ?", f.TokenID).Update("key", key).Error)
			case "cap":
				source.QuotaLimit = 200
				require.NoError(t, db.Model(&Token{}).Where("id = ?", f.TokenID).Update("remain_quota", 120).Error)
			case "payer":
				require.NoError(t, db.Model(&OAuthDerivedTextCharge{}).Where("ref = ?", ref).Update("payer_id", f.UserID+1).Error)
			case "attempt":
				require.NoError(t, db.Model(&OAuthDerivedTextCharge{}).Where("ref = ?", ref).Update("attempt", 1).Error)
			case "cache_price":
				f.CacheRatio = .25
			}
			// Full Save intentionally exercises the real source validation hook.
			require.NoError(t, db.Save(&source).Error)
			var token Token
			var grant OAuthGrant
			require.NoError(t, db.First(&token, f.TokenID).Error)
			require.NoError(t, db.First(&grant, "grant_ref = ?", f.GrantRef).Error)
			require.NoError(t, validateOAuthDerivedTokenBinding(&source, &grant, &token, time.Now().Unix()))
			_, err = ReserveOAuthDerivedText(ctx, ref, f, 80)
			require.Error(t, err)
			permit, err := ClaimOAuthDerivedText(ctx, ref, f, 80)
			require.Error(t, err)
			assert.Nil(t, permit)
			var stored OAuthDerivedTextCharge
			var user User
			var after Token
			require.NoError(t, db.First(&stored, "ref = ?", ref).Error)
			require.NoError(t, db.First(&user, f.UserID).Error)
			require.NoError(t, db.First(&after, f.TokenID).Error)
			assert.Equal(t, 20, user.Quota)
			assert.Equal(t, token.RemainQuota, after.RemainQuota)
			assert.Equal(t, token.UsedQuota, after.UsedQuota)
			assert.Equal(t, original.State, stored.State)
			assert.Equal(t, original.Version, stored.Version)
			assert.Nil(t, stored.Actual)
			assert.Zero(t, stored.ClaimAt)
		})
	}
}

func TestOAuthDerivedTextClaimDeadline(t *testing.T) {
	for _, kind := range []string{"after_locks", "after_commit", "valid"} {
		t.Run(kind, func(t *testing.T) {
			db, f := newOAuthTextFixture(t)
			ctx := context.Background()
			ref := strings.Repeat("b", 64)
			_, err := ReserveOAuthDerivedText(ctx, ref, f, 80)
			require.NoError(t, err)
			var token Token
			require.NoError(t, db.First(&token, f.TokenID).Error)
			deadline := token.ExpiredTime
			calls := 0
			chargeRead := false
			require.NoError(t, db.Callback().Query().After("gorm:query").Register("claim_charge_read", func(tx *gorm.DB) {
				if tx.Statement.Table == "oauth_derived_text_charges" {
					_, chargeRead = tx.Statement.Dest.(*OAuthDerivedTextCharge)
				}
			}))
			permit, err := claimOAuthDerivedText(ctx, ref, f, 80, func() time.Time {
				require.True(t, chargeRead, "clock must be sampled after the locked charge read")
				calls++
				now := deadline - 1
				if kind == "after_locks" || kind == "after_commit" && calls == 2 {
					now = deadline
				}
				return time.Unix(now, 0)
			})
			require.NoError(t, db.Callback().Query().Remove("claim_charge_read"))
			if kind == "valid" {
				require.NoError(t, err)
				require.NotNil(t, permit)
				assert.Equal(t, deadline, permit.Deadline)
				assert.Equal(t, ref, permit.Ref)
			} else {
				require.Error(t, err)
				assert.Nil(t, permit)
			}
			var stored OAuthDerivedTextCharge
			var user User
			require.NoError(t, db.First(&stored, "ref = ?", ref).Error)
			require.NoError(t, db.First(&user, f.UserID).Error)
			assert.Equal(t, 20, user.Quota)
			assert.Nil(t, stored.Actual)
			if kind == "after_locks" {
				assert.Equal(t, "reserved", stored.State)
				assert.EqualValues(t, 1, stored.Version)
				assert.Zero(t, stored.SendDeadline)
				assert.Equal(t, 1, calls)
			} else {
				assert.Equal(t, "send_claimed", stored.State)
				assert.Equal(t, deadline, stored.SendDeadline)
				assert.Equal(t, 2, calls)
				replay, e := ClaimOAuthDerivedText(ctx, ref, f, 80)
				require.NoError(t, e)
				assert.Nil(t, replay)
				_, e = ReserveOAuthDerivedText(ctx, strings.Repeat("c", 64), f, 1)
				require.Error(t, e)
			}
		})
	}
}

func TestOAuthDerivedTextCachedSettlement(t *testing.T) {
	db, f := newOAuthTextFixture(t)
	ctx := context.Background()
	ref := strings.Repeat("b", 64)
	f.CacheRatio = .25
	_, err := ReserveOAuthDerivedText(ctx, ref, f, 80)
	require.NoError(t, err)
	permit, err := ClaimOAuthDerivedText(ctx, ref, f, 80)
	require.NoError(t, err)
	require.NotNil(t, permit)
	saved, err := ReadOAuthDerivedTextCharge(ctx, ref)
	require.NoError(t, err)
	var facts OAuthTextFacts
	require.NoError(t, common.UnmarshalJsonStr(saved.Facts, &facts))
	assert.Equal(t, .25, facts.CacheRatio)
	usage := OAuthTextUsage{Prompt: 20, Completion: 40, Total: 60, Cached: 20}
	_, err = FinalizeOAuthDerivedTextSnapshot(ctx, ref, 45, usage, strings.Repeat("f", 64))
	require.Error(t, err)
	c, err := FinalizeOAuthDerivedTextSnapshot(ctx, ref, 45, usage, saved.Fingerprint)
	require.NoError(t, err)
	assert.Equal(t, "settled", c.State)
	var storedUsage OAuthTextUsage
	require.NoError(t, common.UnmarshalJsonStr(c.Usage, &storedUsage))
	assert.Equal(t, usage, storedUsage)
	_, err = FinalizeOAuthDerivedTextSnapshot(ctx, ref, 45, usage, saved.Fingerprint)
	require.NoError(t, err)
	usage.Cached = 0
	_, err = FinalizeOAuthDerivedTextSnapshot(ctx, ref, 45, usage, saved.Fingerprint)
	require.Error(t, err)
	var user User
	require.NoError(t, db.First(&user, f.UserID).Error)
	assert.Equal(t, 55, user.Quota)
}

func TestReadOAuthDerivedTextAuthority(t *testing.T) {
	for _, database := range []common.DatabaseType{common.DatabaseTypeSQLite, common.DatabaseTypeMySQL, common.DatabaseTypePostgreSQL} {
		t.Run(string(database), func(t *testing.T) {
			for _, scenario := range []string{"valid", "manual", "unknown_history", "missing_table", "missing_token", "wrong_user", "wrong_token", "revoked_source", "expired_source", "disabled_token", "expired_token", "unlimited_token", "stale_key", "incomplete_source", "invalid_policy", "quota_mismatch", "revoked_grant", "expired_grant", "revoked_session", "expired_session", "stale_session_version", "stale_auth_version", "disabled_user", "cleanup_unready", "visibility_error", "rebind_after_lookup", "revoke_after_lookup", "historical_finalize"} {
				t.Run(scenario, func(t *testing.T) {
					db, facts := newOAuthTextDatabaseFixture(t, database, oauthTextAuthorityDialect(t, database))
					ctx := context.Background()
					userID, tokenID := facts.UserID, facts.TokenID
					var source OAuthDerivedTokenSource
					require.NoError(t, db.First(&source, "grant_ref = ?", facts.GrantRef).Error)
					now := time.Now().Unix()
					switch scenario {
					case "manual":
						require.NoError(t, db.Delete(&source).Error)
						kind, err := ClassifyOAuthDerivedToken(ctx, tokenID)
						require.NoError(t, err)
						require.Equal(t, OAuthDerivedTokenManualProven, kind)
					case "unknown_history":
						require.NoError(t, db.Delete(&OAuthDerivedTokenHistory{}, 1).Error)
					case "missing_table":
						require.NoError(t, db.Migrator().DropTable(&OAuthDerivedTokenSource{}))
					case "missing_token":
						require.NoError(t, db.Unscoped().Delete(&Token{}, tokenID).Error)
					case "wrong_user":
						userID++
					case "wrong_token":
						tokenID++
					case "revoked_source":
						reason := "revoked"
						source.TerminalAt, source.TerminalReason = &now, &reason
						require.NoError(t, db.Save(&source).Error)
					case "expired_source":
						source.ExpiresAt = now - 1
						require.NoError(t, db.Save(&source).Error)
					case "disabled_token":
						require.NoError(t, db.Model(&Token{}).Where("id = ?", tokenID).UpdateColumn("status", common.TokenStatusDisabled).Error)
					case "expired_token":
						require.NoError(t, db.Model(&Token{}).Where("id = ?", tokenID).UpdateColumn("expired_time", now-1).Error)
					case "unlimited_token":
						require.NoError(t, db.Model(&Token{}).Where("id = ?", tokenID).UpdateColumn("unlimited_quota", true).Error)
					case "stale_key":
						require.NoError(t, db.Model(&Token{}).Where("id = ?", tokenID).UpdateColumn("key", "replacement-synthetic-key").Error)
					case "incomplete_source":
						// Deliberate persisted corruption; ordinary Save correctly refuses it.
						require.NoError(t, db.Model(&source).UpdateColumn("key_ref", nil).Error)
					case "invalid_policy":
						require.NoError(t, db.Model(&source).UpdateColumn("policy_hash", "invalid").Error)
					case "quota_mismatch":
						require.NoError(t, db.Model(&Token{}).Where("id = ?", tokenID).UpdateColumn("remain_quota", 99).Error)
					case "revoked_grant":
						require.NoError(t, db.Model(&OAuthGrant{}).Where("grant_ref = ?", facts.GrantRef).Updates(map[string]any{"state": "revoked", "revoked_at": now}).Error)
					case "expired_grant":
						require.NoError(t, db.Model(&OAuthGrant{}).Where("grant_ref = ?", facts.GrantRef).UpdateColumn("expires_at", now-1).Error)
					case "revoked_session":
						require.NoError(t, db.Model(&UserSession{}).Where("sid = ?", "unit-session").UpdateColumn("revoked_at", now).Error)
					case "expired_session":
						require.NoError(t, db.Model(&UserSession{}).Where("sid = ?", "unit-session").UpdateColumn("expires_at", now-1).Error)
					case "stale_session_version":
						require.NoError(t, db.Model(&UserSession{}).Where("sid = ?", "unit-session").UpdateColumn("version", 2).Error)
					case "stale_auth_version":
						require.NoError(t, db.Model(&User{}).Where("id = ?", userID).UpdateColumn("auth_version", 2).Error)
					case "disabled_user":
						require.NoError(t, db.Model(&User{}).Where("id = ?", userID).UpdateColumn("status", common.UserStatusDisabled).Error)
					case "cleanup_unready":
						require.NoError(t, InitOAuthCleanupStore(false))
					case "historical_finalize":
						ref := strings.Repeat("b", 64)
						_, err := ReserveOAuthDerivedText(ctx, ref, facts, 80)
						require.NoError(t, err)
						permit, err := ClaimOAuthDerivedText(ctx, ref, facts, 80)
						require.NoError(t, err)
						require.NotNil(t, permit)
						require.NoError(t, db.Model(&OAuthGrant{}).Where("grant_ref = ?", facts.GrantRef).UpdateColumn("state", "revoked").Error)
					}
					before := oauthTextAuthorityRows(t, db)
					changed := false
					if scenario == "visibility_error" || scenario == "rebind_after_lookup" || scenario == "revoke_after_lookup" {
						require.NoError(t, db.Callback().Query().After("gorm:query").Register("authority_interleave", func(tx *gorm.DB) {
							if changed || tx.Statement.Table != "oauth_derived_token_sources" {
								return
							}
							if scenario == "visibility_error" {
								tx.AddError(errors.New("controlled SQL visibility failure"))
								return
							}
							row, ok := tx.Statement.Dest.(*OAuthDerivedTokenSource)
							if !ok || tx.RowsAffected != 1 {
								return
							}
							// The preliminary source read completed outside the locking
							// transaction. Commit the change before the locked reread.
							changed = true
							update := *row
							if scenario == "rebind_after_lookup" {
								update.BindingHash = strings.Repeat("c", 64)
							} else {
								reason := "revoked"
								update.TerminalAt, update.TerminalReason = &now, &reason
							}
							require.NoError(t, db.Save(&update).Error)
							before = oauthTextAuthorityRows(t, db)
						}))
					}
					got, err := ReadOAuthDerivedTextAuthority(ctx, userID, tokenID)
					if scenario == "visibility_error" || strings.HasSuffix(scenario, "after_lookup") {
						require.NoError(t, db.Callback().Query().Remove("authority_interleave"))
						if scenario != "visibility_error" {
							require.True(t, changed, "mutation must occur between preliminary and locked reads")
						}
					}
					if scenario == "valid" {
						require.NoError(t, err)
						require.Equal(t, &OAuthTextFacts{GrantRef: facts.GrantRef, UserID: facts.UserID, TokenID: facts.TokenID, PolicyHash: source.PolicyHash}, got, "only SQL-owned initial facts; no price/route/request or permission")
						_, err = ReserveOAuthDerivedText(ctx, strings.Repeat("b", 64), *got, 80)
						require.Error(t, err, "initial facts cannot reserve")
						permit, err := ClaimOAuthDerivedText(ctx, strings.Repeat("b", 64), *got, 80)
						require.Error(t, err)
						require.Nil(t, permit)
					} else {
						require.ErrorIs(t, err, ErrOAuthTextCharge)
						assert.Nil(t, got)
					}
					assert.Equal(t, before, oauthTextAuthorityRows(t, db), "read must not mutate balances, source, token, grant/session or receipts")
					if scenario == "historical_finalize" {
						settled, err := FinalizeOAuthDerivedText(ctx, strings.Repeat("b", 64), 60, OAuthTextUsage{Prompt: 20, Completion: 40, Total: 60})
						require.NoError(t, err)
						assert.Equal(t, "settled", settled.State)
						assert.Equal(t, facts.UserID, settled.PayerID)
						var user User
						var token Token
						require.NoError(t, db.First(&user, facts.UserID).Error)
						require.NoError(t, db.First(&token, facts.TokenID).Error)
						assert.Equal(t, 40, user.Quota)
						assert.Equal(t, 40, token.RemainQuota)
						assert.Equal(t, 60, token.UsedQuota)
					}
				})
			}
		})
	}
}

// Compare hashes of all fixture rows so assertion failures never print keys or
// session fields. This covers balances and authority state, not just receipts.
func oauthTextAuthorityRows(t *testing.T, db *gorm.DB) map[string]string {
	t.Helper()
	out := make(map[string]string)
	tables, err := db.Migrator().GetTables()
	require.NoError(t, err)
	for _, table := range tables {
		var rows []map[string]any
		require.NoError(t, db.Table(table).Find(&rows).Error)
		raw, err := common.Marshal(rows)
		require.NoError(t, err)
		sum := sha256.Sum256(raw)
		out[table] = hex.EncodeToString(sum[:])
	}
	return out
}

func oauthTextAuthorityDialect(t *testing.T, database common.DatabaseType) gorm.Dialector {
	t.Helper()
	if database == common.DatabaseTypeSQLite {
		return sqlite.Open(filepath.Join(t.TempDir(), "authority.sqlite"))
	}
	env := "TEST_MYSQL_DSN"
	if database == common.DatabaseTypePostgreSQL {
		env = "TEST_POSTGRES_DSN"
	}
	dsn := os.Getenv(env)
	if dsn == "" {
		require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"))
		t.Skip(env + " is not configured")
	}
	require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
	if database == common.DatabaseTypeMySQL {
		cfg, err := mysqlconfig.ParseDSN(dsn)
		require.NoError(t, err)
		host, _, err := net.SplitHostPort(cfg.Addr)
		require.NoError(t, err)
		require.Equal(t, "tcp", cfg.Net)
		require.Equal(t, "127.0.0.1", host)
		require.True(t, strings.HasPrefix(cfg.DBName, "newapi_ci_"))
		return mysql.Open(dsn)
	}
	// The same effective-target checks as the service fixture are required here;
	// model tests cannot import service (service imports model).
	target, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, target.Scheme)
	require.NotEmpty(t, target.Host)
	require.NotEmpty(t, target.Path)
	require.NotEqual(t, "/", target.Path)
	require.Empty(t, target.Fragment)
	query, err := url.ParseQuery(target.RawQuery)
	require.NoError(t, err)
	for key, values := range query {
		require.Contains(t, []string{"sslmode", "connect_timeout"}, key)
		require.Len(t, values, 1)
	}
	require.Empty(t, os.Getenv("PGSERVICE"))
	require.Empty(t, os.Getenv("PGSERVICEFILE"))
	cfg, err := pgx.ParseConfig(dsn)
	require.True(t, err == nil, "invalid PostgreSQL test config")
	require.Equal(t, "127.0.0.1", cfg.Host)
	require.True(t, strings.HasPrefix(cfg.Database, "newapi_ci_"))
	for _, fallback := range cfg.Fallbacks {
		require.NotNil(t, fallback)
		require.Equal(t, "127.0.0.1", fallback.Host)
	}
	sqlDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
	return postgres.New(postgres.Config{Conn: sqlDB})
}
