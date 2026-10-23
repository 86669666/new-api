package model

import (
	"context"
	"errors"
	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func newOAuthTextFixture(t *testing.T) (*gorm.DB, OAuthTextFacts) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "charge.sqlite")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sql, err := db.DB()
	require.NoError(t, err)
	sql.SetMaxOpenConns(1)
	old, kind, cleanup := DB, common.MainDatabaseType(), oauthCleanupDB.Load()
	DB = db
	common.SetMainDatabaseType(common.DatabaseTypeSQLite)
	t.Cleanup(func() {
		DB = old
		common.SetMainDatabaseType(kind)
		oauthCleanupDB.Store(cleanup)
		require.NoError(t, sql.Close())
	})
	require.NoError(t, db.AutoMigrate(&User{}, &Token{}, &UserSession{}, &SessionRevocationEvent{}, &OAuthGrant{}, &OAuthOperation{}, &OAuthArtifact{}, &OAuthCleanupJob{}, &OAuthDerivedTokenSource{}, &OAuthDerivedTokenHistory{}, &OAuthDerivedTextCharge{}))
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
	require.NoError(t, db.Create(&OAuthDerivedTokenHistory{ID: 1, SchemaVersion: 1, HistorySeal: h, SealedAt: now - 30}).Error)
	var version string
	require.NoError(t, db.Raw("SELECT sqlite_version()").Scan(&version).Error)
	t.Log("SQLite", version)
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
				wg.Go(func() { won, e := ClaimOAuthDerivedText(ctx, ref, f, 80); results <- won; errs <- e })
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
		assert.True(t, won)
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
				assert.False(t, won)
				return
			}
			won, err := ClaimOAuthDerivedText(ctx, ref, f, 80)
			require.NoError(t, err)
			require.True(t, won)
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
