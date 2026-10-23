package model

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func createReserveTestUser(t *testing.T, quota int) User {
	t.Helper()
	user := User{
		Username:    "reserve-user-" + common.GetRandomString(6),
		Password:    "unused-password-hash",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AuthVersion: 1,
		Quota:       quota,
		AffCode:     "reserve-aff-" + common.GetRandomString(8),
	}
	require.NoError(t, DB.Create(&user).Error)
	return user
}

func createReserveTestToken(t *testing.T, remainQuota int) Token {
	t.Helper()
	token := Token{
		UserId:      1,
		Key:         "reserve-token-" + common.GetRandomString(8),
		Name:        "reserve-test",
		Status:      common.TokenStatusEnabled,
		ExpiredTime: -1,
		RemainQuota: remainQuota,
	}
	require.NoError(t, token.Insert())
	return token
}

func getUserQuotaFromDB(t *testing.T, id int) int {
	t.Helper()
	var user User
	require.NoError(t, DB.Select("quota").First(&user, id).Error)
	return user.Quota
}

func getTokenFromDB(t *testing.T, id int) Token {
	t.Helper()
	var token Token
	require.NoError(t, DB.First(&token, id).Error)
	return token
}

func resetBatchUpdateTestState(t *testing.T) {
	t.Helper()
	require.NoError(t, DB.AutoMigrate(&OAuthDerivedTextCharge{}))
	oldBatchEnabled := common.BatchUpdateEnabled
	common.BatchUpdateEnabled = false
	for i := range BatchUpdateTypeCount {
		batchUpdateLocks[i].Lock()
		batchUpdateStores[i] = make(map[int]int)
		batchUpdateLocks[i].Unlock()
	}
	t.Cleanup(func() {
		common.BatchUpdateEnabled = oldBatchEnabled
		for i := range BatchUpdateTypeCount {
			batchUpdateLocks[i].Lock()
			batchUpdateStores[i] = make(map[int]int)
			batchUpdateLocks[i].Unlock()
		}
	})
}

func TestTryReserveQuotaWithoutRedis(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)

	user := createReserveTestUser(t, 100)
	reserved, err := TryReserveUserQuota(user.Id, 60)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, 40, getUserQuotaFromDB(t, user.Id))

	reserved, err = TryReserveUserQuota(user.Id, 41)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 40, getUserQuotaFromDB(t, user.Id))

	token := createReserveTestToken(t, 80)
	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 25, false)
	require.NoError(t, err)
	assert.True(t, reserved)
	reloaded := getTokenFromDB(t, token.Id)
	assert.Equal(t, 55, reloaded.RemainQuota)
	assert.Equal(t, 25, reloaded.UsedQuota)

	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 56, false)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 55, getTokenFromDB(t, token.Id).RemainQuota)
}

func TestRedisBatchReserveUsesSQLWalletAndSQLToken(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	useUserCacheMiniRedis(t)
	common.BatchUpdateEnabled = true

	user := createReserveTestUser(t, 10)
	reserved, err := TryReserveUserQuota(user.Id, 8)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, 2, getUserQuotaFromDB(t, user.Id), "wallet money must commit before success even with batch enabled")

	reserved, err = TryReserveUserQuota(user.Id, 3)
	require.NoError(t, err)
	assert.False(t, reserved, "stale DB balance must not authorize a second spend")
	cachedUser, err := GetUserCache(user.Id)
	require.NoError(t, err)
	assert.Equal(t, 2, cachedUser.Quota)

	token := createReserveTestToken(t, 9)
	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 7, false)
	require.NoError(t, err)
	assert.True(t, reserved)
	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 3, false)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 2, getTokenFromDB(t, token.Id).RemainQuota)

	batchUpdate()
	assert.Equal(t, 2, getUserQuotaFromDB(t, user.Id))
	reloadedToken := getTokenFromDB(t, token.Id)
	assert.Equal(t, 2, reloadedToken.RemainQuota)
	assert.Equal(t, 7, reloadedToken.UsedQuota)
}

func TestBatchUpdateAccumulatesTwoMaximumRequestCharges(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	common.BatchUpdateEnabled = true

	user := createReserveTestUser(t, common.MaxQuota*2+100)
	require.NoError(t, DecreaseUserQuota(user.Id, common.MaxQuota, false))
	require.NoError(t, DecreaseUserQuota(user.Id, common.MaxQuota, false))

	batchUpdate()
	assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
}

func TestBatchUpdateAccumulatorSaturatesOverflow(t *testing.T) {
	resetBatchUpdateTestState(t)

	addNewRecord(BatchUpdateTypeUserQuota, 1, math.MaxInt)
	addNewRecord(BatchUpdateTypeUserQuota, 1, 1)
	batchUpdateLocks[BatchUpdateTypeUserQuota].Lock()
	assert.Equal(t, math.MaxInt, batchUpdateStores[BatchUpdateTypeUserQuota][1])
	batchUpdateLocks[BatchUpdateTypeUserQuota].Unlock()

	batchUpdateLocks[BatchUpdateTypeUserQuota].Lock()
	batchUpdateStores[BatchUpdateTypeUserQuota] = make(map[int]int)
	batchUpdateLocks[BatchUpdateTypeUserQuota].Unlock()
	addNewRecord(BatchUpdateTypeUserQuota, 1, math.MinInt)
	addNewRecord(BatchUpdateTypeUserQuota, 1, -1)
	batchUpdateLocks[BatchUpdateTypeUserQuota].Lock()
	assert.Equal(t, math.MinInt, batchUpdateStores[BatchUpdateTypeUserQuota][1])
	batchUpdateLocks[BatchUpdateTypeUserQuota].Unlock()
}

func TestReserveUsesSQLWhenRedisIsUnavailable(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	server := useUserCacheMiniRedis(t)

	user := createReserveTestUser(t, 20)
	require.NoError(t, populateUserCache(user))
	server.Close()

	// SQL remains the only wallet authority even while the projection is unavailable.
	reserved, err := TryReserveUserQuota(user.Id, 5)
	require.NoError(t, err)
	assert.True(t, reserved)
	assert.Equal(t, 15, getUserQuotaFromDB(t, user.Id))

	reserved, err = TryReserveUserQuota(user.Id, 16)
	require.NoError(t, err)
	assert.False(t, reserved)
	assert.Equal(t, 15, getUserQuotaFromDB(t, user.Id))
}

func TestSynchronousReserveCompensatesCacheWhenPersistenceFails(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	useUserCacheMiniRedis(t)

	user := createReserveTestUser(t, 10)
	require.NoError(t, populateUserCache(user))
	require.NoError(t, DB.Delete(&user).Error)

	reserved, err := TryReserveUserQuota(user.Id, 6)
	assert.False(t, reserved)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	cached, cacheErr := cacheGetUserBase(user.Id)
	require.NoError(t, cacheErr)
	assert.Equal(t, 10, cached.Quota)

	token := createReserveTestToken(t, 12)
	_, err = GetTokenByKey(token.Key, true)
	require.NoError(t, err)
	require.NoError(t, DB.Delete(&token).Error)
	reserved, err = TryReserveTokenQuota(token.Id, token.Key, 7, false)
	assert.False(t, reserved)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	cachedToken, cacheErr := cacheGetTokenByKey(token.Key)
	require.Error(t, cacheErr)
	assert.Nil(t, cachedToken, "deleted SQL token cannot be authorized from stale cache")
}

func TestTokenCacheInitPreservesLiveQuotaAndFenceBlocksStaleSnapshot(t *testing.T) {
	truncateTables(t)
	resetBatchUpdateTestState(t)
	server := useUserCacheMiniRedis(t)

	token := createReserveTestToken(t, 100)
	loaded, err := GetTokenByKey(token.Key, true)
	require.NoError(t, err)
	stale := *loaded

	require.NoError(t, common.RDB.HSet(context.Background(), getTokenCacheKey(token.Key), "RemainQuota", 30, "UsedQuota", 70).Err())

	// Redis may retain a legacy delta, but callers must observe committed SQL money.
	code, err := cacheInitToken(stale)
	require.NoError(t, err)
	assert.Equal(t, 2, code)
	cached, err := cacheGetTokenByKey(token.Key)
	require.NoError(t, err)
	assert.Equal(t, 100, cached.RemainQuota)

	// 变更期间：fence 删除缓存并拦截并发读者手中的过期快照。
	require.NoError(t, invalidateTokenCacheForMutation(token.Key))
	code, err = cacheInitToken(stale)
	require.NoError(t, err)
	assert.Zero(t, code, "the pre-mutation snapshot must not be published while fenced")
	_, err = cacheGetTokenByKey(token.Key)
	assert.Error(t, err)

	// fence 过期后可重新从数据库水合。
	server.FastForward(time.Duration(tokenCacheFenceSeconds+1) * time.Second)
	fresh, err := GetTokenByKey(token.Key, false)
	require.NoError(t, err)
	assert.Equal(t, 100, fresh.RemainQuota)
	cached, err = cacheGetTokenByKey(token.Key)
	require.NoError(t, err)
	assert.Equal(t, 100, cached.RemainQuota)
}

// Real databases use the existing guarded OAuth fixture; Redis is either the
// dedicated local CI service or the existing in-process fixture for local runs.
func newSQLWalletFixture(t *testing.T, database common.DatabaseType) (*gorm.DB, OAuthTextFacts) {
	t.Helper()
	db, facts := newOAuthTextDatabaseFixture(t, database, oauthTextAuthorityDialect(t, database))
	require.NoError(t, db.AutoMigrate(&Task{}))
	t.Cleanup(func() { assert.NoError(t, db.Migrator().DropTable(&Task{})) })
	resetBatchUpdateTestState(t)
	addr := os.Getenv("NEWAPI_TEST_REDIS_ADDR")
	if addr == "" {
		require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"), "real Redis is required for the matrix")
		useUserCacheMiniRedis(t)
		return db, facts
	}
	require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	require.NotEmpty(t, port)
	client := redis.NewClient(&redis.Options{Addr: addr})
	require.NoError(t, client.Ping(context.Background()).Err())
	old, enabled := common.RDB, common.RedisEnabled
	common.RDB, common.RedisEnabled = client, true
	t.Cleanup(func() {
		assert.NoError(t, client.Del(context.Background(), getUserCacheKey(facts.UserID)).Err())
		common.RDB, common.RedisEnabled = old, enabled
		assert.NoError(t, client.Close())
	})
	return db, facts
}

func TestSQLWalletAuthority(t *testing.T) {
	for _, database := range []common.DatabaseType{common.DatabaseTypeSQLite, common.DatabaseTypeMySQL, common.DatabaseTypePostgreSQL} {
		t.Run(string(database), func(t *testing.T) {
			for _, scenario := range []string{"stale_projection", "financial_batch", "concurrent_reserve", "concurrent_derived_reserve", "zero", "send_claimed", "held", "historical_finalize", "delta_sql_failure", "gate_read_failure", "missing_store", "missing_user", "bounded_delta", "additional_arrears", "additional_held", "additional_boundary"} {
				t.Run(scenario, func(t *testing.T) {
					db, facts := newSQLWalletFixture(t, database)
					ctx := context.Background()
					ref := strings.Repeat("b", 64)
					var user User
					require.NoError(t, db.First(&user, facts.UserID).Error)
					require.NoError(t, populateUserCache(user))
					switch scenario {
					case "additional_arrears":
						ok, err := TryReserveAdditionalUserQuota(user.Id, 140)
						require.NoError(t, err)
						require.True(t, ok)
						assert.Equal(t, -40, getUserQuotaFromDB(t, user.Id))
					case "additional_held":
						require.NoError(t, db.Create(&OAuthDerivedTextCharge{Ref: ref, UserID: user.Id, State: "held"}).Error)
						for _, amount := range []int{0, 140} {
							ok, err := TryReserveAdditionalUserQuota(user.Id, amount)
							require.Error(t, err)
							assert.False(t, ok)
						}
						assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
					case "additional_boundary":
						require.NoError(t, db.Model(&User{}).Where("id = ?", user.Id).UpdateColumn("quota", -common.MaxWalletQuota+1).Error)
						ok, err := TryReserveAdditionalUserQuota(user.Id, 2)
						require.ErrorIs(t, err, ErrWalletQuotaLimitExceeded)
						assert.False(t, ok)
						ok, err = TryReserveAdditionalUserQuota(user.Id, 1)
						require.NoError(t, err)
						require.True(t, ok)
						assert.Equal(t, -common.MaxWalletQuota, getUserQuotaFromDB(t, user.Id))
					case "stale_projection":
						ok, err := TryReserveUserQuota(user.Id, 80)
						require.NoError(t, err)
						require.True(t, ok)
						// A pre-debit hydration arrives after commit/invalidation.
						require.NoError(t, populateUserCache(user))
						quota, err := GetUserQuota(user.Id, false)
						require.NoError(t, err)
						assert.Equal(t, 20, quota)
						cached, err := GetUserCache(user.Id)
						require.NoError(t, err)
						assert.Equal(t, 20, cached.Quota)
						ok, err = TryReserveUserQuota(user.Id, 21)
						require.NoError(t, err)
						assert.False(t, ok)
						require.NoError(t, IncreaseUserQuota(user.Id, 10, false))
						_, err = GetUserCache(user.Id) // hydrated from the credited SQL row
						require.NoError(t, err)
						require.NoError(t, cacheIncrUserQuota(user.Id, 10)) // delayed credit notification
						cached, err = GetUserCache(user.Id)
						require.NoError(t, err)
						assert.Equal(t, 30, cached.Quota, "notification must not apply credit twice")
						assert.Equal(t, 30, getUserQuotaFromDB(t, user.Id))
					case "financial_batch":
						common.BatchUpdateEnabled = true
						ok, err := TryReserveUserQuota(user.Id, 80)
						require.NoError(t, err)
						require.True(t, ok)
						require.NoError(t, IncreaseUserQuota(user.Id, 10, false))
						require.NoError(t, DecreaseUserQuota(user.Id, 5, false))
						assert.Equal(t, 25, getUserQuotaFromDB(t, user.Id))
						assert.Empty(t, batchUpdateStores[BatchUpdateTypeUserQuota])
						UpdateUserUsedQuotaAndRequestCount(user.Id, 80)
						batchUpdate()
						// An old process's deferred money is not analytics and cannot
						// be blindly applied after SQL-authoritative admission.
						addNewRecord(BatchUpdateTypeUserQuota, user.Id, -70)
						batchUpdate()
						require.NoError(t, db.First(&user, user.Id).Error)
						assert.Equal(t, 25, user.Quota)
						assert.Equal(t, 80, user.UsedQuota)
						assert.Equal(t, 1, user.RequestCount)
						assert.Equal(t, -70, batchUpdateStores[BatchUpdateTypeUserQuota][user.Id], "old obligation retained for reconciliation")
					case "concurrent_reserve", "concurrent_derived_reserve":
						sqlDB, err := db.DB()
						require.NoError(t, err)
						sqlDB.SetMaxOpenConns(2)
						start := make(chan struct{})
						type result struct {
							won     bool
							err     error
							derived bool
						}
						results := make(chan result, 2)
						var wg sync.WaitGroup
						for i := range 2 {
							wg.Go(func() {
								<-start
								if i == 1 && scenario == "concurrent_derived_reserve" {
									charge, err := ReserveOAuthDerivedText(ctx, ref, facts, 80)
									results <- result{charge != nil, err, true}
								} else {
									ok, err := TryReserveUserQuota(user.Id, 60)
									results <- result{ok, err, false}
								}
							})
						}
						close(start)
						wg.Wait()
						close(results)
						wins, balance, tokenRemain := 0, 100, 100
						for got := range results {
							if got.won {
								require.NoError(t, got.err)
								wins++
								balance -= 60
								if got.derived {
									balance -= 20
									tokenRemain -= 80
								}
							} else if got.err != nil {
								// SQLite may reject the competing writer; it must not
								// report success or leave any financial effect.
								if database == common.DatabaseTypeSQLite && !errors.Is(got.err, ErrOAuthTextCharge) {
									require.Contains(t, got.err.Error(), "database is locked")
								} else {
									require.True(t, got.derived)
									require.ErrorIs(t, got.err, ErrOAuthTextCharge)
								}
							}
						}
						assert.Equal(t, 1, wins)
						assert.Equal(t, balance, getUserQuotaFromDB(t, user.Id))
						assert.Equal(t, tokenRemain, getTokenFromDB(t, facts.TokenID).RemainQuota)
					case "zero":
						ok, err := TryReserveUserQuota(user.Id, 0)
						require.NoError(t, err)
						assert.True(t, ok)
						assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
						// Ordinary admission has no receipt to exclude, including
						// a malformed empty-ref row already present in the store.
						require.NoError(t, db.Create(&OAuthDerivedTextCharge{UserID: user.Id, State: "held"}).Error)
						ok, err = TryReserveUserQuota(user.Id, 0)
						assert.ErrorIs(t, err, ErrOAuthTextCharge)
						assert.False(t, ok)
					case "send_claimed", "held", "historical_finalize":
						charge, err := ReserveOAuthDerivedText(ctx, ref, facts, 80)
						require.NoError(t, err)
						permit, err := ClaimOAuthDerivedText(ctx, ref, facts, 80)
						require.NoError(t, err)
						require.NotNil(t, permit)
						if scenario == "held" {
							charge, err = FinalizeOAuthDerivedTextSnapshot(ctx, ref, 110, OAuthTextUsage{Prompt: 20, Completion: 90, Total: 110}, charge.Fingerprint)
							require.NoError(t, err)
							require.Equal(t, "held", charge.State)
						}
						for _, amount := range []int{0, 1} {
							ok, err := TryReserveUserQuota(user.Id, amount)
							assert.ErrorIs(t, err, ErrOAuthTextCharge)
							assert.False(t, ok)
							ok, err = TryReserveAdditionalUserQuota(user.Id, amount)
							assert.ErrorIs(t, err, ErrOAuthTextCharge)
							assert.False(t, ok)
						}
						assert.Equal(t, 20, getUserQuotaFromDB(t, user.Id))
						if scenario == "historical_finalize" {
							require.NoError(t, db.Model(&OAuthGrant{}).Where("grant_ref = ?", facts.GrantRef).Update("state", "revoked").Error)
							// Historical legacy delta/refund is allowed despite gate.
							require.NoError(t, DecreaseUserQuota(user.Id, 5, false))
							require.NoError(t, IncreaseUserQuota(user.Id, 5, false))
							for range 2 {
								charge, err = FinalizeOAuthDerivedTextSnapshot(ctx, ref, 60, OAuthTextUsage{Prompt: 20, Completion: 40, Total: 60}, charge.Fingerprint)
								require.NoError(t, err)
								assert.Equal(t, "settled", charge.State)
								assert.Equal(t, facts.UserID, charge.PayerID)
								assert.Equal(t, 40, getUserQuotaFromDB(t, user.Id))
							}
							assert.Equal(t, 40, getTokenFromDB(t, facts.TokenID).RemainQuota)
						}
					case "delta_sql_failure":
						failure := errors.New("controlled wallet SQL failure")
						require.NoError(t, db.Callback().Update().Before("gorm:update").Register("wallet_failure", func(tx *gorm.DB) { tx.AddError(failure) }))
						err1 := IncreaseUserQuota(user.Id, 10, false)
						err2 := DecreaseUserQuota(user.Id, 10, false)
						ok, err3 := TryReserveUserQuota(user.Id, 10)
						require.NoError(t, db.Callback().Update().Remove("wallet_failure"))
						assert.ErrorIs(t, err1, failure)
						assert.ErrorIs(t, err2, failure)
						assert.ErrorIs(t, err3, failure)
						assert.False(t, ok)
						assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
						cached, err := cacheGetUserBase(user.Id)
						require.NoError(t, err)
						assert.Equal(t, 100, cached.Quota)
					case "gate_read_failure", "missing_store":
						if scenario == "missing_store" {
							require.NoError(t, db.Migrator().DropTable(&OAuthDerivedTextCharge{}))
						} else {
							require.NoError(t, db.Callback().Query().Before("gorm:query").Register("gate_failure", func(tx *gorm.DB) {
								if tx.Statement.Table == "oauth_derived_text_charges" {
									tx.AddError(errors.New("controlled charge visibility failure"))
								}
							}))
						}
						for _, amount := range []int{0, 10} {
							ok, err := TryReserveUserQuota(user.Id, amount)
							assert.Error(t, err)
							assert.False(t, ok)
							ok, err = TryReserveAdditionalUserQuota(user.Id, amount)
							assert.Error(t, err)
							assert.False(t, ok)
						}
						assert.Equal(t, 100, getUserQuotaFromDB(t, user.Id))
					case "missing_user":
						require.NoError(t, db.Delete(&user).Error)
						ok, err := TryReserveUserQuota(user.Id, 0)
						assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
						assert.False(t, ok)
						assert.ErrorIs(t, DecreaseUserQuota(user.Id, 1, false), gorm.ErrRecordNotFound)
					case "bounded_delta":
						require.NoError(t, db.Model(&User{}).Where("id = ?", user.Id).Update("quota", common.MaxWalletQuota).Error)
						assert.ErrorIs(t, IncreaseUserQuota(user.Id, 1, false), ErrWalletQuotaLimitExceeded)
						assert.Equal(t, common.MaxWalletQuota, getUserQuotaFromDB(t, user.Id))
						require.NoError(t, db.Model(&User{}).Where("id = ?", user.Id).Update("quota", -common.MaxWalletQuota).Error)
						assert.ErrorIs(t, DecreaseUserQuota(user.Id, 1, false), ErrWalletQuotaLimitExceeded)
						assert.Equal(t, -common.MaxWalletQuota, getUserQuotaFromDB(t, user.Id))
					}
				})
			}
		})
	}
}
