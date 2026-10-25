package model

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type setMiniRedisTimeOnEvalHook struct {
	server *miniredis.Miniredis
	at     time.Time
}

func (hook setMiniRedisTimeOnEvalHook) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	if cmd.Name() == "eval" {
		hook.server.SetTime(hook.at)
	}
	return ctx, nil
}

func (setMiniRedisTimeOnEvalHook) AfterProcess(context.Context, redis.Cmder) error {
	return nil
}

func (setMiniRedisTimeOnEvalHook) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}

func (setMiniRedisTimeOnEvalHook) AfterProcessPipeline(context.Context, []redis.Cmder) error {
	return nil
}

func setupUserSessionTest(t *testing.T) {
	t.Helper()
	require.NoError(t, DB.AutoMigrate(&User{}, &UserSession{}, &SessionRevocationEvent{}))
	require.NoError(t, DB.Exec("DELETE FROM user_sessions").Error)
	oldRedisEnabled := common.RedisEnabled
	oldActiveLimit := common.UserSessionActiveLimit
	oldIssuanceLimit := common.UserSessionIssuanceLimit
	oldIssuanceWindow := common.UserSessionIssuanceWindowSeconds
	oldRevokedRetention := common.UserSessionRevokedRetentionDays
	common.RedisEnabled = false
	common.UserSessionActiveLimit = common.DefaultUserSessionActiveLimit
	common.UserSessionIssuanceLimit = common.DefaultUserSessionIssuanceLimit
	common.UserSessionIssuanceWindowSeconds = int64(common.DefaultUserSessionIssuanceWindowSeconds)
	common.UserSessionRevokedRetentionDays = common.DefaultUserSessionRevokedRetentionDays
	t.Cleanup(func() {
		common.RedisEnabled = oldRedisEnabled
		common.UserSessionActiveLimit = oldActiveLimit
		common.UserSessionIssuanceLimit = oldIssuanceLimit
		common.UserSessionIssuanceWindowSeconds = oldIssuanceWindow
		common.UserSessionRevokedRetentionDays = oldRevokedRetention
	})
}

func createUserSessionTestUser(t *testing.T, userID int, authVersion int64) {
	t.Helper()
	user := User{
		Id:          userID,
		Username:    fmt.Sprintf("user-session-%d", userID),
		Password:    "unused",
		Status:      common.UserStatusEnabled,
		Role:        common.RoleCommonUser,
		Group:       "default",
		AffCode:     fmt.Sprintf("session-aff-%d", userID),
		AuthVersion: authVersion,
	}
	require.NoError(t, DB.Create(&user).Error)
	t.Cleanup(func() { _ = DB.Unscoped().Delete(&User{}, userID).Error })
}

func newTestUserSession(sid string, userID int, now int64) *UserSession {
	return &UserSession{
		SID:             sid,
		UserID:          userID,
		Version:         1,
		UserAuthVersion: 1,
		Status:          UserSessionStatusActive,
		RefreshHash:     fmt.Sprintf("current-%s", sid),
		LoginMethod:     "password",
		IP:              "127.0.0.1",
		UserAgent:       "model-test",
		CreatedAt:       now,
		LastActiveAt:    now,
		ExpiresAt:       now + int64((30*24*time.Hour)/time.Second),
	}
}

func TestUserSessionCacheTTLUsesShortCacheWindow(t *testing.T) {
	setupUserSessionTest(t)
	server := useUserCacheMiniRedis(t)
	now := time.Now().Unix()
	tests := []struct {
		name       string
		status     string
		expiresAt  int64
		wantMaxTTL time.Duration
	}{
		{name: "active", status: UserSessionStatusActive, expiresAt: now + 300, wantMaxTTL: 2 * time.Second},
		{name: "revoking", status: UserSessionStatusRevoking, expiresAt: now + 300, wantMaxTTL: 2 * time.Second},
		{name: "revoked", status: UserSessionStatusRevoked, expiresAt: now + 300, wantMaxTTL: 2 * time.Second},
		{name: "already expired", status: UserSessionStatusRevoked, expiresAt: now - 1, wantMaxTTL: time.Second},
	}

	for index, test := range tests {
		sid := fmt.Sprintf("short-cache-ttl-%d", index)
		entry := newTestUserSession(sid, 1100+index, now).cacheEntry()
		entry.Status = test.status
		entry.ExpiresAt = test.expiresAt
		if test.status != UserSessionStatusActive {
			entry.RevokedAt = now
		}

		cacheDeadline := time.Time{}
		if test.status == UserSessionStatusActive {
			cacheDeadline = userSessionCacheDeadline()
		}
		require.NoError(t, writeUserSessionCache(entry, cacheDeadline), test.name)
		ttl := server.TTL(userSessionCacheKey(sid))
		assert.Positive(t, ttl, test.name)
		assert.LessOrEqual(t, ttl, test.wantMaxTTL, test.name)
	}

	initialTTL := server.TTL(userSessionCacheKey("short-cache-ttl-0"))
	server.FastForward(time.Second)
	_, err := getUserSessionCache("short-cache-ttl-0")
	require.NoError(t, err)
	remainingTTL := server.TTL(userSessionCacheKey("short-cache-ttl-0"))
	assert.Positive(t, remainingTTL)
	assert.LessOrEqual(t, remainingTTL, initialTTL-time.Second, "cache reads must not renew the bounded TTL")

	common.SyncFrequency = 10
	nearExpiry := newTestUserSession("short-cache-ttl-near-expiry", 1199, now).cacheEntry()
	nearExpiry.ExpiresAt = time.Now().Add(2 * time.Second).Unix()
	nearExpiryDeadline := userSessionCacheDeadline()
	remainingLifetime := time.Until(time.Unix(nearExpiry.ExpiresAt, 0))
	require.NoError(t, writeUserSessionCache(nearExpiry, nearExpiryDeadline))
	nearExpiryTTL := server.TTL(userSessionCacheKey(nearExpiry.SID))
	assert.Positive(t, nearExpiryTTL)
	assert.LessOrEqual(t, nearExpiryTTL, remainingLifetime, "cache TTL must not exceed the Session remaining lifetime")

	common.SyncFrequency = 0
	fallback := newTestUserSession("short-cache-ttl-fallback", 1200, now).cacheEntry()
	fallback.ExpiresAt = now + 300
	require.NoError(t, writeUserSessionCache(fallback, userSessionCacheDeadline()))
	fallbackTTL := server.TTL(userSessionCacheKey(fallback.SID))
	assert.Greater(t, fallbackTTL, 59*time.Second)
	assert.LessOrEqual(t, fallbackTTL, 60*time.Second, "non-positive cache frequency must use the existing 60-second fallback")
}

func TestStaleActiveSessionCacheFillCannotRestartWindowAfterDenyExpires(t *testing.T) {
	setupUserSessionTest(t)
	server := useUserCacheMiniRedis(t)
	now := time.Now().Unix()
	active := newTestUserSession("stale-active-cache-fill", 1201, now).cacheEntry()
	denied := *active
	denied.Status = UserSessionStatusRevoked
	denied.RevokedAt = now
	denied.RevokedReason = "test-revoke"

	require.NoError(t, writeUserSessionCache(&denied, time.Time{}))
	cacheKey := userSessionCacheKey(active.SID)
	assert.True(t, server.Exists(cacheKey))
	server.FastForward(3 * time.Second)
	assert.False(t, server.Exists(cacheKey), "the short deny tombstone must have expired in this race setup")

	err := writeUserSessionCache(active, time.Now().Add(-time.Millisecond))
	assert.ErrorIs(t, err, errUserSessionCacheObservationStale)
	assert.False(t, server.Exists(cacheKey), "a delayed pre-revoke active snapshot must not restart a fresh cache window")
}

func TestActiveSessionCacheFillUsesRemainingObservationWindow(t *testing.T) {
	setupUserSessionTest(t)
	server := useUserCacheMiniRedis(t)
	now := time.Now().Unix()
	entry := newTestUserSession("bounded-active-cache-fill", 1202, now).cacheEntry()
	deadline := time.Now().Add(1500 * time.Millisecond)

	require.NoError(t, writeUserSessionCache(entry, deadline))
	ttl := server.TTL(userSessionCacheKey(entry.SID))
	assert.Positive(t, ttl)
	assert.LessOrEqual(t, ttl, 1500*time.Millisecond, "a delayed fill must inherit only the unused observation window")
}

func TestSessionCacheLuaUsesAbsoluteActiveAndRelativeDenyExpiry(t *testing.T) {
	setupUserSessionTest(t)
	server := useUserCacheMiniRedis(t)
	now := time.Now().Unix()
	deadline := time.Now().Add(10 * time.Second)
	common.RDB.AddHook(setMiniRedisTimeOnEvalHook{server: server, at: deadline.Add(time.Second)})

	active := newTestUserSession("delayed-active-cache-eval", 1203, now).cacheEntry()
	require.NoError(t, writeUserSessionCache(active, deadline))
	assert.False(t, server.Exists(userSessionCacheKey(active.SID)), "an active fill executed after its absolute deadline must not recreate the cache")

	denied := newTestUserSession("delayed-deny-cache-eval", 1204, now).cacheEntry()
	denied.Status = UserSessionStatusRevoked
	denied.RevokedAt = now
	denied.RevokedReason = "test-revoke"
	require.NoError(t, writeUserSessionCache(denied, time.Time{}))
	denyTTL := server.TTL(userSessionCacheKey(denied.SID))
	assert.Positive(t, denyTTL)
	assert.LessOrEqual(t, denyTTL, 2*time.Second, "a delayed deny publication must receive a full relative short TTL at Redis execution")
}

func TestUserSessionCreateListAndRevokeOne(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	user := User{Id: 1001, Username: "session-list-user", Password: "password", AuthVersion: 1}
	require.NoError(t, DB.Create(&user).Error)
	t.Cleanup(func() { _ = DB.Unscoped().Delete(&User{}, user.Id).Error })
	first := newTestUserSession("session-one", 1001, now)
	second := newTestUserSession("session-two", 1001, now+1)
	require.NoError(t, CreateUserSession(first))
	require.NoError(t, CreateUserSession(second))

	sessions, err := ListActiveUserSessions(1001, first.SID, now)
	require.NoError(t, err)
	require.Len(t, sessions, 2)
	assert.Equal(t, first.SID, sessions[0].SID)

	revoked, err := RevokeUserSession(1001, first.SID, "user_revoked")
	require.NoError(t, err)
	assert.True(t, revoked)
	revoked, err = RevokeUserSession(1001, first.SID, "duplicate")
	require.NoError(t, err)
	assert.False(t, revoked)

	_, err = GetUserSessionCached(first.SID)
	assert.ErrorIs(t, err, ErrUserSessionInactive)
	active, err := GetUserSessionCached(second.SID)
	require.NoError(t, err)
	assert.Equal(t, second.SID, active.SID)
}

func TestRotateUserSessionRefreshRaceAndReuse(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	createUserSessionTestUser(t, 1002, 1)
	session := newTestUserSession("rotate-session", 1002, now)
	require.NoError(t, CreateUserSession(session))

	rotated, err := RotateUserSessionRefresh(1002, session.SID, session.RefreshHash, "next-hash", now+10, 30*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "next-hash", rotated.RefreshHash)
	assert.Equal(t, session.RefreshHash, rotated.PreviousRefreshHash)
	assert.Equal(t, now+40, rotated.PreviousValidUntil)

	_, err = RotateUserSessionRefresh(1002, session.SID, session.RefreshHash, "unused-hash", now+20, 30*time.Second)
	assert.ErrorIs(t, err, ErrUserSessionRefreshRace)
	_, err = RotateUserSessionRefresh(1002, session.SID, "unknown-hash", "unused-hash", now+20, 30*time.Second)
	assert.ErrorIs(t, err, ErrUserSessionRefreshInvalid)
	stored, getErr := GetUserSessionBySID(session.SID)
	require.NoError(t, getErr)
	assert.Equal(t, UserSessionStatusActive, stored.Status)

	_, err = RotateUserSessionRefresh(1002, session.SID, session.RefreshHash, "unused-hash", now+41, 30*time.Second)
	assert.ErrorIs(t, err, ErrUserSessionRefreshReuse)
	stored, getErr = GetUserSessionBySID(session.SID)
	require.NoError(t, getErr)
	assert.Equal(t, UserSessionStatusRevoked, stored.Status)
	assert.Equal(t, "refresh_reuse", stored.RevokedReason)
}

func TestUserSessionPreviousRefreshHashNormalizesLegacyPadding(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	createUserSessionTestUser(t, 1010, 1)
	digest := strings.Repeat("a", 64)

	blank := newTestUserSession("legacy-blank-previous-hash", 1010, now)
	blank.PreviousRefreshHash = strings.Repeat(" ", 64)
	blank.PreviousValidUntil = now + 60
	require.NoError(t, DB.Create(blank).Error)
	loadedBlank, err := GetUserSessionBySID(blank.SID)
	require.NoError(t, err)
	assert.Empty(t, loadedBlank.PreviousRefreshHash)

	valid := newTestUserSession("legacy-valid-previous-hash", 1010, now)
	valid.RefreshHash = strings.Repeat("b", 64)
	valid.PreviousRefreshHash = digest
	valid.PreviousValidUntil = now + 60
	require.NoError(t, DB.Create(valid).Error)
	loadedValid, err := GetUserSessionBySID(valid.SID)
	require.NoError(t, err)
	assert.Equal(t, digest, loadedValid.PreviousRefreshHash)

	require.NoError(t, DB.Model(&UserSession{}).Where("sid = ?", valid.SID).
		Updates(map[string]any{
			"previous_refresh_hash": digest + "   ",
			"previous_valid_until":  now + 60,
		}).Error)
	_, err = RotateUserSessionRefresh(valid.UserID, valid.SID, digest, strings.Repeat("c", 64), now+1, 30*time.Second)
	assert.ErrorIs(t, err, ErrUserSessionRefreshRace)

	revoked, err := RevokeUserSessionByRefreshHash(valid.SID, digest, "legacy-padded-refresh-logout")
	require.NoError(t, err)
	assert.True(t, revoked, "refresh-cookie logout must accept a legacy CHAR-padded previous digest inside its grace window")
}

func TestUserSessionCacheExcludesRefreshDigests(t *testing.T) {
	setupUserSessionTest(t)
	useUserCacheMiniRedis(t)
	now := time.Now().Unix()
	session := newTestUserSession("cache-without-refresh-digests", 1011, now)
	session.PreviousRefreshHash = strings.Repeat("a", 64)
	session.PreviousValidUntil = now + 30
	require.NoError(t, writeUserSessionCache(session.cacheEntry(), userSessionCacheDeadline()))

	cacheKey := userSessionCacheKey(session.SID)
	fields, err := common.RDB.HGetAll(context.Background(), cacheKey).Result()
	require.NoError(t, err)
	assert.NotContains(t, fields, "RefreshHash")
	assert.NotContains(t, fields, "PreviousRefreshHash")
	assert.NotContains(t, fields, "PreviousValidUntil")

	require.NoError(t, common.RDB.HSet(context.Background(), cacheKey,
		"RefreshHash", strings.Repeat("b", 64),
		"PreviousRefreshHash", strings.Repeat("c", 64)+"   ",
		"PreviousValidUntil", now+30,
	).Err())
	entry, err := getUserSessionCache(session.SID)
	require.NoError(t, err)
	cachedSession := entry.session()
	assert.Empty(t, cachedSession.RefreshHash)
	assert.Empty(t, cachedSession.PreviousRefreshHash)
	assert.Zero(t, cachedSession.PreviousValidUntil)
}

func TestRevokeOtherUserSessionsKeepsCurrent(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	createUserSessionTestUser(t, 1003, 1)
	createUserSessionTestUser(t, 1004, 1)
	for _, sid := range []string{"current-session", "other-one", "other-two"} {
		session := newTestUserSession(sid, 1003, now)
		if sid == "other-one" {
			// A historical active row can carry another auth version. New admission
			// correctly rejects it, so seed this legacy residual directly.
			session.UserAuthVersion = 99
			require.NoError(t, DB.Create(session).Error)
			continue
		}
		require.NoError(t, CreateUserSession(session))
	}
	require.NoError(t, CreateUserSession(newTestUserSession("different-user", 1004, now)))

	count, err := RevokeOtherUserSessions(1003, "current-session", "revoke_others")
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	current, err := GetUserSessionCached("current-session")
	require.NoError(t, err)
	assert.Equal(t, UserSessionStatusActive, current.Status)
	_, err = GetUserSessionCached("other-one")
	assert.True(t, errors.Is(err, ErrUserSessionInactive))
	stale, err := GetUserSessionBySID("other-one")
	require.NoError(t, err)
	assert.Equal(t, UserSessionStatusRevoked, stale.Status, "revocation must include active sessions from stale auth versions")
	different, err := GetUserSessionCached("different-user")
	require.NoError(t, err)
	assert.Equal(t, 1004, different.UserID)
}

func TestRevokeUserSessionByRefreshHashRequiresSecret(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	createUserSessionTestUser(t, 1005, 1)
	session := newTestUserSession("refresh-logout-session", 1005, now)
	require.NoError(t, CreateUserSession(session))

	revoked, err := RevokeUserSessionByRefreshHash(session.SID, "wrong-hash", "logout")
	require.NoError(t, err)
	assert.False(t, revoked)
	active, err := GetUserSessionCached(session.SID)
	require.NoError(t, err)
	assert.Equal(t, UserSessionStatusActive, active.Status)

	revoked, err = RevokeUserSessionByRefreshHash(session.SID, session.RefreshHash, "logout")
	require.NoError(t, err)
	assert.True(t, revoked)
	_, err = GetUserSessionCached(session.SID)
	assert.ErrorIs(t, err, ErrUserSessionInactive)
}

func TestUserSessionGrowthCountsUseBroadActiveAndStrictIssuancePredicates(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	createUserSessionTestUser(t, 1006, 7)
	rows := []UserSession{
		*newTestUserSession("count-current-version", 1006, now-10),
		*newTestUserSession("count-stale-version", 1006, now-9),
		*newTestUserSession("count-expired", 1006, now-8),
		*newTestUserSession("count-revoked", 1006, now-7),
		*newTestUserSession("count-cutoff", 1006, now-3600),
	}
	rows[0].UserAuthVersion = 7
	rows[1].UserAuthVersion = 2
	rows[2].UserAuthVersion = 7
	rows[2].ExpiresAt = now
	rows[3].UserAuthVersion = 7
	rows[3].Status = UserSessionStatusRevoked
	rows[3].RevokedAt = now - 1
	rows[4].UserAuthVersion = 7
	rows[4].CreatedAt = now - 3600
	rows[4].ExpiresAt = now
	require.NoError(t, DB.Create(&rows).Error)

	activeCount, err := CountActiveUserSessions(1006, now)
	require.NoError(t, err)
	assert.Equal(t, int64(2), activeCount, "active count includes stale auth versions but excludes expired and revoked rows")

	issuedCount, err := CountUserSessionsCreatedSince(1006, now-3600)
	require.NoError(t, err)
	assert.Equal(t, int64(4), issuedCount, "issuance count includes every status and uses a strict cutoff")
	globalCount, err := CountUserSessionsCreatedSince(0, now-3600)
	require.NoError(t, err)
	assert.Equal(t, issuedCount, globalCount)
}

func TestListActiveUserSessionsKeepsCurrentAndBoundsOtherSessions(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	createUserSessionTestUser(t, 1007, 7)
	current := newTestUserSession("list-current", 1007, now-1000)
	current.UserAuthVersion = 7
	rows := make([]UserSession, 0, 107)
	rows = append(rows, *current)
	for i := range 105 {
		session := newTestUserSession(fmt.Sprintf("list-other-%03d", i), 1007, now-int64(i))
		session.UserAuthVersion = 7
		rows = append(rows, *session)
	}
	stale := newTestUserSession("list-stale-auth-version", 1007, now+1)
	stale.UserAuthVersion = 6
	rows = append(rows, *stale)
	require.NoError(t, DB.CreateInBatches(rows, 100).Error)

	sessions, err := ListActiveUserSessions(1007, current.SID, now)
	require.NoError(t, err)
	require.Len(t, sessions, 100)
	assert.Equal(t, current.SID, sessions[0].SID)
	for _, session := range sessions {
		assert.Equal(t, int64(7), session.UserAuthVersion)
		assert.NotEqual(t, stale.SID, session.SID)
	}

	sessionsWithoutCurrent, err := ListActiveUserSessions(1007, "missing-current", now)
	require.NoError(t, err)
	assert.Len(t, sessionsWithoutCurrent, userSessionListLimit, "a missing current SID must not reduce the total list limit")
}

func TestRevokeUserSessionsReturnsCumulativeProgressAndSupportsRetry(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	createUserSessionTestUser(t, 1008, 1)
	rows := make([]UserSession, 501)
	for i := range rows {
		rows[i] = *newTestUserSession(fmt.Sprintf("batch-revoke-%03d", i), 1008, now)
	}
	require.NoError(t, DB.CreateInBatches(rows, 100).Error)
	var event *SessionRevocationEvent
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		var err error
		event, err = StartSessionRevocationWithTx(tx, 1008, "", "session_revoked")
		return err
	}))
	first, err := RunSessionRevocationBatch(t.Context(), *event)
	require.NoError(t, err)
	require.Equal(t, "pending", first.State)
	require.Equal(t, int64(500), first.AffectedCount)
	forcedErr := errors.New("forced next event batch failure")
	callbackName := "test:fail_next_session_event_batch"
	require.NoError(t, DB.Callback().Update().Before("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "user_sessions" {
			tx.AddError(forcedErr)
		}
	}))
	t.Cleanup(func() { _ = DB.Callback().Update().Remove(callbackName) })
	_, err = RunSessionRevocationBatch(t.Context(), *first)
	require.ErrorIs(t, err, forcedErr)
	var unchanged SessionRevocationEvent
	require.NoError(t, DB.Where("event_ref = ?", first.EventRef).First(&unchanged).Error)
	assert.Equal(t, first.Revision, unchanged.Revision)
	assert.Equal(t, int64(500), unchanged.AffectedCount)
	require.NoError(t, DB.Callback().Update().Remove(callbackName))
	completed, err := RunSessionRevocationBatch(t.Context(), unchanged)
	require.NoError(t, err)
	assert.Equal(t, "local_complete", completed.State)
	assert.Equal(t, int64(501), completed.AffectedCount)
	var active int64
	require.NoError(t, DB.Model(&UserSession{}).Where("user_id = ? AND status = ?", 1008, UserSessionStatusActive).Count(&active).Error)
	assert.Zero(t, active)
}

func TestDeleteExpiredUserSessionsLoopsInChunksAndRechecksPredicate(t *testing.T) {
	setupUserSessionTest(t)
	now := time.Now().Unix()
	common.UserSessionRevokedRetentionDays = 7
	common.UserSessionIssuanceWindowSeconds = 3600
	oldCreatedAt := now - 7200
	rows := make([]UserSession, 0, userSessionCleanupScanLimit+5)
	race := newTestUserSession("cleanup-race", 1009, now-1000)
	race.CreatedAt = oldCreatedAt
	race.ExpiresAt = now - 1000
	rows = append(rows, *race)
	for i := range userSessionCleanupScanLimit + 1 {
		session := newTestUserSession(fmt.Sprintf("cleanup-expired-%04d", i), 1009, now-100)
		session.CreatedAt = oldCreatedAt - int64(i)
		session.ExpiresAt = now - 100
		rows = append(rows, *session)
	}
	oldRevoked := newTestUserSession("cleanup-old-revoked", 1009, now-10)
	oldRevoked.CreatedAt = oldCreatedAt
	oldRevoked.Status = UserSessionStatusRevoked
	oldRevoked.RevokedAt = now - int64(8*24*time.Hour/time.Second)
	rows = append(rows, *oldRevoked)
	recentRevoked := newTestUserSession("cleanup-recent-revoked", 1009, now-9)
	recentRevoked.CreatedAt = oldCreatedAt
	recentRevoked.Status = UserSessionStatusRevoked
	recentRevoked.RevokedAt = now - int64(6*24*time.Hour/time.Second)
	recentRevoked.ExpiresAt = now - 100
	rows = append(rows, *recentRevoked)
	recentIssuedExpired := newTestUserSession("cleanup-recent-issued-expired", 1009, now-1800)
	recentIssuedExpired.ExpiresAt = now - 100
	rows = append(rows, *recentIssuedExpired)
	expiryBoundary := newTestUserSession("cleanup-expiry-boundary", 1009, now-7)
	expiryBoundary.CreatedAt = oldCreatedAt
	expiryBoundary.ExpiresAt = now
	rows = append(rows, *expiryBoundary)
	revokedBoundary := newTestUserSession("cleanup-revoked-boundary", 1009, now-6)
	revokedBoundary.CreatedAt = oldCreatedAt
	revokedBoundary.Status = UserSessionStatusRevoked
	revokedBoundary.RevokedAt = now - int64(7*24*time.Hour/time.Second)
	rows = append(rows, *revokedBoundary)
	live := newTestUserSession("cleanup-live", 1009, now-8)
	rows = append(rows, *live)
	require.NoError(t, DB.CreateInBatches(rows, 100).Error)

	callbackName := "test:recheck_user_session_cleanup_predicate"
	deleteCalls := 0
	mutated := false
	require.NoError(t, DB.Callback().Delete().Before("gorm:delete").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Table != "user_sessions" {
			return
		}
		deleteCalls++
		if !mutated {
			mutated = true
			tx.Exec("UPDATE user_sessions SET expires_at = ? WHERE sid = ?", now+3600, race.SID)
		}
	}))
	t.Cleanup(func() { _ = DB.Callback().Delete().Remove(callbackName) })

	require.NoError(t, DeleteExpiredUserSessions(now))
	require.NoError(t, DeleteOldRevokedUserSessions(now))
	assert.Equal(t, 4, deleteCalls, "expired and retained-revoked scans each delete in bounded chunks")
	var remaining []UserSession
	require.NoError(t, DB.Order("sid").Find(&remaining).Error)
	require.Len(t, remaining, 6)
	remainingSIDs := make([]string, 0, len(remaining))
	for _, session := range remaining {
		remainingSIDs = append(remainingSIDs, session.SID)
	}
	assert.ElementsMatch(t, []string{
		race.SID,
		recentRevoked.SID,
		recentIssuedExpired.SID,
		expiryBoundary.SID,
		revokedBoundary.SID,
		live.SID,
	}, remainingSIDs)
}

func TestUserSessionGrowthQueryIndexesExist(t *testing.T) {
	setupUserSessionTest(t)
	migrator := DB.Migrator()
	assert.True(t, migrator.HasIndex(&UserSession{}, "idx_user_sessions_expires_at"))
	assert.True(t, migrator.HasIndex(&UserSession{}, "idx_user_sessions_user_created"))
	assert.True(t, migrator.HasIndex(&UserSession{}, "idx_user_sessions_status_revoked"))
}

func TestUserBaseIncludesAuthorizationFields(t *testing.T) {
	user := User{
		Id:          42,
		Username:    "cache-user",
		Role:        common.RoleAdminUser,
		Status:      common.UserStatusEnabled,
		Group:       "vip",
		Quota:       123,
		AuthVersion: 7,
	}
	base := user.ToBaseUser()
	assert.Equal(t, user.Role, base.Role)
	assert.Equal(t, user.AuthVersion, base.AuthVersion)
	assert.Equal(t, userCacheSchemaVersion, base.CacheSchema)
	assert.Equal(t, user.Quota, base.Quota)
}

func TestUserUpdateBumpsAuthVersionOnlyForAuthorizationChanges(t *testing.T) {
	setupUserSessionTest(t)
	user := &User{
		Username: "auth-version-user",
		Password: "hashed-placeholder",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
		Group:    "default",
	}
	require.NoError(t, DB.Create(user).Error)
	t.Cleanup(func() { _ = DB.Unscoped().Delete(&User{}, user.Id).Error })
	assert.Equal(t, int64(1), user.AuthVersion)

	user.DisplayName = "profile-only"
	require.NoError(t, user.Update(false))
	assert.Equal(t, int64(1), user.AuthVersion)

	user.Group = "vip"
	require.NoError(t, user.Update(false))
	assert.Equal(t, int64(2), user.AuthVersion)

	user.Role = common.RoleAdminUser
	require.NoError(t, user.Update(false))
	assert.Equal(t, int64(3), user.AuthVersion)
}

func TestPasswordResetBumpsAuthVersionAndRevokesSessions(t *testing.T) {
	for _, source := range []string{"trusted", "recovery_flow"} {
		t.Run(source, func(t *testing.T) {
			setupUserSessionTest(t)
			user := &User{
				Username: "password-reset-user", Password: "old-hash", Email: "password-reset@example.com",
				Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default",
			}
			require.NoError(t, DB.Create(user).Error)
			t.Cleanup(func() { _ = DB.Unscoped().Delete(&User{}, user.Id).Error })
			session := newTestUserSession("password-reset-session", user.Id, time.Now().Unix())
			require.NoError(t, CreateUserSession(session))

			if source == "recovery_flow" {
				token, err := CreatePasswordResetFlow(user.Id, user.Email)
				require.NoError(t, err)
				require.NoError(t, ResetUserPasswordWithFlow(t.Context(), user.Email, token, "new-password"))
			} else {
				require.NoError(t, ResetUserPasswordByEmail(user.Email, "new-password"))
			}
			var stored User
			require.NoError(t, DB.First(&stored, user.Id).Error)
			assert.Equal(t, int64(2), stored.AuthVersion)
			assert.True(t, common.ValidatePasswordAndHash("new-password", stored.Password))
			storedSession, err := GetUserSessionBySID(session.SID)
			require.NoError(t, err)
			assert.Equal(t, UserSessionStatusRevoked, storedSession.Status)
			assert.Equal(t, "password_reset", storedSession.RevokedReason)
		})
	}
}

func TestSecurityRevocationReasonsPreserveInvalidation(t *testing.T) {
	for _, reason := range []string{"password_reset", "admin_demote"} {
		for _, retainedSID := range []string{"", "current"} {
			t.Run(reason+"/retained="+retainedSID, func(t *testing.T) {
				db, _ := oauthBirthFixture(t)
				sqlDB, err := db.DB()
				require.NoError(t, err)
				sqlDB.SetMaxOpenConns(1)
				oldDB, oldLogDB, oldCleanupDB := DB, LOG_DB, oauthCleanupDB.Load()
				DB, LOG_DB = db, db
				t.Cleanup(func() {
					DB, LOG_DB = oldDB, oldLogDB
					oauthCleanupDB.Store(oldCleanupDB)
				})
				setupUserSessionTest(t)
				require.NoError(t, db.AutoMigrate(&OAuthGrant{}, &OAuthOperation{}, &OAuthArtifact{}, &OAuthCleanupJob{}))
				require.NoError(t, InitOAuthCleanupStore(true))
				server := useUserCacheMiniRedis(t)
				createUserSessionTestUser(t, 5101, 1)
				createUserSessionTestUser(t, 5102, 1)
				var user User
				require.NoError(t, db.First(&user, 5101).Error)
				require.NoError(t, populateUserCache(user))
				stale := *user.ToBaseUser()
				now := time.Now().Unix()
				for _, sid := range []string{"current", "other", "foreign"} {
					userID := 5101
					if sid == "foreign" {
						userID = 5102
					}
					require.NoError(t, CreateUserSession(newTestUserSession(sid, userID, now)))
					grant := OAuthGrant{
						GrantRef: OAuthGrantRef("https://issuer.example", sid), ConsentRef: OAuthGrantRef("https://issuer.example", "consent-"+sid),
						GrantID: sid, Issuer: "https://issuer.example", ClientID: "test-client", Subject: fmt.Sprint(userID), UserID: userID,
						OriginSID: sid, SessionVersion: 1, UserAuthVersion: 1, Scopes: "openid", PolicyHash: strings.Repeat("a", 64),
						ConsentRequestID: "consent-" + sid, HydraLoginSessionID: "login-" + sid, State: "active", Revision: 1,
						CreatedAt: now, ApprovedAt: now, ExpiresAt: now + 3600,
					}
					require.NoError(t, db.Create(&grant).Error)
					require.NoError(t, db.Create(&OAuthOperation{
						OperationRef: OAuthGrantRef("https://issuer.example", "op-"+sid), Issuer: grant.Issuer, UserID: userID,
						ClientID: grant.ClientID, OriginSID: sid, GrantRef: grant.GrantRef, AuthVersion: 1, SessionVersion: 1,
						GrantRevision: 1, Kind: "token", State: "reserved", CreatedAt: now,
					}).Error)
				}
				var event *SessionRevocationEvent
				require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
					if _, err := incrementUserAuthVersionWithTx(tx, user.Id); err != nil {
						return err
					}
					var err error
					event, err = StartSessionRevocationWithTx(tx, user.Id, retainedSID, reason)
					return err
				}))
				// OAuth sources include the retained browser's grant, even when
				// only the other local browser sessions are in this event's range.
				var grants []OAuthGrant
				require.NoError(t, db.Find(&grants).Error)
				require.Len(t, grants, 3)
				for _, grant := range grants {
					if grant.UserID == user.Id {
						assert.Equal(t, "revoked", grant.State)
						assert.Equal(t, "session_revoked", grant.RevokedReason)
						assert.Positive(t, grant.RevokedAt)
					} else {
						assert.Equal(t, "active", grant.State)
						assert.Zero(t, grant.RevokedAt)
					}
				}
				var operations []OAuthOperation
				require.NoError(t, db.Find(&operations).Error)
				require.Len(t, operations, 3)
				for _, operation := range operations {
					want := "cancelled"
					if operation.UserID != user.Id {
						want = "reserved"
					}
					assert.Equal(t, want, operation.State)
				}
				var job OAuthCleanupJob
				require.NoError(t, db.Where("source_session_event_ref = ?", event.EventRef).First(&job).Error)
				assert.Equal(t, "user", job.Scope)
				assert.Empty(t, job.Value)
				assert.Equal(t, "session_revoked", job.Reason)
				// Model recovery after the producer's temporary fence expires.
				// The worker must still prevent an arbitrarily delayed old cache fill.
				server.FastForward(time.Duration(userAuthFenceTTLSeconds()+1) * time.Second)
				require.NoError(t, CompleteSessionSecurityChange(event, true))
				assert.Equal(t, "local_complete", event.State)
				assert.Equal(t, reason, event.Reason)
				assert.ErrorIs(t, writeUserCache(&stale, true), ErrUserAuthCachePending)
				cached, err := GetUserCache(user.Id)
				require.NoError(t, err)
				assert.EqualValues(t, 2, cached.AuthVersion)
				var sessions []UserSession
				require.NoError(t, db.Order("sid").Find(&sessions).Error)
				require.Len(t, sessions, 3)
				var affected int64
				for _, session := range sessions {
					if session.UserID == user.Id && session.SID != retainedSID {
						affected++
						assert.Equal(t, UserSessionStatusRevoked, session.Status)
						assert.Equal(t, reason, session.RevokedReason)
						assert.Positive(t, session.RevokedAt)
					} else {
						assert.Equal(t, UserSessionStatusActive, session.Status)
						assert.Empty(t, session.RevokedReason)
						assert.Zero(t, session.RevokedAt)
					}
				}
				assert.Equal(t, affected, event.AffectedCount)
			})
		}
	}
}
