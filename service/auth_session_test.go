package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupAuthSessionTestDB(t *testing.T, cancellationSafe ...bool) *model.User {
	t.Helper()
	previousDB, previousRedis := model.DB, common.RedisEnabled
	previousActiveLimit := common.UserSessionActiveLimit
	previousIssuanceLimit := common.UserSessionIssuanceLimit
	previousIssuanceWindow := common.UserSessionIssuanceWindowSeconds
	previousRevokedRetention := common.UserSessionRevokedRetentionDays
	previousAlertThreshold := common.UserSessionHourlyAlertThreshold
	dsn := ":memory:"
	if len(cancellationSafe) > 0 && cancellationSafe[0] {
		dsn = filepath.Join(t.TempDir(), "auth-session.db")
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.AuthFlow{}, &model.UserAccessToken{}))
	model.DB = db
	common.RedisEnabled = false
	common.UserSessionActiveLimit = common.DefaultUserSessionActiveLimit
	common.UserSessionIssuanceLimit = common.DefaultUserSessionIssuanceLimit
	common.UserSessionIssuanceWindowSeconds = int64(common.DefaultUserSessionIssuanceWindowSeconds)
	common.UserSessionRevokedRetentionDays = common.DefaultUserSessionRevokedRetentionDays
	common.UserSessionHourlyAlertThreshold = common.DefaultUserSessionHourlyAlertThreshold
	t.Cleanup(func() {
		model.DB = previousDB
		common.RedisEnabled = previousRedis
		common.UserSessionActiveLimit = previousActiveLimit
		common.UserSessionIssuanceLimit = previousIssuanceLimit
		common.UserSessionIssuanceWindowSeconds = previousIssuanceWindow
		common.UserSessionRevokedRetentionDays = previousRevokedRetention
		common.UserSessionHourlyAlertThreshold = previousAlertThreshold
		_ = sqlDB.Close()
	})
	user := &model.User{
		Username:    "session-user",
		Password:    "unused-password-hash",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AuthVersion: 1,
	}
	require.NoError(t, db.Create(user).Error)
	return user
}

func useIndependentAuthSessionRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	previousRedisEnabled := common.RedisEnabled
	previousRDB := common.RDB
	previousSyncFrequency := common.SyncFrequency
	serverA := miniredis.RunT(t)
	serverB := miniredis.RunT(t)
	clientA := redis.NewClient(&redis.Options{Addr: serverA.Addr()})
	clientB := redis.NewClient(&redis.Options{Addr: serverB.Addr()})
	common.RedisEnabled = true
	common.SyncFrequency = 2
	common.RDB = clientA
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
		common.RedisEnabled = previousRedisEnabled
		common.RDB = previousRDB
		common.SyncFrequency = previousSyncFrequency
	})
	return serverA, clientA, serverB, clientB
}

func cachedLoginSessionKey(t *testing.T, server *miniredis.Miniredis) string {
	t.Helper()
	for _, key := range server.Keys() {
		if strings.HasPrefix(key, "auth:session:") {
			return key
		}
	}
	require.FailNow(t, "login session was not cached")
	return ""
}

func TestCreateLoginSessionEnforcesActiveLimitAcrossAuthVersions(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)
	common.UserSessionActiveLimit = 50
	common.UserSessionIssuanceLimit = 100
	now := time.Now().Unix()
	rows := make([]model.UserSession, 0, 49)
	for i := range 49 {
		authVersion := user.AuthVersion
		if i == 0 {
			authVersion++
		}
		rows = append(rows, model.UserSession{
			SID:             fmt.Sprintf("active-limit-%02d", i),
			UserID:          user.Id,
			Version:         1,
			UserAuthVersion: authVersion,
			Status:          model.UserSessionStatusActive,
			RefreshHash:     fmt.Sprintf("hash-%02d", i),
			LoginMethod:     "password",
			CreatedAt:       now - int64(i),
			LastActiveAt:    now - int64(i),
			ExpiresAt:       now + 3600,
		})
	}
	require.NoError(t, model.DB.Create(&rows).Error)

	_, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	require.NoError(t, err, "49 active sessions must allow creation of the 50th")

	_, err = CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, model.ErrUserSessionLimit)
	var count int64
	require.NoError(t, model.DB.Model(&model.UserSession{}).Count(&count).Error)
	assert.Equal(t, int64(50), count)
}

func TestCreateLoginSessionEnforcesIssuanceLimitAcrossAllStatuses(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)
	common.UserSessionActiveLimit = 10
	common.UserSessionIssuanceLimit = 3
	common.UserSessionIssuanceWindowSeconds = 60
	now := time.Now().Unix()
	rows := []model.UserSession{
		{
			SID: "issuance-limit-revoked", UserID: user.Id, Version: 1, UserAuthVersion: user.AuthVersion + 1,
			Status: model.UserSessionStatusRevoked, RefreshHash: "hash-revoked", LoginMethod: "password",
			CreatedAt: now - 2, LastActiveAt: now - 2, ExpiresAt: now + 3600, RevokedAt: now - 1,
		},
		{
			SID: "issuance-limit-expired", UserID: user.Id, Version: 1, UserAuthVersion: user.AuthVersion,
			Status: model.UserSessionStatusActive, RefreshHash: "hash-expired", LoginMethod: "password",
			CreatedAt: now - 1, LastActiveAt: now - 1, ExpiresAt: now - 1,
		},
		{
			SID: "issuance-outside-effective-window", UserID: user.Id, Version: 1, UserAuthVersion: user.AuthVersion,
			Status: model.UserSessionStatusRevoked, RefreshHash: "hash-outside", LoginMethod: "password",
			CreatedAt: now - 61, LastActiveAt: now - 61, ExpiresAt: now + 3600, RevokedAt: now - 60,
		},
	}
	require.NoError(t, model.DB.Create(&rows).Error)

	_, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	require.NoError(t, err, "rows outside the effective issuance window must not consume the limit")

	_, err = CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, model.ErrUserSessionIssuanceLimit)
	var count int64
	require.NoError(t, model.DB.Model(&model.UserSession{}).Count(&count).Error)
	assert.Equal(t, int64(4), count)
}

func TestPasswordResetDoesNotClearSessionIssuanceHistory(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)
	common.UserSessionActiveLimit = 50
	common.UserSessionIssuanceLimit = 1
	email := "session-reset@example.com"
	require.NoError(t, model.DB.Model(user).Update("email", email).Error)

	_, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NoError(t, model.ResetUserPasswordByEmail(email, "new-password"))

	_, err = CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, model.ErrUserSessionIssuanceLimit)
}

func TestCreateLoginSessionFailsClosedWhenLimitCountFails(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)
	forcedErr := errors.New("forced session count failure")
	callbackName := "test:fail_user_session_limit_count"
	callbackRegistered := true
	require.NoError(t, model.DB.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "user_sessions" {
			tx.AddError(forcedErr)
		}
	}))
	t.Cleanup(func() {
		if callbackRegistered {
			_ = model.DB.Callback().Query().Remove(callbackName)
		}
	})

	_, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, forcedErr)
	require.NoError(t, model.DB.Callback().Query().Remove(callbackName))
	callbackRegistered = false
	var count int64
	require.NoError(t, model.DB.Model(&model.UserSession{}).Count(&count).Error)
	assert.Zero(t, count)
}

func TestCleanupAuthArtifactsAlertsBeforeDeletingHourlyIssuance(t *testing.T) {
	setupAuthSessionTestDB(t)
	common.UserSessionHourlyAlertThreshold = 2
	common.UserSessionIssuanceWindowSeconds = 1
	now := time.Now()
	boundaryRows := make([]model.UserSession, 0, 2)
	for i := range 2 {
		boundaryRows = append(boundaryRows, model.UserSession{
			SID: "hourly-boundary-" + string(rune('a'+i)), UserID: 1, Version: 1, UserAuthVersion: 1,
			Status: model.UserSessionStatusActive, RefreshHash: "hash", LoginMethod: "password",
			CreatedAt: now.Add(-2 * time.Second).Unix(), LastActiveAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(-time.Minute).Unix(),
		})
	}
	require.NoError(t, model.DB.Create(&boundaryRows).Error)

	var logBuffer bytes.Buffer
	common.LogWriterMu.Lock()
	previousErrorWriter := gin.DefaultErrorWriter
	gin.DefaultErrorWriter = &logBuffer
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultErrorWriter = previousErrorWriter
		common.LogWriterMu.Unlock()
	})

	cleanupAuthArtifacts()
	assert.Empty(t, logBuffer.String(), "the hourly alert uses a strict greater-than threshold")
	var count int64
	require.NoError(t, model.DB.Model(&model.UserSession{}).Count(&count).Error)
	assert.Zero(t, count)

	exceededRows := make([]model.UserSession, 0, 3)
	for i := range 3 {
		exceededRows = append(exceededRows, model.UserSession{
			SID: "hourly-exceeded-" + string(rune('a'+i)), UserID: 1, Version: 1, UserAuthVersion: 1,
			Status: model.UserSessionStatusActive, RefreshHash: "hash", LoginMethod: "password",
			CreatedAt: now.Add(-2 * time.Second).Unix(), LastActiveAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(-time.Minute).Unix(),
		})
	}
	require.NoError(t, model.DB.Create(&exceededRows).Error)
	logBuffer.Reset()
	cleanupAuthArtifacts()
	assert.Contains(t, logBuffer.String(), "hourly user session issuance exceeded alert threshold")
	require.NoError(t, model.DB.Model(&model.UserSession{}).Count(&count).Error)
	assert.Zero(t, count, "alerting must happen before expired rows are deleted")
}

func TestCleanupAuthArtifactsRemovesOnlyExpiredRecords(t *testing.T) {
	setupAuthSessionTestDB(t)
	now := time.Now()
	oldExpiry := now.Add(-25 * time.Hour)
	require.NoError(t, model.DB.Create(&model.UserSession{
		SID: "expired-session", UserID: 1, Version: 1, UserAuthVersion: 1,
		Status: model.UserSessionStatusActive, RefreshHash: "hash", LoginMethod: "password",
		CreatedAt: oldExpiry.Unix(), LastActiveAt: oldExpiry.Unix(), ExpiresAt: oldExpiry.Unix(),
	}).Error)
	require.NoError(t, model.DB.Create(&model.AuthFlow{
		TokenHash: "expired-flow", Purpose: model.AuthFlowPurposeTwoFALogin,
		ExpiresAt: oldExpiry,
	}).Error)
	require.NoError(t, model.DB.Create(&model.AuthFlow{
		TokenHash: "recent-flow", Purpose: model.AuthFlowPurposeTwoFALogin,
		ExpiresAt: now.Add(time.Minute),
	}).Error)

	retention := time.Duration(common.UserSessionRevokedRetentionDays) * 24 * time.Hour
	for _, token := range []model.UserAccessToken{
		{Name: "past retention", TokenHash: "past-retention", ExpiresAt: now.Add(-retention - time.Hour).Unix()},
		{Name: "within retention", TokenHash: "within-retention", ExpiresAt: now.Add(-retention + time.Hour).Unix()},
		{Name: "never expires", TokenHash: "never-expires"},
	} {
		token.UserId = 1
		require.NoError(t, model.DB.Create(&token).Error)
	}

	cleanupAuthArtifacts()

	var sessionCount int64
	require.NoError(t, model.DB.Model(&model.UserSession{}).Count(&sessionCount).Error)
	assert.Zero(t, sessionCount)
	var flows []model.AuthFlow
	require.NoError(t, model.DB.Find(&flows).Error)
	require.Len(t, flows, 1)
	assert.Equal(t, "recent-flow", flows[0].TokenHash)
	var kept []string
	require.NoError(t, model.DB.Model(&model.UserAccessToken{}).Order("id").Pluck("token_hash", &kept).Error)
	assert.Equal(t, []string{"within-retention", "never-expires"}, kept)
}

func TestCleanupAuthArtifactsContinuesWithRevokedCleanupAfterExpiredBatchFailure(t *testing.T) {
	setupAuthSessionTestDB(t)
	now := time.Now()
	oldCreatedAt := now.Add(-8 * 24 * time.Hour).Unix()
	require.NoError(t, model.DB.Create(&[]model.UserSession{
		{
			SID: "failed-expired-cleanup", UserID: 1, Version: 1, UserAuthVersion: 1,
			Status: model.UserSessionStatusActive, RefreshHash: "hash-expired", LoginMethod: "password",
			CreatedAt: oldCreatedAt, LastActiveAt: oldCreatedAt, ExpiresAt: now.Add(-time.Minute).Unix(),
		},
		{
			SID: "independent-revoked-cleanup", UserID: 1, Version: 1, UserAuthVersion: 1,
			Status: model.UserSessionStatusRevoked, RefreshHash: "hash-revoked", LoginMethod: "password",
			CreatedAt: oldCreatedAt, LastActiveAt: oldCreatedAt, ExpiresAt: now.Add(time.Hour).Unix(),
			RevokedAt: now.Add(-8 * 24 * time.Hour).Unix(),
		},
	}).Error)

	forcedErr := errors.New("forced expired cleanup failure")
	callbackName := "test:fail_first_user_session_cleanup_batch"
	failedFirstDelete := false
	require.NoError(t, model.DB.Callback().Delete().Before("gorm:delete").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "user_sessions" && !failedFirstDelete {
			failedFirstDelete = true
			tx.AddError(forcedErr)
		}
	}))
	t.Cleanup(func() { _ = model.DB.Callback().Delete().Remove(callbackName) })

	cleanupAuthArtifacts()

	var expired model.UserSession
	require.NoError(t, model.DB.First(&expired, "sid = ?", "failed-expired-cleanup").Error)
	var revoked model.UserSession
	assert.ErrorIs(t, model.DB.First(&revoked, "sid = ?", "independent-revoked-cleanup").Error, gorm.ErrRecordNotFound)
}

func TestLoginSessionCreateRefreshAndRevoke(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)

	bundle, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	require.NoError(t, err)
	assert.NotEmpty(t, bundle.RefreshToken)
	identity, err := ParseAccessToken(bundle.AccessToken)
	require.NoError(t, err)
	_, cachedUser, err := ValidateLoginSession(identity)
	require.NoError(t, err)
	assert.Equal(t, user.Id, cachedUser.Id)
	require.NoError(t, RevokeByRefreshToken(bundle.Session.SID+".wrong-refresh-secret", "", "logout"))
	_, _, err = ValidateLoginSession(identity)
	require.NoError(t, err, "a caller that only knows sid must not be able to revoke the session")

	refreshed, _, err := RefreshLoginSession(bundle.RefreshToken, bundle.Session.SID, "127.0.0.2", "test-agent-2")
	require.NoError(t, err)
	assert.NotEqual(t, bundle.RefreshToken, refreshed.RefreshToken)
	recovered, _, err := RefreshLoginSession(bundle.RefreshToken, bundle.Session.SID, "127.0.0.2", "test-agent-2")
	require.NoError(t, err)
	assert.Equal(t, refreshed.RefreshToken, recovered.RefreshToken, "a concurrent refresh must recover the winner's rotated token")

	_, _, err = RefreshLoginSession(refreshed.RefreshToken, "different-session", "127.0.0.2", "test-agent-2")
	assert.ErrorIs(t, err, ErrLoginSessionMismatch)

	require.NoError(t, RevokeByRefreshToken(refreshed.RefreshToken, refreshed.Session.SID, "logout"))
	_, _, err = ValidateLoginSession(identity)
	assert.True(t, errors.Is(err, ErrLoginSessionRevoked))
}

func TestIndependentRedisSessionRevokeConvergesAfterCacheTTL(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)
	_, clientA, serverB, clientB := useIndependentAuthSessionRedis(t)

	common.RDB = clientA
	bundle, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "node-a")
	require.NoError(t, err)
	identity, err := ParseAccessToken(bundle.AccessToken)
	require.NoError(t, err)

	common.RDB = clientB
	_, _, err = ValidateLoginSession(identity)
	require.NoError(t, err)
	assert.NotEmpty(t, cachedLoginSessionKey(t, serverB), "node B must hold its own session cache entry")

	common.RDB = clientA
	require.NoError(t, RevokeByRefreshToken(bundle.RefreshToken, bundle.Session.SID, "logout"))

	serverB.FastForward(3 * time.Second)
	common.RDB = clientB
	_, _, err = ValidateLoginSession(identity)
	assert.ErrorIs(t, err, ErrLoginSessionRevoked)
}

func TestIndependentRedisAuthVersionAdvanceConvergesAfterCacheTTL(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)
	_, clientA, serverB, clientB := useIndependentAuthSessionRedis(t)

	common.RDB = clientA
	bundle, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "node-a")
	require.NoError(t, err)
	oldIdentity, err := ParseAccessToken(bundle.AccessToken)
	require.NoError(t, err)

	common.RDB = clientB
	_, _, err = ValidateLoginSession(oldIdentity)
	require.NoError(t, err)
	cacheKey := cachedLoginSessionKey(t, serverB)
	version := serverB.HGet(cacheKey, "Version")
	assert.Equal(t, "1", version, "node B must hold the pre-rotation session version")

	common.RDB = clientA
	rotated, err := AdvanceCurrentSessionSecurity(oldIdentity, "security_update")
	require.NoError(t, err)
	newIdentity, err := ParseAccessToken(rotated.AccessToken)
	require.NoError(t, err)
	assert.Greater(t, newIdentity.SessionVersion, oldIdentity.SessionVersion)
	assert.Greater(t, newIdentity.UserAuthVersion, oldIdentity.UserAuthVersion)

	serverB.FastForward(3 * time.Second)
	common.RDB = clientB
	_, _, err = ValidateLoginSession(newIdentity)
	require.NoError(t, err)
	_, _, err = ValidateLoginSession(oldIdentity)
	assert.ErrorIs(t, err, ErrLoginSessionRevoked)
}

func TestUserAuthVersionInvalidatesExistingSession(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)
	bundle, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "test-agent")
	require.NoError(t, err)
	identity, err := ParseAccessToken(bundle.AccessToken)
	require.NoError(t, err)

	_, err = model.BumpUserAuthVersion(user.Id)
	require.NoError(t, err)
	_, _, err = ValidateLoginSession(identity)
	assert.ErrorIs(t, err, ErrLoginSessionRevoked)
	_, err = CreateLoginSessionAtAuthVersion(user.Id, identity.UserAuthVersion, "2fa", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrLoginSessionRevoked, "a pending 2FA flow must not survive an auth-version change")
}

// Exercise the real factor -> rotation -> proof -> domain path. HTTP transport
// and the cross-database matrix are owned by the independent router suite.
func TestOrganizationVerificationLifecycleAndFailureAtomicity(t *testing.T) {
	for _, failure := range []string{"none", "rotation_insert", "proof_insert", "signer", "confirm_read", "confirm_cleanup"} {
		t.Run(failure, func(t *testing.T) {
			useTestSessionSecret(t)
			user := setupAuthSessionTestDB(t, true)
			require.NoError(t, model.DB.AutoMigrate(&model.TwoFA{}, &model.PasskeyCredential{}, &model.Organization{}, &model.OrganizationMember{}, &model.OrganizationInvitation{}, &model.OrganizationOwnershipTransfer{}, &model.OrganizationEvent{}))
			enabled, encrypted := common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled
			common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled = true, false
			t.Cleanup(func() { common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled = enabled, encrypted })
			password := "organization-real-password-test"
			hash, err := common.Password2Hash(password)
			require.NoError(t, err)
			require.NoError(t, model.DB.Model(user).Update("password", hash).Error)
			bundle, err := CreateLoginSession(user.Id, "password", "", "")
			require.NoError(t, err)
			identity, err := ParseAccessToken(bundle.AccessToken)
			require.NoError(t, err)
			old, err := model.GetUserSessionBySID(identity.SessionID)
			require.NoError(t, err)
			org, err := model.CreateOrganization(identity, "Bound organization")
			require.NoError(t, err)
			data, err := common.Marshal(map[string]any{"revision": fmt.Sprint(org.Revision), "disabled": true, "reason": ""})
			require.NoError(t, err)
			wire, cmd, err := DecodeOrganizationCommand("self_disable", data, false, fmt.Sprint(org.ID), "", "")
			require.NoError(t, err)
			op, _, _, err := PreviewOrganizationOperation(identity, "self_disable", wire, cmd)
			require.NoError(t, err)
			sentinel := errors.New("test publication failure")
			if failure == "rotation_insert" || failure == "proof_insert" {
				require.NoError(t, model.DB.Callback().Create().Before("gorm:create").Register("test:organization-failure", func(tx *gorm.DB) {
					if failure == "rotation_insert" && tx.Statement.Table == "user_sessions" {
						tx.AddError(sentinel)
					}
					if flow, ok := tx.Statement.Dest.(*model.AuthFlow); ok && failure == "proof_insert" && flow.Purpose == model.AuthFlowPurposeSecurityProof {
						tx.AddError(sentinel)
					}
				}))
				t.Cleanup(func() { _ = model.DB.Callback().Create().Remove("test:organization-failure") })
			}
			if failure == "signer" {
				original := signOrganizationProof
				signOrganizationProof = func(authClaims) (string, error) { return "", sentinel }
				t.Cleanup(func() { signOrganizationProof = original })
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cleanupAttempted := false
			cleanupFailure := errors.New("test cleanup unavailable")
			if failure == "confirm_read" || failure == "confirm_cleanup" {
				created := false
				confirmationFailed := false
				require.NoError(t, model.DB.Callback().Create().After("gorm:create").Register("test:track-rotation", func(tx *gorm.DB) {
					if tx.Statement.Table == "user_sessions" && tx.Error == nil {
						created = true
					}
				}))
				require.NoError(t, model.DB.Callback().Query().Before("gorm:query").Register("test:confirm-failure", func(tx *gorm.DB) {
					if !created || tx.Statement.Table != "user_sessions" {
						return
					}
					if _, count := tx.Statement.Dest.(*int64); count && !confirmationFailed {
						confirmationFailed = true
						cancel() // A known committed rotation must still receive fresh bounded cleanup.
						tx.AddError(sentinel)
						return
					}
					if confirmationFailed && !cleanupAttempted {
						cleanupAttempted = true
						assert.NoError(t, tx.Statement.Context.Err())
						deadline, ok := tx.Statement.Context.Deadline()
						assert.True(t, ok)
						assert.LessOrEqual(t, time.Until(deadline), 10*time.Second)
						if failure == "confirm_cleanup" {
							tx.AddError(cleanupFailure)
						}
					}
				}))
				t.Cleanup(func() {
					_ = model.DB.Callback().Create().Remove("test:track-rotation")
					_ = model.DB.Callback().Query().Remove("test:confirm-failure")
				})
			}
			proof, err := VerifyOrganizationInputWithContext(ctx, identity, VerificationInput{Scope: op.Scope, Context: op.Context, Method: VerificationMethodPassword, Password: password})
			if failure == "confirm_read" || failure == "confirm_cleanup" {
				assert.True(t, cleanupAttempted)
				require.NoError(t, model.DB.Callback().Create().Remove("test:track-rotation"))
				require.NoError(t, model.DB.Callback().Query().Remove("test:confirm-failure"))
				if failure == "confirm_cleanup" {
					assert.ErrorIs(t, err, cleanupFailure)
				}
			}

			if failure != "none" {
				require.ErrorIs(t, err, sentinel)
				require.Nil(t, proof)
				oldAfter, e := model.GetUserSessionBySID(old.SID)
				require.NoError(t, e)
				expected := model.UserSessionStatusRevoked
				if failure == "rotation_insert" {
					expected = model.UserSessionStatusActive
				}
				assert.Equal(t, expected, oldAfter.Status)
				var active int64
				require.NoError(t, model.DB.Model(&model.UserSession{}).Where("user_id = ? AND status = ?", user.Id, model.UserSessionStatusActive).Count(&active).Error)
				if failure == "rotation_insert" || failure == "confirm_cleanup" {
					assert.EqualValues(t, 1, active)
				} else {
					assert.Zero(t, active)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, proof.AuthBundle)
			next, err := ParseAccessToken(proof.AuthBundle.AccessToken)
			require.NoError(t, err)
			assert.NotEqual(t, identity.SessionID, next.SessionID)
			nextSession, err := model.GetUserSessionBySID(next.SessionID)
			require.NoError(t, err)
			assert.Equal(t, old.ExpiresAt, nextSession.ExpiresAt)
			assert.Equal(t, identity.UserAuthVersion, next.UserAuthVersion)
			assert.EqualValues(t, 1, next.SessionVersion)
			_, _, err = ValidateLoginSession(identity)
			assert.Error(t, err)
			// A context mismatch does not consume a valid proof.
			changed := wire
			reason := "different reason"
			changed.Reason = &reason
			altered := cmd
			altered.Reason = reason
			_, err = ExecuteOrganizationLifecycle(next, "self_disable", changed, altered, proof.ProofToken)
			require.ErrorIs(t, err, ErrProofContext)
			// Once consumed, a business rollback cannot refund the proof.
			require.NoError(t, model.DB.Callback().Create().Before("gorm:create").Register("test:event-failure", func(tx *gorm.DB) {
				if tx.Statement.Table == "organization_events" {
					tx.AddError(sentinel)
				}
			}))
			_, err = ExecuteOrganizationLifecycle(next, "self_disable", wire, cmd, proof.ProofToken)
			require.ErrorIs(t, err, sentinel)
			require.NoError(t, model.DB.Callback().Create().Remove("test:event-failure"))
			var unchanged model.Organization
			require.NoError(t, model.DB.First(&unchanged, org.ID).Error)
			assert.Equal(t, org.Revision, unchanged.Revision)
			assert.Zero(t, unchanged.SelfDisabledAt)
			_, err = ExecuteOrganizationLifecycle(next, "self_disable", wire, cmd, proof.ProofToken)
			assert.ErrorIs(t, err, ErrProofConsumed)
			// A new ceremony succeeds and reports the event captured inside its commit.
			proof, err = VerifyOrganizationInput(next, VerificationInput{Scope: op.Scope, Context: op.Context, Method: VerificationMethodPassword, Password: password})
			require.NoError(t, err)
			next, err = ParseAccessToken(proof.AuthBundle.AccessToken)
			require.NoError(t, err)
			receipt, err := ExecuteOrganizationLifecycle(next, "self_disable", wire, cmd, proof.ProofToken)
			require.NoError(t, err)
			var event model.OrganizationEvent
			require.NoError(t, model.DB.First(&event, receipt.EventID).Error)
			assert.Equal(t, "organization.self_disable", event.Action)
			assert.Equal(t, org.Revision+1, receipt.Revision)
			assert.Equal(t, org.ID, receipt.ObjectID)
			assert.Zero(t, receipt.Generation)
		})
	}
}

func TestOrganizationCommandStrictWireContract(t *testing.T) {
	for _, body := range []string{
		`{"revision":"1","disabled":false,"reason":""}`,
		`{"revision":"1","disabled":false,"reason":"x","reason":"y"}`,
		`{"revision":"1","disabled":null,"reason":""}`,
		`{"revision":"1","reason":""}`,
		`{"revision":1,"disabled":false,"reason":""}`,
		`{"revision":"01","disabled":false,"reason":""}`,
		`{"revision":"","disabled":false,"reason":""}`,
		`{"revision":"9223372036854775808","disabled":false,"reason":""}`,
		`{"revision":"1","disabled":false,"reason":"","extra":0}`,
		`{"revision":"1","disabled":false,"reason":""} {}`,
	} {
		t.Run(body, func(t *testing.T) {
			wire, cmd, err := DecodeOrganizationCommand("self_disable", []byte(body), false, "1", "", "")
			if body == `{"revision":"1","disabled":false,"reason":""}` {
				require.NoError(t, err)
				require.NotNil(t, wire.Disabled)
				assert.False(t, *wire.Disabled)
				require.NotNil(t, wire.Reason)
				assert.Empty(t, *wire.Reason)
				assert.False(t, cmd.Disabled)
			} else {
				assert.Error(t, err)
			}
		})
	}
	assert.Error(t, common.ValidateStrictJSONObject([]byte(`{"a":{"key":1,"key":2}}`)))
	assert.Error(t, common.ValidateStrictJSONObject([]byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'}))
}

func TestOrganizationAttemptBudgetAcrossSessionsAndScopes(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t)
	require.NoError(t, model.DB.AutoMigrate(&model.TwoFA{}, &model.PasskeyCredential{}))
	first, err := CreateLoginSession(user.Id, "password", "", "")
	require.NoError(t, err)
	second, err := CreateLoginSession(user.Id, "password", "", "")
	require.NoError(t, err)
	a, err := ParseAccessToken(first.AccessToken)
	require.NoError(t, err)
	b, err := ParseAccessToken(second.AccessToken)
	require.NoError(t, err)
	for n := range 5 {
		identity := a
		if n%2 == 1 {
			identity = b
		}
		row, err := model.ReserveOrganizationVerificationAttempt(identity)
		require.NoError(t, err)
		assert.Empty(t, row.Payload)
		assert.Equal(t, identity.SessionID, row.SessionId)
		assert.WithinDuration(t, row.CreatedAt.Add(300*time.Second), row.ExpiresAt, time.Millisecond)
	}
	_, err = model.ReserveOrganizationVerificationAttempt(b)
	var budget *model.OrganizationVerificationBudgetError
	require.ErrorAs(t, err, &budget)
	assert.GreaterOrEqual(t, budget.RetryAfter, 1)
	assert.LessOrEqual(t, budget.RetryAfter, 300)
	var count int64
	require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("purpose = ?", "org_verify_attempt").Count(&count).Error)
	assert.EqualValues(t, 5, count)
	var oldest model.AuthFlow
	require.NoError(t, model.DB.Where("purpose = ?", "org_verify_attempt").Order("created_at,id").First(&oldest).Error)
	require.NoError(t, model.DB.Model(&oldest).Update("created_at", time.Now().Add(-301*time.Second)).Error)
	_, err = model.ReserveOrganizationVerificationAttempt(a)
	require.NoError(t, err)
}

// These are parser/service regressions, not WebAuthn signature or real HTTP tests.
func TestOrganizationProducerWireEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name, body         string
		finish, valid      bool
		required, optional []string
	}{
		{"preview", `{"action":"self_disable","command":{}}`, false, true, []string{"action", "command"}, nil},
		{"preview alias", `{"ACTION":"self_disable","command":{}}`, false, false, []string{"action", "command"}, nil},
		{"preview semantic duplicate", `{"action":"self_disable","Action":"dissolve","command":{}}`, false, false, []string{"action", "command"}, nil},
		{"begin", `{"scope":"organization.dissolve","context":{},"rp_id":"example.com"}`, false, true, []string{"scope", "context"}, []string{"rp_id"}},
		{"begin alias", `{"scope":"organization.dissolve","context":{},"RP_ID":"example.com"}`, false, false, []string{"scope", "context"}, []string{"rp_id"}},
		{"null userHandle", `{"flow_token":"fixture","credential":{"response":{"userHandle":null},"clientExtensionResults":{"example":true}}}`, true, true, []string{"flow_token", "credential"}, nil},
		{"omitted userHandle", `{"flow_token":"fixture","credential":{"response":{}}}`, true, true, []string{"flow_token", "credential"}, nil},
		{"nonempty userHandle", `{"flow_token":"fixture","credential":{"response":{"userHandle":"AQ"}}}`, true, true, []string{"flow_token", "credential"}, nil},
		{"finish alias", `{"FLOW_TOKEN":"fixture","credential":{}}`, true, false, []string{"flow_token", "credential"}, nil},
		{"finish semantic duplicate", `{"flow_token":"fixture","FLOW_TOKEN":"different","credential":{}}`, true, false, []string{"flow_token", "credential"}, nil},
		{"null envelope", `{"flow_token":null,"credential":{"response":{"userHandle":null}}}`, true, false, []string{"flow_token", "credential"}, nil},
		{"null credential", `{"flow_token":"fixture","credential":null}`, true, false, []string{"flow_token", "credential"}, nil},
		{"null signature", `{"flow_token":"fixture","credential":{"response":{"signature":null}}}`, true, false, []string{"flow_token", "credential"}, nil},
		{"duplicate internal key", `{"flow_token":"fixture","credential":{"response":{"userHandle":null,"userHandle":"AQ"}}}`, true, false, []string{"flow_token", "credential"}, nil},
		{"null strict context", `{"scope":"organization.dissolve","context":{"command":null}}`, false, false, []string{"scope", "context"}, []string{"rp_id"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validate := common.ValidateStrictJSONObject
			if tc.finish {
				validate = common.ValidateWebAuthnFinishJSONObject
			}
			err := validate([]byte(tc.body))
			if err == nil {
				err = common.ValidateJSONObjectFields([]byte(tc.body), tc.required, tc.optional)
			}
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if tc.name == "null userHandle" {
				assert.Error(t, common.ValidateStrictJSONObject([]byte(tc.body)))
			}
		})
	}
}

func TestOrganizationRequestCancellationStages(t *testing.T) {
	for _, stage := range []string{"before_request", "after_budget", "after_otp"} {
		t.Run(stage, func(t *testing.T) {
			useTestSessionSecret(t)
			user := setupAuthSessionTestDB(t, true)
			require.NoError(t, model.DB.AutoMigrate(&model.TwoFA{}, &model.PasskeyCredential{}, &model.Organization{}, &model.OrganizationMember{}, &model.OrganizationInvitation{}, &model.OrganizationOwnershipTransfer{}, &model.OrganizationEvent{}))
			hash, err := common.Password2Hash("fixture-password")
			require.NoError(t, err)
			require.NoError(t, model.DB.Model(user).Update("password", hash).Error)
			enabled, encrypted := common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled
			common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled = true, false
			t.Cleanup(func() { common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled = enabled, encrypted })
			bundle, err := CreateLoginSession(user.Id, "password", "", "")
			require.NoError(t, err)
			identity, err := ParseAccessToken(bundle.AccessToken)
			require.NoError(t, err)
			org, err := model.CreateOrganization(identity, "cancel fixture")
			require.NoError(t, err)
			wire, cmd, err := DecodeOrganizationCommand("self_disable", []byte(fmt.Sprintf(`{"revision":"%d","disabled":true,"reason":""}`, org.Revision)), false, fmt.Sprint(org.ID), "", "")
			require.NoError(t, err)
			op, _, _, err := PreviewOrganizationOperation(identity, "self_disable", wire, cmd)
			require.NoError(t, err)
			input := VerificationInput{Scope: op.Scope, Context: op.Context, Method: VerificationMethodPassword, Password: "fixture-password"}
			var factor model.TwoFA
			if stage == "after_otp" {
				factor = model.TwoFA{UserId: user.Id, Secret: "JBSWY3DPEHPK3PXP", IsEnabled: true}
				require.NoError(t, model.DB.Create(&factor).Error)
				input.Method = VerificationMethodTwoFA
				input.Code, err = totp.GenerateCode(factor.Secret, time.Now())
				require.NoError(t, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			committedStage := false
			if stage == "before_request" {
				cancel()
			} else {
				require.NoError(t, model.DB.Callback().Create().After("gorm:create").Register("test:cancel-stage", func(tx *gorm.DB) {
					flow, ok := tx.Statement.Dest.(*model.AuthFlow)
					if ok && tx.Error == nil && (stage == "after_budget" && flow.Purpose == "org_verify_attempt" || stage == "after_otp" && flow.Purpose == "totp_step") {
						committedStage = true
					}
				}))
				// The next stage's first read is reached only after the preceding transaction returns.
				// TOTP updates the factor after marker insertion, but performs no further reads.
				require.NoError(t, model.DB.Callback().Query().Before("gorm:query").Register("test:cancel-next-read", func(tx *gorm.DB) {
					if committedStage {
						cancel()
						tx.AddError(ctx.Err())
					}
				}))
			}
			proof, err := VerifyOrganizationInputWithContext(ctx, identity, input)
			assert.ErrorIs(t, err, context.Canceled)
			assert.Nil(t, proof)
			if stage != "before_request" {
				require.NoError(t, model.DB.Callback().Create().Remove("test:cancel-stage"))
				require.NoError(t, model.DB.Callback().Query().Remove("test:cancel-next-read"))
			}
			var attempts, proofs, markers, sessions int64
			require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("purpose = ?", "org_verify_attempt").Count(&attempts).Error)
			require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("purpose = ?", model.AuthFlowPurposeSecurityProof).Count(&proofs).Error)
			require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("purpose = ?", "totp_step").Count(&markers).Error)
			require.NoError(t, model.DB.Model(&model.UserSession{}).Count(&sessions).Error)
			if stage == "before_request" {
				assert.Zero(t, attempts)
			} else {
				assert.EqualValues(t, 1, attempts)
			}
			assert.Zero(t, proofs)
			assert.EqualValues(t, 1, sessions)
			if stage == "after_otp" {
				assert.Positive(t, markers)
				valid, err := factor.ValidateTOTPAndUpdateUsage(input.Code)
				require.NoError(t, err)
				assert.False(t, valid, "committed OTP must remain consumed")
			} else {
				assert.Zero(t, markers)
			}
			// Both read and write entry points honor an already cancelled parent.
			_, err = model.GetOrganizationLifecycleStateWithContext(ctx, identity, org.ID, false)
			assert.ErrorIs(t, err, context.Canceled)
			_, err = model.ExecuteOrganizationCommandWithContext(ctx, identity, "rename", model.OrganizationCommand{OrganizationID: org.ID, Revision: org.Revision, Name: "must not persist"})
			assert.ErrorIs(t, err, context.Canceled)
			err = model.ValidateOrganizationAttemptWithTx(model.DB.WithContext(ctx), identity, 1)
			assert.ErrorIs(t, err, context.Canceled)
			var unchanged model.Organization
			require.NoError(t, model.DB.First(&unchanged, org.ID).Error)
			assert.Equal(t, org.Name, unchanged.Name)
		})
	}
}

func TestOrganizationTOTPParentDeadline(t *testing.T) {
	useTestSessionSecret(t)
	user := setupAuthSessionTestDB(t, true)
	require.NoError(t, model.DB.AutoMigrate(&model.TwoFA{}))
	factor := model.TwoFA{UserId: user.Id, Secret: "JBSWY3DPEHPK3PXP", IsEnabled: true}
	require.NoError(t, model.DB.Create(&factor).Error)
	for _, ttl := range []time.Duration{time.Minute, time.Second} {
		ctx, cancel := context.WithTimeout(context.Background(), ttl)
		parentDeadline, _ := ctx.Deadline()
		observed := false
		require.NoError(t, model.DB.Callback().Update().Before("gorm:update").Register("test:totp-deadline", func(tx *gorm.DB) {
			if observed {
				return
			}
			observed = true
			deadline, ok := tx.Statement.Context.Deadline()
			assert.True(t, ok)
			assert.LessOrEqual(t, deadline.Sub(time.Now()), 10*time.Second)
			assert.False(t, deadline.After(parentDeadline))
			cancel()
			tx.AddError(ctx.Err())
		}))
		valid, err := factor.ValidateTOTPAndUpdateUsageWithContext(ctx, "000000")
		assert.True(t, observed)
		assert.False(t, valid)
		assert.ErrorIs(t, err, context.Canceled)
		require.NoError(t, model.DB.Callback().Update().Remove("test:totp-deadline"))
		cancel()
	}
	var markers int64
	require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("purpose = ?", "totp_step").Count(&markers).Error)
	assert.Zero(t, markers)
}
