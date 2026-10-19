package model

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestHardDeleteUserFailsClosedWhenAuthFenceCannotPublish(t *testing.T) {
	truncateTables(t)

	user := User{Username: "hard-delete-user", Password: "password", TelegramId: "hard-delete-telegram"}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, user.TelegramId, user.Id)
	}))
	require.NoError(t, DB.Create(&Token{UserId: user.Id, Key: "hard-delete-token"}).Error)
	require.NoError(t, DB.Create(&UserAccessToken{UserId: user.Id, TokenHash: AccessTokenFingerprint("nap_hard-delete-token")}).Error)
	require.NoError(t, DB.Create(&TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}).Error)
	require.NoError(t, DB.Create(&TwoFABackupCode{UserId: user.Id, CodeHash: "hash"}).Error)
	require.NoError(t, DB.Create(&PasskeyCredential{UserID: user.Id, CredentialID: "credential", PublicKey: "public-key"}).Error)
	require.NoError(t, DB.Create(&UserOAuthBinding{UserId: user.Id, ProviderId: 1, ProviderUserId: "provider-user"}).Error)
	require.NoError(t, DB.Create(&UserSession{
		SID: "hard-delete-session", UserID: user.Id, Version: 1, UserAuthVersion: 1,
		Status: UserSessionStatusActive, RefreshHash: "refresh-hash", LoginMethod: "password",
		LastActiveAt: 1, ExpiresAt: 2,
	}).Error)
	require.NoError(t, DB.Create(&AuthFlow{
		TokenHash: "hard-delete-auth-flow", Purpose: AuthFlowPurposeTwoFALogin,
		UserId: user.Id, ExpiresAt: time.Now().Add(time.Minute),
	}).Error)

	oldRedisEnabled, oldRDB := common.RedisEnabled, common.RDB
	common.RedisEnabled = true
	common.RDB = redis.NewClient(&redis.Options{
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("forced redis failure")
		},
		MaxRetries: -1,
	})
	t.Cleanup(func() {
		_ = common.RDB.Close()
		common.RedisEnabled, common.RDB = oldRedisEnabled, oldRDB
	})

	_, err := HardDeleteUserById(user.Id)
	require.Error(t, err)

	var count int64
	require.NoError(t, DB.Unscoped().Model(&User{}).Where("id = ?", user.Id).Count(&count).Error)
	assert.EqualValues(t, 1, count)
	for _, record := range []any{
		&Token{},
		&TwoFA{},
		&TwoFABackupCode{},
		&PasskeyCredential{},
		&UserOAuthBinding{},
		&UserSession{},
		&AuthFlow{},
		&ExternalIdentityClaim{},
		&UserAccessToken{},
	} {
		require.NoError(t, DB.Unscoped().Model(record).Where("user_id = ?", user.Id).Count(&count).Error)
		assert.EqualValues(t, 1, count)
	}
}

func TestHardDeleteUserPublishesTombstoneAndPurgesAuthenticationData(t *testing.T) {
	truncateTables(t)
	server := useUserCacheMiniRedis(t)

	user := User{
		Username: "hard-delete-success", Password: "password", AuthVersion: 1,
		TelegramId: "hard-delete-success-telegram",
	}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, user.TelegramId, user.Id)
	}))
	require.NoError(t, DB.Create(&Token{UserId: user.Id, Key: "hard-delete-success-token"}).Error)
	require.NoError(t, DB.Create(&UserAccessToken{UserId: user.Id, TokenHash: AccessTokenFingerprint("nap_hard-delete-success-token")}).Error)
	require.NoError(t, DB.Create(&TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}).Error)
	require.NoError(t, DB.Create(&TwoFABackupCode{UserId: user.Id, CodeHash: "hash"}).Error)
	require.NoError(t, DB.Create(&PasskeyCredential{UserID: user.Id, CredentialID: "credential-success", PublicKey: "public-key"}).Error)
	require.NoError(t, DB.Create(&UserOAuthBinding{UserId: user.Id, ProviderId: 1, ProviderUserId: "provider-user-success"}).Error)
	require.NoError(t, DB.Create(&UserSession{
		SID: "hard-delete-success-session", UserID: user.Id, Version: 1, UserAuthVersion: 1,
		Status: UserSessionStatusActive, RefreshHash: "refresh-hash", LoginMethod: "password",
		LastActiveAt: 1, ExpiresAt: 2,
	}).Error)
	require.NoError(t, DB.Create(&AuthFlow{
		TokenHash: "hard-delete-success-flow", Purpose: AuthFlowPurposeTwoFALogin,
		UserId: user.Id, ExpiresAt: time.Now().Add(time.Minute),
	}).Error)
	require.NoError(t, populateUserCache(user))
	// Administrative hard deletion commonly targets an already soft-deleted
	// user; the shared version increment must therefore query unscoped.
	require.NoError(t, DB.Delete(&user).Error)

	revokedAccessTokens, err := HardDeleteUserById(user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 1, revokedAccessTokens)

	var count int64
	require.NoError(t, DB.Unscoped().Model(&User{}).Where("id = ?", user.Id).Count(&count).Error)
	assert.Zero(t, count)
	for _, record := range []any{
		&Token{},
		&TwoFA{},
		&TwoFABackupCode{},
		&PasskeyCredential{},
		&UserOAuthBinding{},
		&UserSession{},
		&AuthFlow{},
		&ExternalIdentityClaim{},
		&UserAccessToken{},
	} {
		require.NoError(t, DB.Unscoped().Model(record).Where("user_id = ?", user.Id).Count(&count).Error)
		assert.Zero(t, count)
	}
	assert.False(t, server.Exists(getUserAuthFenceKey(user.Id)))
	committed, err := common.RDB.Get(t.Context(), getUserAuthVersionKey(user.Id)).Result()
	require.NoError(t, err)
	assert.Equal(t, "2", committed)
	assert.False(t, server.Exists(getUserCacheKey(user.Id)))
}

func TestIncrementFailedAttemptsCountsConcurrentFailures(t *testing.T) {
	truncateTables(t)

	user := User{Username: "twofa-cas-user", Password: "password"}
	require.NoError(t, DB.Create(&user).Error)
	twoFA := TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}
	require.NoError(t, DB.Create(&twoFA).Error)

	const attempts = 4
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			errs <- (&TwoFA{Id: twoFA.Id}).IncrementFailedAttempts()
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	var reloaded TwoFA
	require.NoError(t, DB.First(&reloaded, twoFA.Id).Error)
	assert.Equal(t, attempts, reloaded.FailedAttempts)
}

func TestValidateBackupCodeCanOnlySucceedOnce(t *testing.T) {
	truncateTables(t)

	const code = "ABCD-1234"
	user := User{Id: 123, Username: "backup-code-user", Password: "password", AuthVersion: 1}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, DB.Create(&TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: false}).Error)
	hashedCode, err := common.HashBackupCode(code)
	require.NoError(t, err)
	require.NoError(t, DB.Create(&TwoFABackupCode{UserId: user.Id, CodeHash: hashedCode}).Error)

	const attempts = 2
	results := make(chan bool, attempts)
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			valid, err := ValidateBackupCode(123, code)
			results <- valid
			errs <- err
		})
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	wins := 0
	for valid := range results {
		if valid {
			wins++
		}
	}
	assert.Equal(t, 1, wins)

	remaining, err := GetUnusedBackupCodeCount(123)
	require.NoError(t, err)
	assert.Zero(t, remaining)
}

func TestPendingTwoFASetupAPIsRejectEnabledFactor(t *testing.T) {
	truncateTables(t)

	user := User{Username: "enabled-twofa-guard", Password: "password", Status: common.UserStatusEnabled, AuthVersion: 1}
	require.NoError(t, DB.Create(&user).Error)
	twoFA := TwoFA{UserId: user.Id, Secret: "secret", IsEnabled: true}
	require.NoError(t, DB.Create(&twoFA).Error)

	session := UserSession{SID: "enabled-factor-session", UserID: user.Id, Version: 1, UserAuthVersion: 1, Status: UserSessionStatusActive, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, DB.Create(&session).Error)
	identity := AuthSessionIdentity{UserID: user.Id, SessionID: session.SID, UserAuthVersion: 1, SessionVersion: 1}
	authorization := &AuthFlowAuthorization{AuthSessionIdentity: identity, ProofID: 1, Scope: "2fa.setup", ContextHash: "setup-context", Method: "password"}
	_, err := CreateTwoFAEnrollment(identity, authorization, "replacement-secret", []string{"ABCD-1234"}, time.Now().Add(time.Minute))
	require.ErrorIs(t, err, ErrTwoFAAlreadyEnabled)

	var stored TwoFA
	require.NoError(t, DB.First(&stored, twoFA.Id).Error)
	assert.True(t, stored.IsEnabled)
	var backupCodeCount int64
	require.NoError(t, DB.Model(&TwoFABackupCode{}).Where("user_id = ?", user.Id).Count(&backupCodeCount).Error)
	assert.Zero(t, backupCodeCount)
}

func TestSecurityFactorMutationsAdvanceUserAuthVersion(t *testing.T) {
	truncateTables(t)

	user := User{
		Username:    "security-factor-version-user",
		Password:    "password",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AuthVersion: 1,
	}
	require.NoError(t, DB.Create(&user).Error)
	session := UserSession{SID: "factor-version-session", UserID: user.Id, Version: 1, UserAuthVersion: 1, Status: UserSessionStatusActive, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, DB.Create(&session).Error)
	identity := AuthSessionIdentity{UserID: user.Id, SessionID: session.SID, UserAuthVersion: 1, SessionVersion: 1}
	authorization := &AuthFlowAuthorization{AuthSessionIdentity: identity, ProofID: 1, Scope: "2fa.setup", ContextHash: "setup-context", Method: "password"}
	token, err := CreateTwoFAEnrollment(identity, authorization, "JBSWY3DPEHPK3PXP", []string{"ABCD-1234"}, time.Now().Add(time.Minute))
	require.NoError(t, err)
	code, err := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	require.NoError(t, err)
	require.NoError(t, EnableTwoFAEnrollment(identity, token, code))
	assertUserAuthVersion(t, user.Id, 2)
	assert.ErrorIs(t, EnableTwoFAEnrollment(identity, token, code), ErrTwoFASetupInvalid)
	assertUserAuthVersion(t, user.Id, 2)
	require.NoError(t, ReplaceBackupCodesWithAuthVersion(user.Id, []string{"ABCD-1234"}))
	assertUserAuthVersion(t, user.Id, 3)
	require.NoError(t, DisableTwoFAWithAuthVersion(user.Id))
	assertUserAuthVersion(t, user.Id, 4)

	credential := &PasskeyCredential{UserID: user.Id, CredentialID: "credential-id", PublicKey: "public-key"}
	require.NoError(t, UpsertPasskeyCredentialWithAuthVersion(credential))
	assertUserAuthVersion(t, user.Id, 5)
	require.NoError(t, DeletePasskeyByUserIDWithAuthVersion(user.Id))
	assertUserAuthVersion(t, user.Id, 6)
}

func TestUpdatePasskeyAssertionStateCannotRewriteRegistrationIdentity(t *testing.T) {
	truncateTables(t)
	require.NoError(t, DB.AutoMigrate(&Option{}))
	previousSettings := *system_setting.GetPasskeySettings()
	domainKeys := map[string]any{"key": []string{"ServerAddress", "passkey.rp_id", "passkey.legacy_rp_ids", "passkey.origins"}}
	var previousOptions []Option
	require.NoError(t, DB.Where(domainKeys).Find(&previousOptions).Error)
	t.Cleanup(func() {
		*system_setting.GetPasskeySettings() = previousSettings
		require.NoError(t, DB.Where(domainKeys).Delete(&Option{}).Error)
		if len(previousOptions) > 0 {
			require.NoError(t, DB.Create(&previousOptions).Error)
		}
	})
	*system_setting.GetPasskeySettings() = system_setting.PasskeySettings{RPID: "example.com", Origins: "https://example.com"}
	for _, option := range []Option{{Key: "passkey.rp_id", Value: "example.com"}, {Key: "passkey.legacy_rp_ids", Value: ""}, {Key: "passkey.origins", Value: "https://example.com"}} {
		require.NoError(t, DB.Save(&option).Error)
	}

	user := User{Username: "passkey-assertion-state", Password: "password", AuthVersion: 1}
	require.NoError(t, DB.Create(&user).Error)
	credentialID := []byte("stable-credential-id")
	stored := PasskeyCredential{
		UserID:          user.Id,
		CredentialID:    base64.StdEncoding.EncodeToString(credentialID),
		PublicKey:       "original-public-key",
		AttestationType: "packed",
		AAGUID:          "original-aaguid",
		SignCount:       1,
		Transports:      `["usb"]`,
		Attachment:      "platform",
	}
	require.NoError(t, DB.Create(&stored).Error)
	usedAt := time.Now().UTC().Truncate(time.Second)
	validated := &webauthn.Credential{
		ID:              credentialID,
		PublicKey:       []byte("replacement-public-key"),
		AttestationType: "none",
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: true,
			BackupState:    true,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       []byte("replacement-aaguid"),
			SignCount:    8,
			CloneWarning: true,
		},
	}
	require.NoError(t, UpdatePasskeyAssertionState(user.Id, validated, usedAt, "example.com"))

	var updated PasskeyCredential
	require.NoError(t, DB.First(&updated, stored.ID).Error)
	assert.Equal(t, stored.CredentialID, updated.CredentialID)
	assert.Equal(t, stored.PublicKey, updated.PublicKey)
	assert.Equal(t, stored.AttestationType, updated.AttestationType)
	assert.Equal(t, stored.AAGUID, updated.AAGUID)
	assert.Equal(t, stored.Transports, updated.Transports)
	assert.Equal(t, stored.Attachment, updated.Attachment)
	assert.EqualValues(t, 8, updated.SignCount)
	assert.True(t, updated.CloneWarning)
	assert.True(t, updated.UserPresent)
	assert.True(t, updated.UserVerified)
	assert.True(t, updated.BackupEligible)
	assert.True(t, updated.BackupState)
	require.NotNil(t, updated.LastUsedAt)
	assert.Equal(t, usedAt.Unix(), updated.LastUsedAt.Unix())

	// Organization assertions reject clone reports and stale registration identity.
	assert.ErrorIs(t, UpdateOrganizationPasskeyAssertionState(user.Id, validated, usedAt, "example.com", &updated), ErrFriendlyPasskeyNotFound)
	validated.Authenticator.CloneWarning = false
	stale := updated
	stale.PublicKey = "replaced-after-signature"
	assert.ErrorIs(t, UpdateOrganizationPasskeyAssertionState(user.Id, validated, usedAt, "example.com", &stale), ErrFriendlyPasskeyNotFound)
	// Backed-up authenticators may report a lower/zero counter; persistence must
	// keep the high-water mark rather than regress it.
	validated.Authenticator.SignCount = 0
	require.NoError(t, UpdateOrganizationPasskeyAssertionState(user.Id, validated, usedAt, "example.com", &updated))
	require.NoError(t, DB.First(&updated, stored.ID).Error)
	assert.EqualValues(t, 8, updated.SignCount)
	require.NoError(t, DB.Model(&updated).Update("backup_eligible", false).Error)
	updated.BackupEligible = false
	validated.Flags.BackupEligible = false
	assert.ErrorIs(t, UpdateOrganizationPasskeyAssertionState(user.Id, validated, usedAt, "example.com", &updated), ErrFriendlyPasskeyNotFound)
	// Cancellation must return while the original serialization lock is still
	// held. No waiter goroutine may later acquire it and update the credential.
	for _, mode := range []string{"cancelled_before", "cancelled_while_locked", "expired_deadline", "deadline_while_locked"} {
		t.Run("lock_wait_"+mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expectedError := context.Canceled
			if mode == "expired_deadline" {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				expectedError = context.DeadlineExceeded
			} else if mode == "deadline_while_locked" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				expectedError = context.DeadlineExceeded
			} else if mode == "cancelled_before" {
				cancel()
			}
			passkeyOptionMutex.Lock()
			locked := true
			defer func() {
				if locked {
					passkeyOptionMutex.Unlock()
				}
			}()
			started := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				close(started)
				done <- UpdateOrganizationPasskeyAssertionStateWithContext(ctx, user.Id, validated, usedAt, "example.com", &updated)
			}()
			<-started
			if mode != "deadline_while_locked" {
				cancel()
			}
			select {
			case err := <-done:
				assert.ErrorIs(t, err, expectedError)
			case <-time.After(2 * time.Second):
				// Release and join the test worker before failing; no leaked test
				// goroutine may outlive the SQLite fixture.
				passkeyOptionMutex.Unlock()
				locked = false
				<-done
				t.Fatal("cancelled assertion remained blocked on the Passkey lock")
			}
			passkeyOptionMutex.Unlock()
			locked = false
			var unchanged PasskeyCredential
			require.NoError(t, DB.First(&unchanged, updated.ID).Error)
			assert.Equal(t, updated.SignCount, unchanged.SignCount)
			assert.Equal(t, updated.LastUsedAt, unchanged.LastUsedAt)
		})
	}
	validated.ID = []byte("another-credential")
	assert.ErrorIs(t, UpdatePasskeyAssertionState(user.Id, validated, usedAt, "example.com"), ErrPasskeyNotFound)
}

func assertUserAuthVersion(t *testing.T, userID int, expected int64) {
	t.Helper()
	var version int64
	require.NoError(t, DB.Model(&User{}).Where("id = ?", userID).Select("auth_version").Scan(&version).Error)
	assert.Equal(t, expected, version)
}

func TestTOTPStepClaimSurvivesAuthVersionChangeAndEnrollment(t *testing.T) {
	truncateTables(t)
	user := User{Username: "totp-step-user", Password: "unused", Status: common.UserStatusEnabled, AuthVersion: 1}
	require.NoError(t, DB.Create(&user).Error)
	secret := "JBSWY3DPEHPK3PXP"
	factor := TwoFA{UserId: user.Id, Secret: secret, IsEnabled: true}
	require.NoError(t, DB.Create(&factor).Error)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	ok, err := factor.ValidateTOTPAndUpdateUsage(code)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, DB.Model(&user).Update("auth_version", 2).Error)
	ok, err = factor.ValidateTOTPAndUpdateUsage(code)
	require.NoError(t, err)
	assert.False(t, ok)
	var markers []AuthFlow
	require.NoError(t, DB.Where("purpose = ?", "totp_step").Find(&markers).Error)
	require.NotEmpty(t, markers)
	for _, marker := range markers {
		assert.Empty(t, marker.Payload)
		assert.NotContains(t, marker.TokenHash, secret)
		assert.NotContains(t, marker.TokenHash, code)
		assert.True(t, marker.ExpiresAt.After(time.Now().Add(4*time.Minute)))
	}
	require.NoError(t, DB.Model(&factor).Updates(map[string]any{"is_enabled": false, "failed_attempts": 0}).Error)
	identity := AuthSessionIdentity{UserID: user.Id, SessionID: "totp-enrollment-session", SessionVersion: 1, UserAuthVersion: 2}
	require.NoError(t, DB.Create(&UserSession{SID: identity.SessionID, UserID: user.Id, Version: 1, UserAuthVersion: 2, Status: UserSessionStatusActive, RefreshHash: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour).Unix()}).Error)
	payload, err := common.Marshal(twoFAEnrollmentPayload{TwoFAID: factor.Id, SecretHash: common.GenerateHMACWithKey([]byte("twofa-enrollment:"+common.SessionSecret), secret), Authorization: &AuthFlowAuthorization{AuthSessionIdentity: identity, ProofID: 1}})
	require.NoError(t, err)
	token, _, err := CreateAuthFlow(AuthFlowCreate{Purpose: AuthFlowPurposeTwoFASetup, UserId: user.Id, SessionId: identity.SessionID, Payload: string(payload), ExpiresAt: time.Now().Add(time.Minute)})
	require.NoError(t, err)
	assert.ErrorIs(t, EnableTwoFAEnrollment(identity, token, code), ErrTwoFACodeInvalid)
	var pending TwoFA
	require.NoError(t, DB.First(&pending, factor.Id).Error)
	assert.False(t, pending.IsEnabled)
	assert.Equal(t, 1, pending.FailedAttempts)
	// Successful activation claims the next accepted step before auth_version changes.
	next, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	require.NoError(t, err)
	require.NoError(t, EnableTwoFAEnrollment(identity, token, next))
	require.NoError(t, DB.First(&pending, factor.Id).Error)
	ok, err = pending.ValidateTOTPAndUpdateUsage(next)
	require.NoError(t, err)
	assert.False(t, ok)
}
