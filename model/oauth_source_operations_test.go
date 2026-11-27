package model

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// Both DSNs must belong to a disposable target reached through its local socket.
// Provision the service account separately, with neither source writes nor DDL.
func TestOAuthProtectedSourceOperationsDatabase(t *testing.T) {
	engine := os.Getenv("NEWAPI_SOURCE_OPS_TEST_ENGINE")
	if engine == "" {
		t.Skip("requires an isolated database installer and restricted role")
	}
	role, target := "source_ops_service", os.Getenv("NEWAPI_SOURCE_OPS_TEST_TARGET")
	require.Regexp(t, "^h29_source_[a-z0-9_]+$", target)
	adminDSN, _, err := oauthBootstrapDSN(engine, os.Getenv("NEWAPI_SOURCE_OPS_TEST_ADMIN_DSN"), target)
	require.NoError(t, err)
	serviceDSN, _, err := oauthBootstrapDSN(engine, os.Getenv("NEWAPI_SOURCE_OPS_TEST_SERVICE_DSN"), target)
	require.NoError(t, err)
	admin, err := openOAuthBootstrapDB(engine, adminDSN)
	require.NoError(t, err)
	adminPool, err := admin.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adminPool.Close()) })
	require.NoError(t, admin.AutoMigrate(&OAuthDerivedTokenSource{}, &OAuthDerivedTokenHistory{},
		&OAuthDerivedTokenBootstrapIdentity{}, &Token{}, &User{}, &UserSession{}, &OAuthGrant{}, &AuthFlow{}))
	require.NoError(t, validateOAuthDerivedTokenSchema(admin))
	install := func() error {
		switch engine {
		case "postgres":
			return installPostgresOAuthSourceOperations(admin, role)
		case "mysql":
			return admin.Connection(func(conn *gorm.DB) error {
				return installMySQLOAuthSourceOperations(conn, target, role)
			})
		}
		return fmt.Errorf("unexpected engine %q", engine)
	}
	require.NoError(t, install())
	require.NoError(t, install(), "installer must adopt the installed definition idempotently")
	switch engine {
	case "postgres":
		require.NoError(t, admin.Exec("GRANT SELECT, UPDATE ON tokens TO source_ops_service").Error)
	case "mysql":
		require.NoError(t, admin.Exec("GRANT SELECT, UPDATE ON `"+target+"`.`tokens` TO 'source_ops_service'@'localhost'").Error)
	}
	service, err := openOAuthBootstrapDB(engine, serviceDSN)
	require.NoError(t, err)
	servicePool, err := service.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, servicePool.Close()) })
	now, grant := time.Now().Unix(), strings.Repeat("a", 64)
	source := OAuthDerivedTokenSource{GrantRef: grant, UserID: 1, SchemaVersion: 1, QuotaLimit: 90,
		ExpiresAt: now + 800, PolicyHash: strings.Repeat("b", 64), BindingHash: strings.Repeat("c", 64),
		VerifiedAt: now - 1, ProofExpiresAt: now + 50, PermitDeadline: now + 40, VerifiedMethod: "2fa", ProofFlowID: 1}
	require.NoError(t, admin.Create(&source).Error)
	require.NoError(t, admin.Exec("INSERT INTO tokens (id, status) VALUES (11, 1)").Error)
	var version string
	require.NoError(t, admin.Raw("SELECT VERSION()").Scan(&version).Error)
	t.Logf("%s %s", engine, version)
	for _, query := range []string{
		"UPDATE oauth_derived_token_sources SET terminal_at = 0",
		"DELETE FROM oauth_derived_token_sources",
		"INSERT INTO oauth_derived_token_sources SELECT * FROM oauth_derived_token_sources",
		"TRUNCATE TABLE oauth_derived_token_sources",
	} {
		assert.ErrorContains(t, service.Exec(query).Error, "denied")
	}
	reserve := "SELECT newapi_oauth_source.reserve_source(?, ?, ?, ?, ?, ?, ?)"
	if engine == "mysql" {
		reserve = "CALL newapi_oauth_reserve_source(?, ?, ?, ?, ?, ?, ?)"
	}
	assert.ErrorContains(t, service.Exec(reserve, 1, grant, 1, 90, now+800, source.PolicyHash, source.BindingHash).Error, "denied")

	t.Setenv("OAUTH_PROTECTED_SOURCE_OPS", "true")
	_, err = lockOAuthSources(service, 1, grant)
	require.ErrorIs(t, err, ErrOAuthDerivedTokenUnknown)
	rollback := errors.New("rollback caller transaction")
	for _, prepare := range []bool{false, true} {
		txResult := service.Session(&gorm.Session{PrepareStmt: prepare}).Transaction(func(tx *gorm.DB) error {
			got, err := lockOAuthSource(tx, 1, grant)
			require.NoError(t, err)
			require.Equal(t, grant, got.GrantRef)
			require.NoError(t, terminalOAuthToken(tx, got, "revoked", now))
			require.NoError(t, tx.Exec("UPDATE tokens SET status = 2 WHERE id = 11").Error)
			require.NoError(t, tx.Where("grant_ref = ?", grant).First(got).Error)
			require.NotNil(t, got.TerminalReason)
			require.Equal(t, "revoked", *got.TerminalReason)
			if !prepare {
				return rollback
			}
			return nil
		})
		var got OAuthDerivedTokenSource
		require.NoError(t, service.Where("grant_ref = ?", grant).First(&got).Error)
		var status int
		require.NoError(t, service.Raw("SELECT status FROM tokens WHERE id = 11").Scan(&status).Error)
		if !prepare {
			require.ErrorIs(t, txResult, rollback)
			assert.Nil(t, got.TerminalReason)
			assert.Equal(t, 1, status)
		} else {
			require.NoError(t, txResult)
			require.NotNil(t, got.TerminalReason)
			assert.Equal(t, "revoked", *got.TerminalReason)
			assert.Equal(t, 2, status)
		}
	}
}

func TestOAuthTrustedIssueAttestationDatabase(t *testing.T) {
	engine := os.Getenv("NEWAPI_SOURCE_OPS_TEST_ENGINE")
	if engine == "" {
		t.Skip("requires an isolated database installer and separate attestor role")
	}
	ctx := t.Context()
	target := os.Getenv("NEWAPI_SOURCE_OPS_TEST_TARGET")
	require.Regexp(t, "^h29_issue_[a-z0-9_]+$", target)
	rawServiceDSN := os.Getenv("NEWAPI_SOURCE_OPS_TEST_SERVICE_DSN")
	rawWriterDSN := os.Getenv("NEWAPI_SOURCE_OPS_TEST_ATTESTOR_DSN")
	open := func(raw string) *gorm.DB {
		dsn, _, err := oauthBootstrapDSN(engine, raw, target)
		require.NoError(t, err)
		db, err := openOAuthBootstrapDB(engine, dsn)
		require.NoError(t, err)
		pool, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, pool.Close()) })
		return db
	}
	admin := open(os.Getenv("NEWAPI_SOURCE_OPS_TEST_ADMIN_DSN"))
	require.NoError(t, admin.AutoMigrate(&OAuthDerivedTokenSource{}, &OAuthDerivedTokenHistory{},
		&OAuthDerivedTokenBootstrapIdentity{}, &Token{}, &User{}, &UserSession{}, &OAuthGrant{}, &AuthFlow{}))

	const gateway, attestor = "source_ops_service", "source_ops_attestor"
	install := func() error {
		if engine == "postgres" {
			if err := installPostgresOAuthSourceOperations(admin, gateway); err != nil {
				return err
			}
			return admin.Transaction(func(tx *gorm.DB) error {
				return installOAuthIssueAttestations(tx, target, gateway, attestor)
			})
		}
		return admin.Connection(func(tx *gorm.DB) error {
			if err := installMySQLOAuthSourceOperations(tx, target, gateway); err != nil {
				return err
			}
			return installOAuthIssueAttestations(tx, target, gateway, attestor)
		})
	}
	require.NoError(t, admin.Migrator().CreateTable(&OAuthIssueAttestation{}))
	require.ErrorIs(t, install(), errOAuthBootstrap, "an unpaired relation cannot be trusted")
	require.NoError(t, admin.Migrator().DropTable(&OAuthIssueAttestation{}))
	if engine == "postgres" {
		require.NoError(t, admin.Exec("CREATE ROLE source_ops_other NOINHERIT LOGIN").Error)
		require.NoError(t, admin.Exec("GRANT source_ops_attestor TO source_ops_other").Error)
		require.ErrorIs(t, install(), errOAuthBootstrap, "another login must not be able to switch to the attestor")
		require.NoError(t, admin.Exec("DROP ROLE source_ops_other").Error)
	} else {
		require.NoError(t, admin.Exec("CREATE USER 'source_ops_other'@'localhost'").Error)
		require.NoError(t, admin.Exec("GRANT INSERT ON `"+target+"`.* TO 'source_ops_other'@'localhost'").Error)
		require.ErrorIs(t, install(), errOAuthBootstrap, "database-wide write access must block installation")
		require.NoError(t, admin.Exec("REVOKE INSERT ON `"+target+"`.* FROM 'source_ops_other'@'localhost'").Error)
		require.NoError(t, admin.Exec("GRANT CREATE TEMPORARY TABLES ON `"+target+"`.* TO 'source_ops_other'@'localhost'").Error)
		require.ErrorIs(t, install(), errOAuthBootstrap, "a temporary table must not be able to shadow the protected proof")
		require.False(t, admin.Migrator().HasTable(&OAuthIssueAttestation{}))
		require.NoError(t, admin.Exec("DROP USER 'source_ops_other'@'localhost'").Error)
		// MySQL can commit the owned routine before creating the table.
		require.NoError(t, admin.Connection(func(tx *gorm.DB) error {
			return prepareMySQLOAuthIssueInstaller(tx, target, gateway, attestor,
				"`"+target+"`.`"+oauthIssueAttestationTable+"`")
		}))
		require.False(t, admin.Migrator().HasTable(&OAuthIssueAttestation{}))
	}
	require.NoError(t, install())
	require.NoError(t, install())
	var now = time.Now().Unix()
	require.NoError(t, admin.Create(&User{Id: 1, Username: "fixture-user", Status: 1, AuthVersion: 3}).Error)
	require.NoError(t, admin.Create(&UserSession{SID: "fixture-sid", UserID: 1, Status: "active",
		Version: 4, UserAuthVersion: 3, ExpiresAt: now + 3600}).Error)
	grant := OAuthGrant{GrantID: strings.Repeat("g", 43), Issuer: "https://fixture.invalid/", ClientID: "test-client",
		Subject: "1", UserID: 1, ConsentRequestID: "one", OriginSID: "fixture-sid", SessionVersion: 4, UserAuthVersion: 3,
		PolicyHash: strings.Repeat("b", 64), Scopes: `["profile","tokens:write"]`, State: "prepared",
		Revision: 1, CreatedAt: now, ExpiresAt: now + 1200}
	grant.GrantRef = OAuthGrantRef(grant.Issuer, grant.GrantID)
	grant.ConsentRef = OAuthConsentRef(grant.Issuer, grant.ConsentRequestID)
	require.NoError(t, admin.Create(&grant).Error)
	if engine == "postgres" {
		require.NoError(t, admin.Exec("GRANT SELECT, UPDATE ON oauth_grants TO source_ops_service").Error)
	} else {
		require.NoError(t, admin.Exec("GRANT SELECT, UPDATE ON `"+target+"`.`oauth_grants` TO 'source_ops_service'@'localhost'").Error)
	}
	service := open(rawServiceDSN)
	writer := open(rawWriterDSN)
	prior := DB
	DB = service
	t.Cleanup(func() { DB = prior })
	_, err := OpenOAuthIssueAttestationWriter(ctx, rawServiceDSN, rawServiceDSN)
	require.ErrorIs(t, err, ErrOAuthDerivedTokenUnknown)
	_, err = OpenOAuthIssueAttestationWriter(ctx, rawServiceDSN, os.Getenv("NEWAPI_SOURCE_OPS_TEST_ADMIN_DSN"))
	require.ErrorIs(t, err, ErrOAuthDerivedTokenUnknown)
	attestationWriter, err := OpenOAuthIssueAttestationWriter(ctx, rawServiceDSN, rawWriterDSN)
	require.NoError(t, err)
	writerPool, err := attestationWriter.db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, writerPool.Close()) })
	for _, query := range []string{
		"INSERT INTO oauth_derived_issue_attestations (grant_ref) VALUES ('x')",
		"UPDATE oauth_derived_issue_attestations SET expires_at = 0",
		"DELETE FROM oauth_derived_issue_attestations",
		"SELECT 1 FROM oauth_derived_issue_attestations",
	} {
		assert.ErrorContains(t, service.Exec(query).Error, "denied")
	}
	assert.ErrorContains(t, writer.Exec("DELETE FROM oauth_derived_issue_attestations").Error, "denied")
	a := OAuthIssueAttestation{
		GrantRef: grant.GrantRef, ConsentRef: grant.ConsentRef, ProofDigest: strings.Repeat("a", 64), ProofFlowID: 1,
		UserID: 1, OriginSID: grant.OriginSID, SessionVersion: grant.SessionVersion, UserAuthVersion: grant.UserAuthVersion,
		Issuer: grant.Issuer, ClientID: grant.ClientID, Scopes: grant.Scopes, PolicyHash: grant.PolicyHash,
		BindingHash: strings.Repeat("c", 64), VerifiedMethod: "2fa", VerifiedAt: now - 1, ProofExpiresAt: now + 45,
		QuotaLimit: 65, ExpiresAt: now + 900,
	}
	t.Setenv("OAUTH_PROTECTED_SOURCE_OPS", "true")
	call := func(tx *gorm.DB) error {
		return reserveAttestedOAuthSource(tx, &grant)
	}
	approve := func(tx *gorm.DB) error {
		return tx.Model(&OAuthGrant{}).Where("grant_ref = ?", grant.GrantRef).
			Updates(map[string]any{"state": "approved", "approved_at": now, "revision": 2}).Error
	}
	require.ErrorIs(t, service.Transaction(func(tx *gorm.DB) error {
		require.NoError(t, approve(tx))
		return call(tx)
	}), ErrOAuthDerivedTokenUnknown)
	require.NoError(t, attestationWriter.Append(ctx, a))
	duplicate := a
	duplicate.GrantRef, duplicate.ConsentRef, duplicate.ProofFlowID = strings.Repeat("d", 64), strings.Repeat("e", 64), 17
	require.ErrorIs(t, attestationWriter.Append(ctx, duplicate), ErrOAuthDerivedTokenUnknown)
	require.ErrorIs(t, service.Transaction(call), ErrOAuthDerivedTokenUnknown)
	require.ErrorIs(t, service.Transaction(func(tx *gorm.DB) error {
		require.NoError(t, approve(tx))
		require.NoError(t, tx.Model(&grant).Update("scopes", `["tokens:write"]`).Error)
		return call(tx)
	}), ErrOAuthDerivedTokenUnknown)
	for _, commit := range []bool{false, true} {
		rollback := errors.New("rollback after successful reservation")
		err := service.Transaction(func(tx *gorm.DB) error {
			require.NoError(t, approve(tx))
			require.NoError(t, call(tx))
			if !commit {
				return rollback
			}
			return nil
		})
		var source OAuthDerivedTokenSource
		errSource := service.First(&source).Error
		if !commit {
			require.ErrorIs(t, err, rollback)
			require.ErrorIs(t, errSource, gorm.ErrRecordNotFound)
			continue
		}
		require.NoError(t, err)
		require.NoError(t, errSource)
		require.Equal(t, a.BindingHash, source.BindingHash)
		require.Equal(t, a.QuotaLimit, source.QuotaLimit)
		require.Nil(t, source.TokenID)
		hasReservation, err := OAuthGrantHasIssueReservation(ctx, grant.GrantRef)
		require.NoError(t, err)
		require.True(t, hasReservation)
	}
	if engine == "postgres" {
		require.NoError(t, admin.Exec("CREATE SCHEMA issue_fixture_shadow").Error)
		require.NoError(t, admin.Exec("CREATE TABLE issue_fixture_shadow.oauth_derived_token_sources (grant_ref char(64))").Error)
		require.NoError(t, admin.Exec("GRANT USAGE ON SCHEMA issue_fixture_shadow TO source_ops_service").Error)
		require.NoError(t, admin.Exec("GRANT SELECT ON issue_fixture_shadow.oauth_derived_token_sources TO source_ops_service").Error)
		require.NoError(t, service.Connection(func(conn *gorm.DB) error {
			require.NoError(t, conn.Exec("SET search_path TO issue_fixture_shadow, public").Error)
			defer conn.Exec("RESET search_path")
			DB = conn
			defer func() { DB = service }()
			reserved, err := OAuthGrantHasIssueReservation(ctx, grant.GrantRef)
			require.NoError(t, err)
			require.True(t, reserved)
			return nil
		}))
	}
	require.ErrorIs(t, service.Transaction(call), ErrOAuthDerivedTokenUnknown)
}

func TestOAuthFirstKeyDatabase(t *testing.T) {
	engine := os.Getenv("NEWAPI_FIRST_KEY_ENGINE")
	if engine == "" {
		t.Skip("requires the isolated protected-source installer and separate issuer account")
	}
	ctx := t.Context()
	target := os.Getenv("NEWAPI_FIRST_KEY_TARGET")
	require.Regexp(t, "^h29_key_[a-z0-9_]+$", target)
	open := func(raw string) *gorm.DB {
		dsn, _, err := oauthBootstrapDSN(engine, raw, target)
		require.NoError(t, err)
		db, err := openOAuthBootstrapDB(engine, dsn)
		require.NoError(t, err)
		pool, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, pool.Close()) })
		return db
	}
	adminDSN := os.Getenv("NEWAPI_FIRST_KEY_ADMIN_DSN")
	serviceDSN := os.Getenv("NEWAPI_FIRST_KEY_SERVICE_DSN")
	writerDSN := os.Getenv("NEWAPI_FIRST_KEY_ATTESTOR_DSN")
	issuerDSN := os.Getenv("NEWAPI_FIRST_KEY_ISSUER_DSN")
	admin := open(adminDSN)
	prior, master, kind := DB, common.IsMasterNode, common.MainDatabaseType()
	t.Cleanup(func() {
		DB, common.IsMasterNode = prior, master
		common.SetMainDatabaseType(kind)
	})
	DB, common.IsMasterNode = admin, true
	common.SetMainDatabaseType(common.DatabaseType(engine))
	require.NoError(t, InitOAuthGrantStore(true))
	require.NoError(t, admin.AutoMigrate(&SessionRevocationEvent{}))
	const gateway, attestor, issuer = "source_key_service", "source_key_attestor", "source_key_issuer"
	install := func() error {
		if engine == "postgres" {
			if err := installPostgresOAuthSourceOperations(admin, gateway); err != nil {
				return err
			}
			return admin.Transaction(func(tx *gorm.DB) error {
				if err := installOAuthIssueAttestations(tx, target, gateway, attestor); err != nil {
					return err
				}
				return installOAuthFirstKey(tx, target, gateway, attestor, issuer)
			})
		}
		return admin.Connection(func(tx *gorm.DB) error {
			if err := installMySQLOAuthSourceOperations(tx, target, gateway); err != nil {
				return err
			}
			if err := installOAuthIssueAttestations(tx, target, gateway, attestor); err != nil {
				return err
			}
			return installOAuthFirstKey(tx, target, gateway, attestor, issuer)
		})
	}
	require.NoError(t, install())
	if engine == "postgres" {
		require.NoError(t, admin.Exec("CREATE ROLE source_key_other LOGIN NOINHERIT").Error)
		require.NoError(t, admin.Exec("GRANT EXECUTE ON FUNCTION "+issueComplete+" TO source_key_other").Error)
		require.ErrorIs(t, install(), errOAuthBootstrap)
		require.NoError(t, admin.Exec("REVOKE EXECUTE ON FUNCTION "+issueComplete+" FROM source_key_other").Error)
		require.NoError(t, admin.Exec("DROP ROLE source_key_other").Error)
	} else {
		require.NoError(t, admin.Exec("CREATE USER 'source_key_other'@'localhost'").Error)
		require.NoError(t, admin.Exec("GRANT EXECUTE ON PROCEDURE `"+target+"`.`newapi_oauth_complete_issue` TO 'source_key_other'@'localhost'").Error)
		require.ErrorIs(t, install(), errOAuthBootstrap)
		require.NoError(t, admin.Exec("DROP USER 'source_key_other'@'localhost'").Error)
	}
	require.NoError(t, install())
	tables, err := issueReadTables(admin)
	require.NoError(t, err)
	for _, table := range append(tables, "users", "user_sessions", "o_auth_artifacts") {
		if engine == "postgres" {
			require.NoError(t, admin.Exec("GRANT SELECT ON public."+table+" TO "+gateway).Error)
		} else {
			require.NoError(t, admin.Exec("GRANT SELECT ON `"+target+"`.`"+table+"` TO '"+gateway+"'@'localhost'").Error)
		}
	}
	service := open(serviceDSN)
	writer := open(writerDSN)
	DB, common.IsMasterNode = service, false
	require.NoError(t, InitOAuthGrantStore(true))
	t.Setenv("SQL_DSN", serviceDSN)
	t.Setenv("OAUTH_PROTECTED_SOURCE_OPS", "true")
	_, err = OpenOAuthFirstKeyIssuer(ctx, serviceDSN, adminDSN)
	require.ErrorIs(t, err, ErrOAuthDerivedTokenUnknown)
	_, err = OpenOAuthFirstKeyIssuer(ctx, serviceDSN, writerDSN)
	require.ErrorIs(t, err, ErrOAuthDerivedTokenUnknown)
	executor, err := OpenOAuthFirstKeyIssuer(ctx, serviceDSN, issuerDSN)
	require.NoError(t, err)
	attestation, err := OpenOAuthIssueAttestationWriter(ctx, serviceDSN, writerDSN)
	require.NoError(t, err)
	keyRead := `SELECT "key" FROM tokens`
	if engine == "mysql" {
		keyRead = "SELECT `key` FROM tokens"
	}
	require.ErrorContains(t, executor.db.Exec(keyRead).Error, "denied")
	require.ErrorContains(t, executor.db.Exec("SELECT access_token FROM users").Error, "denied")
	require.ErrorContains(t, executor.db.Exec("UPDATE oauth_derived_token_sources SET terminal_at = 0").Error, "denied")
	guard := "SELECT newapi_oauth_source.lock_issue_grant(CAST(? AS bigint), CAST(? AS text))"
	if engine == "mysql" {
		guard = "CALL newapi_oauth_lock_issue_grant(?, ?)"
	}
	for _, conn := range []*gorm.DB{service, writer} {
		require.ErrorContains(t, conn.Exec(guard, 1, "invalid").Error, "denied")
	}
	now := time.Now().Unix()
	require.NoError(t, admin.Create(&User{Id: 1, Username: "key-fixture", Status: 1, AuthVersion: 3}).Error)
	require.NoError(t, admin.Create(&UserSession{SID: "key-session", UserID: 1, Status: "active",
		Version: 4, UserAuthVersion: 3, ExpiresAt: now + 3600}).Error)
	seed := func(n int, until int64) (*OAuthGrant, OAuthGrantAuthorization) {
		id := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(strconv.Itoa(n), 32)))
		grant := &OAuthGrant{GrantID: id, Issuer: "https://issuer.invalid/", ClientID: "fixture-client", Subject: "1",
			UserID: 1, ConsentRequestID: strconv.Itoa(n), OriginSID: "key-session", SessionVersion: 4, UserAuthVersion: 3,
			PolicyHash: strings.Repeat("b", 64), Scopes: `["profile","tokens:write"]`, State: "approved",
			Revision: 2, CreatedAt: now, ApprovedAt: now, ExpiresAt: now + 1800}
		grant.GrantRef, grant.ConsentRef = OAuthGrantRef(grant.Issuer, id), OAuthConsentRef(grant.Issuer, grant.ConsentRequestID)
		require.NoError(t, admin.Create(grant).Error)
		a := OAuthIssueAttestation{GrantRef: grant.GrantRef, ConsentRef: grant.ConsentRef, ProofFlowID: int64(10_000 + n),
			ProofDigest: fmt.Sprintf("%064x", n), UserID: 1, OriginSID: grant.OriginSID, SessionVersion: 4, UserAuthVersion: 3,
			Issuer: grant.Issuer, ClientID: grant.ClientID, Scopes: grant.Scopes, PolicyHash: grant.PolicyHash,
			BindingHash: strings.Repeat("c", 64), VerifiedMethod: "2fa", VerifiedAt: now - 5,
			ProofExpiresAt: now + 45, QuotaLimit: 105, ExpiresAt: now + 900}
		require.NoError(t, attestation.Append(ctx, a))
		require.NoError(t, service.Transaction(func(tx *gorm.DB) error { return reserveAttestedOAuthSource(tx, grant) }))
		require.NoError(t, admin.Model(grant).Updates(map[string]any{"state": "active", "revision": 3}).Error)
		if until < now {
			require.NoError(t, admin.Model(&OAuthDerivedTokenSource{}).Where("grant_ref = ?", grant.GrantRef).
				UpdateColumn("permit_deadline", now-1).Error)
		}
		return grant, OAuthGrantAuthorization{Issuer: grant.Issuer, GrantID: id, ClientID: grant.ClientID, Subject: "1",
			UserID: 1, AuthVersion: 3, GrantExpiresAt: grant.ExpiresAt, TokenExpiresAt: now + 800,
			Scopes: []string{"tokens:write", "profile"}}
	}
	grant, claims := seed(1, now+45)
	_, err = executor.Issue(ctx, claims, 2, "fixture", "idem-1")
	require.ErrorIs(t, err, ErrOAuthGrantInvalid)
	_, expired := seed(2, now-1)
	_, err = executor.Issue(ctx, expired, 3, "fixture", "idem-expired")
	require.ErrorIs(t, err, ErrOAuthIssueClosed)
	t.Run("binding_failure_rolls_back_key", func(t *testing.T) {
		drop := "DROP TRIGGER fixture_reject_source_update"
		create := `CREATE TRIGGER fixture_reject_source_update BEFORE UPDATE ON oauth_derived_token_sources
			FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture rollback'`
		if engine == "postgres" {
			require.NoError(t, admin.Exec(`CREATE FUNCTION fixture_reject_source_update() RETURNS trigger
				LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture rollback'; END;$$`).Error)
			create = `CREATE TRIGGER fixture_reject_source_update BEFORE UPDATE ON oauth_derived_token_sources
				FOR EACH ROW EXECUTE PROCEDURE fixture_reject_source_update()`
			drop += " ON oauth_derived_token_sources"
		}
		require.NoError(t, admin.Exec(create).Error)
		t.Cleanup(func() { require.NoError(t, admin.Exec(drop).Error) })
		_, err := executor.Issue(ctx, claims, 3, "fixture", "idem-1")
		require.ErrorIs(t, err, ErrOAuthDerivedTokenUnknown)
		var count int64
		require.NoError(t, admin.Model(&Token{}).Count(&count).Error)
		require.Zero(t, count)
	})
	var wg sync.WaitGroup
	var issued [2]*OAuthIssuedKey
	var failures [2]error
	for n := range issued {
		wg.Go(func() { issued[n], failures[n] = executor.Issue(ctx, claims, 3, "fixture", "idem-1") })
	}
	wg.Wait()
	require.NoError(t, failures[0])
	require.NoError(t, failures[1])
	require.Equal(t, issued[0].ID, issued[1].ID)
	require.NotEqual(t, issued[0].Key == "", issued[1].Key == "")
	_, err = executor.Issue(ctx, claims, 3, "new name", "idem-1")
	require.ErrorIs(t, err, ErrOAuthIssueConflict)
	_, err = executor.Issue(ctx, claims, 3, "fixture", "idem-other")
	require.ErrorIs(t, err, ErrOAuthIssueConflict)
	var source OAuthDerivedTokenSource
	require.NoError(t, admin.Where("grant_ref = ?", grant.GrantRef).First(&source).Error)
	var token Token
	require.NoError(t, admin.First(&token, issued[0].ID).Error)
	require.NoError(t, validateOAuthDerivedTokenBinding(&source, grant, &token, time.Now().Unix()))
	require.Equal(t, 105, token.RemainQuota)
	require.False(t, token.UnlimitedQuota)
	for n := 3; n <= 4; n++ {
		_, other := seed(n, now+45)
		_, err := executor.Issue(ctx, other, 3, "fixture", "idem-"+strconv.Itoa(n))
		require.NoError(t, err)
	}
	require.NoError(t, admin.Exec("UPDATE oauth_derived_token_sources SET terminal_at = ?, terminal_reason = 'revoked' WHERE grant_ref = ?", time.Now().Unix(), grant.GrantRef).Error)
	_, over := seed(5, now+45)
	_, err = executor.Issue(ctx, over, 3, "fixture", "idem-over")
	require.ErrorIs(t, err, ErrOAuthIssueLimit, "revocation does not refund the rolling success budget")
	var count int64
	require.NoError(t, admin.Model(&Token{}).Count(&count).Error)
	require.EqualValues(t, 3, count)
}
