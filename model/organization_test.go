package model

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	mysqlconfig "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

type organizationFixture struct {
	t          *testing.T
	identities []AuthSessionIdentity
}

// Only explicitly configured loopback test instances are accepted. Each suite
// owns a fresh database and drops only tables it created; no shared fixtures.
func organizationDatabase(t *testing.T, dialect string) *organizationFixture {
	t.Helper()
	var driver gorm.Dialector
	switch dialect {
	case "sqlite":
		driver = sqlite.Open(filepath.Join(t.TempDir(), "organization.db") + "?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)&_txlock=immediate")
	case "mysql":
		require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
		dsn := os.Getenv("TEST_MYSQL_DSN")
		require.NotEmpty(t, dsn)
		cfg, err := mysqlconfig.ParseDSN(dsn)
		require.NoError(t, err)
		host, _, err := net.SplitHostPort(cfg.Addr)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", host)
		require.Equal(t, "tcp", cfg.Net)
		require.True(t, strings.HasPrefix(cfg.DBName, "newapi_ci_"))
		driver = mysql.Open(dsn)
	case "postgres":
		require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
		dsn := os.Getenv("TEST_POSTGRES_DSN")
		require.NotEmpty(t, dsn)
		u, err := url.Parse(dsn)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", u.Hostname())
		require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "newapi_ci_"))
		driver = postgres.Open(dsn)
	default:
		t.Fatal("unknown test dialect")
	}
	// Production uses unprefixed tables. Foreign dialect suite owns an explicit
	// isolated test database; reject preexisting domain tables instead of deleting.
	db, err := gorm.Open(driver, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), NamingStrategy: schema.NamingStrategy{}})
	require.NoError(t, err)
	for _, v := range []any{&Organization{}, &OrganizationMember{}, &OrganizationInvitation{}, &OrganizationOwnershipTransfer{}, &OrganizationEvent{}} {
		require.False(t, db.Migrator().HasTable(v), "dedicated organization test database must be fresh")
	}
	previous, oldLog := DB, LOG_DB
	oldType := common.MainDatabaseType()
	oldRedis := common.RedisEnabled
	DB, LOG_DB = db, db
	common.SetMainDatabaseType(common.DatabaseType(dialect))
	common.RedisEnabled = false
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(6)
	sqlDB.SetMaxIdleConns(6)
	tables := []any{&User{}, &UserSession{}, &AuthFlow{}, &UserAccessToken{}, &ExternalIdentityClaim{}, &Token{}, &PasskeyCredential{}, &TwoFA{}, &TwoFABackupCode{}, &UserOAuthBinding{}, &Organization{}, &OrganizationMember{}, &OrganizationInvitation{}, &OrganizationOwnershipTransfer{}, &OrganizationEvent{}}
	owned := dialect == "sqlite"
	t.Cleanup(func() {
		if dialect != "sqlite" && owned {
			for j := len(tables) - 1; j >= 0; j-- {
				assert.NoError(t, db.Migrator().DropTable(tables[j]))
			}
		}
		assert.NoError(t, sqlDB.Close())
		DB, LOG_DB = previous, oldLog
		common.SetMainDatabaseType(oldType)
		common.RedisEnabled = oldRedis
		organizationNow = time.Now
	})
	// Claim remote fixtures only after proving the dedicated database is empty.
	if dialect != "sqlite" {
		names, err := db.Migrator().GetTables()
		require.NoError(t, err)
		require.Empty(t, names, "use a new dedicated newapi_ci_* database")
		owned = true
	}
	require.NoError(t, db.AutoMigrate(tables...))
	var version string
	q := "SELECT version()"
	if dialect == "sqlite" {
		q = "SELECT sqlite_version()"
		var mode string
		require.NoError(t, db.Raw("PRAGMA journal_mode").Scan(&mode).Error)
		require.Equal(t, "wal", mode)
	}
	require.NoError(t, db.Raw(q).Scan(&version).Error)
	t.Logf("%s %s; max connections 6; owned temporary database", dialect, version)
	f := &organizationFixture{t: t}
	for n := range 7 {
		u := User{Username: fmt.Sprintf("org-user-%d", n), AffCode: fmt.Sprintf("org-%d", n), Status: common.UserStatusEnabled, Role: common.RoleCommonUser, AuthVersion: 1, Password: "fixture-nonempty-password"}
		if n == 6 {
			u.Role = common.RoleRootUser
		}
		require.NoError(t, DB.Create(&u).Error)
		sid := fmt.Sprintf("organization-session-%d", u.Id)
		require.NoError(t, DB.Create(&UserSession{SID: sid, UserID: u.Id, Version: 1, UserAuthVersion: 1, Status: UserSessionStatusActive, RefreshHash: strings.Repeat("a", 64), LoginMethod: "password", ExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix()}).Error)
		f.identities = append(f.identities, AuthSessionIdentity{UserID: u.Id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
	}
	return f
}
func (f *organizationFixture) org(owner int) *Organization {
	o, err := CreateOrganization(f.identities[owner], "Organization")
	require.NoError(f.t, err)
	return o
}
func (f *organizationFixture) command(orgID int64) OrganizationCommand {
	var o Organization
	require.NoError(f.t, DB.First(&o, orgID).Error)
	return OrganizationCommand{OrganizationID: o.ID, Revision: o.Revision}
}
func (f *organizationFixture) proof(actor int, action string, c OrganizationCommand, b OrganizationAuthorizationBinding) *OrganizationAuthorization {
	return &OrganizationAuthorization{Identity: f.identities[actor], ProofID: 1, Action: action, Method: "password", ConsumedAt: time.Now().Unix() - 1, ValidUntil: time.Now().Unix() + 300, Binding: b}
}
func (f *organizationFixture) authorize(actor int, action string, c OrganizationCommand) OrganizationCommand {
	b := OrganizationAuthorizationBinding{OrganizationID: c.OrganizationID, Revision: c.Revision}
	switch action {
	case "change_role":
		b.TargetUserID = c.TargetUserID
		b.Role = c.Role
	case "remove":
		b.TargetUserID = c.TargetUserID
		b.Role = OrganizationRoleAdmin
	case "self_disable", "platform_disable":
		b.Disabled = c.Disabled
		b.Reason = c.Reason
	case "invite", "reissue":
		b.TargetUserID = c.TargetUserID
		b.Role = c.Role
		b.ObjectID = c.ObjectID
		b.Generation = c.Generation + 1
	case "transfer_initiate", "transfer_accept":
		var o Organization
		require.NoError(f.t, DB.First(&o, c.OrganizationID).Error)
		var v OrganizationOwnershipTransfer
		require.NoError(f.t, DB.Where("organization_id = ?", o.ID).Find(&v).Error)
		from, to := f.identities[actor].UserID, c.TargetUserID
		generation := v.Generation + 1
		if action == "transfer_accept" {
			from, to = v.FromUserID, v.ToUserID
			generation = v.Generation
		}
		var a, z OrganizationMember
		require.NoError(f.t, DB.Where("organization_id = ? AND user_id = ?", o.ID, from).First(&a).Error)
		require.NoError(f.t, DB.Where("organization_id = ? AND user_id = ?", o.ID, to).First(&z).Error)
		b.Replace = c.Replace
		b.TargetUserID = to
		b.ObjectID = v.ID
		b.Generation = generation
		b.FromUserID = from
		b.ToUserID = to
		b.OwnershipVersion = o.OwnershipVersion
		b.FromMemberRevision = a.Revision
		b.ToMemberRevision = z.Revision
	}
	c.Authorization = f.proof(actor, action, c, b)
	return c
}
func (f *organizationFixture) invite(orgID int64, actor, target int, role string) OrganizationInvitation {
	c := f.command(orgID)
	c.TargetUserID = f.identities[target].UserID
	c.Role = role
	if role == OrganizationRoleAdmin {
		c = f.authorize(actor, "invite", c)
	}
	require.NoError(f.t, InviteOrganizationMember(f.identities[actor], c))
	var v OrganizationInvitation
	require.NoError(f.t, DB.Where("organization_id = ? AND target_user_id = ?", orgID, c.TargetUserID).First(&v).Error)
	return v
}
func (f *organizationFixture) accept(orgID int64, target int, v OrganizationInvitation) {
	c := f.command(orgID)
	c.ObjectID = v.ID
	c.Generation = v.Generation
	require.NoError(f.t, AcceptOrganizationInvitation(f.identities[target], c))
}
func (f *organizationFixture) join(orgID int64, actor, target int, role string) {
	v := f.invite(orgID, actor, target, role)
	f.accept(orgID, target, v)
}

// Default execution is SQLite only. Strict A03 runs require all three children;
// selecting a remote child without its DSN fails, never falls back or skips.
func TestOrganizationLifecycleDatabaseMatrix(t *testing.T) {
	dialects := []string{"sqlite"}
	if os.Getenv("NEWAPI_REQUIRE_DATABASES") == "1" {
		dialects = []string{"sqlite", "mysql", "postgres"}
	} else if d := os.Getenv("TEST_ORGANIZATION_DIALECT"); d != "" {
		dialects = []string{d}
	}
	for _, dialect := range dialects {
		t.Run(dialect, func(t *testing.T) {
			t.Run("lifecycle", func(t *testing.T) { testOrganizationLifecycle(t, organizationDatabase(t, dialect)) })
			t.Run("authorization", func(t *testing.T) { testOrganizationAuthorization(t, organizationDatabase(t, dialect)) })
			t.Run("history_and_expiry", func(t *testing.T) { testOrganizationHistory(t, organizationDatabase(t, dialect)) })
			t.Run("event_rollback_and_deletion", func(t *testing.T) { testOrganizationRollback(t, organizationDatabase(t, dialect)) })
			t.Run("concurrency", func(t *testing.T) { testOrganizationConcurrency(t, organizationDatabase(t, dialect)) })
			t.Run("transfer_replacement_rollback", func(t *testing.T) { testOrganizationTransferRollback(t, organizationDatabase(t, dialect)) })
			t.Run("read_permissions", func(t *testing.T) { testOrganizationReads(t, organizationDatabase(t, dialect)) })
			t.Run("schema", func(t *testing.T) { testOrganizationSchema(t, organizationDatabase(t, dialect)) })
			t.Run("invitation_revision_disclosure", func(t *testing.T) {
				f := organizationDatabase(t, dialect)
				base := time.Now().Unix()
				deadline := base + 120
				var clock atomic.Int64
				clock.Store(base)
				organizationNow = func() time.Time { return time.Unix(clock.Load(), 0) }
				t.Cleanup(func() { organizationNow = time.Now })
				o := f.org(0)
				command := f.command(o.ID)
				rename := command
				rename.Name = "advanced revision"
				require.NoError(t, RenameOrganization(f.identities[0], rename))
				current := f.command(o.ID).Revision
				command.TargetUserID, command.Role = f.identities[1].UserID, OrganizationRoleMember
				require.NoError(t, DB.Model(&UserSession{}).Where("sid = ?", f.identities[0].SessionID).Update("expires_at", deadline).Error)
				_, err := ExecuteOrganizationCommandWithContext(t.Context(), f.identities[0], "invite", command)
				require.ErrorIs(t, err, ErrOrganizationConflict)
				var disclosed *OrganizationRevisionConflictError
				require.ErrorAs(t, err, &disclosed)
				assert.Equal(t, current, disclosed.Revision)
				var eventsBefore int64
				require.NoError(t, DB.Model(&OrganizationEvent{}).Where("organization_id = ?", o.ID).Count(&eventsBefore).Error)
				var expired atomic.Bool
				const callback = "organization:invitation_revision_expiry"
				require.NoError(t, DB.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
					organization, selected := tx.Statement.Dest.(*Organization)
					_, inTransaction := tx.Statement.ConnPool.(gorm.TxCommitter)
					if selected && inTransaction && organization.ID == o.ID && expired.CompareAndSwap(false, true) {
						// Identity/session were valid and locked before this organization
						// read. Advance past expiry as a completed lock wait would.
						clock.Store(deadline)
					}
				}))
				t.Cleanup(func() { _ = DB.Callback().Query().Remove(callback) })
				_, err = ExecuteOrganizationCommandWithContext(t.Context(), f.identities[0], "invite", command)
				require.ErrorIs(t, err, ErrOrganizationConflict)
				var hidden *OrganizationRevisionConflictError
				assert.False(t, errors.As(err, &hidden), "session expiry after identity validation must suppress revision disclosure")
				assert.True(t, expired.Load(), "the clock must advance after the transactional organization read")
				var eventsAfter, invitations int64
				require.NoError(t, DB.Model(&OrganizationEvent{}).Where("organization_id = ?", o.ID).Count(&eventsAfter).Error)
				require.NoError(t, DB.Model(&OrganizationInvitation{}).Where("organization_id = ?", o.ID).Count(&invitations).Error)
				assert.Equal(t, eventsBefore, eventsAfter)
				assert.Zero(t, invitations)
			})
			if dialect == "mysql" || dialect == "postgres" {
				for _, subject := range []string{"session", "authorization", "invitation", "transfer"} {
					t.Run("row_lock_expiry/"+subject, func(t *testing.T) {
						testOrganizationRowLockExpiry(t, organizationDatabase(t, dialect), dialect, subject)
					})
				}
			}
		})
	}
}

func testOrganizationLifecycle(t *testing.T, f *organizationFixture) {
	o := f.org(0)
	f.join(o.ID, 0, 1, OrganizationRoleAdmin)
	f.join(o.ID, 1, 2, OrganizationRoleMember)
	c := f.command(o.ID)
	c.Name = "Renamed"
	require.NoError(t, RenameOrganization(f.identities[1], c))
	c = f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	c.Role = OrganizationRoleMember
	require.NoError(t, ChangeOrganizationMemberRole(f.identities[0], f.authorize(0, "change_role", c)))
	c = f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	c.Role = OrganizationRoleAdmin
	require.NoError(t, ChangeOrganizationMemberRole(f.identities[0], f.authorize(0, "change_role", c)))
	require.ErrorIs(t, LeaveOrganization(f.identities[0], f.command(o.ID)), ErrOrganizationForbidden)
	c = f.command(o.ID)
	c.TargetUserID = f.identities[2].UserID
	require.NoError(t, RemoveOrganizationMember(f.identities[1], c))
	var removed OrganizationMember
	require.NoError(t, DB.Where("organization_id = ? AND user_id = ?", o.ID, c.TargetUserID).First(&removed).Error)
	c = f.command(o.ID)
	var invitation OrganizationInvitation
	require.NoError(t, DB.Where("organization_id = ? AND target_user_id = ?", o.ID, removed.UserID).First(&invitation).Error)
	c.TargetUserID = removed.UserID
	c.Role = OrganizationRoleMember
	c.ObjectID = invitation.ID
	c.Generation = invitation.Generation
	require.NoError(t, ReissueOrganizationInvitation(f.identities[0], c))
	require.NoError(t, DB.First(&invitation, invitation.ID).Error)
	f.accept(o.ID, 2, invitation)
	var restored OrganizationMember
	require.NoError(t, DB.First(&restored, removed.ID).Error)
	assert.Equal(t, removed.ID, restored.ID)
	assert.Greater(t, restored.Revision, removed.Revision)
	c = f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	require.NoError(t, InitiateOrganizationOwnershipTransfer(f.identities[0], f.authorize(0, "transfer_initiate", c)))
	var tr OrganizationOwnershipTransfer
	require.NoError(t, DB.Where("organization_id = ?", o.ID).First(&tr).Error)
	c = f.command(o.ID)
	c.ObjectID = tr.ID
	c.Generation = tr.Generation
	require.NoError(t, AcceptOrganizationOwnershipTransfer(f.identities[1], f.authorize(1, "transfer_accept", c)))
	view, err := GetOrganizationForActor(f.identities[1], o.ID)
	require.NoError(t, err)
	assert.Equal(t, OrganizationRoleOwner, view.MyRole)
	view, err = GetOrganizationForActor(f.identities[0], o.ID)
	require.NoError(t, err)
	assert.Equal(t, OrganizationRoleAdmin, view.MyRole)
	c = f.command(o.ID)
	c.Disabled = true
	require.NoError(t, SetOrganizationSelfDisabled(f.identities[1], f.authorize(1, "self_disable", c)))
	c = f.command(o.ID)
	c.Disabled = true
	require.NoError(t, SetOrganizationPlatformDisabled(f.identities[6], f.authorize(6, "platform_disable", c)))
	c = f.command(o.ID)
	require.NoError(t, SetOrganizationPlatformDisabled(f.identities[6], f.authorize(6, "platform_disable", c)))
	view, err = GetOrganizationForActor(f.identities[1], o.ID)
	require.NoError(t, err)
	assert.True(t, view.SelfDisabled)
	assert.False(t, view.PlatformDisabled)
	_, err = ListOrganizationMembersForActor(f.identities[1], o.ID, OrganizationPage{Limit: 10})
	require.ErrorIs(t, err, ErrOrganizationDisabled)
	require.NoError(t, LeaveOrganization(f.identities[2], f.command(o.ID)))
	c = f.command(o.ID)
	require.NoError(t, SetOrganizationSelfDisabled(f.identities[1], f.authorize(1, "self_disable", c)))
	c = f.command(o.ID)
	require.NoError(t, DissolveOrganization(f.identities[1], f.authorize(1, "dissolve", c)))
	assert.ErrorIs(t, RenameOrganization(f.identities[1], OrganizationCommand{OrganizationID: o.ID, Revision: f.command(o.ID).Revision, Name: "no"}), ErrOrganizationTerminal)
}

func testOrganizationAuthorization(t *testing.T, f *organizationFixture) {
	o := f.org(0)
	f.join(o.ID, 0, 1, OrganizationRoleMember)
	c := f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	c.Role = OrganizationRoleAdmin
	assert.ErrorIs(t, ChangeOrganizationMemberRole(f.identities[0], c), ErrOrganizationForbidden)
	c = f.authorize(0, "change_role", c)
	// Every identity and action-binding scalar is independently substituted.
	for _, section := range []string{"record", "identity", "binding"} {
		original := *c.Authorization
		var value reflect.Value
		switch section {
		case "record":
			value = reflect.ValueOf(&original).Elem()
		case "identity":
			value = reflect.ValueOf(&original.Identity).Elem()
		case "binding":
			value = reflect.ValueOf(&original.Binding).Elem()
		}
		for n := range value.NumField() {
			field := value.Field(n)
			if field.Kind() == reflect.Struct {
				continue
			}
			saved := reflect.New(field.Type()).Elem()
			saved.Set(field)
			switch field.Kind() {
			case reflect.String:
				field.SetString("incorrect")
			case reflect.Int, reflect.Int64:
				field.SetInt(field.Int() + 1)
			case reflect.Bool:
				field.SetBool(!field.Bool())
			default:
				continue
			}
			bad := c
			copyAuth := original
			bad.Authorization = &copyAuth
			// ProofID is supplied by the trusted adapter; changing one positive ID is
			// not cryptographic forgery detection. Invalid zero IDs are rejected.
			name := value.Type().Field(n).Name
			if section == "record" && (name == "ProofID" || name == "ConsumedAt" || name == "ValidUntil") {
				field.SetInt(0)
				copyAuth = original
			}
			assert.Error(t, ChangeOrganizationMemberRole(f.identities[0], bad), section+"."+name)
			field.Set(saved)
		}
	}
	require.NoError(t, ChangeOrganizationMemberRole(f.identities[0], c))
	c = f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	c.Role = OrganizationRoleAdmin
	assert.ErrorIs(t, ChangeOrganizationMemberRole(f.identities[0], f.authorize(0, "change_role", c)), ErrOrganizationConflict)
	c = f.command(o.ID)
	c.TargetUserID = f.identities[2].UserID
	c.Role = OrganizationRoleAdmin
	assert.ErrorIs(t, InviteOrganizationMember(f.identities[1], c), ErrOrganizationForbidden)
	c = f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	assert.ErrorIs(t, RemoveOrganizationMember(f.identities[0], c), ErrOrganizationForbidden)
	for _, sid := range []string{"", "pat:1", "legacy:1", "missing"} {
		identity := f.identities[0]
		identity.SessionID = sid
		_, err := CreateOrganization(identity, "bad")
		assert.Error(t, err)
	}
	_, err := GetOrganizationForActor(f.identities[6], o.ID)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
	c = f.command(o.ID)
	c.Name = "forbidden"
	assert.ErrorIs(t, RenameOrganization(f.identities[6], c), ErrOrganizationForbidden)
	c = f.command(o.ID)
	c.Name = "changed"
	c.TargetUserID = 1
	assert.ErrorIs(t, RenameOrganization(f.identities[0], c), ErrOrganizationInvalidInput)
	var inv OrganizationInvitation
	inv = f.invite(o.ID, 1, 2, OrganizationRoleMember)
	require.NoError(t, DB.Model(&User{}).Where("id = ?", f.identities[1].UserID).Update("status", common.UserStatusDisabled).Error)
	c = f.command(o.ID)
	c.ObjectID = inv.ID
	c.Generation = inv.Generation
	assert.ErrorIs(t, AcceptOrganizationInvitation(f.identities[2], c), ErrOrganizationForbidden)
	require.NoError(t, DB.Model(&User{}).Where("id = ?", f.identities[1].UserID).Update("status", common.UserStatusEnabled).Error)
	for _, change := range []string{"disabled", "deleted", "revoked"} {
		switch change {
		case "disabled":
			require.NoError(t, DB.Model(&User{}).Where("id = ?", f.identities[5].UserID).Update("status", common.UserStatusDisabled).Error)
		case "deleted":
			require.NoError(t, DB.Model(&User{}).Where("id = ?", f.identities[5].UserID).Update("deleted_at", time.Now()).Error)
		case "revoked":
			require.NoError(t, DB.Model(&UserSession{}).Where("sid = ?", f.identities[5].SessionID).Update("status", UserSessionStatusRevoked).Error)
		}
		_, err := CreateOrganization(f.identities[5], "invalid actor")
		assert.Error(t, err, change)
		require.NoError(t, DB.Unscoped().Model(&User{}).Where("id = ?", f.identities[5].UserID).Updates(map[string]any{"status": common.UserStatusEnabled, "deleted_at": nil}).Error)
	}
	rootChange := f.command(o.ID)
	rootChange.Disabled = true
	require.NoError(t, DB.Model(&User{}).Where("id = ?", f.identities[6].UserID).Update("role", common.RoleAdminUser).Error)
	assert.ErrorIs(t, SetOrganizationPlatformDisabled(f.identities[6], f.authorize(6, "platform_disable", rootChange)), ErrOrganizationForbidden)
	require.NoError(t, DB.Model(&User{}).Where("id = ?", f.identities[6].UserID).Update("role", common.RoleRootUser).Error)
	other := f.org(3)
	c = f.command(other.ID)
	c.ObjectID = inv.ID
	c.Generation = inv.Generation
	assert.ErrorIs(t, AcceptOrganizationInvitation(f.identities[2], c), ErrOrganizationNotFound)
	require.NoError(t, DB.Model(&Organization{}).Where("id = ?", other.ID).Update("revision", int64(math.MaxInt64)).Error)
	c = f.command(other.ID)
	c.Name = "overflow"
	assert.ErrorIs(t, RenameOrganization(f.identities[3], c), ErrOrganizationConflict)
}

func testOrganizationHistory(t *testing.T, f *organizationFixture) {
	o := f.org(0)
	v := f.invite(o.ID, 0, 3, OrganizationRoleAdmin)
	original := v
	c := f.command(o.ID)
	c.ObjectID = v.ID
	c.Generation = v.Generation
	require.NoError(t, DeclineOrganizationInvitation(f.identities[3], c))
	for range 2 {
		c = f.command(o.ID)
		c.ObjectID = v.ID
		c.Generation = v.Generation
		c.TargetUserID = v.TargetUserID
		c.Role = OrganizationRoleMember
		require.NoError(t, ReissueOrganizationInvitation(f.identities[0], c))
		require.NoError(t, DB.First(&v, v.ID).Error)
	}
	result, err := GetOrganizationInvitationResult(f.identities[3], o.ID, v.ID, original.Generation)
	require.NoError(t, err)
	assert.Equal(t, OrganizationDeclined, result.Status)
	assert.Equal(t, OrganizationRoleAdmin, result.Role)
	assert.Equal(t, original.ExpiresAt, result.ExpiresAt)
	result, err = GetOrganizationInvitationResult(f.identities[3], o.ID, v.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, OrganizationRevoked, result.Status)
	assert.Equal(t, "reissued", result.ReasonCode)
	_, err = GetOrganizationInvitationResult(f.identities[4], o.ID, v.ID, 1)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
	c = f.command(o.ID)
	c.ObjectID = v.ID
	c.Generation = 1
	assert.ErrorIs(t, AcceptOrganizationInvitation(f.identities[3], c), ErrOrganizationConflict)
	now := time.Now().Unix()
	require.NoError(t, DB.Model(&OrganizationInvitation{}).Where("id = ?", v.ID).Update("expires_at", now).Error)
	c.Generation = v.Generation
	assert.ErrorIs(t, AcceptOrganizationInvitation(f.identities[3], c), ErrOrganizationExpired)
	require.NoError(t, ExpireOrganizationInvitations(o.ID))
	require.NoError(t, DB.First(&v, v.ID).Error)
	assert.Equal(t, OrganizationExpired, v.Status)
	f.join(o.ID, 0, 1, OrganizationRoleMember)
	c = f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	require.NoError(t, InitiateOrganizationOwnershipTransfer(f.identities[0], f.authorize(0, "transfer_initiate", c)))
	var tr OrganizationOwnershipTransfer
	require.NoError(t, DB.Where("organization_id = ?", o.ID).First(&tr).Error)
	c = f.command(o.ID)
	c.ObjectID = tr.ID
	c.Generation = tr.Generation
	require.NoError(t, DeclineOrganizationOwnershipTransfer(f.identities[1], c))
	result, err = GetOrganizationOwnershipTransferResult(f.identities[0], o.ID, tr.ID, tr.Generation)
	require.NoError(t, err)
	assert.Equal(t, OrganizationDeclined, result.Status)
	c = f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	c.ObjectID = tr.ID
	c.Generation = tr.Generation
	require.NoError(t, InitiateOrganizationOwnershipTransfer(f.identities[0], f.authorize(0, "transfer_initiate", c)))
	require.NoError(t, DB.First(&tr, tr.ID).Error)
	c = f.command(o.ID)
	c.ObjectID = tr.ID
	c.Generation = tr.Generation
	require.NoError(t, CancelOrganizationOwnershipTransfer(f.identities[0], c))
	c = f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	c.ObjectID = tr.ID
	c.Generation = tr.Generation
	require.NoError(t, InitiateOrganizationOwnershipTransfer(f.identities[0], f.authorize(0, "transfer_initiate", c)))
	require.NoError(t, DB.First(&tr, tr.ID).Error)
	require.NoError(t, DB.Model(&tr).Update("expires_at", now).Error)
	require.NoError(t, ExpireOrganizationOwnershipTransfer(o.ID))
	require.NoError(t, DB.First(&tr, tr.ID).Error)
	assert.Equal(t, OrganizationExpired, tr.Status)
	inv := f.invite(o.ID, 0, 4, OrganizationRoleMember)
	c = f.command(o.ID)
	c.Disabled = true
	require.NoError(t, SetOrganizationSelfDisabled(f.identities[0], f.authorize(0, "self_disable", c)))
	result, err = GetOrganizationInvitationResult(f.identities[4], o.ID, inv.ID, inv.Generation)
	require.NoError(t, err)
	assert.Equal(t, OrganizationRevoked, result.Status)
	_, err = ListOrganizationEventsForActor(f.identities[4], o.ID, OrganizationPage{Limit: 10})
	assert.ErrorIs(t, err, ErrOrganizationForbidden)
}

func testOrganizationRollback(t *testing.T, f *organizationFixture) {
	o := f.org(0)
	inv := f.invite(o.ID, 0, 5, OrganizationRoleMember)
	before := f.command(o.ID)
	require.NoError(t, DB.Callback().Create().Before("gorm:create").Register("organization-event-failure", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "OrganizationEvent" {
			tx.AddError(errors.New("injected event failure"))
		}
	}))
	c := before
	c.ObjectID = inv.ID
	c.Generation = inv.Generation
	err := AcceptOrganizationInvitation(f.identities[5], c)
	require.ErrorContains(t, err, "injected event failure")
	require.NoError(t, DB.Callback().Create().Remove("organization-event-failure"))
	assert.Equal(t, before.Revision, f.command(o.ID).Revision)
	var count int64
	require.NoError(t, DB.Model(&OrganizationMember{}).Where("organization_id = ? AND user_id = ?", o.ID, f.identities[5].UserID).Count(&count).Error)
	assert.Zero(t, count)
	require.NoError(t, DB.First(&inv, inv.ID).Error)
	assert.Equal(t, OrganizationPending, inv.Status)
	f.accept(o.ID, 5, inv)
	server := useUserCacheMiniRedis(t)
	uid := f.identities[5].UserID
	var user User
	require.NoError(t, DB.First(&user, uid).Error)
	_, err = user.Delete()
	assert.ErrorIs(t, err, ErrOrganizationMembershipActive)
	_, err = user.HardDelete()
	assert.ErrorIs(t, err, ErrOrganizationMembershipActive)
	assert.False(t, server.Exists(getUserAuthFenceKey(uid)))
	var after User
	require.NoError(t, DB.First(&after, uid).Error)
	assert.Equal(t, user.AuthVersion, after.AuthVersion)
	require.NoError(t, LeaveOrganization(f.identities[5], f.command(o.ID)))
	_, err = user.Delete()
	require.NoError(t, err)
}

// Instrument the actual SQL BeginTx boundary, not a single-connection mock.
// Tests can prove the contender reaches transaction acquisition while a winner
// holds its transaction; SQLite queues it at BEGIN IMMEDIATE.
type organizationBeginPool struct {
	*sql.DB
	attempted chan struct{}
	begins    atomic.Int32
}

func (p *organizationBeginPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	if p.begins.Add(1) == 2 {
		close(p.attempted)
	}
	return p.DB.BeginTx(ctx, opts)
}

func testOrganizationConcurrency(t *testing.T, f *organizationFixture) {
	for _, race := range []string{"accept_accept", "revoke_accept", "disable_accept", "remove_transfer", "cancel_transfer", "delete_join", "lock_wait_expiry", "reissue_accept", "platform_disable_accept", "proof_wait_expiry", "invitation_wait_expiry", "transfer_accept_accept"} {
		t.Run(race, func(t *testing.T) {
			o := f.org(0)
			v := f.invite(o.ID, 0, 4, OrganizationRoleMember)
			c := f.command(o.ID)
			c.ObjectID = v.ID
			c.Generation = v.Generation
			var winning, losing func() error
			winning = func() error { return AcceptOrganizationInvitation(f.identities[4], c) }
			losing = func() error { return AcceptOrganizationInvitation(f.identities[4], c) }
			switch race {
			case "revoke_accept":
				winning = func() error { return RevokeOrganizationInvitation(f.identities[0], c) }
			case "reissue_accept":
				reissue := c
				reissue.TargetUserID = v.TargetUserID
				reissue.Role = OrganizationRoleMember
				winning = func() error { return ReissueOrganizationInvitation(f.identities[0], reissue) }
			case "platform_disable_accept":
				d := f.command(o.ID)
				d.Disabled = true
				d = f.authorize(6, "platform_disable", d)
				winning = func() error { return SetOrganizationPlatformDisabled(f.identities[6], d) }
			case "proof_wait_expiry", "invitation_wait_expiry":
				holder := f.org(0)
				rename := f.command(holder.ID)
				rename.Name = "independent lock holder"
				winning = func() error { return RenameOrganization(f.identities[0], rename) }
				if race == "proof_wait_expiry" {
					d := f.command(o.ID)
					d.Disabled = true
					d = f.authorize(0, "self_disable", d)
					d.Authorization.ValidUntil = time.Now().Unix() + 10
					losing = func() error { return SetOrganizationSelfDisabled(f.identities[0], d) }
				}
			case "disable_accept":
				d := f.command(o.ID)
				d.Disabled = true
				d = f.authorize(0, "self_disable", d)
				winning = func() error { return SetOrganizationSelfDisabled(f.identities[0], d) }
			case "delete_join":
				// A committed join must cause concurrent deletion to refuse before fencing.
				losing = func() error { u := User{Id: f.identities[4].UserID}; _, err := u.Delete(); return err }
			case "remove_transfer", "cancel_transfer", "transfer_accept_accept":
				f.accept(o.ID, 4, v)
				trc := f.command(o.ID)
				trc.TargetUserID = f.identities[4].UserID
				require.NoError(t, InitiateOrganizationOwnershipTransfer(f.identities[0], f.authorize(0, "transfer_initiate", trc)))
				var tr OrganizationOwnershipTransfer
				require.NoError(t, DB.Where("organization_id = ?", o.ID).First(&tr).Error)
				accept := f.command(o.ID)
				accept.ObjectID = tr.ID
				accept.Generation = tr.Generation
				accept = f.authorize(4, "transfer_accept", accept)
				losing = func() error { return AcceptOrganizationOwnershipTransfer(f.identities[4], accept) }
				if race == "transfer_accept_accept" {
					winning = func() error { return AcceptOrganizationOwnershipTransfer(f.identities[4], accept) }
				} else if race == "remove_transfer" {
					remove := f.command(o.ID)
					remove.TargetUserID = f.identities[4].UserID
					winning = func() error { return RemoveOrganizationMember(f.identities[0], remove) }
				} else {
					cancel := f.command(o.ID)
					cancel.ObjectID = tr.ID
					cancel.Generation = tr.Generation
					winning = func() error { return CancelOrganizationOwnershipTransfer(f.identities[0], cancel) }
				}
			case "lock_wait_expiry":
				rename := f.command(o.ID)
				rename.Name = "lock holder"
				winning = func() error { return RenameOrganization(f.identities[0], rename) }
			}
			sqlDB, err := DB.DB()
			require.NoError(t, err)
			pool := &organizationBeginPool{DB: sqlDB, attempted: make(chan struct{})}
			originalPool, originalStatementPool := DB.ConnPool, DB.Statement.ConnPool
			DB.ConnPool = pool
			DB.Statement.ConnPool = pool
			entered, release := make(chan struct{}), make(chan struct{})
			var first atomic.Bool
			require.NoError(t, DB.Callback().Create().Before("gorm:create").Register("organization-event-barrier", func(tx *gorm.DB) {
				if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "OrganizationEvent" && first.CompareAndSwap(false, true) {
					close(entered)
					<-release
				}
			}))
			var clock atomic.Int64
			clock.Store(time.Now().Unix())
			organizationNow = func() time.Time { return time.Unix(clock.Load(), 0) }
			winner, loser := make(chan error, 1), make(chan error, 1)
			go func() { winner <- winning() }()
			<-entered
			go func() { loser <- losing() }()
			<-pool.attempted
			if race == "lock_wait_expiry" {
				clock.Store(time.Now().Add(31 * 24 * time.Hour).Unix())
			}
			if race == "proof_wait_expiry" {
				clock.Store(time.Now().Unix() + 10)
			}
			if race == "invitation_wait_expiry" {
				clock.Store(v.ExpiresAt)
			}
			close(release)
			winErr, loseErr := <-winner, <-loser
			organizationNow = time.Now
			DB.ConnPool = originalPool
			DB.Statement.ConnPool = originalStatementPool
			require.NoError(t, DB.Callback().Create().Remove("organization-event-barrier"))
			require.NoError(t, winErr)
			require.Error(t, loseErr)
			if race == "delete_join" {
				assert.ErrorIs(t, loseErr, ErrOrganizationMembershipActive)
			}
			if race == "lock_wait_expiry" {
				assert.ErrorIs(t, loseErr, ErrOrganizationUnauthenticated)
			}
			if race == "proof_wait_expiry" {
				assert.ErrorIs(t, loseErr, ErrOrganizationForbidden)
			}
			if race == "invitation_wait_expiry" {
				assert.ErrorIs(t, loseErr, ErrOrganizationExpired)
			}
			if race == "platform_disable_accept" {
				restore := f.command(o.ID)
				require.NoError(t, SetOrganizationPlatformDisabled(f.identities[6], f.authorize(6, "platform_disable", restore)))
			}
			var slots int64
			require.NoError(t, DB.Model(&OrganizationMember{}).Where("organization_id = ? AND user_id = ? AND removed_at = 0", o.ID, f.identities[4].UserID).Count(&slots).Error)
			expected := int64(0)
			if race == "accept_accept" || race == "delete_join" || race == "cancel_transfer" || race == "transfer_accept_accept" {
				expected = 1
			}
			assert.Equal(t, expected, slots)
			var saved Organization
			require.NoError(t, DB.First(&saved, o.ID).Error)
			owner := 0
			if race == "transfer_accept_accept" {
				owner = 4
				assert.EqualValues(t, 2, saved.OwnershipVersion)
			}
			assert.Equal(t, f.identities[owner].UserID, saved.OwnerUserID)
			dissolve := f.command(o.ID)
			require.NoError(t, DissolveOrganization(f.identities[owner], f.authorize(owner, "dissolve", dissolve)))
		})
	}
}
func testOrganizationSchema(t *testing.T, f *organizationFixture) {
	tables := []any{&Organization{}, &OrganizationMember{}, &OrganizationInvitation{}, &OrganizationOwnershipTransfer{}, &OrganizationEvent{}}
	require.NoError(t, DB.AutoMigrate(tables...))
	require.NoError(t, DB.AutoMigrate(tables...))
	o := f.org(0)
	inv := f.invite(o.ID, 0, 1, OrganizationRoleMember)
	var before Organization
	require.NoError(t, DB.First(&before, o.ID).Error)
	require.NoError(t, DB.AutoMigrate(tables...))
	require.NoError(t, DB.AutoMigrate(tables...))
	var after Organization
	require.NoError(t, DB.First(&after, o.ID).Error)
	assert.Equal(t, before, after)
	duplicate := inv
	duplicate.ID = 0
	assert.Error(t, DB.Create(&duplicate).Error)
	var m OrganizationMember
	require.NoError(t, DB.Where("organization_id = ?", o.ID).First(&m).Error)
	m.ID = 0
	assert.Error(t, DB.Create(&m).Error)
	for _, name := range []string{"uq_org_member", "idx_org_member_user"} {
		assert.True(t, DB.Migrator().HasIndex(&OrganizationMember{}, name))
	}
	for _, name := range []string{"uq_org_invitee", "idx_org_invitee_inbox"} {
		assert.True(t, DB.Migrator().HasIndex(&OrganizationInvitation{}, name))
	}
	assert.True(t, DB.Migrator().HasIndex(&OrganizationOwnershipTransfer{}, "uq_org_transfer"))
}

func testOrganizationReads(t *testing.T, f *organizationFixture) {
	o := f.org(0)
	other := f.org(3)
	f.join(o.ID, 0, 1, OrganizationRoleAdmin)
	f.join(o.ID, 0, 2, OrganizationRoleMember)
	invitation := f.invite(o.ID, 0, 4, OrganizationRoleMember)
	_ = f.invite(other.ID, 3, 5, OrganizationRoleMember)
	page := OrganizationPage{Limit: 1}
	orgs, err := ListOrganizationsForActor(f.identities[2], page)
	require.NoError(t, err)
	require.Len(t, orgs, 1)
	assert.Equal(t, o.ID, orgs[0].ID)
	assert.Equal(t, OrganizationRoleMember, orgs[0].MyRole)
	page.AfterID = orgs[0].ID
	orgs, err = ListOrganizationsForActor(f.identities[2], page)
	require.NoError(t, err)
	assert.Empty(t, orgs)
	page.AfterID = 0
	members, err := ListOrganizationMembersForActor(f.identities[2], o.ID, page)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, OrganizationRoleOwner, members[0].Role)
	page.AfterID = members[0].ID
	next, err := ListOrganizationMembersForActor(f.identities[2], o.ID, page)
	require.NoError(t, err)
	require.Len(t, next, 1)
	assert.Greater(t, next[0].ID, members[0].ID)
	page.AfterID = 0
	_, err = ListOrganizationMembersForActor(f.identities[2], other.ID, page)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
	_, err = ListOrganizationEventsForActor(f.identities[2], o.ID, page)
	assert.ErrorIs(t, err, ErrOrganizationForbidden)
	events, err := ListOrganizationEventsForActor(f.identities[1], o.ID, page)
	require.NoError(t, err)
	require.Len(t, events, 1)
	inbox, err := ListPendingOrganizationInvitationsForActor(f.identities[4], page)
	require.NoError(t, err)
	require.Len(t, inbox, 1)
	assert.Equal(t, invitation.ID, inbox[0].ObjectID)
	ctx := context.Background()
	targetView, err := GetOrganizationInvitationResultWithContext(ctx, f.identities[4], o.ID, invitation.ID, invitation.Generation)
	require.NoError(t, err)
	require.NotNil(t, targetView.OrganizationRevision)
	assert.Equal(t, OrganizationPending, targetView.Status)
	_, err = GetOrganizationInvitationResultWithContext(ctx, f.identities[5], o.ID, invitation.ID, invitation.Generation)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
	platform, err := GetOrganizationLifecycleStateWithContext(ctx, f.identities[6], o.ID, true)
	require.NoError(t, err)
	assert.Equal(t, o.ID, platform.ID)
	_, err = GetOrganizationLifecycleStateWithContext(ctx, f.identities[6], o.ID, false)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
	_, err = GetOrganizationLifecycleStateWithContext(ctx, f.identities[4], o.ID, true)
	assert.ErrorIs(t, err, ErrOrganizationForbidden)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = ListPendingOrganizationInvitationsForActorWithContext(cancelled, f.identities[4], page)
	assert.ErrorIs(t, err, context.Canceled)
	_, err = GetOrganizationInvitationResultWithContext(cancelled, f.identities[4], o.ID, invitation.ID, invitation.Generation)
	assert.ErrorIs(t, err, context.Canceled)
	_, err = GetOrganizationLifecycleStateWithContext(cancelled, f.identities[6], o.ID, true)
	assert.ErrorIs(t, err, context.Canceled)

	_, err = ListOrganizationsForActor(f.identities[0], OrganizationPage{Limit: 101})
	assert.ErrorIs(t, err, ErrOrganizationInvalidInput)
	require.NoError(t, LeaveOrganization(f.identities[1], f.command(o.ID)))
	var ownInvitation OrganizationInvitation
	require.NoError(t, DB.Where("organization_id = ? AND target_user_id = ?", o.ID, f.identities[1].UserID).First(&ownInvitation).Error)
	history, err := GetOrganizationInvitationResultWithContext(ctx, f.identities[1], o.ID, ownInvitation.ID, ownInvitation.Generation)
	require.NoError(t, err)
	assert.Equal(t, OrganizationAccepted, history.Status)
	assert.Nil(t, history.OrganizationRevision)
	_, err = GetOrganizationInvitationResultWithContext(ctx, f.identities[5], o.ID, ownInvitation.ID, ownInvitation.Generation)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)

	_, err = ListOrganizationEventsForActor(f.identities[1], o.ID, page)
	assert.ErrorIs(t, err, ErrOrganizationForbidden)
	_, err = GetOrganizationInvitationResult(f.identities[1], o.ID, invitation.ID, invitation.Generation)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
	c := f.command(o.ID)
	c.Disabled = true
	c.Reason = "private operator detail"
	require.NoError(t, SetOrganizationPlatformDisabled(f.identities[6], f.authorize(6, "platform_disable", c)))
	view, err := GetOrganizationForActor(f.identities[2], o.ID)
	require.NoError(t, err)
	assert.True(t, view.PlatformDisabled)
	encoded, err := common.Marshal(view)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), c.Reason)
	_, err = ListOrganizationMembersForActor(f.identities[2], o.ID, page)
	assert.ErrorIs(t, err, ErrOrganizationDisabled)
	_, err = ListOrganizationEventsForActor(f.identities[0], o.ID, page)
	assert.ErrorIs(t, err, ErrOrganizationDisabled)
	result, err := GetOrganizationInvitationResult(f.identities[4], o.ID, invitation.ID, invitation.Generation)
	require.NoError(t, err)
	assert.Equal(t, OrganizationRevoked, result.Status)
	require.NoError(t, LeaveOrganization(f.identities[2], f.command(o.ID)))
	// Disabled recipients retain only their own generation result, never the
	// actionable name/revision. Removed members cannot use the member route.
	assert.Nil(t, result.OrganizationName)
	assert.Nil(t, result.OrganizationRevision)
	_, err = GetOrganizationInvitationResultWithContext(ctx, f.identities[2], o.ID, invitation.ID, invitation.Generation)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
	_, err = GetOrganizationLifecycleStateWithContext(ctx, f.identities[2], o.ID, false)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
	platform, err = GetOrganizationLifecycleStateWithContext(ctx, f.identities[6], o.ID, true)
	require.NoError(t, err)
	assert.True(t, platform.PlatformDisabled)

	_, err = GetOrganizationForActor(f.identities[2], o.ID)
	assert.ErrorIs(t, err, ErrOrganizationNotFound)
}

func testOrganizationTransferRollback(t *testing.T, f *organizationFixture) {
	o := f.org(0)
	f.join(o.ID, 0, 1, OrganizationRoleMember)
	f.join(o.ID, 0, 2, OrganizationRoleMember)
	c := f.command(o.ID)
	c.TargetUserID = f.identities[1].UserID
	require.NoError(t, InitiateOrganizationOwnershipTransfer(f.identities[0], f.authorize(0, "transfer_initiate", c)))
	var transfer OrganizationOwnershipTransfer
	require.NoError(t, DB.Where("organization_id = ?", o.ID).First(&transfer).Error)
	c = f.command(o.ID)
	c.TargetUserID = f.identities[2].UserID
	c.ObjectID, c.Generation = transfer.ID, transfer.Generation
	assert.ErrorIs(t, InitiateOrganizationOwnershipTransfer(f.identities[0], f.authorize(0, "transfer_initiate", c)), ErrOrganizationConflict)
	c.Replace = true
	require.NoError(t, InitiateOrganizationOwnershipTransfer(f.identities[0], f.authorize(0, "transfer_initiate", c)))
	old, err := GetOrganizationOwnershipTransferResult(f.identities[1], o.ID, transfer.ID, transfer.Generation)
	require.NoError(t, err)
	assert.Equal(t, OrganizationCancelled, old.Status)
	assert.Equal(t, "replaced", old.ReasonCode)
	require.NoError(t, DB.First(&transfer, transfer.ID).Error)
	assert.EqualValues(t, 2, transfer.Generation)
	var before Organization
	require.NoError(t, DB.First(&before, o.ID).Error)
	var members []OrganizationMember
	require.NoError(t, DB.Where("organization_id = ?", o.ID).Order("id").Find(&members).Error)
	c = f.command(o.ID)
	c.ObjectID, c.Generation = transfer.ID, transfer.Generation
	c = f.authorize(2, "transfer_accept", c)
	require.NoError(t, DB.Callback().Create().Before("gorm:create").Register("transfer-event-failure", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "OrganizationEvent" {
			tx.AddError(errors.New("transfer event failed"))
		}
	}))
	assert.ErrorContains(t, AcceptOrganizationOwnershipTransfer(f.identities[2], c), "transfer event failed")
	require.NoError(t, DB.Callback().Create().Remove("transfer-event-failure"))
	var after Organization
	require.NoError(t, DB.First(&after, o.ID).Error)
	assert.Equal(t, before, after)
	var afterMembers []OrganizationMember
	require.NoError(t, DB.Where("organization_id = ?", o.ID).Order("id").Find(&afterMembers).Error)
	assert.Equal(t, members, afterMembers)
	var afterTransfer OrganizationOwnershipTransfer
	require.NoError(t, DB.First(&afterTransfer, transfer.ID).Error)
	assert.Equal(t, transfer, afterTransfer)
	require.NoError(t, AcceptOrganizationOwnershipTransfer(f.identities[2], c))
	result, err := GetOrganizationOwnershipTransferResult(f.identities[2], o.ID, transfer.ID, transfer.Generation)
	require.NoError(t, err)
	assert.Equal(t, OrganizationAccepted, result.Status)
	duplicate := afterTransfer
	duplicate.ID = 0
	assert.Error(t, DB.Create(&duplicate).Error)
}

// This observation contract targets MySQL 8 and PostgreSQL 15 only. SQLite's
// BEGIN IMMEDIATE tests above do not exercise a later SELECT FOR UPDATE wait.
func testOrganizationRowLockExpiry(t *testing.T, f *organizationFixture, dialect, subject string) {
	t.Helper()
	originalDB := DB
	base := time.Now().Unix()
	deadline := base + 120
	var clock atomic.Int64
	clock.Store(base)
	organizationNow = func() time.Time { return time.Unix(clock.Load(), 0) }
	defer func() { organizationNow = time.Now }()
	o := f.org(0)
	actor := 0
	c := f.command(o.ID)
	var operation func() error
	var expected error
	switch subject {
	case "session":
		require.NoError(t, DB.Model(&UserSession{}).Where("sid = ?", f.identities[0].SessionID).Update("expires_at", deadline).Error)
		c.Name = "valid before expiry"
		operation = func() error { return RenameOrganization(f.identities[0], c) }
		expected = ErrOrganizationUnauthenticated
	case "authorization":
		c.Disabled = true
		c = f.authorize(0, "self_disable", c)
		c.Authorization.ValidUntil = deadline
		operation = func() error { return SetOrganizationSelfDisabled(f.identities[0], c) }
		expected = ErrOrganizationForbidden
	case "invitation":
		actor = 1
		inv := f.invite(o.ID, 0, actor, OrganizationRoleMember)
		require.NoError(t, DB.Model(&inv).Update("expires_at", deadline).Error)
		c = f.command(o.ID)
		c.ObjectID, c.Generation = inv.ID, inv.Generation
		operation = func() error { return AcceptOrganizationInvitation(f.identities[actor], c) }
		expected = ErrOrganizationExpired
	case "transfer":
		actor = 1
		f.join(o.ID, 0, actor, OrganizationRoleMember)
		c = f.command(o.ID)
		c.TargetUserID = f.identities[actor].UserID
		c = f.authorize(0, "transfer_initiate", c)
		c.Authorization.ConsumedAt = base - 1
		require.NoError(t, InitiateOrganizationOwnershipTransfer(f.identities[0], c))
		var transfer OrganizationOwnershipTransfer
		require.NoError(t, DB.Where("organization_id = ?", o.ID).First(&transfer).Error)
		require.NoError(t, DB.Model(&transfer).Update("expires_at", deadline).Error)
		c = f.command(o.ID)
		c.ObjectID, c.Generation = transfer.ID, transfer.Generation
		c = f.authorize(actor, "transfer_accept", c)
		operation = func() error { return AcceptOrganizationOwnershipTransfer(f.identities[actor], c) }
		expected = ErrOrganizationExpired
	default:
		t.Fatal("unknown row-lock expiry subject")
	}
	if c.Authorization != nil {
		c.Authorization.ConsumedAt = base - 1
	}
	// Prove the exact command is valid at the initial clock, without retaining
	// mutations. The nested domain transaction uses the same outer SQL transaction.
	before := organizationRowLockSnapshot(t, originalDB, o.ID)
	rollback := errors.New("rollback valid initial command")
	err := originalDB.Transaction(func(tx *gorm.DB) error {
		DB = tx
		defer func() { DB = originalDB }()
		if err := operation(); err != nil {
			return err
		}
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	require.Equal(t, before, organizationRowLockSnapshot(t, originalDB, o.ID))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := originalDB.DB()
	require.NoError(t, err)
	holderConn, err := pool.Conn(ctx)
	require.NoError(t, err)
	defer holderConn.Close()
	contenderConn, err := pool.Conn(ctx)
	require.NoError(t, err)
	defer contenderConn.Close()
	observer, err := pool.Conn(ctx)
	require.NoError(t, err)
	defer observer.Close()
	identitySQL := "SELECT CONNECTION_ID()"
	lockSQL := "SELECT id FROM organizations WHERE id = ? FOR UPDATE"
	if dialect == "postgres" {
		identitySQL = "SELECT pg_backend_pid()"
		lockSQL = "SELECT id FROM organizations WHERE id = $1 FOR UPDATE"
	}
	var holderID, contenderID int64
	require.NoError(t, holderConn.QueryRowContext(ctx, identitySQL).Scan(&holderID))
	require.NoError(t, contenderConn.QueryRowContext(ctx, identitySQL).Scan(&contenderID))
	require.NotEqual(t, holderID, contenderID)
	holder, err := holderConn.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer holder.Rollback()
	var lockedID int64
	require.NoError(t, holder.QueryRowContext(ctx, lockSQL, o.ID).Scan(&lockedID))
	require.Equal(t, o.ID, lockedID)

	// Pin prefetch and the actual domain transaction to the known contender
	// connection. Holder locks only the organization row, never users/sessions.
	pinned := originalDB.Session(&gorm.Session{NewDB: true, Context: ctx})
	pinned.ConnPool, pinned.Statement.ConnPool = contenderConn, contenderConn
	var sessionRead, querySignalled atomic.Bool
	queryReached := make(chan bool, 1)
	const sessionCallback = "organization-row-lock-session"
	const rowCallback = "organization-row-lock-query"
	require.NoError(t, originalDB.Callback().Query().After("gorm:query").Register(sessionCallback, func(tx *gorm.DB) {
		if _, transactional := tx.Statement.ConnPool.(*sql.Tx); !transactional || tx.Error != nil {
			return
		}
		if s, ok := tx.Statement.Dest.(*UserSession); ok && s.SID == f.identities[actor].SessionID && s.ExpiresAt > clock.Load() && s.Status == UserSessionStatusActive {
			sessionRead.Store(true)
		}
	}))
	defer originalDB.Callback().Query().Remove(sessionCallback)
	require.NoError(t, originalDB.Callback().Query().Before("gorm:query").Register(rowCallback, func(tx *gorm.DB) {
		_, transactional := tx.Statement.ConnPool.(*sql.Tx)
		_, locking := tx.Statement.Clauses["FOR"]
		if transactional && locking && tx.Statement.Schema != nil && tx.Statement.Schema.Name == "Organization" && querySignalled.CompareAndSwap(false, true) {
			queryReached <- sessionRead.Load()
		}
	}))
	defer originalDB.Callback().Query().Remove(rowCallback)
	DB = pinned
	finished := false
	done := make(chan error, 1)
	defer func() {
		cancel()
		_ = holder.Rollback()
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("contender did not exit after cancellation and holder rollback")
			}
		}
		DB = originalDB
	}()
	go func() { done <- operation() }()
	select {
	case authenticated := <-queryReached:
		require.True(t, authenticated, "later org query must follow successful active session read")
	case err := <-done:
		finished = true
		t.Fatalf("contender ended before later row query: %v", err)
	case <-ctx.Done():
		t.Fatal("contender did not reach later row query within deadline")
	}

	// The callback is only a program-point marker. Server metadata below must
	// independently identify this contender waiting on this holder's row lock.
	waitSQL := `SELECT EXISTS (
 SELECT 1 FROM performance_schema.data_lock_waits w
 JOIN performance_schema.threads requester ON requester.THREAD_ID = w.REQUESTING_THREAD_ID
 JOIN performance_schema.threads blocker ON blocker.THREAD_ID = w.BLOCKING_THREAD_ID
 JOIN performance_schema.data_locks requested ON requested.ENGINE = w.ENGINE AND requested.ENGINE_LOCK_ID = w.REQUESTING_ENGINE_LOCK_ID
 WHERE requester.PROCESSLIST_ID = ? AND blocker.PROCESSLIST_ID = ?
 AND requested.OBJECT_SCHEMA = DATABASE() AND requested.OBJECT_NAME = 'organizations'
 AND requested.INDEX_NAME = 'PRIMARY' AND requested.LOCK_TYPE = 'RECORD'
 AND requested.LOCK_STATUS = 'WAITING' AND requested.LOCK_DATA = ?)`
	args := []any{contenderID, holderID, fmt.Sprint(o.ID)}
	if dialect == "postgres" {
		// PostgreSQL row conflicts commonly wait on the holder's transaction ID;
		// the holder's only locking statement above targets this exact org row.
		waitSQL = `SELECT EXISTS (
 SELECT 1 FROM pg_stat_activity a WHERE a.pid = $1 AND a.datname = current_database()
 AND a.wait_event_type = 'Lock' AND $2 = ANY(pg_blocking_pids(a.pid))
 AND EXISTS (SELECT 1 FROM pg_locks l WHERE l.pid = a.pid
 AND l.relation = 'organizations'::regclass AND l.mode = 'RowShareLock' AND l.granted))`
		args = []any{contenderID, holderID}
	}
	waiting := false
	observations := 0
	for observations < 1024 && ctx.Err() == nil {
		observations++
		require.NoError(t, observer.QueryRowContext(ctx, waitSQL, args...).Scan(&waiting), "lock metadata must be available, never skipped")
		if waiting {
			break
		}
	}
	require.True(t, waiting, "server row-lock wait was not observed within bounded metadata queries")
	t.Logf("row-lock wait confirmed: engine=%s holder=%d contender=%d organization=%d metadata_queries=%d initial_session_read=true", dialect, holderID, contenderID, o.ID, observations)
	clock.Store(deadline)
	require.NoError(t, holder.Rollback())
	select {
	case err = <-done:
		finished = true
	case <-ctx.Done():
		t.Fatal("contender did not finish after releasing row lock")
	}
	require.ErrorIs(t, err, expected)
	assert.Equal(t, before, organizationRowLockSnapshot(t, originalDB, o.ID), "expiry must leave all domain rows, events and revisions unchanged")
}

// The full domain state includes reusable slots and event IDs, not just counts.
func organizationRowLockSnapshot(t *testing.T, db *gorm.DB, orgID int64) any {
	t.Helper()
	var snapshot struct {
		Organization Organization
		Members      []OrganizationMember
		Invitations  []OrganizationInvitation
		Transfers    []OrganizationOwnershipTransfer
		Events       []OrganizationEvent
	}
	require.NoError(t, db.First(&snapshot.Organization, orgID).Error)
	for _, dest := range []any{&snapshot.Members, &snapshot.Invitations, &snapshot.Transfers, &snapshot.Events} {
		require.NoError(t, db.Where("organization_id = ?", orgID).Order("id").Find(dest).Error)
	}
	return snapshot
}
