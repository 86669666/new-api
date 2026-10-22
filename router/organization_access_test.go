package router

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlclickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/pkg/jsplugin"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/billing_setting"
	"github.com/QuantumNous/new-api/setting/config"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	sqlmysql "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/clickhouse"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	gormlogger "gorm.io/gorm/logger"
)

// These integration tests deliberately use SetRouter and signed, persisted sessions.
// The external A03 runner supplies dedicated endpoints; no shared services/default DSNs.
// Test bodies contain no credential logging and do not install simplified handlers.
var organizationFixtureSequence atomic.Int64

type organizationHTTPFixture struct {
	db         *gorm.DB
	mainDSN    string
	mainKind   string
	server     *httptest.Server
	client     *http.Client
	engine     *gin.Engine
	users      map[string]*model.User
	bearer     map[string]string
	sids       map[string]string
	orgA, orgB int64
	logs       *organizationLogBuffer
}

// Test-owned HTTP transport rejects external provider attempts before dialing.
type organizationLoopbackTransport struct {
	next     http.RoundTripper
	rejected atomic.Int64
}

func (r *organizationLoopbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() != "127.0.0.1" && req.URL.Hostname() != "::1" {
		r.rejected.Add(1)
		return nil, fmt.Errorf("test outbound destination denied")
	}
	return r.next.RoundTrip(req)
}

type organizationLogBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *organizationLogBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}
func (b *organizationLogBuffer) snapshot() string {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.String()
}

// Validate the actual driver interpretation before any dial, migration, or CREATE.
// Only the receipt-bound loopback port and a small set of non-routing options pass.
func organizationFixtureDSN(kind, source, receiptPort string) error {
	denied := fmt.Errorf("fixture DSN does not match dedicated endpoint")
	port, err := strconv.Atoi(receiptPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != receiptPort {
		return denied
	}
	endpoint := net.JoinHostPort("127.0.0.1", receiptPort)
	if kind == "mysql" {
		c, err := sqlmysql.ParseDSN(source)
		if err != nil || c.Net != "tcp" || c.Addr != endpoint || c.TLSConfig != "" || len(c.Params) != 0 {
			return denied
		}
		// ParseDSN consumes known routing options; reject all unapproved raw options too.
		_, query, _ := strings.Cut(source, "?")
		q, err := url.ParseQuery(query)
		if err != nil {
			return denied
		}
		for key, values := range q {
			if key != "parseTime" || len(values) != 1 || values[0] != "true" {
				return denied
			}
		}
		return nil
	}
	u, err := url.Parse(source)
	if err != nil || u.Host != endpoint || u.Fragment != "" || u.Opaque != "" {
		return denied
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return denied
	}
	allowed := map[string]bool{}
	switch kind {
	case "postgres":
		if u.Scheme != "postgres" && u.Scheme != "postgresql" {
			return denied
		}
		allowed["sslmode"] = true
		c, err := pgx.ParseConfig(source)
		if err != nil || c.Host != "127.0.0.1" || int(c.Port) != port || len(c.Fallbacks) != 0 || c.TLSConfig != nil || len(c.RuntimeParams) != 0 {
			return denied
		}
	case "clickhouse":
		if u.Scheme != "clickhouse" {
			return denied
		}
		for _, key := range []string{"username", "password", "dial_timeout", "read_timeout"} {
			allowed[key] = true
		}
		c, err := sqlclickhouse.ParseDSN(source)
		if err != nil || len(c.Addr) != 1 || c.Addr[0] != endpoint || c.Protocol != sqlclickhouse.Native || c.TLS != nil || c.HTTPProxyURL != nil {
			return denied
		}
	default:
		return denied
	}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			return denied
		}
	}
	return nil
}

func TestOrganizationFixtureDSNBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, kind, dsn, port string
		valid                 bool
	}{
		{"mysql_owned", "mysql", "root@tcp(127.0.0.1:23456)/owned?parseTime=true", "23456", true},
		{"postgres_owned", "postgres", "postgres://postgres@127.0.0.1:23456/owned?sslmode=disable", "23456", true},
		{"clickhouse_owned", "clickhouse", "clickhouse://127.0.0.1:23456/owned", "23456", true},
		{"mysql_port_mismatch", "mysql", "root@tcp(127.0.0.1:23457)/owned?parseTime=true", "23456", false},
		{"mysql_foreign", "mysql", "root@tcp(10.10.88.120:6379)/owned", "6379", false},
		{"mysql_unix", "mysql", "root@unix(/tmp/shared.sock)/owned", "23456", false},
		{"postgres_host_override", "postgres", "postgres://postgres@127.0.0.1:23456/owned?sslmode=disable&host=10.10.88.120", "23456", false},
		{"postgres_multihost", "postgres", "postgres://postgres@127.0.0.1:23456,10.10.88.120:5432/owned?sslmode=disable", "23456", false},
		{"postgres_port_override", "postgres", "postgres://postgres@127.0.0.1:23456/owned?sslmode=disable&port=6379", "23456", false},
		{"clickhouse_proxy", "clickhouse", "clickhouse://127.0.0.1:23456/owned?http_proxy=http%3A%2F%2F10.10.88.120%3A6379", "23456", false},
		{"clickhouse_multihost", "clickhouse", "clickhouse://127.0.0.1:23456,10.10.88.120:9000/owned", "23456", false},
		{"hostname_alias", "postgres", "postgres://postgres@localhost:23456/owned?sslmode=disable", "23456", false},
		{"malformed", "postgres", "%", "23456", false},
		{"missing_receipt", "mysql", "root@tcp(127.0.0.1:23456)/owned", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := organizationFixtureDSN(tc.kind, tc.dsn, tc.port)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// A dedicated database is created with a collision-failing name and is dropped
// only by the cleanup registered after that successful CREATE. SQLite is a real file.
func organizationTestDB(t *testing.T, kind, source string) (*gorm.DB, string) {
	t.Helper()
	owner := os.Getenv("NEWAPI_S2_OWNED")
	boundedSuite := slices.Contains([]string{"g10-organization-identity", "g10-organization-task-read", "g11-organization-invitation-presentation", "g12-organization-task-batch", "g13-organization-task-export", "g14-organization-task-list-revocation", "g15-organization-task-funding-isolation", "g16-organization-capabilities", "g17-organization-wallet", "g18-site-description", "g19-organization-name-uniqueness", "g19-model-capability-metadata", "g19-oauth-userinfo", "g19-oauth-provider-bridge", "g19-client-events-receiver", "g19-tools-search", "g20-token-error-codes", "g20-token-usage", "g21-w02-clickhouse", "g20-quota-remaining-display", "g21-organization-create-rate", "g1-W03-08-client-stats", "g1-W03-09-client-config"}, owner)
	if boundedSuite {
		require.Contains(t, []string{"sqlite", "mysql", "postgres"}, kind)
		require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
		require.Equal(t, "none", os.Getenv("NEWAPI_S2_CACHE_MODE"))
		require.Equal(t, kind, os.Getenv("NEWAPI_S2_MAIN"))
		require.Equal(t, kind, os.Getenv("NEWAPI_S2_LOG"))
	}
	config := &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)}
	if kind == "sqlite" {
		p := filepath.Join(t.TempDir(), "organization.db")
		db, err := gorm.Open(sqlite.Open(p), config)
		require.NoError(t, err)
		conn, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, conn.Close()) })
		t.Log("SQLite fixture: temporary file")
		return db, p
	}
	if !boundedSuite {
		require.Contains(t, []string{"g5-A03", "g6-A03"}, owner, "dedicated runtime receipt required")
	}
	require.NoError(t, organizationFixtureDSN(kind, source, os.Getenv("NEWAPI_S2_"+strings.ToUpper(kind)+"_PORT")))
	// Use one canonical identifier for unquoted CREATE/DROP and the connection DSN.
	name := "newapi_s2_" + strings.ToLower(strings.ReplaceAll(common.NewRequestId(), "-", ""))
	require.Regexp(t, `^[a-z][a-z0-9_]*$`, name)
	require.LessOrEqual(t, len(name), 63, "fixture database identifier must not be truncated")
	var adminDial, testDial gorm.Dialector
	var dsn string
	if kind == "mysql" {
		c, err := sqlmysql.ParseDSN(source)
		require.NoError(t, err)
		require.Equal(t, "tcp", c.Net)
		h, _, err := net.SplitHostPort(c.Addr)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", h)
		adminDial = mysql.Open(source)
		c.DBName = name
		dsn = c.FormatDSN()
		testDial = mysql.Open(dsn)
	} else {
		u, err := url.Parse(source)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", u.Hostname())
		require.NotEmpty(t, u.Port())
		u.Path = "/" + name
		dsn = u.String()
		switch kind {
		case "postgres":
			adminDial = postgres.New(postgres.Config{DSN: source, PreferSimpleProtocol: true})
			testDial = postgres.New(postgres.Config{DSN: dsn, PreferSimpleProtocol: true})
		case "clickhouse":
			require.Equal(t, "clickhouse", u.Scheme)
			adminDial = clickhouse.Open(source)
			testDial = clickhouse.Open(dsn)
		default:
			t.Fatalf("unsupported fixture engine %q", kind)
		}
	}
	admin, err := gorm.Open(adminDial, config)
	require.NoError(t, err)
	ac, err := admin.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ac.Close()) })
	require.NoError(t, admin.Exec("CREATE DATABASE "+name).Error)
	t.Cleanup(func() { require.NoError(t, admin.Exec("DROP DATABASE "+name).Error) })
	db, err := gorm.Open(testDial, config)
	require.NoError(t, err)
	conn, err := db.DB()
	require.NoError(t, err)
	conn.SetMaxOpenConns(8)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	if kind == "postgres" {
		var currentDatabase string
		require.NoError(t, db.Raw("SELECT current_database()").Scan(&currentDatabase).Error)
		require.Equal(t, name, currentDatabase, "connected fixture database must match the created identifier")
	}
	t.Logf("owned database: %s engine=%s", name, kind)
	return db, dsn
}

func newOrganizationHTTPFixture(t *testing.T) *organizationHTTPFixture {
	originalTransport := http.DefaultTransport
	deny := &organizationLoopbackTransport{next: originalTransport}
	http.DefaultTransport = deny
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
		assert.Zero(t, deny.rejected.Load(), "production handler attempted forbidden outbound HTTP")
	})
	for _, client := range []*http.Client{service.GetHttpClient(), service.GetSSRFProtectedHTTPClient()} {
		if client == nil {
			continue
		}
		old := client.Transport
		client.Transport = deny
		t.Cleanup(func() { client.Transport = old })
	}

	t.Helper()
	oldDB, oldLog := model.DB, model.LOG_DB
	oldMain, oldLogType := common.MainDatabaseType(), common.LogDatabaseType()
	oldRedis, oldMemory, oldRDB := common.RedisEnabled, common.MemoryCacheEnabled, common.RDB
	oldMaster, oldSecret, oldRate := common.IsMasterNode, common.SessionSecret, common.GlobalApiRateLimitEnable
	oldRegistry := jsplugin.DefaultRegistry
	oldWriter, oldErrWriter := gin.DefaultWriter, gin.DefaultErrorWriter
	t.Cleanup(func() {
		model.DB, model.LOG_DB = oldDB, oldLog
		common.SetDatabaseTypes(oldMain, oldLogType)
		common.RedisEnabled, common.MemoryCacheEnabled, common.RDB = oldRedis, oldMemory, oldRDB
		common.IsMasterNode, common.SessionSecret, common.GlobalApiRateLimitEnable = oldMaster, oldSecret, oldRate
		jsplugin.DefaultRegistry = oldRegistry
		gin.DefaultWriter, gin.DefaultErrorWriter = oldWriter, oldErrWriter
	})
	t.Setenv("FRONTEND_BASE_URL", "")
	t.Setenv("TRUSTED_PROXIES", "")
	common.RedisEnabled = false
	common.MemoryCacheEnabled = os.Getenv("NEWAPI_S2_CACHE_MODE") == "memory"
	common.IsMasterNode = false
	common.GlobalApiRateLimitEnable = false
	secret, err := common.GenerateRandomCharsKey(48)
	require.NoError(t, err)
	common.SessionSecret = secret
	kind := os.Getenv("NEWAPI_S2_MAIN")
	if kind == "" {
		kind = "sqlite"
	}
	db, mainDSN := organizationTestDB(t, kind, os.Getenv("NEWAPI_S2_MAIN_DSN"))
	model.DB = db
	common.SetDatabaseTypes(common.DatabaseType(kind), common.DatabaseType(kind))
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.UserAccessToken{}, &model.Option{}, &model.Token{}, &model.Task{}, &model.Log{}, &model.CasbinRule{}, &model.AuthzRole{}, &model.Organization{}, &model.OrganizationMember{}, &model.OrganizationInvitation{}, &model.OrganizationOwnershipTransfer{}, &model.OrganizationEvent{}, &model.OrganizationCreationRequest{}, &model.OrganizationWallet{}, &model.OrganizationWalletEntry{}))
	t.Setenv("LOG_SQL_DSN", "")
	require.NoError(t, model.InitLogDB())
	logKind := os.Getenv("NEWAPI_S2_LOG")
	if logKind == "" {
		logKind = kind
	}
	if logKind != kind || os.Getenv("NEWAPI_S2_LOG_DSN") != "" {
		_, dsn := organizationTestDB(t, logKind, os.Getenv("NEWAPI_S2_LOG_DSN"))
		t.Setenv("LOG_SQL_DSN", dsn)
		common.IsMasterNode = true
		require.NoError(t, model.InitLogDB())
		common.IsMasterNode = false
		lc, err := model.LOG_DB.DB()
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, lc.Close()) })
	}
	require.NoError(t, model.MigrateAuditLogs())
	require.NoError(t, i18n.Init())
	common.IsMasterNode = true
	require.NoError(t, authz.Init(db))
	common.IsMasterNode = false
	require.NoError(t, model.EnsureLegacyAccessTokenRetireAt(time.Now().Unix()))
	for label, conn := range map[string]*gorm.DB{"main": db, "log": model.LOG_DB} {
		q := "SELECT version()"
		if conn.Dialector.Name() == "sqlite" {
			q = "SELECT sqlite_version()"
		}
		var version string
		require.NoError(t, conn.Raw(q).Scan(&version).Error)
		t.Logf("%s engine=%s version=%s", label, conn.Dialector.Name(), version)
	}
	if os.Getenv("NEWAPI_S2_CACHE_MODE") == "redis" {
		socket := os.Getenv("NEWAPI_S2_REDIS_SOCKET")
		root := os.Getenv("NEWAPI_S2_RUN_ROOT")
		require.NotEmpty(t, root)
		require.True(t, filepath.IsAbs(root))
		require.Equal(t, filepath.Join(root, "redis.sock"), socket)
		require.Contains(t, []string{"g5-A03", "g6-A03"}, os.Getenv("NEWAPI_S2_OWNED"))
		redisDB, err := strconv.Atoi(os.Getenv("NEWAPI_S2_REDIS_DB"))
		require.NoError(t, err)
		require.GreaterOrEqual(t, redisDB, 0)
		require.Less(t, redisDB, 16)
		common.RDB = redis.NewClient(&redis.Options{Network: "unix", Addr: socket, DB: redisDB})
		require.NoError(t, common.RDB.Ping(context.Background()).Err())
		common.RedisEnabled = true
		t.Cleanup(func() { require.NoError(t, common.RDB.Close()) })
	}
	f := &organizationHTTPFixture{db: db, mainDSN: mainDSN, mainKind: kind, users: map[string]*model.User{}, bearer: map[string]string{}, sids: map[string]string{}, orgA: 9007199254740993, orgB: 9007199254740995, logs: &organizationLogBuffer{}}
	baseID := int(organizationFixtureSequence.Add(100)) + 61000
	for i, name := range []string{"owner", "admin", "member", "foreign", "root", "empty", "revoked"} {
		role := common.RoleCommonUser
		if name == "root" {
			role = common.RoleRootUser
		}
		user := &model.User{Id: baseID + i, Username: "s2-" + name, Password: "fixture-not-login-password", Role: role, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: fmt.Sprint(baseID + i)}
		require.NoError(t, db.Create(user).Error)
		f.users[name] = user
		sid := "s2-" + common.NewRequestId()
		f.sids[name] = sid
		require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: user.Id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("a", 64), LoginMethod: "password", ExpiresAt: time.Now().Unix() + 3600}))
		token, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: user.Id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
		require.NoError(t, err)
		f.bearer[name] = token
	}
	relayKey, err := common.GenerateRandomCharsKey(40)
	require.NoError(t, err)
	require.NoError(t, db.Create(&model.Token{UserId: f.users["owner"].Id, Key: relayKey, Status: common.TokenStatusEnabled, ExpiredTime: -1}).Error)
	f.bearer["relay"] = "sk-" + relayKey
	for _, o := range []model.Organization{{ID: f.orgA, Name: "organization-A", OwnerUserID: f.users["owner"].Id, CreatedByUserID: f.users["owner"].Id, Revision: 9007199254740993, OwnershipVersion: 1}, {ID: f.orgB, Name: "organization-B", OwnerUserID: f.users["foreign"].Id, CreatedByUserID: f.users["foreign"].Id, Revision: 1, OwnershipVersion: 1}} {
		require.NoError(t, db.Create(&o).Error)
	}
	for _, entry := range []struct {
		user, role string
		org        int64
	}{{"owner", "member", f.orgA}, {"admin", "admin", f.orgA}, {"member", "member", f.orgA}, {"revoked", "member", f.orgA}, {"foreign", "member", f.orgB}, {"member", "member", f.orgB}} {
		require.NoError(t, db.Create(&model.OrganizationMember{OrganizationID: entry.org, UserID: f.users[entry.user].Id, Role: entry.role, Revision: 9007199254740993, JoinedAt: 1}).Error)
	}
	require.NoError(t, db.Create(&model.OrganizationEvent{ID: 9007199254740993, OrganizationID: f.orgA, OrganizationRevision: 9007199254740993, ActorUserID: 0, Action: "organization.rename", CreatedAt: time.Now().Unix()}).Error)
	jsplugin.DefaultRegistry = jsplugin.NewRegistry()
	// A real loaded query alias enters the production NoRoute dispatcher. No provider hook is used.
	_, err = jsplugin.DefaultRegistry.Register(routerPluginSource("s2alias", "1.0.0", `[{method:"GET",path:"/s2alias/jobs/:task_id",type:"query",render:"native"}]`), jsplugin.Options{Key: "s2alias", Version: "1.0.0"})
	require.NoError(t, err)
	gin.DefaultWriter, gin.DefaultErrorWriter = f.logs, f.logs
	f.engine = gin.New()
	f.engine.Use(middleware.RequestId())
	middleware.SetUpLogger(f.engine)
	SetRouter(f.engine, WebAssets{IndexPage: []byte("s2-frontend-fallback")})
	f.server = httptest.NewServer(f.engine)
	f.client = f.server.Client()
	f.client.Timeout = 10 * time.Second
	t.Cleanup(f.server.Close)
	return f
}

func (f *organizationHTTPFixture) request(t *testing.T, method, path, actor, body string, headers http.Header) (int, http.Header, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Accept-Language", "en")
	if actor != "" {
		raw, ok := f.bearer[actor]
		if !ok {
			raw = actor
		}
		req.Header.Set("Authorization", "Bearer "+raw)
	}
	for k, values := range headers {
		req.Header[k] = append([]string(nil), values...)
	}
	resp, err := f.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	data := map[string]any{}
	if len(raw) > 0 {
		require.NoError(t, common.Unmarshal(raw, &data), "response must be JSON, status=%d", resp.StatusCode)
	}
	return resp.StatusCode, resp.Header, data
}

func organizationError(t *testing.T, status int, h http.Header, b map[string]any, want int, code string) {
	t.Helper()
	require.Equal(t, want, status)
	assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
	assert.Empty(t, h.Values("Set-Cookie"))
	assert.Equal(t, code, b["code"])
	assert.Equal(t, false, b["success"])
	if data, present := b["data"]; present && code == "ORG_STATE_CHANGED" {
		revision, ok := data.(map[string]any)
		require.True(t, ok)
		require.Len(t, revision, 1)
		value, ok := revision["revision"].(string)
		require.True(t, ok)
		_, valid := middleware.ParseOrganizationDecimal(value)
		assert.True(t, valid)
	} else {
		assert.NotContains(t, slices.Collect(maps.Keys(b)), "data")
	}
}

// This fixture exercises authenticated client telemetry against isolated stores.
// It is not a real Cherry upload or a deployed telemetry service.
// The only injected commit ambiguity is an acknowledged real commit followed
// by a synthetic transport-like error, so retry must converge to count zero.
type clientEventsUncertainPool struct {
	gorm.ConnPool
	fired *atomic.Bool
}

func (p *clientEventsUncertainPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	var pool gorm.ConnPool
	var err error
	if beginner, ok := p.ConnPool.(gorm.ConnPoolBeginner); ok {
		pool, err = beginner.BeginTx(ctx, opts)
	} else if beginner, ok := p.ConnPool.(gorm.TxBeginner); ok {
		pool, err = beginner.BeginTx(ctx, opts)
	} else {
		return nil, errors.New("fixture cannot begin transaction")
	}
	if err != nil {
		return nil, err
	}
	return &clientEventsUncertainTx{ConnPool: pool, fired: p.fired}, nil
}

type clientEventsUncertainTx struct {
	gorm.ConnPool
	fired *atomic.Bool
}

func (tx *clientEventsUncertainTx) Commit() error {
	err := tx.ConnPool.(gorm.TxCommitter).Commit()
	if err == nil && tx.fired.CompareAndSwap(false, true) {
		return errors.New("fixture commit acknowledgement lost")
	}
	return err
}
func (tx *clientEventsUncertainTx) Rollback() error { return tx.ConnPool.(gorm.TxCommitter).Rollback() }

func TestRelayTokenErrorCodesHTTP(t *testing.T) {
	require.Equal(t, "g20-token-error-codes", os.Getenv("NEWAPI_S2_OWNED"))
	f := newOrganizationHTTPFixture(t)
	now := time.Now().Unix()
	for index, tc := range []struct {
		name       string
		status     int
		expires    int64
		quota      int
		missing    bool
		code       string
		wantStatus int
	}{
		{"stored_expired", common.TokenStatusExpired, now + 3600, 10, false, "token_expired", http.StatusUnauthorized},
		{"expired_timestamp", common.TokenStatusEnabled, now - 3600, 10, false, "token_expired", http.StatusUnauthorized},
		{"stored_exhausted", common.TokenStatusExhausted, -1, 10, false, "token_exhausted", http.StatusUnauthorized},
		{"exhausted_quota", common.TokenStatusEnabled, -1, 0, false, "token_exhausted", http.StatusUnauthorized},
		{"disabled_precedes_expiry", common.TokenStatusDisabled, now - 3600, 0, false, "token_disabled", http.StatusUnauthorized},
		{"unknown_status", 999, -1, 10, false, "token_invalid", http.StatusUnauthorized},
		{"unknown_key", common.TokenStatusEnabled, -1, 10, true, "token_invalid", http.StatusUnauthorized},
		{"valid", common.TokenStatusEnabled, -1, 10, false, "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := fmt.Sprintf("state%02d%s", index, strings.Repeat("x", 32))
			if !tc.missing {
				require.NoError(t, f.db.Create(&model.Token{UserId: f.users["owner"].Id, Key: key,
					Status: tc.status, ExpiredTime: tc.expires, RemainQuota: tc.quota}).Error)
			}
			for _, language := range []string{"en", "zh-CN"} {
				status, _, body := f.request(t, http.MethodGet, "/v1/models", "sk-"+key, "", http.Header{"Accept-Language": {language}})
				assert.Equal(t, tc.wantStatus, status, language)
				if tc.code == "" {
					assert.NotContains(t, body, "error")
					continue
				}
				errorBody, ok := body["error"].(map[string]any)
				require.True(t, ok, language)
				assert.Equal(t, tc.code, errorBody["code"], language)
				assert.Equal(t, "new_api_error", errorBody["type"], language)
				message, ok := errorBody["message"].(string)
				require.True(t, ok)
				assert.Contains(t, message, map[string]string{"en": "Invalid token", "zh-CN": "无效的令牌"}[language])
				assert.NotContains(t, message, key)
			}
			assert.NotContains(t, f.logs.snapshot(), key)
		})
	}

	t.Run("database_failure_is_not_a_token_state", func(t *testing.T) {
		const callback = "test:relay-token-state-database-failure"
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
			if tx.Statement.Table == "tokens" {
				tx.AddError(errors.New("isolated token lookup failure"))
			}
		}))
		defer f.db.Callback().Query().Remove(callback)
		status, _, body := f.request(t, http.MethodGet, "/v1/models", "sk-databasefailure", "", nil)
		assert.Equal(t, http.StatusInternalServerError, status)
		errorBody, ok := body["error"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "", errorBody["code"])
		assert.Equal(t, "new_api_error", errorBody["type"])
	})
}

func TestRelayTokenCachedErrorCodesHTTP(t *testing.T) {
	require.Equal(t, "g20-token-error-codes", os.Getenv("NEWAPI_S2_OWNED"))
	f := newOrganizationHTTPFixture(t)
	address := os.Getenv("NEWAPI_TOKEN_STATE_REDIS_ADDR")
	host, port, err := net.SplitHostPort(address)
	require.NoError(t, err, "an explicitly owned Redis endpoint is required")
	require.Equal(t, "127.0.0.1", host)
	require.Equal(t, os.Getenv("NEWAPI_TOKEN_STATE_REDIS_PORT"), port)
	client := redis.NewClient(&redis.Options{Addr: address})
	require.NoError(t, client.Ping(context.Background()).Err())
	previousRedis, previousClient := common.RedisEnabled, common.RDB
	common.RedisEnabled, common.RDB = true, client
	defer func() {
		common.RedisEnabled, common.RDB = previousRedis, previousClient
		require.NoError(t, client.Close())
	}()
	for index, tc := range []struct {
		name    string
		status  int
		expires int64
		code    string
	}{
		{"live_quota_ahead_of_database", common.TokenStatusEnabled, -1, "token_exhausted"},
		{"expired_without_database_status_write", common.TokenStatusEnabled, time.Now().Unix() - 3600, "token_expired"},
		{"disabled_precedes_expiry_and_quota", common.TokenStatusDisabled, time.Now().Unix() - 3600, "token_disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := fmt.Sprintf("cachedstate%02d%s", index, common.NewRequestId())
			token := &model.Token{UserId: f.users["owner"].Id, Key: key, Status: tc.status, ExpiredTime: tc.expires, RemainQuota: 50}
			require.NoError(t, f.db.Create(token).Error)
			_, err := model.GetTokenByKey(key, true)
			require.NoError(t, err)
			cacheKey := "token:" + common.GenerateHMAC(key)
			require.NoError(t, client.HSet(context.Background(), cacheKey, "RemainQuota", 0).Err())
			for _, language := range []string{"en", "zh-CN"} {
				status, _, body := f.request(t, http.MethodGet, "/v1/models", "sk-"+key, "", http.Header{"Accept-Language": {language}})
				assert.Equal(t, http.StatusUnauthorized, status)
				errorBody, ok := body["error"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, tc.code, errorBody["code"], language)
				status, _, _ = f.request(t, http.MethodGet, "/api/usage/token/", "sk-"+key, "", http.Header{"Accept-Language": {language}})
				if tc.status == common.TokenStatusDisabled {
					assert.Equal(t, http.StatusUnauthorized, status)
				} else {
					assert.Equal(t, http.StatusOK, status)
				}
			}
			var stored model.Token
			require.NoError(t, f.db.First(&stored, token.Id).Error)
			assert.Equal(t, tc.status, stored.Status)
			assert.Equal(t, 50, stored.RemainQuota, "classifying a cached rejection must not settle cached quota")
			assert.NotContains(t, f.logs.snapshot(), key)
			require.NoError(t, client.Del(context.Background(), cacheKey).Err())
		})
	}
}

func TestClientEventsReceiverHTTP(t *testing.T) {
	t.Setenv("CLIENT_EVENTS_ENABLED", "false")
	t.Setenv("CLIENT_EVENTS_RETENTION_DAYS", "30")
	t.Setenv("CLIENT_EVENTS_RATE_LIMIT", "600")
	require.NoError(t, service.InitClientEventsConfig())
	t.Cleanup(func() {
		t.Setenv("CLIENT_EVENTS_ENABLED", "false")
		require.NoError(t, service.InitClientEventsConfig())
	})
	f := newOrganizationHTTPFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.ClientEvent{}, &model.SystemTask{}, &model.SystemTaskLock{}))
	// Init sets only the environment fallback; observe the fresh fixture Option table.
	require.NoError(t, model.ReloadClientEventsConfig())
	require.NoError(t, f.engine.SetTrustedProxies(nil))
	var relay model.Token
	require.NoError(t, f.db.Where(map[string]any{"key": f.bearer["relay"][3:]}).First(&relay).Error)
	relay.Key = "EventsFixture" + strings.Repeat("a", 28)
	require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("key", relay.Key).Error)
	f.bearer["relay"] = "sk-" + relay.Key
	tokens := map[string]*model.Token{"relay": &relay}
	for _, name := range []string{"rotate", "foreign", "limit", "expiry"} {
		key, err := common.GenerateRandomCharsKey(40)
		require.NoError(t, err)
		owner := f.users["owner"].Id
		if name == "foreign" {
			owner = f.users["foreign"].Id
		}
		token := &model.Token{UserId: owner, Key: key, Status: common.TokenStatusEnabled, ExpiredTime: -1}
		require.NoError(t, f.db.Create(token).Error)
		tokens[name] = token
		f.bearer["events-"+name] = "sk-" + key
	}
	encode := func(v any) string { data, err := common.Marshal(v); require.NoError(t, err); return string(data) }
	config := func(enabled bool, limit int) {
		t.Setenv("CLIENT_EVENTS_ENABLED", strconv.FormatBool(enabled))
		t.Setenv("CLIENT_EVENTS_RATE_LIMIT", strconv.Itoa(limit))
		require.NoError(t, service.InitClientEventsConfig())
		require.NoError(t, model.ReloadClientEventsConfig())
	}
	const clientID = "8a6c0e0e-6f3b-4c55-9d0e-2a1f7c9b1e11"
	const privateCanary = "never-store-client-content-canary"
	stamp := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano)
	event := func(kind string, data any) map[string]any {
		return map[string]any{"event_type": kind, "timestamp": stamp, "data": data}
	}
	envelope := func(events ...any) map[string]any {
		return map[string]any{"client_id": clientID, "channel": "cherry-studio", "events": events}
	}
	launch := event("app_launch", map[string]any{"version": "1.0.0", "os": "darwin", "messages": privateCanary, "ignored": nil})
	post := func(body any, actor string) (int, http.Header, map[string]any) {
		return f.request(t, http.MethodPost, "/api/events", actor, encode(body), http.Header{"Content-Type": {"application/json"}, "X-Client-Id": {clientID}})
	}
	failure := func(status int, h http.Header, b map[string]any, want int) {
		assert.Equal(t, want, status)
		assert.Equal(t, false, b["success"])
		assert.Contains(t, b, "code")
		assert.NotContains(t, b, "count")
		assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
		assert.Empty(t, h.Get("Location"))
		assert.NotContains(t, encode(b), privateCanary)
	}
	rowCount := func() int64 {
		var n int64
		require.NoError(t, f.db.Model(&model.ClientEvent{}).Count(&n).Error)
		return n
	}
	accounting := func() string {
		value := map[string]any{}
		for table, columns := range map[string]string{"tokens": "id,user_id,remain_quota,used_quota,accessed_time", "users": "id,quota,used_quota,request_count"} {
			var rows []map[string]any
			require.NoError(t, f.db.Table(table).Select(columns).Order("id").Find(&rows).Error)
			value[table] = rows
		}
		for _, table := range []string{"logs", "quota_data", "organization_wallets", "organization_wallet_entries"} {
			if f.db.Migrator().HasTable(table) {
				var count int64
				require.NoError(t, f.db.Table(table).Count(&count).Error)
				value[table] = count
			}
		}
		return fmt.Sprintf("%x", sha256.Sum256([]byte(encode(value))))
	}
	beforeAccounting := accounting()
	t.Run("current_credentials_and_isolation", func(t *testing.T) {
		status, h, b := post(envelope(launch), "relay")
		failure(status, h, b, 404)
		config(true, 600)
		for _, actor := range []string{"", "owner", "sk-unknown", "nap_fixture", "Bearer sk-unknown"} {
			status, h, b = post(envelope(launch), actor)
			failure(status, h, b, 401)
		}
		for _, statusValue := range []int{common.TokenStatusDisabled, common.TokenStatusExpired, 99} {
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("status", statusValue).Error)
			status, h, b = post(envelope(launch), "relay")
			failure(status, h, b, 401)
		}
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Updates(map[string]any{"status": common.TokenStatusEnabled, "expired_time": time.Now().Unix() - 1}).Error)
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 401)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("expired_time", -1).Error)
		require.NoError(t, f.db.Delete(&model.Token{}, relay.Id).Error)
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 401)
		require.NoError(t, f.db.Unscoped().Model(&model.Token{}).Where("id = ?", relay.Id).Update("deleted_at", nil).Error)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).Update("status", common.UserStatusDisabled).Error)
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 403)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).Update("status", common.UserStatusEnabled).Error)
		require.NoError(t, f.db.Delete(&model.User{}, f.users["owner"].Id).Error)
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 403)
		require.NoError(t, f.db.Unscoped().Model(&model.User{}).Where("id = ?", f.users["owner"].Id).Update("deleted_at", nil).Error)
		variant := strings.ToUpper(relay.Key)
		var matches int64
		require.NoError(t, f.db.Model(&model.Token{}).Where(map[string]any{"key": variant}).Count(&matches).Error)
		t.Logf("case-variant SQL equivalence=%t; HTTP must still reject", matches > 0)
		status, h, b = post(envelope(launch), "sk-"+variant)
		failure(status, h, b, 401)
		for _, authorization := range []string{"bearer " + f.bearer["relay"] + "-suffix", "Bearer  " + f.bearer["relay"], "Bearer " + f.bearer["relay"] + "\u00a0"} {
			status, h, b = f.request(t, http.MethodPost, "/api/events", "", encode(envelope(launch)), http.Header{"Content-Type": {"application/json"}, "Authorization": {authorization}})
			failure(status, h, b, 401)
		}
		status, h, b = f.request(t, http.MethodPost, "/api/events", "", encode(envelope(launch)), http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer " + f.bearer["relay"], "Bearer " + f.bearer["relay"]}})
		failure(status, h, b, 400)
		assert.Zero(t, rowCount())
		allow := "203.0.113.0/24"
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("allow_ips", allow).Error)
		status, h, b = f.request(t, http.MethodPost, "/api/events", "relay", encode(envelope(launch)), http.Header{"Content-Type": {"application/json"}, "X-Forwarded-For": {"203.0.113.5"}})
		failure(status, h, b, 403)
		require.NoError(t, f.engine.SetTrustedProxies([]string{"127.0.0.1"}))
		status, _, b = f.request(t, http.MethodPost, "/api/events", "relay", encode(envelope(launch)), http.Header{"Content-Type": {"application/json"}, "X-Forwarded-For": {"203.0.113.5"}})
		require.Equal(t, 200, status)
		assert.EqualValues(t, 1, b["count"])
		require.NoError(t, f.engine.SetTrustedProxies(nil))
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("allow_ips", "").Error)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("status", common.TokenStatusExhausted).Error)
		status, _, b = post(envelope(launch), "relay")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 0, b["count"])
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("status", common.TokenStatusEnabled).Error)
		status, _, b = post(envelope(launch), "events-foreign")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 1, b["count"])
		assert.EqualValues(t, 2, rowCount())
	})
	t.Run("validation_and_resource_limits", func(t *testing.T) {
		initial := rowCount()
		for _, raw := range []string{`null`, `[]`, `{"client_id":"` + clientID + `","client_id":"` + clientID + `","channel":"cherry-studio","events":[]}`, encode(map[string]any{"Client_id": clientID, "channel": "cherry-studio", "events": []any{launch}}), encode(envelope()), encode(envelope(nil)), strings.Repeat(" ", 256*1024+1)} {
			want := 400
			if len(raw) > 256*1024 {
				want = 413
			}
			status, h, b := f.request(t, http.MethodPost, "/api/events", "relay", raw, http.Header{"Content-Type": {"application/json"}})
			failure(status, h, b, want)
		}
		status, h, b := f.request(t, http.MethodPost, "/api/events", "relay", `{"client_id":"`+clientID+`","channel":"cherry-studio","events":[{"event_type":"app_update","data":{"version":"x","version":"y"}}]}`, http.Header{"Content-Type": {"application/json"}})
		failure(status, h, b, 400)
		invalid := []any{event("unknown", map[string]any{"data": nil}), event("app_update", map[string]any{"version": nil}), event("app_launch", map[string]any{"version": "x", "os": "wrong"})}
		for _, counter := range []any{-1, 1.5, "1", nil, uint64(9007199254740992)} {
			invalid = append(invalid, event("token_usage", map[string]any{"provider": "new-api", "model": "fixture", "input_tokens": counter, "output_tokens": 1}))
		}
		old := event("app_update", map[string]any{"version": "x"})
		old["timestamp"] = time.Now().Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano)
		future := event("app_update", map[string]any{"version": "x"})
		future["timestamp"] = time.Now().Add(2 * time.Hour).Format(time.RFC3339Nano)
		nullTime := event("app_update", map[string]any{"version": "x"})
		nullTime["timestamp"] = nil
		invalid = append(invalid, old, future, nullTime)
		for _, value := range invalid {
			status, _, b = post(envelope(value), "relay")
			require.Equal(t, 200, status)
			assert.EqualValues(t, 0, b["count"])
		}
		raw := `{"client_id":"` + clientID + `","channel":"cherry-studio","events":[{"event_type":"app_update","timestamp":"` + stamp + `","data":{"version":"\ud800"}}]}`
		status, _, b = f.request(t, http.MethodPost, "/api/events", "relay", raw, http.Header{"Content-Type": {"application/json"}})
		require.Equal(t, 200, status)
		assert.EqualValues(t, 0, b["count"])
		for _, lexeme := range []string{"1e3", "1.0", "9223372036854775808"} {
			raw = `{"client_id":"` + clientID + `","channel":"cherry-studio","events":[{"event_type":"token_usage","data":{"provider":"x","model":"x","input_tokens":` + lexeme + `,"output_tokens":1}}]}`
			status, _, b = f.request(t, http.MethodPost, "/api/events", "relay", raw, http.Header{"Content-Type": {"application/json"}})
			require.Equal(t, 200, status)
			assert.EqualValues(t, 0, b["count"])
		}
		assert.Equal(t, initial, rowCount())
		ten := make([]any, 10)
		for i := range ten {
			ten[i] = launch
		}
		status, _, b = post(envelope(ten...), "relay")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 0, b["count"])
		status, h, b = post(envelope(append(ten, launch)...), "relay")
		failure(status, h, b, 400)
		oversized := event("app_update", map[string]any{"version": "x", "unknown": strings.Repeat("x", 64*1024)})
		status, h, b = post(envelope(oversized), "relay")
		failure(status, h, b, 413)
		// Unknown nullable subtrees are discarded, not recursively strict-validated.
		unknown := envelope(event("app_update", map[string]any{"version": "nullable-unknown", "unknown": map[string]any{"x": nil}}))
		unknown["unknown"] = nil
		status, _, b = post(unknown, "relay")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 1, b["count"])
		maxEvent := event("token_usage", map[string]any{"provider": "new-api", "model": "safe-integer", "input_tokens": int64(9007199254740991), "output_tokens": 0})
		status, _, b = post(envelope(maxEvent), "relay")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 1, b["count"])
		config(true, 1)
		status, _, _ = post(envelope(launch), "events-limit")
		require.Equal(t, 200, status)
		status, h, b = post(envelope(launch), "events-limit")
		failure(status, h, b, 429)
		retry, err := strconv.Atoi(h.Get("Retry-After"))
		require.NoError(t, err)
		assert.Positive(t, retry)
		config(true, 600)
		oldGlobal, oldNumber, oldDuration := common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration
		t.Cleanup(func() {
			common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = oldGlobal, oldNumber, oldDuration
		})
		common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = true, 2, 60
		config(false, 600)
		common.RedisEnabled = true
		common.RDB = nil
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 404)
		config(true, 600)
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 503)
		common.RedisEnabled = false
		for range 2 {
			status, _, _ = post(envelope(launch), "relay")
			require.Equal(t, 200, status, "one global admission per request")
		}
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 429)
		common.GlobalApiRateLimitEnable = false
		common.RedisEnabled = true
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 503)
		common.RedisEnabled = false
		common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = oldGlobal, oldNumber, oldDuration
	})
	t.Run("durability_and_deduplication", func(t *testing.T) {
		usage := event("token_usage", map[string]any{"provider": "new-api", "model": "concurrent", "input_tokens": 123, "output_tokens": 456})
		before := rowCount()
		results := make(chan map[string]any, 2)
		var wg sync.WaitGroup
		for _, actor := range []string{"relay", "events-rotate"} {
			wg.Go(func() {
				status, _, b := post(envelope(usage, usage), actor)
				assert.Equal(t, 200, status)
				results <- b
			})
		}
		wg.Wait()
		close(results)
		sum := 0.0
		for b := range results {
			if value, ok := b["count"].(float64); ok {
				sum += value
			}
		}
		assert.EqualValues(t, 1, sum)
		assert.Equal(t, before+1, rowCount())
		withDefault := event("token_usage", map[string]any{"output_tokens": 456, "input_tokens": 123, "model": "concurrent", "provider": "new-api", "source": "chat", "secret": privateCanary})
		status, _, b := post(envelope(withDefault), "events-rotate")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 0, b["count"])
		missing := event("app_update", map[string]any{"version": "no-client-time"})
		delete(missing, "timestamp")
		status, _, b = post(envelope(missing), "relay")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 1, b["count"])
		var writes atomic.Int64
		callback := "events-second-write-fails"
		require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" && writes.Add(1) == 2 {
				tx.AddError(errors.New("fixture private cause"))
			}
		}))
		before = rowCount()
		a := event("app_update", map[string]any{"version": "rollback-a"})
		z := event("app_update", map[string]any{"version": "rollback-z"})
		status, h, b := post(envelope(a, z), "relay")
		failure(status, h, b, 503)
		assert.Equal(t, before, rowCount())
		require.NoError(t, f.db.Callback().Create().Remove(callback))
		// A real commit followed by lost acknowledgement is503. Retrying timestamped
		// rows after restoring the pool returns0 without duplicating the row.
		var fired atomic.Bool
		pool, statementPool := f.db.Config.ConnPool, f.db.Statement.ConnPool
		wrapper := &clientEventsUncertainPool{ConnPool: pool, fired: &fired}
		f.db.Config.ConnPool, f.db.Statement.ConnPool = wrapper, wrapper
		status, h, b = post(envelope(a), "relay")
		f.db.Config.ConnPool, f.db.Statement.ConnPool = pool, statementPool
		failure(status, h, b, 503)
		assert.True(t, fired.Load())
		assert.Equal(t, before+1, rowCount())
		status, _, b = post(envelope(a), "relay")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 0, b["count"])
		var rows []model.ClientEvent
		require.NoError(t, f.db.Order("id").Find(&rows).Error)
		encoded := encode(rows)
		assert.NotContains(t, encoded, privateCanary)
		for _, row := range rows {
			assert.NotEmpty(t, row.Fingerprint)
			assert.Positive(t, row.UserID)
			assert.NotEmpty(t, row.ClientID)
			assert.NotContains(t, encoded, relay.Key)
		}
	})
	t.Run("cleanup_and_current_authority", func(t *testing.T) {
		cache := miniredis.RunT(t)
		oldRDB := common.RDB
		common.RDB = redis.NewClient(&redis.Options{Addr: cache.Addr()})
		common.RedisEnabled = true
		t.Cleanup(func() { require.NoError(t, common.RDB.Close()); common.RDB = oldRDB; common.RedisEnabled = false })
		_, err := model.GetTokenByKey(relay.Key, false)
		require.NoError(t, err)
		_, err = model.GetUserCache(f.users["owner"].Id)
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("status", common.TokenStatusDisabled).Error)
		status, h, b := post(envelope(launch), "relay")
		failure(status, h, b, 401)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", relay.Id).Update("status", common.TokenStatusEnabled).Error)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).Update("status", common.UserStatusDisabled).Error)
		status, h, b = post(envelope(launch), "relay")
		failure(status, h, b, 403)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).Update("status", common.UserStatusEnabled).Error)
		common.RedisEnabled = false
		// Revoke after the preliminary ordinary read, before the final transaction.
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		var gated atomic.Bool
		callback := "events-before-authority-transaction"
		require.NoError(t, f.db.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
			if tx.Statement.Table == "users" && gated.CompareAndSwap(false, true) {
				close(entered)
				<-release
			}
		}))
		done := make(chan int, 1)
		before := rowCount()
		go func() { status, _, _ := post(envelope(launch), "events-rotate"); done <- status }()
		t.Cleanup(func() { once.Do(func() { close(release) }); _ = f.db.Callback().Query().Remove(callback) })
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("authority barrier not reached")
		}
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens["rotate"].Id).Update("status", common.TokenStatusDisabled).Error)
		once.Do(func() { close(release) })
		assert.Equal(t, 401, <-done)
		assert.Equal(t, before, rowCount())
		require.NoError(t, f.db.Callback().Query().Remove(callback))
		// Expiry after an insert wait must roll back the inserted row.
		deadline := time.Now().Unix() + 1
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens["expiry"].Id).Update("expired_time", deadline).Error)
		var waited atomic.Bool
		callback = "events-insert-expiry"
		require.NoError(t, f.db.Callback().Create().After("gorm:create").Register(callback, func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				waited.Store(true)
				timer := time.NewTimer(time.Until(time.Unix(deadline, 0)))
				defer timer.Stop()
				<-timer.C
			}
		}))
		expiring := event("app_update", map[string]any{"version": "expired-after-wait"})
		status, h, b = post(envelope(expiring), "events-expiry")
		failure(status, h, b, 401)
		assert.True(t, waited.Load(), "expiry must occur after the actual insert wait")
		assert.Equal(t, before, rowCount())
		require.NoError(t, f.db.Callback().Create().Remove(callback))
		cutoff := time.Now().Add(-30 * 24 * time.Hour).Unix()
		expired := model.ClientEvent{UserID: relay.UserId, TokenID: relay.Id, ClientID: clientID, Channel: "cherry-studio", EventType: "app_update", EventTimeMS: (cutoff - 1) * 1000, ReceivedAt: cutoff - 1, Fingerprint: strings.Repeat("e", 64), AppVersion: "retention"}
		boundary := expired
		boundary.ReceivedAt = cutoff
		boundary.Fingerprint = strings.Repeat("f", 64)
		require.NoError(t, f.db.Create(&expired).Error)
		require.NoError(t, f.db.Create(&boundary).Error)
		n, err := model.DeleteClientEventBatch(context.Background(), cutoff)
		require.NoError(t, err)
		assert.EqualValues(t, 1, n)
		n, err = model.DeleteClientEventBatch(context.Background(), cutoff)
		require.NoError(t, err)
		assert.Zero(t, n)
		var kept model.ClientEvent
		require.NoError(t, f.db.First(&kept, boundary.ID).Error)
		old := event("app_update", map[string]any{"version": "retention"})
		old["timestamp"] = time.UnixMilli(expired.EventTimeMS).UTC().Format(time.RFC3339Nano)
		status, _, b = post(envelope(old), "relay")
		require.Equal(t, 200, status)
		assert.EqualValues(t, 0, b["count"])
		config(false, 600)
		handler := service.ClientEventsCleanupHandler{}
		assert.True(t, handler.Enabled())
		for _, cancelled := range []bool{false, true} {
			task, err := model.CreateSystemTask(handler.Type(), struct{}{}, nil)
			require.NoError(t, err)
			task, claimed, err := model.ClaimSystemTask(task.ID, handler.Type(), "events-fixture", time.Now().Add(time.Minute).Unix())
			require.NoError(t, err)
			require.True(t, claimed)
			ctx, cancel := context.WithCancel(context.Background())
			if cancelled {
				cancel()
			}
			handler.Run(ctx, task, "events-fixture")
			cancel()
			var result model.SystemTask
			require.NoError(t, f.db.Where("task_id = ?", task.TaskID).First(&result).Error)
			if cancelled {
				assert.Equal(t, model.SystemTaskStatusFailed, result.Status)
			} else {
				assert.Equal(t, model.SystemTaskStatusSucceeded, result.Status)
			}
		}
		for _, path := range []string{"/api/events?key=" + privateCanary, "/api/events/?key=" + privateCanary} {
			status, h, b = f.request(t, http.MethodPost, path, "relay", "{}", http.Header{"Content-Type": {"application/json"}})
			failure(status, h, b, 404)
			status, h, _ = f.request(t, http.MethodGet, path, "relay", "", nil)
			assert.Equal(t, 404, status)
			assert.Empty(t, h.Get("Location"))
		}
		assert.NotContains(t, f.logs.snapshot(), privateCanary)
		assert.NotContains(t, f.logs.snapshot(), relay.Key)
	})
	assert.Equal(t, beforeAccounting, accounting(), "telemetry never mutates accounting/access totals")
}

// Success with the real stock embed is verified by the root-module browser
// overlay; embed.FS cannot be fabricated from a router-package MapFS fixture.
func TestOAuthProviderPagePrivacyHTTP(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	originalMaster := common.IsMasterNode
	t.Cleanup(func() { common.IsMasterNode = originalMaster })
	const canary = "provider-page-capability-canary"
	const injected = "<script>owned-analytics-canary</script>"
	variants := []string{
		"/oauth/provider/login/", "/oauth/provider/consent/", "//oauth//provider/login",
		"/oauth/provider/login//child", "/%6fauth/provider/login", "/%256fauth/provider/login",
		"/oauth/provider%2flogin", "/oauth/provider/consent/" + canary,
	}
	for _, topology := range []struct {
		name, frontend string
		master         bool
	}{
		{"embedded", "", true},
		{"master_ignores_frontend", "https://frontend.invalid/prefix", true},
		{"split_rejects_locally", "https://frontend.invalid/prefix", false},
	} {
		t.Run(topology.name, func(t *testing.T) {
			common.IsMasterNode = topology.master
			t.Setenv("FRONTEND_BASE_URL", topology.frontend)
			e := gin.New()
			middleware.SetUpLogger(e)
			SetRouter(e, WebAssets{IndexPage: []byte(injected)})
			request := func(method, path string) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				e.ServeHTTP(w, httptest.NewRequest(method, path+"?login_challenge="+canary, nil))
				assert.Equal(t, "private, no-store", w.Header().Get("Cache-Control"))
				assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
				assert.Equal(t, "frame-ancestors 'none'", w.Header().Get("Content-Security-Policy"))
				assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
				assert.Empty(t, w.Header().Get("Location"))
				assert.Empty(t, w.Header().Values("Set-Cookie"))
				assert.NotContains(t, w.Body.String(), canary)
				assert.NotContains(t, w.Body.String(), injected)
				return w
			}
			for _, path := range []string{"/oauth/provider/login", "/oauth/provider/consent"} {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					w := request(method, path)
					expected := http.StatusServiceUnavailable // no BuildFS: never use injected IndexPage
					if topology.frontend != "" && !topology.master {
						expected = http.StatusNotFound
					}
					assert.Equal(t, expected, w.Code)
				}
				assert.Contains(t, []int{400, 404}, request(http.MethodPost, path).Code)
			}
			for _, path := range variants {
				assert.Contains(t, []int{400, 404}, request(http.MethodGet, path).Code)
			}
			// Callback and generic SPA behavior keep the original injected page or
			// split redirect; this namespace does not alter global redirect policy.
			for _, path := range []string{"/oauth/github", "/ordinary-page"} {
				w := httptest.NewRecorder()
				e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				if topology.frontend != "" && !topology.master {
					assert.Equal(t, http.StatusMovedPermanently, w.Code)
					assert.Equal(t, topology.frontend+path, w.Header().Get("Location"))
				} else {
					assert.Equal(t, http.StatusOK, w.Code)
					assert.Equal(t, injected, w.Body.String())
				}
			}
		})
	}
	assert.NotContains(t, f.logs.snapshot(), canary)
	assert.Contains(t, f.logs.snapshot(), "/oauth/provider/[authorization]")
}

func TestOAuthTokenRevocationHTTP(t *testing.T) {
	oldAPI, oldCritical, oldRedis, oldMaster := common.GlobalApiRateLimitEnable, common.CriticalRateLimitEnable, common.RedisEnabled, common.IsMasterNode
	oldWriter, oldMode := gin.DefaultWriter, gin.Mode()
	common.GlobalApiRateLimitEnable, common.CriticalRateLimitEnable, common.RedisEnabled = false, false, false
	gin.SetMode(gin.TestMode)
	logs := &organizationLogBuffer{}
	gin.DefaultWriter = logs
	t.Cleanup(func() {
		common.GlobalApiRateLimitEnable, common.CriticalRateLimitEnable, common.RedisEnabled, common.IsMasterNode = oldAPI, oldCritical, oldRedis, oldMaster
		gin.DefaultWriter = oldWriter
		gin.SetMode(oldMode)
	})
	t.Setenv("TRUSTED_PROXIES", "none")
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	t.Setenv("OAUTH_PROVIDER_BRIDGE_ENABLED", "false")
	t.Setenv("OAUTH_PROVIDER_REVOCATION_ENABLED", "false")
	require.NoError(t, service.InitOAuthUserInfoResource())
	require.NoError(t, service.InitOAuthProviderBridge())
	dbBefore := model.DB
	const canary = "revocation-capability-canary"
	var calls, redirectCalls atomic.Int64
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirectCalls.Add(1) }))
	t.Cleanup(redirect.Close)
	entered := make(chan struct{})
	var mu sync.Mutex
	var received []url.Values
	var warmAddress string
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "/tenant/oauth2/revoke", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		for _, name := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-Host", "X-Forwarded-For", "Idempotency-Key", "X-Idempotency-Key", "X-Caller-Canary"} {
			assert.Empty(t, r.Header.Get(name))
		}
		assert.NotEqual(t, "caller.invalid", r.Host)
		assert.NoError(t, r.ParseForm())
		assert.Len(t, r.PostForm, 2)
		assert.Equal(t, "native-public", r.PostForm.Get("client_id"))
		mu.Lock()
		received = append(received, r.PostForm)
		mu.Unlock()
		w.Header().Set("X-Issuer-Canary", canary)
		w.Header().Set("Set-Cookie", "issuer="+canary)
		switch r.PostForm.Get("token") {
		case "invalid-client":
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"`+canary+`","optional":null}`)
		case "duplicate-error":
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"invalid_client","error":"invalid_client"}`)
		case "unknown-error":
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"invalid_request","cause":"`+canary+`"}`)
		case "storage-error":
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
		case "malformed-error":
			w.WriteHeader(401)
			_, _ = io.WriteString(w, canary)
		case "oversized-error":
			w.WriteHeader(401)
			_, _ = io.WriteString(w, strings.Repeat("x", 4097))
		case "redirect":
			w.Header().Set("Location", redirect.URL+"/"+canary)
			w.WriteHeader(307)
		case "wait":
			close(entered)
			<-r.Context().Done()
		case "warm":
			mu.Lock()
			warmAddress = r.RemoteAddr
			mu.Unlock()
		case "drop":
			mu.Lock()
			assert.Equal(t, warmAddress, r.RemoteAddr, "the credential request uses the established HTTP1 connection")
			mu.Unlock()
			conn, _, err := w.(http.Hijacker).Hijack()
			if assert.NoError(t, err) {
				_ = conn.Close()
			}
		case "wrong-client-masked", "storage-error-masked":
			// The pinned issuer can mask both as200. This is not invalidation evidence.
			_, _ = io.WriteString(w, `{"cause":"`+canary+`"}`)
		}
	}))
	t.Cleanup(issuer.Close)
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	resourceConfig := service.OAuthUserInfoConfig{Enabled: true, IntrospectionURL: issuer.URL + "/admin/oauth2/introspect", Issuer: issuer.URL + "/tenant/", Audience: "newapi-userinfo", ClientIDs: []string{"native-public"}}
	resource, err := service.NewOAuthUserInfoResource(resourceConfig, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	config := service.OAuthProviderConfig{Enabled: true, RevocationEnabled: true, AdminBaseURL: issuer.URL, AuthorizationURL: issuer.URL + "/tenant/oauth2/auth"}
	bridge, err := service.NewOAuthProviderBridge(config, resource)
	require.NoError(t, err)
	newRouter := func(bridge *service.OAuthProviderBridge) *gin.Engine {
		e := gin.New()
		middleware.SetUpLogger(e)
		SetOAuthProviderRouter(e, bridge)
		return e
	}
	serve := func(e *gin.Engine, method, path, body string, headers http.Header) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.113:43210"
		r.Host = "caller.invalid"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for name, values := range headers {
			r.Header[name] = values
		}
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		assert.Equal(t, "private, no-store", w.Header().Get("Cache-Control"))
		assert.Empty(t, w.Header().Values("Set-Cookie"))
		assert.Empty(t, w.Header().Get("Location"))
		assert.Empty(t, w.Header().Get("X-Issuer-Canary"))
		assert.NotContains(t, w.Body.String(), canary)
		return w
	}
	body := func(token string) string {
		return url.Values{"token": {token}, "client_id": {"native-public"}}.Encode()
	}
	t.Run("startup_and_reserved_path", func(t *testing.T) {
		for _, value := range []string{"TRUE", "1", " ", "true"} {
			t.Setenv("OAUTH_PROVIDER_REVOCATION_ENABLED", value)
			assert.ErrorIs(t, service.InitOAuthProviderBridge(), service.ErrOAuthProviderConfiguration)
		}
		t.Setenv("OAUTH_PROVIDER_REVOCATION_ENABLED", "false")
		require.NoError(t, service.InitOAuthProviderBridge())
		_, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{RevocationEnabled: true}, resource)
		assert.ErrorIs(t, err, service.ErrOAuthProviderConfiguration)
		_, err = service.NewOAuthProviderBridge(config, nil)
		assert.ErrorIs(t, err, service.ErrOAuthProviderConfiguration)
		for _, split := range []bool{false, true} {
			common.IsMasterNode = false
			frontend := ""
			if split {
				frontend = "https://frontend.invalid"
			}
			t.Setenv("FRONTEND_BASE_URL", frontend)
			e := gin.New()
			middleware.SetUpLogger(e)
			SetRouter(e, WebAssets{IndexPage: []byte("owned-SPA-fallback")})
			for _, path := range []string{"/oauth2/revoke", "/oauth2/revoke/", "/oauth2/revoke//", "/oauth2/revoke/child", "/oauth2/%72evoke", "/oauth2%2frevoke/"} {
				for _, method := range []string{http.MethodPost, http.MethodGet, "PROPFIND"} {
					w := serve(e, method, path+"?token="+canary, body("owned-token"), nil)
					assert.Equal(t, 404, w.Code)
					assert.JSONEq(t, `{"error":"not_found"}`, w.Body.String())
				}
			}
			// Ordinary NoRoute remains intact; the reserved path is a local exception.
			w := httptest.NewRecorder()
			e.ServeHTTP(w, httptest.NewRequest("GET", "/unrelated", nil))
			if split {
				assert.Equal(t, 301, w.Code)
				assert.Equal(t, frontend+"/unrelated", w.Header().Get("Location"))
			} else {
				assert.Equal(t, "owned-SPA-fallback", w.Body.String())
			}
			w = httptest.NewRecorder()
			e.ServeHTTP(w, httptest.NewRequest("GET", "/api/status", nil))
			var status struct {
				Data struct {
					OAuth struct {
						Enabled bool `json:"enabled"`
					} `json:"oauth"`
					Features struct {
						OAuth bool `json:"oauth"`
					} `json:"client_features"`
				} `json:"data"`
			}
			require.NoError(t, common.Unmarshal(w.Body.Bytes(), &status))
			assert.False(t, status.Data.OAuth.Enabled)
			assert.False(t, status.Data.Features.OAuth)
		}
		assert.Zero(t, calls.Load())
	})
	e := newRouter(bridge)
	t.Run("strict_form_and_public_identity", func(t *testing.T) {
		before := calls.Load()
		for _, tc := range []struct {
			name, path, body string
			headers          http.Header
		}{
			{name: "missing token", path: "/oauth2/revoke", body: "client_id=native-public"},
			{name: "missing client", path: "/oauth2/revoke", body: "token=owned"},
			{name: "duplicate", path: "/oauth2/revoke", body: "token=owned&token=other&client_id=native-public"},
			{name: "encoded duplicate", path: "/oauth2/revoke", body: "token=owned&%74oken=other&client_id=native-public"},
			{name: "unknown", path: "/oauth2/revoke", body: body("owned") + "&subject=1"},
			{name: "client secret", path: "/oauth2/revoke", body: body("owned") + "&client_secret=secret"},
			{name: "client assertion", path: "/oauth2/revoke", body: body("owned") + "&client_assertion=secret"},
			{name: "percent", path: "/oauth2/revoke", body: body("owned") + "%Q0"},
			{name: "semicolon", path: "/oauth2/revoke", body: body("owned") + ";token=other"},
			{name: "query", path: "/oauth2/revoke?token=" + canary, body: body("owned")},
			{name: "force query", path: "/oauth2/revoke?", body: body("owned")},
			{name: "body cap", path: "/oauth2/revoke", body: strings.Repeat("x", 8193)},
			{name: "token cap", path: "/oauth2/revoke", body: body(strings.Repeat("x", 4097))},
			{name: "unicode", path: "/oauth2/revoke", body: body("owned\u00a0")},
			{name: "whitespace", path: "/oauth2/revoke", body: body(" owned")},
			{name: "empty", path: "/oauth2/revoke", body: body("")},
			{name: "client cap", path: "/oauth2/revoke", body: "token=owned&client_id=" + strings.Repeat("x", 257)},
			{name: "not allowed", path: "/oauth2/revoke", body: "token=owned&client_id=foreign"},
			{name: "hint cap", path: "/oauth2/revoke", body: body("owned") + "&token_type_hint=" + strings.Repeat("x", 257)},
			{name: "hint duplicate", path: "/oauth2/revoke", body: body("owned") + "&token_type_hint=a&token_type_hint=b"},
			{name: "authorization", path: "/oauth2/revoke", body: body("owned"), headers: http.Header{"Authorization": {"Bearer " + canary}}},
			{name: "mixed authorization", path: "/oauth2/revoke", body: body("owned"), headers: http.Header{"Authorization": {"Bearer owned"}, "authorization": {"other"}}},
			{name: "missing media", path: "/oauth2/revoke", body: body("owned"), headers: http.Header{"Content-Type": {}}},
			{name: "JSON", path: "/oauth2/revoke", body: body("owned"), headers: http.Header{"Content-Type": {"application/json"}}},
			{name: "duplicate media", path: "/oauth2/revoke", body: body("owned"), headers: http.Header{"Content-Type": {"application/x-www-form-urlencoded", "application/x-www-form-urlencoded"}}},
			{name: "mixed media", path: "/oauth2/revoke", body: body("owned"), headers: http.Header{"content-type": {"application/json"}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w := serve(e, "POST", tc.path, tc.body, tc.headers)
				assert.Equal(t, 400, w.Code)
				assert.JSONEq(t, `{"error":"invalid_request"}`, w.Body.String())
			})
		}
		assert.Equal(t, before, calls.Load())
		for _, path := range []string{"/oauth2/revoke/", "/oauth2/revoke//", "/oauth2/revoke/child?token=" + canary, "/oauth2/%72evoke"} {
			assert.Equal(t, 400, serve(e, "POST", path, body("owned"), nil).Code)
		}
		assert.Equal(t, 405, serve(e, "DELETE", "/oauth2/revoke?token="+canary, "", nil).Code)
		for _, token := range []string{"sk-expired.synthetic", "refresh.synthetic", "oauth:disabled.synthetic", "a+b/=opaque"} {
			for _, hint := range []string{"", "&token_type_hint=", "&token_type_hint=refresh_token", "&token_type_hint=unknown"} {
				h := http.Header{"Cookie": {"owned=" + canary}, "Forwarded": {"host=caller.invalid"}, "X-Forwarded-Host": {"caller.invalid"}, "X-Forwarded-For": {"198.51.100.1"}, "Idempotency-Key": {"owned"}, "X-Idempotency-Key": {"owned"}, "X-Caller-Canary": {canary}}
				w := serve(e, "POST", "/oauth2/revoke", body(token)+hint, h)
				assert.Equal(t, 200, w.Code)
				assert.Empty(t, w.Body.String())
				mu.Lock()
				assert.Equal(t, token, received[len(received)-1].Get("token"))
				mu.Unlock()
			}
		}
	})
	t.Run("issuer_responses_and_transport", func(t *testing.T) {
		for _, tc := range []struct {
			token  string
			status int
			code   string
		}{
			{"wrong-client-masked", 200, ""}, {"storage-error-masked", 200, ""},
			{"invalid-client", 401, "invalid_client"}, {"duplicate-error", 503, "temporarily_unavailable"},
			{"unknown-error", 503, "temporarily_unavailable"}, {"storage-error", 503, "temporarily_unavailable"},
			{"malformed-error", 503, "temporarily_unavailable"}, {"oversized-error", 503, "temporarily_unavailable"}, {"redirect", 503, "temporarily_unavailable"},
		} {
			w := serve(e, "POST", "/oauth2/revoke", body(tc.token), nil)
			assert.Equal(t, tc.status, w.Code)
			if tc.code == "" {
				assert.Empty(t, w.Body.String())
			} else {
				assert.JSONEq(t, `{"error":"`+tc.code+`"}`, w.Body.String())
			}
		}
		assert.Zero(t, redirectCalls.Load())
		untrusted, err := service.NewOAuthUserInfoResource(resourceConfig, nil)
		require.NoError(t, err)
		defer untrusted.CloseIdleConnections()
		untrustedBridge, err := service.NewOAuthProviderBridge(config, untrusted)
		require.NoError(t, err)
		before := calls.Load()
		assert.Equal(t, 503, serve(newRouter(untrustedBridge), "POST", "/oauth2/revoke", body(canary), nil).Code)
		assert.Equal(t, before, calls.Load())
		require.Equal(t, 200, serve(e, "POST", "/oauth2/revoke", body("warm"), nil).Code)
		before = calls.Load()
		assert.Equal(t, 503, serve(e, "POST", "/oauth2/revoke", body("drop"), http.Header{"Idempotency-Key": {"owned"}, "X-Idempotency-Key": {"owned"}}).Code)
		assert.Equal(t, before+1, calls.Load(), "no sent POST replay on the reused HTTP1 connection")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r := httptest.NewRequest("POST", "/oauth2/revoke", strings.NewReader(body("wait"))).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { e.ServeHTTP(w, r); close(done) }()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("issuer did not receive the bounded request")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("cancellation did not end revocation request")
		}
		assert.Equal(t, 503, w.Code)
		assert.JSONEq(t, `{"error":"temporarily_unavailable"}`, w.Body.String())
	})
	t.Run("limits_and_privacy", func(t *testing.T) {
		oldNum, oldDuration := common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration
		common.GlobalApiRateLimitEnable = true
		common.GlobalApiRateLimitNum = 1
		common.GlobalApiRateLimitDuration = 60
		t.Cleanup(func() {
			common.GlobalApiRateLimitEnable = false
			common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = oldNum, oldDuration
		})
		limited := newRouter(bridge)
		for i := range 2 {
			r := httptest.NewRequest("POST", "/oauth2/revoke", strings.NewReader(body("limited")))
			r.RemoteAddr = "192.0.2.217:43210"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			limited.ServeHTTP(w, r)
			if i == 0 {
				assert.Equal(t, 200, w.Code)
			} else {
				assert.Equal(t, 429, w.Code)
				assert.NotEmpty(t, w.Header().Get("Retry-After"))
			}
			assert.Equal(t, "private, no-store", w.Header().Get("Cache-Control"))
			assert.Empty(t, w.Header().Get("Location"))
		}
		assert.NotContains(t, logs.String(), canary)
		assert.Equal(t, dbBefore, model.DB, "the root never initializes a database")
	})
}

func TestOAuthProviderBridgeHTTP(t *testing.T) {
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	t.Setenv("OAUTH_PROVIDER_BRIDGE_ENABLED", "false")
	require.NoError(t, service.InitOAuthUserInfoResource())
	require.NoError(t, service.InitOAuthProviderBridge())
	f := newOrganizationHTTPFixture(t)
	// This test injects its own bridge/resource instances below. Register their
	// reserved routes once, instead of reusing the fully configured fixture router.
	f.engine = gin.New()
	f.engine.Use(middleware.RequestId())
	middleware.SetUpLogger(f.engine)
	f.engine.NoRoute(func(c *gin.Context) { c.JSON(http.StatusNotFound, gin.H{"error": "not_found"}) })
	SetApiRouter(f.engine)
	f.server.Config.Handler = f.engine
	require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}))
	oldCritical, oldAddress := common.CriticalRateLimitEnable, system_setting.ServerAddress
	common.CriticalRateLimitEnable, system_setting.ServerAddress = false, "https://console.example"
	t.Cleanup(func() { common.CriticalRateLimitEnable, system_setting.ServerAddress = oldCritical, oldAddress })
	const publicAuth = "https://issuer.example/oauth2/auth"
	const logCanary = "provider-capability-canary"
	type attempt struct {
		phase, challenge string
		body             map[string]any
	}
	var mu sync.Mutex
	requests := map[string]map[string]any{}
	gone := map[string]bool{}
	attempts := []attempt{}
	var getHook func(string)
	var putHook func(*http.Request, string)
	var badResume bool
	var producedSubject, producedVersion, producedClient string
	encode := func(value any) []byte { data, err := common.Marshal(value); assert.NoError(t, err); return data }
	clone := func(value map[string]any) map[string]any {
		var result map[string]any
		assert.NoError(t, common.Unmarshal(encode(value), &result))
		return result
	}
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Cookie"))
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("X-Caller-Canary"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/admin/oauth2/introspect" {
			assert.NoError(t, r.ParseForm())
			assert.Len(t, r.PostForm, 1)
			mu.Lock()
			subject, version, client := producedSubject, producedVersion, producedClient
			mu.Unlock()
			value := map[string]any{"active": false}
			if r.PostForm.Get("token") == "provider-produced-token" && subject != "" && version != "" {
				value = map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer", "iss": "https://issuer.example/", "aud": []string{"newapi-userinfo"}, "client_id": client, "sub": subject, "exp": time.Now().Unix() + 3600, "scope": "profile email", "ext": map[string]any{"newapi_auth_version": version}}
			}
			_, _ = w.Write(encode(value))
			return
		}
		phase := "login"
		if strings.Contains(r.URL.Path, "/consent") {
			phase = "consent"
		}
		challenge := r.URL.Query().Get(phase + "_challenge")
		mu.Lock()
		value, exists := requests[challenge]
		expired := gone[challenge]
		if exists {
			value = clone(value)
		}
		onGet, onPut, invalidResume := getHook, putHook, badResume
		mu.Unlock()
		if !exists || expired {
			w.WriteHeader(410)
			_, _ = w.Write([]byte(`{"cause":"provider-capability-canary"}`))
			return
		}
		if r.Method == http.MethodGet {
			if onGet != nil {
				onGet(challenge)
			}
			_, _ = w.Write(encode(value))
			return
		}
		assert.Equal(t, http.MethodPut, r.Method)
		var body map[string]any
		if !assert.NoError(t, common.DecodeJson(r.Body, &body)) {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		attempts = append(attempts, attempt{phase, challenge, body})
		if strings.HasSuffix(r.URL.Path, "/accept") {
			if phase == "login" {
				producedSubject, _ = body["subject"].(string)
			} else {
				if session, ok := body["session"].(map[string]any); ok {
					if access, ok := session["access_token"].(map[string]any); ok {
						producedVersion, _ = access["newapi_auth_version"].(string)
					}
				}
				producedClient, _ = value["client"].(map[string]any)["client_id"].(string)
			}
		}
		mu.Unlock()
		// Accept alone deliberately does not make the challenge USED: Hydra's
		// verifier is consumed later. The local claim must stop a second PUT.
		if onPut != nil {
			onPut(r, challenge)
		}
		u, err := url.Parse(value["request_url"].(string))
		assert.NoError(t, err)
		q := u.Query()
		q.Set(phase+"_verifier", "fixture-verifier-"+logCanary)
		u.RawQuery = q.Encode()
		resume := u.String()
		if invalidResume {
			resume = "https://foreign.example/" + logCanary
		}
		_, _ = w.Write(encode(map[string]any{"redirect_to": resume}))
	}))
	t.Cleanup(issuer.Close)
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{Enabled: true, IntrospectionURL: issuer.URL + "/admin/oauth2/introspect", Issuer: "https://issuer.example/", Audience: "newapi-userinfo", ClientIDs: []string{"cherry-studio"}}, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	config := service.OAuthProviderConfig{Enabled: true, AdminBaseURL: issuer.URL + "/", AuthorizationURL: publicAuth}
	bridge, err := service.NewOAuthProviderBridge(config, resource)
	require.NoError(t, err)
	add := func(phase, challenge, actor string) {
		pkce := sha256.Sum256([]byte("fixture-pkce-verifier"))
		query := url.Values{"client_id": {"cherry-studio"}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:35421/oauth/callback"}, "scope": {"profile email tokens:read"}, "state": {"fixture-state-" + challenge}, "code_challenge": {base64.RawURLEncoding.EncodeToString(pkce[:])}, "code_challenge_method": {"S256"}, "audience": {"newapi-userinfo"}}
		subject := ""
		if phase == "consent" {
			subject = strconv.Itoa(f.users[actor].Id)
		}
		value := map[string]any{"challenge": challenge, "subject": subject, "skip": false, "request_url": publicAuth + "?" + query.Encode(), "requested_scope": []string{"profile", "email", "tokens:read"}, "requested_access_token_audience": []string{"newapi-userinfo"}, "context": nil,
			"client": map[string]any{"client_id": "cherry-studio", "client_name": "Fixture client", "token_endpoint_auth_method": "none", "scope": "profile email tokens:read", "audience": []string{"newapi-userinfo"}, "redirect_uris": []string{"http://127.0.0.1:29873/oauth/callback"}, "grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "skip_consent": false, "logo_uri": nil, "metadata": map[string]any{"optional": nil}}}
		mu.Lock()
		requests[challenge] = value
		mu.Unlock()
	}
	post := func(t *testing.T, path, actor string, body any) (int, http.Header, map[string]any) {
		t.Helper()
		return f.request(t, http.MethodPost, path, actor, string(encode(body)), http.Header{"Content-Type": {"application/json"}})
	}
	preview := func(t *testing.T, phase, challenge, actor string) string {
		t.Helper()
		status, h, body := post(t, "/api/oauth/provider/"+phase+"/preview", actor, map[string]any{"challenge": challenge})
		require.Equal(t, 200, status)
		assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
		assert.Empty(t, h.Values("Set-Cookie"))
		assert.Equal(t, []any{"profile", "email"}, body["allowed_scopes"])
		token, ok := body["preview_token"].(string)
		require.True(t, ok)
		require.Len(t, token, 43)
		assert.LessOrEqual(t, body["expires_at"].(float64), float64(time.Now().Add(5*time.Minute).Unix()))
		return token
	}
	decision := func(t *testing.T, phase, challenge, token, actor, action string, scopes ...string) (int, http.Header, map[string]any) {
		t.Helper()
		body := map[string]any{"challenge": challenge, "preview_token": token, "decision": action}
		if phase == "consent" {
			body["selected_scopes"] = append([]string{}, scopes...)
		}
		return post(t, "/api/oauth/provider/"+phase, actor, body)
	}
	putCount := func() int { mu.Lock(); defer mu.Unlock(); return len(attempts) }
	assertFailure := func(t *testing.T, status int, h http.Header, body map[string]any) {
		t.Helper()
		assert.GreaterOrEqual(t, status, 400)
		assert.NotContains(t, body, "redirect_to")
		assert.NotContains(t, body, "preview_token")
		assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
		assert.Empty(t, h.Get("Location"))
		assert.Empty(t, h.Values("Set-Cookie"))
	}
	counts := func() []int64 {
		result := []int64{}
		for _, table := range []any{&model.User{}, &model.UserSession{}, &model.Token{}, &model.UserAccessToken{}} {
			var n int64
			require.NoError(t, f.db.Model(table).Count(&n).Error)
			result = append(result, n)
		}
		return result
	}
	patKey := model.AccessTokenPrefix + strings.Repeat("b", 48)
	pat := &model.UserAccessToken{Name: "Provider boundary fixture", TokenHash: model.AccessTokenFingerprint(patKey), ExpiresAt: time.Now().Unix() + 3600}
	require.NoError(t, pat.SetScopes([]string{"profile:read"}))
	require.NoError(t, model.CreateUserAccessToken(f.users["owner"].Id, pat, 20))
	f.bearer["provider-pat"] = patKey
	otherSID := "s2-provider-" + common.NewRequestId()
	require.NoError(t, model.CreateUserSession(&model.UserSession{SID: otherSID, UserID: f.users["owner"].Id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("b", 64), LoginMethod: "password", ExpiresAt: time.Now().Unix() + 3600}))
	f.bearer["owner-other"], _, err = service.IssueAccessToken(service.AuthIdentity{UserID: f.users["owner"].Id, SessionID: otherSID, UserAuthVersion: 1, SessionVersion: 1})
	require.NoError(t, err)
	before := counts()

	t.Run("real_session_and_explicit_decision", func(t *testing.T) {
		add("login", "first-login", "owner")
		status, h, _ := post(t, "/api/oauth/provider/login/preview?challenge="+logCanary, "owner", map[string]any{"challenge": "first-login"})
		assert.Equal(t, 404, status)
		assert.Empty(t, h.Get("Location"))
		for _, invalid := range []service.OAuthProviderConfig{{Enabled: true, AdminBaseURL: "http://untrusted.example/", AuthorizationURL: publicAuth}, {Enabled: true, AdminBaseURL: issuer.URL + "/?secret=" + logCanary, AuthorizationURL: publicAuth}, {Enabled: true, AdminBaseURL: issuer.URL, AuthorizationURL: "https://foreign.example/oauth2/auth"}} {
			_, err := service.NewOAuthProviderBridge(invalid, resource)
			require.ErrorIs(t, err, service.ErrOAuthProviderConfiguration)
		}
		SetOAuthResourceRouter(f.engine, resource)
		SetOAuthProviderRouter(f.engine, bridge)
		for _, actor := range []string{"", "relay", "provider-pat", "provider-produced-token"} {
			status, h, b := post(t, "/api/oauth/provider/login/preview", actor, map[string]any{"challenge": "first-login"})
			assertFailure(t, status, h, b)
		}
		for _, headers := range []http.Header{
			{"Origin": {"https://foreign.example"}}, {"Origin": {"https://console.example", "https://console.example"}},
			{"Origin": {"https://console.example"}, "Sec-Fetch-Site": {"cross-site"}},
			{"Sec-Fetch-Site": {"same-origin"}}, {"Authorization": {"Bearer " + f.bearer["owner"], "Bearer " + f.bearer["owner"]}},
		} {
			headers.Set("Content-Type", "application/json")
			status, h, b := f.request(t, http.MethodPost, "/api/oauth/provider/login/preview", "owner", `{"challenge":"first-login"}`, headers)
			assertFailure(t, status, h, b)
		}
		for _, body := range []string{`{"challenge":"first-login","challenge":"first-login"}`, `{"challenge":null}`, `{"challenge":"first-login","subject":"1"}`, `{"Challenge":"first-login"}`} {
			status, h, b := f.request(t, http.MethodPost, "/api/oauth/provider/login/preview", "owner", body, http.Header{"Content-Type": {"application/json"}})
			assertFailure(t, status, h, b)
		}
		assert.Zero(t, putCount())
		token := preview(t, "login", "first-login", "owner")
		assert.Zero(t, putCount(), "preview cannot accept")
		status, _, b := decision(t, "login", "first-login", token, "owner", "continue")
		require.Equal(t, 200, status)
		assert.Len(t, b, 1)
		assert.Contains(t, b["redirect_to"], publicAuth+"?")
		assert.Equal(t, 1, putCount())
		mu.Lock()
		payload := attempts[0].body
		mu.Unlock()
		assert.Equal(t, map[string]any{"subject": strconv.Itoa(f.users["owner"].Id), "remember": false}, payload)
		for _, path := range []string{"/api/oauth/provider/login", "/api/oauth/provider/login/preview", "/api/oauth/provider/consent", "/api/oauth/provider/consent/preview"} {
			status, h, _ := f.request(t, http.MethodGet, path+"?challenge="+logCanary, "owner", "", nil)
			assert.Equal(t, 404, status)
			assert.Empty(t, h.Get("Location"))
			status, h, b := post(t, path+"/?challenge="+logCanary, "owner", map[string]any{})
			assertFailure(t, status, h, b)
		}
		status, _, b = f.request(t, http.MethodGet, "/api/status", "", "", nil)
		require.Equal(t, 200, status)
		assert.Equal(t, false, b["data"].(map[string]any)["oauth"].(map[string]any)["enabled"])
	})

	t.Run("challenge_client_pkce_binding", func(t *testing.T) {
		for i, kind := range []string{"client", "subject", "skip", "skip-consent", "method", "audience", "pkce", "plain", "state", "redirect", "issuer", "prompt", "max-age", "request-uri", "response-mode", "duplicate-client", "missing-security"} {
			challenge := fmt.Sprintf("invalid-%d", i)
			add("consent", challenge, "owner")
			mu.Lock()
			value := requests[challenge]
			client := value["client"].(map[string]any)
			u, err := url.Parse(value["request_url"].(string))
			require.NoError(t, err)
			q := u.Query()
			switch kind {
			case "client":
				client["client_id"] = "foreign-client"
			case "subject":
				value["subject"] = strconv.Itoa(f.users["foreign"].Id)
			case "skip":
				value["skip"] = true
			case "skip-consent":
				client["skip_consent"] = true
			case "method":
				client["token_endpoint_auth_method"] = "client_secret_basic"
			case "audience":
				value["requested_access_token_audience"] = []string{"foreign"}
			case "pkce":
				q.Set("code_challenge", "not-32-bytes")
			case "plain":
				q.Set("code_challenge_method", "plain")
			case "state":
				q.Del("state")
			case "redirect":
				q.Set("redirect_uri", "http://127.0.0.2:35421/oauth/callback")
			case "issuer":
				u.Host = "foreign.example"
			case "prompt":
				q.Set("prompt", "none")
			case "max-age":
				q.Set("max_age", "0")
			case "request-uri":
				q.Set("request_uri", "urn:fixture")
			case "response-mode":
				q.Set("response_mode", "form_post")
			case "duplicate-client":
				q.Add("client_id", "cherry-studio")
			case "missing-security":
				client["scope"] = nil
			}
			u.RawQuery = q.Encode()
			value["request_url"] = u.String()
			mu.Unlock()
			before := putCount()
			status, h, b := post(t, "/api/oauth/provider/consent/preview", "owner", map[string]any{"challenge": challenge})
			assertFailure(t, status, h, b)
			assert.Equal(t, before, putCount(), kind)
		}
		add("consent", "bound-consent", "owner")
		token := preview(t, "consent", "bound-consent", "owner")
		before := putCount()
		for _, selected := range [][]string{{"profile", "tokens:read"}, {"email"}, {"profile", "profile"}} {
			status, h, b := decision(t, "consent", "bound-consent", token, "owner", "approve", selected...)
			assertFailure(t, status, h, b)
		}
		status, h, b := decision(t, "consent", "bound-consent", token, "foreign", "approve", "profile")
		assertFailure(t, status, h, b)
		status, h, b = decision(t, "consent", "bound-consent", token, "owner-other", "approve", "profile")
		assertFailure(t, status, h, b)
		add("login", "other-phase", "owner")
		status, h, b = decision(t, "login", "other-phase", token, "owner", "continue")
		assertFailure(t, status, h, b)
		for _, field := range []string{"auth_version", "version"} {
			table, where, value := any(&model.User{}), "id = ?", any(f.users["owner"].Id)
			if field == "version" {
				table, where, value = &model.UserSession{}, "sid = ?", f.sids["owner"]
			}
			require.NoError(t, f.db.Model(table).Where(where, value).Update(field, 2).Error)
			status, h, b = decision(t, "consent", "bound-consent", token, "owner", "approve", "profile")
			assertFailure(t, status, h, b)
			require.NoError(t, f.db.Model(table).Where(where, value).Update(field, 1).Error)
		}
		add("consent", "other-consent", "owner")
		status, h, b = decision(t, "consent", "other-consent", token, "owner", "approve", "profile")
		assertFailure(t, status, h, b)
		mu.Lock()
		value := requests["bound-consent"]
		u, err := url.Parse(value["request_url"].(string))
		require.NoError(t, err)
		q := u.Query()
		q.Set("state", "substituted-state")
		u.RawQuery = q.Encode()
		value["request_url"] = u.String()
		mu.Unlock()
		status, h, b = decision(t, "consent", "bound-consent", token, "owner", "approve", "profile")
		assertFailure(t, status, h, b)
		assert.Equal(t, before, putCount())
	})

	t.Run("claim_production_and_userinfo", func(t *testing.T) {
		add("consent", "produced-consent", "owner")
		token := preview(t, "consent", "produced-consent", "owner")
		status, h, body := decision(t, "consent", "produced-consent", token, "owner", "approve", "profile", "email")
		require.Equal(t, 200, status)
		assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
		assert.Len(t, body, 1)
		mu.Lock()
		payload := attempts[len(attempts)-1].body
		mu.Unlock()
		assert.Equal(t, map[string]any{"remember": false, "grant_scope": []any{"profile", "email"}, "grant_access_token_audience": []any{"newapi-userinfo"}, "session": map[string]any{"access_token": map[string]any{"newapi_auth_version": "1"}}}, payload)
		status, _, body = f.request(t, http.MethodGet, "/api/v1/oauth/userinfo", "provider-produced-token", "", nil)
		require.Equal(t, 200, status)
		assert.Equal(t, float64(f.users["owner"].Id), body["id"])
		assert.Equal(t, f.users["owner"].Username, body["username"])
		assert.Len(t, body, 5)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).Update("auth_version", 2).Error)
		status, _, body = f.request(t, http.MethodGet, "/api/v1/oauth/userinfo", "provider-produced-token", "", nil)
		assert.Equal(t, 401, status)
		assert.NotContains(t, body, "username")
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).Update("auth_version", 1).Error)
		add("login", "denied-login", "owner")
		token = preview(t, "login", "denied-login", "owner")
		status, _, _ = decision(t, "login", "denied-login", token, "owner", "deny")
		require.Equal(t, 200, status)
		mu.Lock()
		denied := attempts[len(attempts)-1].body
		mu.Unlock()
		assert.Equal(t, map[string]any{"error": "access_denied"}, denied)
	})

	t.Run("replay_revocation_and_privacy", func(t *testing.T) {
		for _, samePreview := range []bool{true, false} {
			challenge := fmt.Sprintf("concurrent-%t", samePreview)
			add("login", challenge, "owner")
			a := preview(t, "login", challenge, "owner")
			b := a
			if !samePreview {
				b = preview(t, "login", challenge, "owner")
			}
			before := putCount()
			results := make(chan int, 2)
			var wg sync.WaitGroup
			for _, token := range []string{a, b} {
				wg.Go(func() { status, _, _ := decision(t, "login", challenge, token, "owner", "continue"); results <- status })
			}
			wg.Wait()
			close(results)
			successes := 0
			for status := range results {
				if status == 200 {
					successes++
				} else {
					assert.GreaterOrEqual(t, status, 400)
				}
			}
			assert.Equal(t, 1, successes)
			assert.Equal(t, before+1, putCount())
		}
		add("login", "unknown-result", "owner")
		a := preview(t, "login", "unknown-result", "owner")
		mu.Lock()
		putHook = func(r *http.Request, challenge string) {
			if challenge == "unknown-result" {
				<-r.Context().Done()
			}
		}
		mu.Unlock()
		before := putCount()
		status, h, body := decision(t, "login", "unknown-result", a, "owner", "continue")
		assert.Equal(t, 503, status)
		assertFailure(t, status, h, body)
		mu.Lock()
		putHook = nil
		mu.Unlock()
		status, h, body = decision(t, "login", "unknown-result", a, "owner", "continue")
		assertFailure(t, status, h, body)
		b := preview(t, "login", "unknown-result", "owner")
		status, h, body = decision(t, "login", "unknown-result", b, "owner", "continue")
		assertFailure(t, status, h, body)
		assert.Equal(t, before+1, putCount())
		// A real revoke commits while the read-only Admin GET is waiting. The
		// subsequent local transaction must reject before any external PUT.
		add("login", "revoked-before-put", "revoked")
		token := preview(t, "login", "revoked-before-put", "revoked")
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		mu.Lock()
		getHook = func(challenge string) {
			if challenge == "revoked-before-put" {
				close(entered)
				<-release
			}
		}
		mu.Unlock()
		done := make(chan int, 1)
		before = putCount()
		go func() {
			status, _, _ := decision(t, "login", "revoked-before-put", token, "revoked", "continue")
			done <- status
		}()
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("Admin request barrier not reached")
		}
		_, err := model.RevokeUserSession(f.users["revoked"].Id, f.sids["revoked"], "test revoke")
		require.NoError(t, err)
		releaseOnce.Do(func() { close(release) })
		assert.Equal(t, 401, <-done)
		assert.Equal(t, before, putCount())
		mu.Lock()
		getHook = nil
		mu.Unlock()
		// Once PUT has started, a later revoke withholds resume publication but
		// does not pretend to roll back Hydra's already observed acceptance.
		add("login", "revoked-after-put", "empty")
		token = preview(t, "login", "revoked-after-put", "empty")
		entered2, release2 := make(chan struct{}), make(chan struct{})
		var once2 sync.Once
		mu.Lock()
		putHook = func(_ *http.Request, challenge string) {
			if challenge == "revoked-after-put" {
				close(entered2)
				<-release2
			}
		}
		mu.Unlock()
		doneBody := make(chan map[string]any, 1)
		go func() {
			status, _, body := decision(t, "login", "revoked-after-put", token, "empty", "continue")
			assert.Equal(t, 401, status)
			doneBody <- body
		}()
		t.Cleanup(func() { once2.Do(func() { close(release2) }) })
		select {
		case <-entered2:
		case <-time.After(5 * time.Second):
			t.Fatal("Admin write barrier not reached")
		}
		_, err = model.RevokeUserSession(f.users["empty"].Id, f.sids["empty"], "test late revoke")
		require.NoError(t, err)
		once2.Do(func() { close(release2) })
		assert.NotContains(t, <-doneBody, "redirect_to")
		mu.Lock()
		putHook = nil
		mu.Unlock()
		// Delay the session query to the persisted deadline. Validation must use
		// a new clock observation after that database wait, not request entry.
		add("login", "session-wait-expiry", "admin")
		token = preview(t, "login", "session-wait-expiry", "admin")
		var deadline atomic.Int64
		var waited atomic.Bool
		callback := "oauth-provider-session-wait"
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
			if tx.Statement.Table == "user_sessions" && deadline.Load() > 0 && waited.CompareAndSwap(false, true) {
				timer := time.NewTimer(time.Until(time.Unix(deadline.Load(), 0)))
				defer timer.Stop()
				<-timer.C
			}
		}))
		t.Cleanup(func() { require.NoError(t, f.db.Callback().Query().Remove(callback)) })
		mu.Lock()
		getHook = func(challenge string) {
			if challenge == "session-wait-expiry" {
				expires := time.Now().Unix() + 1
				assert.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["admin"]).Update("expires_at", expires).Error)
				deadline.Store(expires)
			}
		}
		mu.Unlock()
		before = putCount()
		status, h, body = decision(t, "login", "session-wait-expiry", token, "admin", "continue")
		assert.Equal(t, 401, status)
		assertFailure(t, status, h, body)
		assert.True(t, waited.Load())
		assert.Equal(t, before, putCount())
		mu.Lock()
		getHook = nil
		mu.Unlock()
		require.NoError(t, f.db.Callback().Query().Remove(callback))
		add("login", "unsafe-resume", "owner")
		token = preview(t, "login", "unsafe-resume", "owner")
		mu.Lock()
		badResume = true
		mu.Unlock()
		status, h, body = decision(t, "login", "unsafe-resume", token, "owner", "continue")
		assert.Equal(t, 503, status)
		assertFailure(t, status, h, body)
		assert.NotContains(t, string(encode(body)), "foreign.example")
		mu.Lock()
		badResume = false
		mu.Unlock()
		// Flow expiry is explicit stored state, not a timing race.
		add("login", "expired-preview", "owner")
		token = preview(t, "login", "expired-preview", "owner")
		require.NoError(t, f.db.Model(&model.AuthFlow{}).Where("purpose = ? AND intent = ?", model.AuthFlowPurposeOAuthProviderPreview, "login").Update("expires_at", time.Now().Add(-time.Minute)).Error)
		before = putCount()
		status, h, body = decision(t, "login", "expired-preview", token, "owner", "continue")
		assertFailure(t, status, h, body)
		assert.Equal(t, before, putCount())
		// Retention is bounded by existing cleanup. Use explicit persisted
		// timestamps; a fresh local preview is not remote issuance-time proof.
		add("login", "retained-attempt", "owner")
		token = preview(t, "login", "retained-attempt", "owner")
		var prior []int64
		require.NoError(t, f.db.Model(&model.AuthFlow{}).Where("purpose = ?", model.AuthFlowPurposeOAuthProviderAttempt).Pluck("id", &prior).Error)
		status, _, _ = decision(t, "login", "retained-attempt", token, "owner", "continue")
		require.Equal(t, 200, status)
		var claim model.AuthFlow
		require.NoError(t, f.db.Where("purpose = ? AND id NOT IN ?", model.AuthFlowPurposeOAuthProviderAttempt, prior).First(&claim).Error)
		require.NotNil(t, claim.ConsumedAt)
		anchor := *claim.ConsumedAt
		require.NoError(t, model.DeleteExpiredAuthFlows(anchor.Add(24*time.Hour-time.Second)))
		var count int64
		require.NoError(t, f.db.Model(&model.AuthFlow{}).Where("id = ?", claim.Id).Count(&count).Error)
		assert.Equal(t, int64(1), count)
		assert.ErrorIs(t, model.ClaimExternalAuthAssertion(model.AuthFlowPurposeOAuthProviderAttempt, "https://issuer.example/\nlogin\nretained-attempt", time.Now().Add(time.Minute)), model.ErrAuthFlowConsumed)
		require.NoError(t, model.DeleteExpiredAuthFlows(anchor.Add(24*time.Hour+time.Second)))
		require.NoError(t, f.db.Model(&model.AuthFlow{}).Where("id = ?", claim.Id).Count(&count).Error)
		assert.Zero(t, count)
		mu.Lock()
		gone["retained-attempt"] = true
		mu.Unlock()
		before = putCount()
		status, h, body = post(t, "/api/oauth/provider/login/preview", "owner", map[string]any{"challenge": "retained-attempt"})
		assertFailure(t, status, h, body)
		assert.Equal(t, before, putCount())
		for _, canary := range []string{logCanary, "provider-produced-token", token, "fixture-verifier-" + logCanary} {
			assert.NotContains(t, f.logs.snapshot(), canary)
		}
	})
	assert.Equal(t, before, counts(), "no new user/session/key is created by the bridge")
}

// The resource uses the real router, TLS HTTP introspection and current owned
// database. The issuer fixture is not a deployed authorization/consent service.
func TestOAuthUserInfoHTTP(t *testing.T) {
	t.Setenv("OAUTH_USERINFO_ENABLED", "false")
	require.NoError(t, service.InitOAuthUserInfoResource())
	f := newOrganizationHTTPFixture(t)
	const credential = "fixture-oauth-token-canary"
	const queryCanary = "fixture-query-token-canary"
	const upstreamCanary = "fixture-upstream-cause-canary"
	user := f.users["owner"]
	require.NoError(t, f.db.Model(user).Updates(map[string]any{"display_name": "Profile display", "email": "profile@example.invalid", "setting": "private-setting-canary"}).Error)
	var mu sync.Mutex
	var reply func(int64, string) (int, []byte)
	var calls atomic.Int64
	claims := func() map[string]any {
		return map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer", "iss": "https://issuer.example/", "aud": []string{"newapi-userinfo"}, "client_id": "cherry-studio", "sub": strconv.Itoa(user.Id), "exp": time.Now().Unix() + 3600, "scope": "profile email", "ext": map[string]any{"newapi_auth_version": "1"}}
	}
	encode := func(value any) []byte {
		data, err := common.Marshal(value)
		assert.NoError(t, err)
		return data
	}
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/admin/oauth2/introspect", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Cookie"))
		assert.Empty(t, r.Header.Get("X-Caller-Canary"))
		if !assert.NoError(t, r.ParseForm()) || !assert.Len(t, r.PostForm, 1) || len(r.PostForm["token"]) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := calls.Add(1)
		mu.Lock()
		respond := reply
		mu.Unlock()
		if respond == nil {
			<-r.Context().Done()
			return
		}
		status, data := respond(n, r.PostForm.Get("token"))
		if status == http.StatusFound {
			w.Header().Set("Location", "https://untrusted.example/"+upstreamCanary)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(data)
	}))
	t.Cleanup(issuer.Close)
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	config := service.OAuthUserInfoConfig{Enabled: true, IntrospectionURL: issuer.URL + "/admin/oauth2/introspect", Issuer: "https://issuer.example/", Audience: "newapi-userinfo", ClientIDs: []string{"cherry-studio", "other-client"}}
	resource, err := service.NewOAuthUserInfoResource(config, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	configure := func(alter func(map[string]any, int64)) {
		calls.Store(0)
		mu.Lock()
		reply = func(n int64, token string) (int, []byte) {
			value := claims()
			if token != credential && token != "sk-trusted-oauth-shape" {
				value = map[string]any{"active": false}
			} else if alter != nil {
				alter(value, n)
			}
			return http.StatusOK, encode(value)
		}
		mu.Unlock()
	}
	read := func(headers http.Header) (int, http.Header, map[string]any) {
		return f.request(t, http.MethodGet, "/api/v1/oauth/userinfo", credential, "", headers)
	}
	checkError := func(status int, header http.Header, body map[string]any, want int, code string) {
		t.Helper()
		assert.Equal(t, want, status)
		assert.Equal(t, map[string]any{"error": code}, body)
		assert.Equal(t, "private, no-store", header.Get("Cache-Control"))
		assert.Empty(t, header.Values("Set-Cookie"))
		if want == 401 {
			assert.Equal(t, `Bearer error="invalid_token"`, header.Get("WWW-Authenticate"))
		}
		if want == 403 {
			assert.Equal(t, `Bearer error="insufficient_scope", scope="profile"`, header.Get("WWW-Authenticate"))
		}
	}
	counts := func() []int64 {
		result := []int64{}
		for _, table := range []any{&model.User{}, &model.UserSession{}, &model.UserAccessToken{}, &model.Token{}} {
			var count int64
			require.NoError(t, f.db.Model(table).Count(&count).Error)
			result = append(result, count)
		}
		return result
	}
	patKey := model.AccessTokenPrefix + strings.Repeat("p", 48)
	pat := &model.UserAccessToken{Name: "OAuth boundary fixture", TokenHash: model.AccessTokenFingerprint(patKey), ExpiresAt: time.Now().Unix() + 3600}
	require.NoError(t, pat.SetScopes([]string{"profile:read"}))
	require.NoError(t, model.CreateUserAccessToken(user.Id, pat, 20))
	f.bearer["pat"] = patKey
	before := counts()

	t.Run("default_off_and_type_boundary", func(t *testing.T) {
		for _, path := range []string{"/api/v1/oauth/userinfo", "/api/v1/oauth/userinfo/"} {
			status, _, _ := f.request(t, http.MethodGet, path+"?access_token="+queryCanary, "", "", nil)
			assert.Equal(t, http.StatusNotFound, status)
		}
		status, _, body := f.request(t, http.MethodGet, "/api/status", "", "", nil)
		require.Equal(t, 200, status)
		assert.Equal(t, false, body["data"].(map[string]any)["oauth"].(map[string]any)["enabled"])
		assert.Equal(t, false, body["data"].(map[string]any)["client_features"].(map[string]any)["oauth"])
		for _, alter := range []func(*service.OAuthUserInfoConfig){
			func(c *service.OAuthUserInfoConfig) { c.IntrospectionURL = "http://example.invalid/secret" },
			func(c *service.OAuthUserInfoConfig) { c.IntrospectionURL += "?secret=" + queryCanary },
			func(c *service.OAuthUserInfoConfig) { c.IntrospectionURL += "#fragment" },
			func(c *service.OAuthUserInfoConfig) { c.Issuer = "https://name:secret@example.invalid/" },
			func(c *service.OAuthUserInfoConfig) { c.Audience = "" },
			func(c *service.OAuthUserInfoConfig) { c.ClientIDs = []string{} },
		} {
			invalid := config
			alter(&invalid)
			_, err := service.NewOAuthUserInfoResource(invalid, roots)
			assert.ErrorIs(t, err, service.ErrOAuthResourceConfiguration)
			assert.Equal(t, "Invalid OAuth userinfo configuration.", err.Error())
		}
		t.Setenv("OAUTH_USERINFO_ENABLED", "invalid-secret-canary")
		assert.ErrorIs(t, service.InitOAuthUserInfoResource(), service.ErrOAuthResourceConfiguration)
		assert.Zero(t, calls.Load())
		// Observe the actual resource chain without substituting authentication.
		f.engine.Use(func(c *gin.Context) {
			c.Next()
			_, authenticated := middleware.GetAuthIdentity(c)
			assert.False(t, authenticated)
			_, session := middleware.GetSessionAuthIdentity(c)
			assert.False(t, session)
			for _, key := range []string{"id", "role", "session_id", "use_access_token", "access_token_identity"} {
				_, present := c.Get(key)
				assert.False(t, present, key)
			}
		})
		SetOAuthResourceRouter(f.engine, resource)
		configure(nil)
		for _, actor := range []string{"", "owner", "relay", "pat", "fixture-id-token", "fixture-refresh-token"} {
			status, h, b := f.request(t, http.MethodGet, "/api/v1/oauth/userinfo", actor, "", http.Header{"Cookie": {"new_api_refresh=fixture-cookie-canary"}})
			checkError(status, h, b, 401, "invalid_token")
		}
		for _, headers := range []http.Header{
			{"Authorization": {"Bearer " + credential, "Bearer " + credential}},
			{"Authorization": {"Bearer " + credential + "," + credential}},
			{"Authorization": {"Bearer  " + credential}},
			{"Authorization": {"Bearer \u00a0" + credential}},
			{"Authorization": {"Bearer " + credential + "\u2003"}},
			{"Authorization": {"Basic " + credential}},
		} {
			status, h, b := read(headers)
			checkError(status, h, b, 401, "invalid_token")
		}
		for _, path := range []string{"/api/v1/oauth/userinfo?access_token=" + queryCanary, "/api/v1/oauth/userinfo/?access_token=" + queryCanary} {
			status, h, b := f.request(t, http.MethodGet, path, credential, "", nil)
			checkError(status, h, b, 401, "invalid_token")
			assert.Empty(t, h.Get("Location"))
		}
		status, _, _ = f.request(t, http.MethodPost, "/api/v1/oauth/userinfo?access_token="+queryCanary, credential, "", nil)
		assert.Equal(t, 404, status)
		for _, path := range []string{"/api/user/self", "/api/organizations/" + strconv.FormatInt(f.orgA, 10), "/api/verify/methods"} {
			status, _, body := f.request(t, http.MethodGet, path, credential, "", nil)
			assert.Contains(t, []int{401, 403}, status)
			assert.NotContains(t, body, "data")
		}
		status, _, body = f.request(t, http.MethodGet, "/api/v1/oauth/userinfo?org_id="+strconv.FormatInt(f.orgA, 10), credential, "", nil)
		assert.Equal(t, 403, status)
		assert.Equal(t, "ORG_RESOURCE_UNSUPPORTED", body["code"])
	})

	t.Run("live_profile_and_scope", func(t *testing.T) {
		for _, email := range []bool{false, true} {
			configure(func(value map[string]any, _ int64) {
				if !email {
					value["scope"] = "profile"
				}
			})
			status, h, b := read(http.Header{"X-Caller-Canary": {"must-not-forward"}})
			require.Equal(t, 200, status)
			want := map[string]any{"id": float64(user.Id), "username": user.Username, "display_name": "Profile display", "group": "default"}
			if email {
				want["email"] = "profile@example.invalid"
			}
			assert.Equal(t, want, b)
			assert.Equal(t, int64(2), calls.Load())
			assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
			assert.Empty(t, h.Values("Set-Cookie"))
		}
		configure(nil)
		status, _, _ := f.request(t, http.MethodGet, "/api/v1/oauth/userinfo", "sk-trusted-oauth-shape", "", nil)
		assert.Equal(t, 200, status, "spelling is not credential kind")
		for _, tc := range []struct {
			name, field string
			value       any
			want        int
		}{
			{"inactive", "active", false, 401}, {"active type", "active", "true", 401},
			{"refresh", "token_use", "refresh_token", 401}, {"ID token", "token_use", "id_token", 401},
			{"scheme", "token_type", "MAC", 401}, {"issuer", "iss", "https://foreign.example/", 401},
			{"audience", "aud", []string{"other"}, 401}, {"audience type", "aud", "newapi-userinfo", 401},
			{"client", "client_id", "unregistered", 401}, {"subject", "sub", "0", 401},
			{"subject canonical", "sub", "01", 401}, {"subject type", "sub", user.Id, 401},
			{"subject overflow", "sub", "9223372036854775808", 401}, {"expiry", "exp", time.Now().Unix() - 1, 401},
			{"expiry type", "exp", "1900000000", 401}, {"not before", "nbf", time.Now().Unix() + 3600, 401},
			{"version type", "ext", map[string]any{"newapi_auth_version": 1}, 401},
			{"version stale", "ext", map[string]any{"newapi_auth_version": "2"}, 401},
			{"scope exact", "scope", "profile:read", 403}, {"empty scope", "scope", "", 403},
			{"scope spacing", "scope", "profile  email", 401},
		} {
			configure(func(value map[string]any, _ int64) { value[tc.field] = tc.value })
			status, h, b := read(nil)
			code := "invalid_token"
			if tc.want == 403 {
				code = "insufficient_scope"
			}
			checkError(status, h, b, tc.want, code)
			assert.Equal(t, int64(1), calls.Load(), tc.name)
		}
		for _, field := range []string{"active", "token_use", "token_type", "iss", "aud", "client_id", "sub", "exp", "scope", "ext"} {
			configure(func(value map[string]any, _ int64) { delete(value, field) })
			status, h, b := read(nil)
			checkError(status, h, b, 401, "invalid_token")
		}
	})

	t.Run("uncached_final_state", func(t *testing.T) {
		for _, scenario := range []string{"inactive", "subject", "client", "email scope", "disabled", "deleted", "auth version"} {
			configure(func(value map[string]any, n int64) {
				if n != 2 {
					return
				}
				switch scenario {
				case "inactive":
					value["active"] = false
				case "subject":
					value["sub"] = strconv.Itoa(f.users["foreign"].Id)
				case "client":
					value["client_id"] = "other-client"
				case "email scope":
					value["scope"] = "profile"
				case "disabled":
					assert.NoError(t, f.db.Model(&model.User{}).Where("id = ?", user.Id).Update("status", common.UserStatusDisabled).Error)
				case "deleted":
					assert.NoError(t, f.db.Delete(&model.User{}, user.Id).Error)
				case "auth version":
					assert.NoError(t, f.db.Model(&model.User{}).Where("id = ?", user.Id).Update("auth_version", 2).Error)
				}
			})
			status, h, b := read(nil)
			checkError(status, h, b, 401, "invalid_token")
			require.NoError(t, f.db.Unscoped().Model(&model.User{}).Where("id = ?", user.Id).Updates(map[string]any{"deleted_at": nil, "status": common.UserStatusEnabled, "auth_version": 1}).Error)
		}
		configure(func(_ map[string]any, n int64) {
			if n == 2 {
				assert.NoError(t, f.db.Model(&model.User{}).Where("id = ?", user.Id).Update("display_name", "Current final display").Error)
			}
		})
		status, _, body := read(nil)
		require.Equal(t, 200, status)
		assert.Equal(t, "Current final display", body["display_name"])
		// Hold the final local query until its exact token expiry. This is an
		// observed query barrier plus claim deadline, not an arbitrary race sleep.
		var localReads atomic.Int64
		var expiry atomic.Int64
		callback := "oauth-expiry-after-local-wait"
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
			if tx.Statement.Table == "users" && localReads.Add(1) == 2 {
				timer := time.NewTimer(time.Until(time.Unix(expiry.Load(), 0)))
				defer timer.Stop()
				<-timer.C
			}
		}))
		t.Cleanup(func() { require.NoError(t, f.db.Callback().Query().Remove(callback)) })
		configure(func(value map[string]any, n int64) {
			if n == 2 {
				deadline := time.Now().Unix() + 1
				expiry.Store(deadline)
				value["exp"] = deadline
			}
		})
		status, h, b := read(nil)
		checkError(status, h, b, 401, "invalid_token")
		assert.Equal(t, int64(2), localReads.Load())
		require.NoError(t, f.db.Callback().Query().Remove(callback))
	})

	t.Run("upstream_failure_and_isolation", func(t *testing.T) {
		for _, scenario := range []string{"status", "redirect", "oversize", "malformed", "duplicate", "timeout"} {
			calls.Store(0)
			mu.Lock()
			reply = func(_ int64, _ string) (int, []byte) {
				switch scenario {
				case "status":
					return 500, []byte(upstreamCanary)
				case "redirect":
					return 302, nil
				case "oversize":
					return 200, encode(map[string]any{"padding": strings.Repeat("x", 65537)})
				case "malformed":
					return 200, []byte(`{"cause":"` + upstreamCanary)
				case "duplicate":
					return 200, []byte(`{"active":true,"active":false}`)
				}
				return 500, nil
			}
			if scenario == "timeout" {
				reply = nil
			}
			mu.Unlock()
			status, h, b := read(nil)
			checkError(status, h, b, 503, "temporarily_unavailable")
			assert.Equal(t, int64(1), calls.Load())
		}
		untrusted, err := service.NewOAuthUserInfoResource(config, nil)
		require.NoError(t, err)
		t.Cleanup(untrusted.CloseIdleConnections)
		_, err = untrusted.Authorize(context.Background(), credential)
		assert.ErrorIs(t, err, service.ErrOAuthResourceUnavailable)
		assert.Equal(t, before, counts(), "userinfo cannot create users/sessions/keys")
		for _, secret := range []string{credential, queryCanary, upstreamCanary, "fixture-cookie-canary", "private-setting-canary"} {
			assert.NotContains(t, f.logs.snapshot(), secret)
		}
	})
}

// Explicit administrator facts enrich already visible rows, never their pricing
// or authorization. The owned runner invokes this one root on each real dialect.
func TestModelCapabilityMetadataHTTP(t *testing.T) {
	require.Equal(t, "g19-model-capability-metadata", os.Getenv("NEWAPI_S2_OWNED"))
	f := newOrganizationHTTPFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.Model{}, &model.Vendor{}, &model.Channel{}, &model.Ability{}, &model.PasskeyCredential{}))
	common.OptionMapRWMutex.Lock()
	previousOptions := common.OptionMap
	common.OptionMap = map[string]string{}
	common.OptionMapRWMutex.Unlock()
	t.Cleanup(func() {
		common.OptionMapRWMutex.Lock()
		common.OptionMap = previousOptions
		common.OptionMapRWMutex.Unlock()
		model.InvalidatePricingCache()
	})
	for _, snapshot := range []struct {
		before  string
		restore func(string) error
		next    string
	}{
		{setting.UserUsableGroups2JSONString(), setting.UpdateUserUsableGroupsByJSONString, `{"default":"Default","g1":"One","g2":"Two","auto":"Auto"}`},
		{setting.AutoGroups2JsonString(), setting.UpdateAutoGroupsByJsonString, `["g1","g2"]`},
		{strconv.Itoa(setting.GetMaxTokenAutoGroups()), setting.UpdateMaxTokenAutoGroups, "2"},
		{ratio_setting.GroupRatio2JSONString(), ratio_setting.UpdateGroupRatioByJSONString, `{"default":1,"g1":2,"g2":3,"private":9}`},
		{ratio_setting.GroupGroupRatio2JSONString(), ratio_setting.UpdateGroupGroupRatioByJSONString, `{"default":{"g1":0.25,"g2":0.5}}`},
		{ratio_setting.ModelPrice2JSONString(), ratio_setting.UpdateModelPriceByJSONString, `{"meta-model":0.05,"META-MODEL":0.06,"vendor/meta-model":0.07,"meta-model-extra":0.08,"meta-unknown":0.09,"meta-hidden":0.1}`},
	} {
		t.Cleanup(func() { require.NoError(t, snapshot.restore(snapshot.before)) })
		require.NoError(t, snapshot.restore(snapshot.next))
	}
	special := ratio_setting.GetGroupRatioSetting().GroupSpecialUsableGroup
	previousSpecial := special.ReadAll()
	special.Clear()
	t.Cleanup(func() { special.Clear(); special.AddAll(previousSpecial) })
	previousPasskey, previousAddress := *system_setting.GetPasskeySettings(), system_setting.ServerAddress
	*system_setting.GetPasskeySettings() = system_setting.PasskeySettings{RPID: "metadata.example", Origins: "https://metadata.example", UserVerification: "preferred"}
	system_setting.ServerAddress = "https://metadata.example"
	t.Cleanup(func() {
		*system_setting.GetPasskeySettings() = previousPasskey
		system_setting.ServerAddress = previousAddress
	})
	require.NoError(t, model.UpdateOption("HeaderNavModules", `{"pricing":true}`))
	require.NoError(t, f.db.Create(&model.Model{ModelName: "meta-model", Description: "Original catalog", Tags: "vision,reasoning,tool-use", NameRule: model.NameRuleExact, Status: 1, SyncOfficial: 1}).Error)
	require.NoError(t, f.db.Create(&model.Model{ModelName: "meta-", Description: "Prefix catalog", Tags: "vision", NameRule: model.NameRulePrefix, Status: 1, SyncOfficial: 1}).Error)
	for _, name := range []string{"meta-model", "META-MODEL", "vendor/meta-model", "meta-model-extra", "meta-unknown", "meta-hidden"} {
		channel := model.Channel{Type: constant.ChannelTypeOpenAI, Name: name, Key: "unused", Status: common.ChannelStatusEnabled}
		require.NoError(t, f.db.Create(&channel).Error)
		groups := []string{"g1", "g2"}
		if name == "meta-hidden" {
			groups = []string{"private"}
		}
		if name == "meta-unknown" {
			groups = []string{"g2"}
		}
		for _, group := range groups {
			require.NoError(t, f.db.Create(&model.Ability{Group: group, Model: name, ChannelId: channel.Id, Enabled: true}).Error)
		}
	}
	var relay model.Token
	require.NoError(t, f.db.Where("user_id = ?", f.users["owner"].Id).First(&relay).Error)
	require.NoError(t, f.db.Model(&relay).Update("group", "g1").Error)
	autoKey, err := common.GenerateRandomCharsKey(40)
	require.NoError(t, err)
	auto := model.Token{UserId: f.users["owner"].Id, Key: autoKey, Group: "auto", Status: common.TokenStatusEnabled, ExpiredTime: -1}
	require.NoError(t, f.db.Create(&auto).Error)
	f.bearer["metadata-auto"] = "sk-" + autoKey
	model.InvalidatePricingCache()
	const key = model.ModelCapabilityMetadataOptionKey
	const declaration = `{"meta-model":{"context_length":128000,"max_output_tokens":4096,"vision":true,"reasoning":false,"tool_use":true},"meta-unknown":{"reasoning":false},"meta-hidden":{"vision":true}}`
	metadataFields := []string{"context_length", "max_output_tokens", "vision", "reasoning", "tool_use", "metadata_source"}
	write := func(t *testing.T, value string) map[string]any {
		t.Helper()
		body, err := common.Marshal(map[string]string{"key": key, "value": value})
		require.NoError(t, err)
		status, _, result := f.request(t, http.MethodPut, "/api/option/", "root", string(body), nil)
		require.Equal(t, http.StatusOK, status)
		return result
	}
	read := func(t *testing.T, actor string) map[string]any {
		t.Helper()
		status, headers, result := f.request(t, http.MethodGet, "/api/pricing", actor, "", nil)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, true, result["success"])
		if actor == "relay" || actor == "metadata-auto" {
			assert.Equal(t, "private, no-store", headers.Get("Cache-Control"))
		}
		return result
	}
	rows := func(t *testing.T, result map[string]any) map[string]map[string]any {
		t.Helper()
		items, ok := result["data"].([]any)
		require.True(t, ok)
		byName := make(map[string]map[string]any, len(items))
		for _, item := range items {
			row, ok := item.(map[string]any)
			require.True(t, ok)
			name, ok := row["model_name"].(string)
			require.True(t, ok)
			byName[name] = row
		}
		return byName
	}
	optionState := func(t *testing.T) ([]model.Option, map[string]string) {
		t.Helper()
		var stored []model.Option
		require.NoError(t, f.db.Order(clause.OrderByColumn{Column: clause.Column{Name: "key"}}).Find(&stored).Error)
		common.OptionMapRWMutex.RLock()
		published := maps.Clone(common.OptionMap)
		common.OptionMapRWMutex.RUnlock()
		return stored, published
	}

	t.Run("authorized_projection_and_versions", func(t *testing.T) {
		baseline := map[string]map[string]any{}
		for _, actor := range []string{"", "owner", "relay", "metadata-auto"} {
			baseline[actor] = read(t, actor)
		}
		require.Contains(t, rows(t, baseline["relay"]), "meta-model")
		assert.NotContains(t, rows(t, baseline["relay"]), "meta-unknown")
		assert.Contains(t, rows(t, baseline["metadata-auto"]), "meta-unknown")
		cacheBefore, err := common.Marshal(model.GetPricing())
		require.NoError(t, err)
		body, err := common.Marshal(map[string]string{"key": key, "value": declaration})
		require.NoError(t, err)
		for _, actor := range []string{"", "owner", "relay"} {
			status, _, result := f.request(t, http.MethodPut, "/api/option/", actor, string(body), nil)
			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, status)
			assert.Equal(t, false, result["success"])
		}
		require.Equal(t, true, write(t, declaration)["success"])
		for actor, before := range baseline {
			after := read(t, actor)
			items := rows(t, after)
			exact := items["meta-model"]
			require.NotNil(t, exact)
			assert.Equal(t, float64(128000), exact["context_length"])
			assert.Equal(t, float64(4096), exact["max_output_tokens"])
			assert.Equal(t, true, exact["vision"])
			assert.Equal(t, false, exact["reasoning"])
			assert.Equal(t, true, exact["tool_use"])
			source, ok := exact["metadata_source"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "administrator", source["kind"])
			assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, source["version"])
			assert.NotContains(t, items, "meta-hidden")
			for _, name := range []string{"META-MODEL", "vendor/meta-model", "meta-model-extra"} {
				require.Contains(t, items, name)
				for _, field := range metadataFields {
					assert.NotContains(t, items[name], field, name)
				}
			}
			if partial, exists := items["meta-unknown"]; exists {
				assert.Equal(t, false, partial["reasoning"])
				for _, field := range []string{"context_length", "max_output_tokens", "vision", "tool_use"} {
					assert.NotContains(t, partial, field)
				}
			}
			for _, item := range items {
				for _, field := range metadataFields {
					delete(item, field)
				}
			}
			assert.Equal(t, before, after, "all original fields and groups must remain exact")
		}
		cacheAfter, err := common.Marshal(model.GetPricing())
		require.NoError(t, err)
		assert.Equal(t, cacheBefore, cacheAfter, "shared pricing cache was not enriched")
		beforeRows := rows(t, read(t, "metadata-auto"))
		exactVersion, partialVersion := beforeRows["meta-model"]["metadata_source"], beforeRows["meta-unknown"]["metadata_source"]
		reordered := `{"meta-hidden":{"vision":false},"meta-unknown":{"reasoning":false},"meta-model":{"tool_use":true,"reasoning":false,"vision":true,"max_output_tokens":4096,"context_length":128000}}`
		require.Equal(t, true, write(t, reordered)["success"])
		reorderedRows := rows(t, read(t, "metadata-auto"))
		assert.Equal(t, exactVersion, reorderedRows["meta-model"]["metadata_source"])
		assert.Equal(t, partialVersion, reorderedRows["meta-unknown"]["metadata_source"])
		require.Equal(t, true, write(t, strings.Replace(reordered, "4096", "8192", 1))["success"])
		changed := rows(t, read(t, "metadata-auto"))
		assert.Equal(t, float64(8192), changed["meta-model"]["max_output_tokens"])
		assert.NotEqual(t, exactVersion, changed["meta-model"]["metadata_source"])
		assert.Equal(t, partialVersion, changed["meta-unknown"]["metadata_source"])
		require.Equal(t, true, write(t, `{}`)["success"])
		assert.Equal(t, baseline["relay"], read(t, "relay"))
		require.NoError(t, f.db.Model(&relay).Update("group", "revoked").Error)
		emptyBefore := read(t, "relay")
		require.Equal(t, []any{}, emptyBefore["data"])
		require.Equal(t, true, write(t, declaration)["success"])
		assert.Equal(t, emptyBefore, read(t, "relay"))
		require.NoError(t, f.db.Model(&relay).Update("group", "g1").Error)
		// Also preserve the existing public nil/empty encoding when no row is available.
		require.NoError(t, f.db.Model(&model.Ability{}).Where("enabled = ?", true).Update("enabled", false).Error)
		model.InvalidatePricingCache()
		require.Equal(t, true, write(t, `{}`)["success"])
		noRows := read(t, "")
		require.Equal(t, true, write(t, declaration)["success"])
		assert.Equal(t, noRows, read(t, ""))
		require.NoError(t, f.db.Model(&model.Ability{}).Where("enabled = ?", false).Update("enabled", true).Error)
		model.InvalidatePricingCache()
	})

	t.Run("strict_input_and_atomicity", func(t *testing.T) {
		beforeRows, beforeMap := optionState(t)
		tooMany := map[string]map[string]bool{}
		for i := range 257 {
			tooMany[fmt.Sprint(i)] = map[string]bool{"vision": true}
		}
		tooManyRaw, err := common.Marshal(tooMany)
		require.NoError(t, err)
		for _, raw := range []string{
			`null`, `[]`, `{"meta-model":{}}`, `{"meta-model":{"Vision":true}}`, `{"meta-model":{"vision":true,"VISION":false}}`,
			`{"meta-model":{"vision":true,"vision":false}}`, `{"meta-model":{"vision":true},"meta-model":{"vision":false}}`,
			`{"meta-model":{"vision":null}}`, `{"meta-model":{"vision":"true"}}`, `{"meta-model":{"context_length":0}}`,
			`{"meta-model":{"max_output_tokens":-1}}`, `{"meta-model":{"max_output_tokens":1.5}}`, `{"meta-model":{"context_length":1e3}}`,
			`{"meta-model":{"context_length":9007199254740992}}`, `{"meta-model":{"metadata_source":{"kind":"provider"}}}`, `{" meta-model":{"vision":true}}`,
			`{"meta\u0000model":{"vision":true}}`, `{"meta-model":{"vision":true}} {}`, string(tooManyRaw), declaration + strings.Repeat(" ", 65536),
		} {
			result := write(t, raw)
			require.Equal(t, false, result["success"])
			assert.Equal(t, "Invalid parameters", result["message"])
			stored, published := optionState(t)
			assert.Equal(t, beforeRows, stored)
			assert.Equal(t, beforeMap, published)
		}
		_, err = model.ParseModelCapabilityMetadata(string([]byte{'{', '"', 0xff, '"', ':', '{', '}', '}'}))
		require.Error(t, err)
		require.Error(t, model.UpdateOptionsBulk(map[string]string{key: `{"meta-model":{"VISION":false}}`, "ServerAddress": system_setting.ServerAddress}))
		_, err = model.UpdatePasskeyDomainOptions(map[string]string{key: `{"meta-model":{"VISION":false}}`, "ServerAddress": system_setting.ServerAddress}, false, "")
		require.Error(t, err)
		storedBeforeFailure, publishedBeforeFailure := optionState(t)
		assert.Equal(t, beforeRows, storedBeforeFailure)
		assert.Equal(t, beforeMap, publishedBeforeFailure)
		fail := errors.New("metadata fixture persistence failure")
		callback := "metadata_option_write_failure"
		require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register(callback, func(tx *gorm.DB) {
			option, ok := tx.Statement.Dest.(*model.Option)
			if ok && option.Key == key {
				tx.AddError(fail)
			}
		}))
		t.Cleanup(func() { _ = f.db.Callback().Update().Remove(callback) })
		for _, mutate := range []func() error{
			func() error { return model.UpdateOption(key, `{}`) },
			func() error {
				return model.UpdateOptionsBulk(map[string]string{key: `{}`, "MetadataControl": "changed"})
			},
			func() error {
				return model.UpdateOptionsBulk(map[string]string{key: `{}`, "ServerAddress": system_setting.ServerAddress})
			},
			func() error {
				_, err := model.UpdatePasskeyDomainOptions(map[string]string{key: `{}`, "ServerAddress": system_setting.ServerAddress}, false, "")
				return err
			},
		} {
			require.ErrorIs(t, mutate(), fail)
			stored, published := optionState(t)
			assert.Equal(t, beforeRows, stored)
			assert.Equal(t, beforeMap, published)
		}
		require.NoError(t, f.db.Where(&model.Option{Key: key}).Delete(&model.Option{}).Error)
		missingRows, missingMap := optionState(t)
		require.ErrorIs(t, model.UpdateOption(key, declaration), fail)
		stored, published := optionState(t)
		assert.Equal(t, missingRows, stored, "failed initial save rolls back FirstOrCreate placeholder")
		assert.Equal(t, missingMap, published)
		require.NoError(t, f.db.Callback().Update().Remove(callback))
		require.Equal(t, true, write(t, declaration)["success"])
	})

	t.Run("reserved_option_identity", func(t *testing.T) {
		if f.mainKind != "mysql" {
			t.Logf("dialect=%s: this leaf does not claim MySQL alias equivalence coverage", f.mainKind)
			return
		}
		writers := []struct {
			name   string
			mutate func(string, string) error
		}{
			{"single", func(name, value string) error { return model.UpdateOption(name, value) }},
			{"bulk", func(name, value string) error {
				return model.UpdateOptionsBulk(map[string]string{name: value, "MetadataControl": "changed"})
			}},
			{"bulk_passkey", func(name, value string) error {
				return model.UpdateOptionsBulk(map[string]string{name: value, "ServerAddress": system_setting.ServerAddress})
			}},
			{"direct_passkey", func(name, value string) error {
				_, err := model.UpdatePasskeyDomainOptions(map[string]string{name: value, "ServerAddress": system_setting.ServerAddress}, false, "")
				return err
			}},
		}
		beforeRows, beforeMap := optionState(t)
		var canonical model.Option
		require.NoError(t, f.db.Where(&model.Option{Key: key}).First(&canonical).Error)
		require.Equal(t, key, canonical.Key)
		beforeMetadata := model.ModelCapabilityMetadataSnapshot()
		var equivalentAlias string
		for _, alias := range []string{"modelcapabilitymetadata", "ModelCapabilityMetadata ", "MódelCapabilityMetadata"} {
			// Match the struct key equality/First lookup used by FirstOrCreate;
			// the engine's actual column collation decides equivalence.
			resolved := model.Option{Key: alias}
			err := f.db.Where(&model.Option{Key: alias}).First(&resolved).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				t.Logf("dialect=%s alias=%q stored_key=<not found> lookup=%v equivalent=false", f.mainKind, alias, err)
			} else {
				require.NoError(t, err, "dialect=%s alias=%q stored_key=%q", f.mainKind, alias, resolved.Key)
				t.Logf("dialect=%s alias=%q stored_key=%q equivalent=%t", f.mainKind, alias, resolved.Key, resolved.Key == key)
			}
			if errors.Is(err, gorm.ErrRecordNotFound) || resolved.Key != key {
				if err == nil {
					// A distinct existing record must be independently present in
					// the complete baseline, rather than an inferred alias.
					require.Contains(t, beforeRows, resolved, "distinct alias=%q stored_key=%q", alias, resolved.Key)
				}
				var unchanged model.Option
				require.NoError(t, f.db.Where(&model.Option{Key: key}).First(&unchanged).Error)
				assert.Equal(t, canonical, unchanged, "non-equivalent alias=%q", alias)
				assert.Equal(t, beforeMetadata, model.ModelCapabilityMetadataSnapshot())
				stored, published := optionState(t)
				assert.Equal(t, beforeRows, stored)
				assert.Equal(t, beforeMap, published)
				continue // No unrelated option writes are needed to prove non-equivalence.
			}
			if equivalentAlias == "" {
				equivalentAlias = alias
			}
			for index, writer := range writers {
				err := writer.mutate(alias, "not-json")
				t.Logf("dialect=%s alias=%q stored_key=%q writer=%d:%s error=%v", f.mainKind, alias, resolved.Key, index, writer.name, err)
				stored, published := optionState(t)
				assert.Equal(t, beforeRows, stored, "alias=%q writer=%s", alias, writer.name)
				assert.Equal(t, beforeMap, published, "alias=%q writer=%s", alias, writer.name)
				require.Error(t, err, "product defect: proven canonical alias=%q stored_key=%q writer=%s accepted", alias, resolved.Key, writer.name)
			}
		}
		require.NotEmpty(t, equivalentAlias, "MySQL fixture must exercise at least one actual canonical alias; equivalence checks cannot pass vacuously")
		require.NoError(t, f.db.Where(&model.Option{Key: key}).Delete(&model.Option{}).Error)
		alias := model.Option{Key: equivalentAlias, Value: declaration}
		require.NoError(t, f.db.Create(&alias).Error)
		resolved := model.Option{Key: key}
		require.NoError(t, f.db.Where(&model.Option{Key: key}).First(&resolved).Error)
		require.Equal(t, equivalentAlias, resolved.Key, "reverse lookup must resolve the proven pre-existing alias")
		aliasRows, aliasMap := optionState(t)
		for index, writer := range writers {
			err := writer.mutate(key, `{}`)
			t.Logf("dialect=%s requested_key=%q stored_key=%q writer=%d:%s reverse=true error=%v", f.mainKind, key, resolved.Key, index, writer.name, err)
			stored, published := optionState(t)
			assert.Equal(t, aliasRows, stored, "reverse alias=%q writer=%s", equivalentAlias, writer.name)
			assert.Equal(t, aliasMap, published, "reverse alias=%q writer=%s", equivalentAlias, writer.name)
			require.Error(t, err, "product defect: canonical request resolved stored alias=%q writer=%s but was accepted", resolved.Key, writer.name)
		}
		require.NoError(t, f.db.Where(&model.Option{Key: alias.Key}).Delete(&model.Option{}).Error)
		require.Equal(t, true, write(t, declaration)["success"])
	})

	t.Run("reload_and_catalog_independence", func(t *testing.T) {
		require.NoError(t, model.UpdateOption("MetadataControl", "unchanged"))
		before := rows(t, read(t, "metadata-auto"))["meta-model"]["metadata_source"]
		var dial gorm.Dialector
		switch f.mainKind {
		case "sqlite":
			dial = sqlite.Open(f.mainDSN)
		case "mysql":
			dial = mysql.Open(f.mainDSN)
		case "postgres":
			dial = postgres.New(postgres.Config{DSN: f.mainDSN, PreferSimpleProtocol: true})
		}
		reopened, err := gorm.Open(dial, &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
		require.NoError(t, err)
		connection, err := reopened.DB()
		require.NoError(t, err)
		t.Cleanup(func() { model.DB = f.db; require.NoError(t, connection.Close()) })
		model.DB = reopened
		model.InitOptionMap()
		assert.Equal(t, before, rows(t, read(t, "metadata-auto"))["meta-model"]["metadata_source"])
		common.OptionMapRWMutex.RLock()
		control := common.OptionMap["MetadataControl"]
		common.OptionMapRWMutex.RUnlock()
		assert.Equal(t, "unchanged", control)
		status, _, options := f.request(t, http.MethodGet, "/api/option/", "root", "", nil)
		require.Equal(t, http.StatusOK, status)
		found := false
		for _, item := range options["data"].([]any) {
			option := item.(map[string]any)
			if option["key"] == key {
				assert.Equal(t, declaration, option["value"])
				found = true
			}
		}
		require.True(t, found)
		var catalog model.Model
		require.NoError(t, reopened.Where(&model.Model{ModelName: "meta-model"}).First(&catalog).Error)
		catalog.Description = "Administrator catalog edit"
		require.NoError(t, catalog.Update())
		require.NoError(t, reopened.First(&catalog, catalog.Id).Error)
		_, err = model.ApplyMetadataSync([]model.MetadataSyncUpdate{{MetadataSyncSelection: model.MetadataSyncSelection{
			ModelName: catalog.ModelName, RecordVersion: model.MetadataRecordVersion(&catalog, nil, nil), Fields: []string{"description"}},
			Values: model.MetadataValues{Description: "Explicit catalog sync", Status: 1, NameRule: model.NameRuleExact}}}, nil)
		require.NoError(t, err)
		assert.Equal(t, before, rows(t, read(t, "metadata-auto"))["meta-model"]["metadata_source"])
		require.NoError(t, reopened.Model(&model.Option{}).Where(&model.Option{Key: key}).Update("value", `{"meta-model":{"Vision":true}}`).Error)
		model.InitOptionMap()
		for _, item := range rows(t, read(t, "metadata-auto")) {
			for _, field := range metadataFields {
				assert.NotContains(t, item, field, "invalid loaded config must be unknown")
			}
		}
		require.Equal(t, true, write(t, `{}`)["success"])
		model.InitOptionMap()
		for _, item := range rows(t, read(t, "metadata-auto")) {
			for _, field := range metadataFields {
				assert.NotContains(t, item, field)
			}
		}
	})
}

// One root covers the public HTTP contract and independent processes sharing
// the owned database. Child mode reconnects only; it never migrates or drops it.
func TestSiteDescriptionHTTP(t *testing.T) {
	if mode := os.Getenv("NEWAPI_SITE_DESCRIPTION_NODE"); mode != "" {
		require.Contains(t, []string{"compete", "reopen", "closed"}, mode)
		require.Equal(t, "g18-site-description", os.Getenv("NEWAPI_S2_OWNED"))
		require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
		require.Equal(t, "none", os.Getenv("NEWAPI_S2_CACHE_MODE"))
		kind, dsn := os.Getenv("NEWAPI_S2_MAIN"), os.Getenv("NEWAPI_SITE_DESCRIPTION_DSN")
		require.Contains(t, []string{"sqlite", "mysql", "postgres"}, kind)
		require.Equal(t, kind, os.Getenv("NEWAPI_S2_LOG"))
		var dial gorm.Dialector
		if kind == "sqlite" {
			require.True(t, filepath.IsAbs(dsn))
			require.Equal(t, "organization.db", filepath.Base(dsn))
			info, err := os.Lstat(dsn)
			require.NoError(t, err)
			require.True(t, info.Mode().IsRegular())
			dial = sqlite.Open(dsn + "?_pragma=busy_timeout(5000)")
		} else {
			require.NoError(t, organizationFixtureDSN(kind, dsn, os.Getenv("NEWAPI_S2_"+strings.ToUpper(kind)+"_PORT")))
			if kind == "mysql" {
				config, err := sqlmysql.ParseDSN(dsn)
				require.NoError(t, err)
				require.Regexp(t, `^newapi_s2_[a-z0-9_]+$`, config.DBName)
				dial = mysql.Open(dsn)
			} else {
				config, err := pgx.ParseConfig(dsn)
				require.NoError(t, err)
				require.Regexp(t, `^newapi_s2_[a-z0-9_]+$`, config.Database)
				dial = postgres.New(postgres.Config{DSN: dsn, PreferSimpleProtocol: true})
			}
		}
		db, err := gorm.Open(dial, &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
		require.NoError(t, err)
		conn, err := db.DB()
		require.NoError(t, err)
		model.DB = db
		if mode == "closed" {
			require.NoError(t, conn.Close())
			require.Error(t, model.InitSiteInstanceID())
			assert.Empty(t, model.SiteInstanceID(), "a failed fresh process must not publish a replacement")
			return
		}
		t.Cleanup(func() { require.NoError(t, conn.Close()) })
		if mode == "compete" {
			ready, release := os.NewFile(3, "ready"), os.NewFile(4, "release")
			require.NotNil(t, ready)
			require.NotNil(t, release)
			t.Cleanup(func() { _ = ready.Close(); _ = release.Close() })
			fired := false
			require.NoError(t, db.Callback().Query().After("gorm:query").Register("site_identity_absent_barrier", func(tx *gorm.DB) {
				if !fired && tx.Statement.Table == "options" && errors.Is(tx.Error, gorm.ErrRecordNotFound) {
					fired = true
					_, err := ready.Write([]byte{1})
					require.NoError(t, err)
					_, err = io.ReadFull(release, make([]byte, 1))
					require.NoError(t, err)
				}
			}))
		}
		require.NoError(t, model.InitSiteInstanceID())
		fmt.Println("SITE_DESCRIPTION_ID=" + model.SiteInstanceID())
		return
	}

	f := newOrganizationHTTPFixture(t)
	oldAddress, oldGithub := system_setting.ServerAddress, common.GitHubOAuthEnabled
	common.OptionMapRWMutex.Lock()
	oldOptions := common.OptionMap
	common.OptionMap = map[string]string{}
	common.OptionMapRWMutex.Unlock()
	t.Cleanup(func() {
		system_setting.ServerAddress, common.GitHubOAuthEnabled = oldAddress, oldGithub
		common.OptionMapRWMutex.Lock()
		common.OptionMap = oldOptions
		common.OptionMapRWMutex.Unlock()
	})
	const key = "SiteInstanceID"
	type node struct {
		cmd            *exec.Cmd
		mode           string
		ready, release *os.File
		output         bytes.Buffer
		cancel         context.CancelFunc
		waited         bool
	}
	startNode := func(t *testing.T, mode string) *node {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		n := &node{cancel: cancel, mode: mode}
		n.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSiteDescriptionHTTP$", "-test.timeout=25s")
		n.cmd.Env = append(os.Environ(), "NEWAPI_SITE_DESCRIPTION_NODE="+mode, "NEWAPI_SITE_DESCRIPTION_DSN="+f.mainDSN)
		n.cmd.Stdout, n.cmd.Stderr = &n.output, &n.output
		var readyWriter, releaseReader *os.File
		if mode == "compete" {
			var err error
			n.ready, readyWriter, err = os.Pipe()
			require.NoError(t, err)
			releaseReader, n.release, err = os.Pipe()
			require.NoError(t, err)
			n.cmd.ExtraFiles = []*os.File{readyWriter, releaseReader}
		}
		t.Cleanup(func() {
			if n.release != nil {
				_ = n.release.Close()
			}
			if n.ready != nil {
				_ = n.ready.Close()
			}
			n.cancel()
			if n.cmd.Process != nil && !n.waited {
				_ = n.cmd.Wait()
			}
		})
		err := n.cmd.Start()
		if readyWriter != nil {
			_ = readyWriter.Close()
			_ = releaseReader.Close()
		}
		require.NoError(t, err)
		return n
	}
	finishNode := func(t *testing.T, n *node) string {
		t.Helper()
		err := n.cmd.Wait()
		n.waited = true
		require.NoError(t, err, "independent initializer failed: %s", n.output.String())
		if n.mode == "closed" {
			return ""
		}
		match := regexp.MustCompile(`(?m)^SITE_DESCRIPTION_ID=([0-9a-f-]{36})$`).FindStringSubmatch(n.output.String())
		require.Len(t, match, 2)
		return match[1]
	}

	t.Run("shared_identity_and_reopen", func(t *testing.T) {
		require.NoError(t, f.db.Create(&model.Option{Key: "ExistingSiteOption", Value: "preserved"}).Error)
		nodes := []*node{startNode(t, "compete"), startNode(t, "compete")}
		for _, n := range nodes {
			_, err := io.ReadFull(n.ready, make([]byte, 1))
			require.NoError(t, err, "both processes must finish their absent read before either inserts")
		}
		for _, n := range nodes {
			_, err := n.release.Write([]byte{1})
			require.NoError(t, err)
		}
		first, second := finishNode(t, nodes[0]), finishNode(t, nodes[1])
		require.Equal(t, first, second)
		parsed, err := uuid.Parse(first)
		require.NoError(t, err)
		require.NotEqual(t, uuid.Nil, parsed)
		require.Equal(t, first, parsed.String())
		require.Equal(t, first, finishNode(t, startNode(t, "reopen")))
		require.NoError(t, model.InitSiteInstanceID())
		require.NoError(t, model.InitSiteInstanceID())
		assert.Equal(t, first, model.SiteInstanceID())
		var rows []model.Option
		require.NoError(t, f.db.Where(&model.Option{Key: key}).Find(&rows).Error)
		require.Equal(t, []model.Option{{Key: key, Value: first}}, rows)
		var existing model.Option
		require.NoError(t, f.db.Where(&model.Option{Key: "ExistingSiteOption"}).First(&existing).Error)
		assert.Equal(t, "preserved", existing.Value)
	})

	t.Run("reserved_option_and_failures", func(t *testing.T) {
		id := model.SiteInstanceID()
		require.NotEmpty(t, id)
		require.NoError(t, f.db.Create(&model.Option{Key: "SiteUnrelatedOption", Value: "unchanged"}).Error)
		common.OptionMapRWMutex.Lock()
		common.OptionMap["SiteUnrelatedOption"] = "unchanged"
		common.OptionMapRWMutex.Unlock()
		snapshot := func() ([]model.Option, map[string]string) {
			var rows []model.Option
			require.NoError(t, f.db.Order(clause.OrderByColumn{Column: clause.Column{Name: "key"}}).Find(&rows).Error)
			common.OptionMapRWMutex.RLock()
			defer common.OptionMapRWMutex.RUnlock()
			return rows, maps.Clone(common.OptionMap)
		}
		beforeRows, beforeMap := snapshot()
		require.Error(t, model.UpdateOption(key, uuid.NewString()))
		for _, values := range []map[string]string{
			{key: uuid.NewString(), "SiteUnrelatedOption": "changed"},
			{key: uuid.NewString(), "passkey.rp_id": "changed.invalid", "SiteUnrelatedOption": "changed"},
		} {
			require.Error(t, model.UpdateOptionsBulk(values))
		}
		afterRows, afterMap := snapshot()
		assert.Equal(t, beforeRows, afterRows)
		assert.Equal(t, beforeMap, afterMap)
		for _, alias := range []string{"siteinstanceid", "SíteInstanceID", "SiteInstanceID "} {
			var resolved model.Option
			err := f.db.Where(&model.Option{Key: alias}).First(&resolved).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				require.NoError(t, model.UpdateOption(alias, "distinct ordinary key"))
			} else {
				require.NoError(t, err)
				require.Equal(t, key, resolved.Key)
				beforeRows, beforeMap = snapshot()
				require.Error(t, model.UpdateOption(alias, "overwrite"))
				require.Error(t, model.UpdateOptionsBulk(map[string]string{alias: "overwrite", "SiteUnrelatedOption": "changed"}))
				require.Error(t, model.UpdateOptionsBulk(map[string]string{alias: "overwrite", "passkey.rp_id": "changed.invalid", "SiteUnrelatedOption": "changed"}))
				afterRows, afterMap = snapshot()
				assert.Equal(t, beforeRows, afterRows, alias)
				assert.Equal(t, beforeMap, afterMap, alias)
			}
			var stored model.Option
			require.NoError(t, f.db.Where(&model.Option{Key: key}).First(&stored).Error)
			assert.Equal(t, id, stored.Value, alias)
		}
		for _, invalid := range []string{"", "invalid", uuid.Nil.String(), "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", id + " "} {
			require.NoError(t, f.db.Model(&model.Option{}).Where(&model.Option{Key: key}).Update("value", invalid).Error)
			require.Error(t, model.InitSiteInstanceID())
			var stored model.Option
			require.NoError(t, f.db.Where(&model.Option{Key: key}).First(&stored).Error)
			assert.Equal(t, invalid, stored.Value, "corrupt identity must not be repaired")
		}
		require.NoError(t, f.db.Model(&model.Option{}).Where(&model.Option{Key: key}).Update("value", id).Error)
		if f.mainKind == "mysql" {
			// This engine's actual collation, not a Go approximation, resolves this alias.
			var alias model.Option
			require.NoError(t, f.db.Where(&model.Option{Key: "siteinstanceid"}).First(&alias).Error)
			require.Equal(t, key, alias.Key)
			require.NoError(t, f.db.Where(&model.Option{Key: key}).Delete(&model.Option{}).Error)
			require.NoError(t, f.db.Create(&model.Option{Key: "siteinstanceid", Value: id}).Error)
			require.Error(t, model.InitSiteInstanceID(), "unexpected stored spelling must not be claimed")
			require.NoError(t, f.db.Where(&model.Option{Key: "siteinstanceid"}).Delete(&model.Option{}).Error)
			require.NoError(t, f.db.Create(&model.Option{Key: key, Value: id}).Error)
		}
		finishNode(t, startNode(t, "closed"))
		require.NoError(t, model.InitSiteInstanceID())
		assert.Equal(t, id, model.SiteInstanceID())
	})

	t.Run("anonymous_links_and_navigation", func(t *testing.T) {
		request := func() map[string]any {
			req, err := http.NewRequest(http.MethodGet, f.server.URL+"/api/status", nil)
			require.NoError(t, err)
			req.Host = "hostile.invalid"
			req.Header.Set("Forwarded", "host=hostile.invalid;proto=https")
			req.Header.Set("X-Forwarded-Host", "hostile.invalid")
			req.Header.Set("X-Forwarded-Proto", "https")
			resp, err := f.client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Empty(t, resp.Header.Values("Set-Cookie"))
			var body map[string]any
			require.NoError(t, common.DecodeJson(resp.Body, &body))
			require.Equal(t, true, body["success"])
			require.Equal(t, "", body["message"])
			data, ok := body["data"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, model.SiteInstanceID(), data["instance_id"])
			assert.Equal(t, map[string]any{"enabled": false}, data["oauth"])
			assert.Equal(t, map[string]any{"token_usage_logs": false, "oauth": false, "model_metadata": false}, data["client_features"])
			assert.Equal(t, system_setting.ServerAddress, data["server_address"])
			assert.Equal(t, common.Version, data["version"])
			assert.Equal(t, common.SystemName, data["system_name"])
			assert.Equal(t, "default", data["theme"])
			raw, err := common.Marshal(data)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "private-option-canary")
			return data
		}
		common.GitHubOAuthEnabled = true
		common.OptionMapRWMutex.Lock()
		common.OptionMap["SMTPToken"] = "private-option-canary"
		common.OptionMapRWMutex.Unlock()
		for _, tc := range []struct {
			address, frontend, prefix string
			master, valid             bool
		}{
			{"https://console.example", "", "https://console.example", false, true},
			{"http://127.0.0.1:3000/base/", "", "http://127.0.0.1:3000/base", false, true},
			{"https://primary.example/root", "https://frontend.example/prefix/", "https://frontend.example/prefix", false, true},
			{"https://primary.example/root", "https://ignored.example", "https://primary.example/root", true, true},
			{"https://primary.example", "invalid", "", false, false},
			{"", "", "", false, false}, {"/relative", "", "", false, false},
			{"//relative.example", "", "", false, false}, {"ftp://example.com", "", "", false, false},
			{"https://user:secret@example.com", "", "", false, false},
			{"https://example.com/?q=1", "", "", false, false}, {"https://example.com/#f", "", "", false, false},
			{"https://example.com/\n", "", "", false, false}, {"https://example.com/\\x", "", "", false, false},
			{"https://example.com/a/../b", "", "", false, false}, {"https://example.com/%2e", "", "", false, false},
			{"https://example.com/a%2fb", "", "", false, false}, {"https://example.com/%252f", "", "", false, false},
			{"https://example.com//a", "", "", false, false}, {"http://example.com:0", "", "", false, false},
		} {
			system_setting.ServerAddress, common.IsMasterNode = tc.address, tc.master
			t.Setenv("FRONTEND_BASE_URL", tc.frontend)
			data := request()
			links := data["console_links"].(map[string]any)
			require.Len(t, links, 4)
			for name, route := range map[string]string{"topup": "/wallet", "usage_logs": "/usage-logs", "keys": "/keys", "pricing": "/pricing"} {
				if tc.valid {
					assert.Equal(t, tc.prefix+route, links[name], tc.address)
				} else {
					assert.Nil(t, links[name], tc.address)
				}
			}
			assert.Equal(t, true, data["github_oauth"], "legacy provider enablement is independent")
		}
		system_setting.ServerAddress, common.IsMasterNode = "https://console.example", false
		t.Setenv("FRONTEND_BASE_URL", "")
		for _, tc := range []struct {
			sidebar, header string
			disabled        []string
		}{
			{"", "", nil}, {`{"console":{"log":false}}`, "", []string{"usage_logs"}},
			{`{"console":{"enabled":false}}`, "", []string{"usage_logs", "keys"}},
			{`{"personal":{"enabled":false}}`, "", []string{"topup"}},
			{`{"console":{"log":"true","token":1},"personal":{"topup":null}}`, "", []string{"topup", "usage_logs", "keys"}},
			{`{"console":{"enabled":"false"}}`, "", nil},
			{`{"console":{"enabled":0}}`, "", []string{"usage_logs", "keys"}},
			{`{"console":{"log":false},`, "invalid", nil},
			{"", `{"console":false}`, nil}, {"", `{"pricing":false}`, []string{"pricing"}},
			{"", `{"pricing":"0"}`, []string{"pricing"}}, {"", `{"pricing":0}`, []string{"pricing"}},
			{"", `{"pricing":{"enabled":false,"requireAuth":true}}`, []string{"pricing"}},
			{"", `{"pricing":{"enabled":true,"requireAuth":true}}`, nil},
		} {
			common.OptionMapRWMutex.Lock()
			common.OptionMap["SidebarModulesAdmin"], common.OptionMap["HeaderNavModules"] = tc.sidebar, tc.header
			common.OptionMapRWMutex.Unlock()
			links := request()["console_links"].(map[string]any)
			for name, route := range map[string]string{"topup": "/wallet", "usage_logs": "/usage-logs", "keys": "/keys", "pricing": "/pricing"} {
				if slices.Contains(tc.disabled, name) {
					assert.Nil(t, links[name], tc.sidebar+tc.header)
				} else {
					assert.Equal(t, "https://console.example"+route, links[name], tc.sidebar+tc.header)
				}
			}
		}
		status, headers, body := f.request(t, "GET", "/api/status?org_id=1", "", "", nil)
		organizationError(t, status, headers, body, 403, "ORG_RESOURCE_UNSUPPORTED")
	})
}

func TestOrganizationAccessHTTP(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	a := strconv.FormatInt(f.orgA, 10)
	b := strconv.FormatInt(f.orgB, 10)
	t.Run("five_operations_roles_and_wire_precision", func(t *testing.T) {
		paths := []string{"/api/organizations", "/api/organization-context?org_id=" + a, "/api/organizations/" + a, "/api/organizations/" + a + "/members", "/api/organizations/" + a + "/events"}
		for _, path := range paths {
			status, h, body := f.request(t, "GET", path, "owner", "", nil)
			require.Equal(t, 200, status)
			assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
			assert.Empty(t, h.Values("Set-Cookie"))
			require.Equal(t, true, body["success"])
			require.IsType(t, map[string]any{}, body["data"])
			status, h, body = f.request(t, "GET", path, "", "", nil)
			organizationError(t, status, h, body, 401, "AUTH_UNAUTHORIZED")
		}
		status, _, body := f.request(t, "GET", "/api/organizations/"+a, "owner", "", nil)
		require.Equal(t, 200, status)
		d := body["data"].(map[string]any)
		assert.Equal(t, a, d["org_id"])
		assert.Equal(t, "9007199254740993", d["revision"])
		assert.Equal(t, "9007199254740993", d["my_member_revision"])
		assert.Len(t, d, 6)
		caps := d["capabilities"].(map[string]any)
		assert.Len(t, caps, 7)
		assert.Equal(t, true, caps["resource_access"])
		assert.Equal(t, true, caps["organization_mutation"])
		for _, key := range []string{"organization_token_issue", "organization_spend"} {
			assert.Equal(t, false, caps[key])
		}
		for _, actor := range []string{"owner", "admin", "member"} {
			status, _, body = f.request(t, "GET", "/api/organizations/"+a, actor, "", nil)
			require.Equal(t, 200, status)
			assert.Equal(t, actor, body["data"].(map[string]any)["my_role"])
		}
		status, h, body := f.request(t, "GET", "/api/organizations/"+a+"/events", "member", "", nil)
		organizationError(t, status, h, body, 403, "ORG_FORBIDDEN")
		for _, actor := range []string{"foreign", "root", "empty"} {
			status, h, body = f.request(t, "GET", "/api/organizations/"+a, actor, "", nil)
			organizationError(t, status, h, body, 404, "ORG_NOT_FOUND")
		}
		status, _, body = f.request(t, "GET", "/api/organizations/"+a+"/events", "admin", "", nil)
		require.Equal(t, 200, status)
		event := body["data"].(map[string]any)["items"].([]any)[0].(map[string]any)
		assert.Equal(t, "0", event["actor_user_id"])
		assert.Equal(t, "organization.rename", event["action"])
		status, _, body = f.request(t, "GET", "/api/organizations?after_id=9223372036854775807", "owner", "", nil)
		require.Equal(t, 200, status)
		page := body["data"].(map[string]any)
		assert.Equal(t, []any{}, page["items"])
		assert.Nil(t, page["next_after_id"])
	})
	t.Run("selector_and_strict_request", func(t *testing.T) {
		cases := []struct{ query, code string }{{"org_id=", "ORG_SELECTOR_INVALID"}, {"org_id=01", "ORG_SELECTOR_INVALID"}, {"org_id=-1", "ORG_SELECTOR_INVALID"}, {"org_id=1e2", "ORG_SELECTOR_INVALID"}, {"org_id=9223372036854775808", "ORG_SELECTOR_INVALID"}, {"org_id=%2531", "ORG_SELECTOR_INVALID"}, {"org_id=%ZZ", "ORG_SELECTOR_INVALID"}, {"org_id=1&org%5Fid=1", "ORG_SELECTOR_INVALID"}, {"ORG_ID=0", "ORG_SELECTOR_INVALID"}, {"organization_id=0", "ORG_SELECTOR_INVALID"}, {"x=a;org_id=1", "ORG_SELECTOR_INVALID"}, {"actor_user_id=1", "ORG_REQUEST_INVALID"}, {"x=%ZZ", "ORG_REQUEST_INVALID"}, {"org_id=0&org_id=0", "ORG_SELECTOR_INVALID"}}
		for _, tc := range cases {
			t.Run(tc.query, func(t *testing.T) {
				s, h, d := f.request(t, "GET", "/api/organization-context?"+tc.query, "owner", "", nil)
				organizationError(t, s, h, d, 400, tc.code)
			})
		}
		s, h, d := f.request(t, "GET", "/api/organization-context?org_id="+a, "owner", "", http.Header{"X-Organization-Id": {a}})
		organizationError(t, s, h, d, 400, "ORG_SELECTOR_CONFLICT")
		s, h, d = f.request(t, "GET", "/api/organization-context", "owner", "", http.Header{"X-Organization-Id": {a, a}})
		organizationError(t, s, h, d, 400, "ORG_SELECTOR_INVALID")
		s, h, d = f.request(t, "GET", "/api/organizations/"+a+"?org_id="+b, "owner", "", nil)
		organizationError(t, s, h, d, 400, "ORG_SELECTOR_CONFLICT")
		s, _, _ = f.request(t, "GET", "/api/organizations/"+a+"?org_id="+a, "owner", "", nil)
		assert.Equal(t, 200, s)
		s, h, d = f.request(t, "GET", "/api/organizations?org_id="+a, "owner", "", nil)
		organizationError(t, s, h, d, 400, "ORG_SELECTOR_NOT_ALLOWED")
		for _, query := range []string{"limit=0", "limit=101", "limit=01", "limit=1&limit=1", "after_id=-1", "after_id=9223372036854775808", "unknown=1"} {
			s, h, d = f.request(t, "GET", "/api/organizations?"+query, "owner", "", nil)
			organizationError(t, s, h, d, 400, "ORG_REQUEST_INVALID")
		}
		for _, header := range []string{"X-Security-Proof", "Idempotency-Key"} {
			s, h, d = f.request(t, "GET", "/api/organization-context", "owner", "", http.Header{header: {"proof-canary"}})
			organizationError(t, s, h, d, 400, "ORG_REQUEST_INVALID")
		}
		s, h, d = f.request(t, "GET", "/api/organization-context", "owner", "{}", nil)
		organizationError(t, s, h, d, 400, "ORG_REQUEST_INVALID")
		req, err := http.NewRequest("GET", f.server.URL+"/api/organization-context", io.NopCloser(strings.NewReader("{}")))
		require.NoError(t, err)
		req.ContentLength = -1
		req.Header.Set("Authorization", "Bearer "+f.bearer["owner"])
		resp, err := f.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, 400, resp.StatusCode)
	})
	t.Run("credential_boundaries", func(t *testing.T) {
		suffix, err := common.GenerateRandomCharsKey(43)
		require.NoError(t, err)
		pat := model.AccessTokenPrefix + suffix
		row := &model.UserAccessToken{Name: "s2", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
		require.NoError(t, row.SetScopes([]string{"*"}))
		require.NoError(t, model.CreateUserAccessToken(f.users["root"].Id, row, service.AccessTokenMaxPerUser))
		for _, path := range []string{"/api/organizations", "/api/organization-context", "/api/organizations/" + a, "/api/organizations/" + a + "/members", "/api/organizations/" + a + "/events"} {
			s, h, d := f.request(t, "GET", path, pat, "", nil)
			organizationError(t, s, h, d, 403, "AUTH_SESSION_REQUIRED")
		}
		require.NoError(t, f.db.Model(row).Update("expires_at", time.Now().Unix()-1).Error)
		ps, ph, pd := f.request(t, "GET", "/api/organization-context", pat, "", nil)
		organizationError(t, ps, ph, pd, 401, "ACCESS_TOKEN_EXPIRED")
		legacy, err := common.GenerateRandomCharsKey(32)
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["root"].Id).Update("access_token", legacy).Error)
		ps, ph, pd = f.request(t, "GET", "/api/organization-context", legacy, "", nil)
		organizationError(t, ps, ph, pd, 403, "AUTH_SESSION_REQUIRED")
		require.NoError(t, f.db.Model(&model.Option{}).Where(&model.Option{Key: "LegacyAccessTokenRetireAt"}).Update("value", fmt.Sprint(time.Now().Unix()-1)).Error)
		require.NoError(t, model.EnsureLegacyAccessTokenRetireAt(time.Now().Unix()))
		ps, ph, pd = f.request(t, "GET", "/api/organization-context", legacy, "", nil)
		organizationError(t, ps, ph, pd, 401, "ACCESS_TOKEN_LEGACY_RETIRED")
		require.NoError(t, f.db.Model(&model.Option{}).Where(&model.Option{Key: "LegacyAccessTokenRetireAt"}).Update("value", fmt.Sprint(time.Now().Unix()+3600)).Error)
		require.NoError(t, model.EnsureLegacyAccessTokenRetireAt(time.Now().Unix()))
		for _, credential := range []string{"not-a-jwt", "sk-s2-not-dashboard"} {
			s, h, d := f.request(t, "GET", "/api/organization-context", credential, "", nil)
			organizationError(t, s, h, d, 401, "AUTH_UNAUTHORIZED")
		}
		s, h, d := f.request(t, "GET", "/api/organization-context", "", "", http.Header{"Cookie": {service.RefreshCookieName + "=refresh-canary"}, "Origin": {"https://cross-site.invalid"}})
		organizationError(t, s, h, d, 401, "AUTH_UNAUTHORIZED")
	})
	t.Run("independent_tab_context", func(t *testing.T) {
		var wg sync.WaitGroup
		for _, org := range []string{a, b, "0"} {
			wg.Go(func() {
				s, _, d := f.request(t, "GET", "/api/organization-context?org_id="+org, "member", "", nil)
				if assert.Equal(t, 200, s) {
					ctx := d["data"].(map[string]any)
					assert.Len(t, ctx, 4)
					assert.Equal(t, org, ctx["org_id"])
					if org == "0" {
						assert.Equal(t, "personal", ctx["scope_kind"])
						assert.Nil(t, ctx["organization"])
					}
				}
			})
		}
		wg.Wait()
	})
	t.Run("filtered_before_limit", func(t *testing.T) {
		disabled := model.Organization{ID: f.orgA - 2, Name: "hidden", OwnerUserID: f.users["owner"].Id, CreatedByUserID: f.users["owner"].Id, Revision: 1, OwnershipVersion: 1, SelfDisabledAt: 1}
		require.NoError(t, f.db.Create(&disabled).Error)
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrganizationID: disabled.ID, UserID: f.users["owner"].Id, Role: "member", Revision: 1}).Error)
		s, _, d := f.request(t, "GET", "/api/organizations?limit=1", "owner", "", nil)
		require.Equal(t, 200, s)
		items := d["data"].(map[string]any)["items"].([]any)
		require.Len(t, items, 1)
		assert.Equal(t, a, items[0].(map[string]any)["org_id"])
		for _, actor := range []string{"owner", "member", "foreign"} {
			s, h, d := f.request(t, "GET", fmt.Sprintf("/api/organizations/%d/events", disabled.ID), actor, "", nil)
			organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
		}
	})
	t.Run("warm_cache_revocation", func(t *testing.T) {
		for _, actor := range []string{"revoked", "empty"} {
			_, err := model.GetUserCache(f.users[actor].Id)
			require.NoError(t, err)
			_, err = model.GetUserSessionCached(f.sids[actor])
			require.NoError(t, err)
		}
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, f.users["revoked"].Id).Updates(map[string]any{"removed_at": time.Now().Unix(), "revision": 9007199254740994}).Error)
		s, h, d := f.request(t, "GET", "/api/organizations/"+a, "revoked", "", nil)
		organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
		// Direct DB mutation intentionally preserves an already warm cache; this tests authoritative rechecks.
		require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid IN ?", []string{f.sids["revoked"], f.sids["empty"]}).Update("status", model.UserSessionStatusRevoked).Error)
		for _, actor := range []string{"revoked", "empty"} {
			if common.RedisEnabled {
				cached, err := model.GetUserSessionCached(f.sids[actor])
				require.NoError(t, err)
				require.Equal(t, model.UserSessionStatusActive, cached.Status, "prove stale Redis value before HTTP rejection")
			}
			for _, path := range []string{"/api/organization-context?org_id=0", "/api/organizations", "/api/organizations/9223372036854775807", "/api/organizations/" + a} {
				s, h, d = f.request(t, "GET", path, actor, "", nil)
				organizationError(t, s, h, d, 401, "AUTH_SESSION_REVOKED")
			}
		}
	})
	t.Run("audit_projection_roundtrip", func(t *testing.T) {
		s, eventHeaders, _ := f.request(t, "GET", "/api/organizations/"+a+"/events", "owner", "", http.Header{"User-Agent": {"s2-ua-secret-canary"}, "Cookie": {"s2-cookie-secret-canary"}})
		require.Equal(t, 200, s)
		s, denialHeaders, _ := f.request(t, "GET", "/api/organizations/"+a, "foreign", "", nil)
		require.Equal(t, 404, s)
		rows, _, err := model.GetAuditLogs(model.AuditLogFilter{Category: model.AuditCategorySecurity}, 0, 1000, common.RoleRootUser)
		require.NoError(t, err)
		actions := map[string]bool{}
		requestIDs := map[string]string{eventHeaders.Get(common.RequestIdKey): "organization.events_read", denialHeaders.Get(common.RequestIdKey): "organization.access_denied"}
		require.NotContains(t, requestIDs, "")
		matched := 0
		for _, row := range rows {
			expectedAction, relevant := requestIDs[row.RequestId]
			if !relevant {
				continue
			}
			matched++
			assert.Equal(t, expectedAction, row.Action)
			assert.Equal(t, "session", row.AuthMethod)
			if expectedAction == "organization.events_read" {
				assert.Equal(t, f.users["owner"].Id, row.UserId)
				assert.Equal(t, 200, row.Status)
				assert.True(t, row.Success)
			} else {
				assert.Equal(t, f.users["foreign"].Id, row.UserId)
				assert.Equal(t, 404, row.Status)
				assert.False(t, row.Success)
			}
			actions[row.Action] = true
			assert.Empty(t, row.Ip)
			assert.Empty(t, row.UserAgent)
			assert.Empty(t, row.Content)
			assert.Empty(t, row.TokenRef)
			require.NotNil(t, row.Other.Op)
			assert.Equal(t, row.Action, row.Other.Op.Action)
			payload, err := common.Marshal(row.Other.Op.Params)
			require.NoError(t, err)
			var params map[string]any
			require.NoError(t, common.Unmarshal(payload, &params))
			assert.Equal(t, a, params["org_id"])
			if expectedAction == "organization.events_read" {
				assert.Equal(t, "allowed", params["decision"])
			} else {
				assert.Equal(t, "ORG_NOT_FOUND", params["decision"])
			}
			assert.NotContains(t, row.Route, "?")
			assert.NotContains(t, row.Route, "SECRET_")

			assert.Nil(t, row.Other.AdminInfo)
			assert.Nil(t, row.Other.AuditInfo)
			assert.Empty(t, row.Other.RootInfo)
			assert.Empty(t, row.Other.UserAgent)
			for key := range row.Other.Op.Params {
				assert.Contains(t, []string{"org_id", "decision"}, key)
			}
		}
		assert.Equal(t, 2, matched)
		assert.True(t, actions["organization.events_read"])
		assert.True(t, actions["organization.access_denied"])
		assert.NotContains(t, f.logs.snapshot(), "s2-ua-secret-canary")
		assert.NotContains(t, f.logs.snapshot(), "s2-cookie-secret-canary")
		old := model.LOG_DB
		model.LOG_DB = nil
		s, failureHeaders, _ := f.request(t, "GET", "/api/organizations/"+a, "foreign", "", nil)
		model.LOG_DB = old
		assert.Equal(t, 404, s)
		assert.Contains(t, f.logs.snapshot(), common.LogText("audit log write failed (request_id=%s): log database unavailable", failureHeaders.Get(common.RequestIdKey)))
	})
}

func TestOrganizationCapabilityProjection(t *testing.T) {
	t.Run("capability_projection", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		a := strconv.FormatInt(f.orgA, 10)
		paths := []string{"/api/organizations", "/api/organization-context?org_id=" + a, "/api/organizations/" + a}
		governance := map[string]bool{"owner": true, "admin": true, "member": false}
		projection := func(actor, role string) {
			t.Helper()
			for index, path := range paths {
				status, headers, body := f.request(t, http.MethodGet, path, actor, "", nil)
				require.Equal(t, http.StatusOK, status, "actor=%s path=%s", actor, path)
				assert.Equal(t, "private, no-store", headers.Get("Cache-Control"))
				data := body["data"].(map[string]any)
				var view map[string]any
				switch index {
				case 0:
					for _, value := range data["items"].([]any) {
						item := value.(map[string]any)
						if item["org_id"] == a {
							view = item
						}
					}
				case 1:
					assert.Equal(t, "organization", data["scope_kind"])
					view = data["organization"].(map[string]any)
				case 2:
					view = data
				}
				require.NotNil(t, view, "actor=%s path=%s", actor, path)
				assert.Equal(t, role, view["my_role"])
				assert.Equal(t, map[string]any{
					"organization_read": true, "members_read": true, "events_read": governance[role],
					"resource_access": true, "organization_mutation": governance[role],
					"organization_token_issue": false, "organization_spend": false,
				}, view["capabilities"], "actor=%s path=%s", actor, path)
			}
		}
		unavailable := func(actor string) {
			t.Helper()
			for index, path := range paths {
				status, headers, body := f.request(t, http.MethodGet, path, actor, "", nil)
				if index != 0 {
					organizationError(t, status, headers, body, http.StatusNotFound, "ORG_NOT_FOUND")
					continue
				}
				require.Equal(t, http.StatusOK, status)
				assert.Equal(t, "private, no-store", headers.Get("Cache-Control"))
				for _, value := range body["data"].(map[string]any)["items"].([]any) {
					assert.NotEqual(t, a, value.(map[string]any)["org_id"])
				}
			}
		}
		for _, actor := range []string{"owner", "admin", "member"} {
			projection(actor, actor)
		}
		unavailable("root")
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrganizationID: f.orgA, UserID: f.users["root"].Id, Role: model.OrganizationRoleMember, Revision: 1, JoinedAt: 1}).Error)
		projection("root", "member")
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, f.users["admin"].Id).Update("role", model.OrganizationRoleMember).Error)
		projection("admin", "member")
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, f.users["member"].Id).Update("removed_at", int64(1)).Error)
		unavailable("member")
		for _, column := range []string{"self_disabled_at", "platform_disabled_at", "dissolved_at"} {
			require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.orgA).Update(column, int64(1)).Error)
			unavailable("owner")
			require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.orgA).Update(column, int64(0)).Error)
		}
		status, _, body := f.request(t, http.MethodGet, "/api/organization-context?org_id=0", "owner", "", nil)
		require.Equal(t, http.StatusOK, status)
		data := body["data"].(map[string]any)
		assert.Equal(t, "personal", data["scope_kind"])
		assert.Nil(t, data["organization"])
		assert.NotContains(t, data, "capabilities")
		require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["root"]).Update("status", model.UserSessionStatusRevoked).Error)
		for _, path := range paths {
			status, headers, body := f.request(t, http.MethodGet, path, "root", "", nil)
			organizationError(t, status, headers, body, http.StatusUnauthorized, "AUTH_SESSION_REVOKED")
		}
	})
}

func TestOrganizationSelectionProductionRoutes(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	allow := map[string]bool{"GET /api/organizations": true, "GET /api/organization-context": true, "GET /api/organizations/:org_id": true, "GET /api/organizations/:org_id/members": true, "GET /api/organizations/:org_id/events": true}
	allow["GET /api/organizations/:org_id/tasks/batch"] = true
	allow["GET /api/organizations/:org_id/tasks/export"] = true
	allow["GET /api/organizations/:org_id/tasks/:task_row_id"] = true
	allow["GET /api/organizations/:org_id/tasks/:task_row_id/artifacts"] = true
	allow["GET /api/organizations/:org_id/tasks/:task_row_id/artifacts/:artifact_key/content"] = true
	allow["HEAD /api/organizations/:org_id/tasks/:task_row_id/artifacts/:artifact_key/content"] = true
	allow["PATCH /api/organizations/:org_id/name"] = true
	allow["POST /api/organizations/:org_id/self-state"] = true
	allow["POST /api/platform/organizations/:org_id/state"] = true
	allow["POST /api/organizations/:org_id/dissolve"] = true
	allow["PATCH /api/organizations/:org_id/members/:user_id/role"] = true
	allow["DELETE /api/organizations/:org_id/members/:user_id"] = true
	allow["POST /api/organizations/:org_id/leave"] = true
	allow["POST /api/organizations/:org_id/invitations"] = true
	allow["POST /api/organizations/:org_id/invitations/:invitation_id/reissue"] = true
	allow["POST /api/organizations/:org_id/invitations/:invitation_id/accept"] = true
	allow["POST /api/organizations/:org_id/invitations/:invitation_id/decline"] = true
	allow["POST /api/organizations/:org_id/invitations/:invitation_id/revoke"] = true
	allow["POST /api/organizations/:org_id/ownership-transfers"] = true
	allow["POST /api/organizations/:org_id/ownership-transfers/:transfer_id/accept"] = true
	allow["POST /api/organizations/:org_id/ownership-transfers/:transfer_id/decline"] = true
	allow["POST /api/organizations/:org_id/ownership-transfers/:transfer_id/cancel"] = true
	allow["GET /api/organizations/:org_id/invitations"] = true
	allow["GET /api/organizations/:org_id/ownership-transfer"] = true
	allow["GET /api/organizations/:org_id/invitations/:invitation_id/generations/:generation"] = true
	allow["GET /api/organizations/:org_id/ownership-transfers/:transfer_id/generations/:generation"] = true
	allow["GET /api/organizations/:org_id/self-state"] = true
	allow["GET /api/platform/organizations/:org_id/state"] = true
	allow["POST /api/organizations/:org_id/authorization-context"] = true
	allow["POST /api/platform/organizations/:org_id/authorization-context"] = true
	pathlessS3 := map[string]bool{"POST /api/organizations": true, "GET /api/organization-invitations": true, "GET /api/organization-ownership-transfers": true, "GET /api/verify/methods": true, "POST /api/verify": true, "POST /api/user/passkey/verify/begin": true, "POST /api/user/passkey/verify/finish": true}
	// Personal resource routes with an organization view enter their own
	// authentication chain instead of the unsupported-selector rejection.
	organizationView := map[string]bool{"GET /api/task/self": true}

	registered := map[string]bool{}
	var writes atomic.Int64
	require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("s2:guard_writes", func(*gorm.DB) { writes.Add(1) }))
	defer f.db.Callback().Create().Remove("s2:guard_writes")
	require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register("s2:guard_writes", func(*gorm.DB) { writes.Add(1) }))
	defer f.db.Callback().Update().Remove("s2:guard_writes")
	require.NoError(t, f.db.Callback().Delete().Before("gorm:delete").Register("s2:guard_writes", func(*gorm.DB) { writes.Add(1) }))
	defer f.db.Callback().Delete().Remove("s2:guard_writes")
	var queries atomic.Int64
	require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("s2:guard_queries", func(*gorm.DB) { queries.Add(1) }))
	defer f.db.Callback().Query().Remove("s2:guard_queries")
	param := regexp.MustCompile(`[:*][^/]+`)
	for _, route := range f.engine.Routes() {
		key := route.Method + " " + route.Path
		registered[key] = true
		if allow[key] {
			continue
		}
		path := param.ReplaceAllString(route.Path, "s2-canary")
		t.Run(key, func(t *testing.T) {
			before := queries.Load()
			s, h, d := f.request(t, route.Method, path+"?org_id=1", "", "", nil)
			wantStatus := 403
			if pathlessS3[key] {
				wantStatus = 400
			}
			if organizationView[key] {
				wantStatus = 401
			}
			assert.Equal(t, wantStatus, s)
			assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
			assert.Equal(t, before, queries.Load(), "guard must precede database lookup")
			if route.Method == "HEAD" {
				assert.Empty(t, d)
				return
			}
			if strings.HasPrefix(path, "/api/") || path == "/api" {
				wantCode := "ORG_RESOURCE_UNSUPPORTED"
				if pathlessS3[key] {
					wantCode = "ORG_SELECTOR_NOT_ALLOWED"
				}
				if organizationView[key] {
					wantCode = "AUTH_UNAUTHORIZED"
				}
				assert.Equal(t, wantCode, d["code"])
			} else {
				require.IsType(t, map[string]any{}, d["error"])
				assert.Equal(t, "organization_scope_unsupported", d["error"].(map[string]any)["code"])
			}
		})
	}
	for route := range allow {
		assert.True(t, registered[route], "formal route absent: %s", route)
	}
	for _, path := range []string{"/s2alias/jobs/missing", "/unknown-s2-route", "/v1/tasks/missing/artifacts/video/content", "/v1/videos/missing/content"} {
		s, _, d := f.request(t, "GET", path+"?org_id=1", "", "", nil)
		assert.Equal(t, 403, s)
		assert.Equal(t, "organization_scope_unsupported", d["error"].(map[string]any)["code"])
	}
	for _, lang := range []string{"en", "zh-CN", "zh-TW"} {
		status, _, body := f.request(t, "GET", "/v1/models?org_id=1", "", "", http.Header{"Accept-Language": {lang}})
		require.Equal(t, 403, status)
		errBody := body["error"].(map[string]any)
		assert.Equal(t, "organization_scope_unsupported", errBody["code"])
		assert.Equal(t, "invalid_request_error", errBody["type"])
		assert.Equal(t, "org_id", errBody["param"])
		assert.Equal(t, map[string]string{"en": "Organization resources are not supported on this endpoint.", "zh-CN": "此接口不支持组织资源。", "zh-TW": "此介面不支援組織資源。"}[lang], errBody["message"])
	}
	// The unselected real alias must enter its production auth chain, not SPA fallback.
	s, _, _ := f.request(t, "GET", "/s2alias/jobs/missing", "", "", nil)
	assert.Equal(t, 401, s)
	for _, path := range []string{"/v1/tasks/missing/artifacts/video/content", "/v1/videos/missing/content"} {
		s, _, d := f.request(t, "GET", path+"?access=access-canary;org_id=1", "relay", "", nil)
		assert.Equal(t, 400, s)
		assert.Equal(t, "organization_selector_invalid", d["error"].(map[string]any)["code"])
	}
	for _, method := range []string{"GET", "POST"} {
		s, _, d := f.request(t, method, "/api/token?org_id=1", "owner", "", nil)
		assert.Equal(t, 403, s)
		assert.Equal(t, "ORG_RESOURCE_UNSUPPORTED", d["code"])
	}
	assert.NotContains(t, f.logs.snapshot(), "access-canary")
	assert.Zero(t, writes.Load(), "selected legacy requests must not write business data")
}

// The generated consumer receives credentials through stdin only and reports no
// secrets. The Go fixture owns the actual production HTTP server for its lifetime.
func TestOrganizationGeneratedConsumer(t *testing.T) {
	if os.Getenv("NEWAPI_S2_CONSUMER") == "" {
		t.Skip("external consumer not configured; scoped matrix runner treats required skips as failure")
	}
	f := newOrganizationHTTPFixture(t)
	payload, err := common.Marshal(map[string]any{"base": f.server.URL, "owner": f.bearer["owner"], "member": f.bearer["member"], "foreign": f.bearer["foreign"], "orgA": strconv.FormatInt(f.orgA, 10), "orgB": strconv.FormatInt(f.orgB, 10)})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Getenv("NEWAPI_S2_NODE"), os.Getenv("NEWAPI_S2_CONSUMER"))
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.CombinedOutput()
	// Consumer uses fixed error labels, never serializes request configuration/token.
	require.NoError(t, err, "generated consumer failed; inspect sanitized runner result")
	assert.Contains(t, string(out), "all-five-live-http-pass")
	require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, f.users["member"].Id).Update("removed_at", time.Now().Unix()).Error)
	var removed map[string]any
	require.NoError(t, common.Unmarshal(payload, &removed))
	removed["removed"] = true
	payload, err = common.Marshal(removed)
	require.NoError(t, err)
	cmd = exec.CommandContext(ctx, os.Getenv("NEWAPI_S2_NODE"), os.Getenv("NEWAPI_S2_CONSUMER"))
	cmd.Stdin = bytes.NewReader(payload)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "generated removed-member consumer failed")
	assert.Contains(t, string(out), "all-five-live-http-pass")
}

func TestOrganizationAccessFreshnessAndFailures(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	a := strconv.FormatInt(f.orgA, 10)
	for _, tc := range []struct{ name, actor, path string }{
		{"revoke_before_data_read_barrier", "member", "/api/organizations/" + a},
		{"revoke_before_task_read_barrier", "revoked", "/api/task/self?org_id=" + a},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("s2:read_barrier", func(tx *gorm.DB) {
				if tx.Statement.Table == "users" {
					once.Do(func() {
						close(reached)
						select {
						case <-release:
						case <-time.After(5 * time.Second):
							tx.AddError(fmt.Errorf("bounded barrier deadline"))
						}
					})
				}
			}))
			defer f.db.Callback().Query().Remove("s2:read_barrier")
			result := make(chan int, 1)
			go func() {
				req, _ := http.NewRequest("GET", f.server.URL+tc.path, nil)
				req.Header.Set("Authorization", "Bearer "+f.bearer[tc.actor])
				resp, err := f.client.Do(req)
				if err != nil {
					result <- 0
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				result <- resp.StatusCode
			}()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("formal data-read barrier not reached")
			}
			err := f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, f.users[tc.actor].Id).Update("removed_at", time.Now().Unix()).Error
			close(release)
			require.NoError(t, err)
			select {
			case status := <-result:
				assert.Equal(t, 404, status)
			case <-time.After(5 * time.Second):
				t.Fatal("request did not finish after release")
			}
		})
	}
	t.Run("expired_session_and_disabled_user_authority", func(t *testing.T) {
		for _, tc := range []struct {
			actor, column string
			value         any
		}{{"admin", "expires_at", int64(1)}, {"foreign", "status", model.UserSessionStatusRevoked}} {
			_, err := model.GetUserSessionCached(f.sids[tc.actor])
			require.NoError(t, err)
			require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids[tc.actor]).Update(tc.column, tc.value).Error)
			s, h, d := f.request(t, "GET", "/api/organization-context?org_id=0", tc.actor, "", nil)
			organizationError(t, s, h, d, 401, "AUTH_SESSION_REVOKED")
		}
		_, err := model.GetUserCache(f.users["empty"].Id)
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["empty"].Id).Update("status", common.UserStatusDisabled).Error)
		s, h, d := f.request(t, "GET", "/api/organizations", "empty", "", nil)
		assert.Equal(t, 401, s)
		assert.Contains(t, []string{"AUTH_USER_DISABLED", "AUTH_SESSION_REVOKED"}, d["code"])
		assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
	})
	t.Run("domain_database_error_is_not_empty_success", func(t *testing.T) {
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("s2:db_failure", func(tx *gorm.DB) {
			if tx.Statement.Table == "organizations" {
				tx.AddError(fmt.Errorf("s2-controlled-database-failure"))
			}
		}))
		defer f.db.Callback().Query().Remove("s2:db_failure")
		s, h, d := f.request(t, "GET", "/api/organizations/"+a, "owner", "", nil)
		organizationError(t, s, h, d, 500, "ORG_INTERNAL_ERROR")
	})
	t.Run("safe_server_log_projection", func(t *testing.T) {
		for _, query := range []string{"org_id=SECRET_SELECTOR_CANARY", "org_id=1&access=SECRET_ACCESS_CANARY&access=SECRET_ACCESS_CANARY", "org_id=1&%61ccess=SECRET_ACCESS_CANARY"} {
			s, _, _ := f.request(t, "GET", "/v1/tasks/SECRET_PATH_CANARY/artifacts/video/content?"+query, "SECRET_AUTH_CANARY", "", http.Header{"Cookie": {"SECRET_COOKIE_CANARY"}, "User-Agent": {"SECRET_UA_CANARY"}, "X-Security-Proof": {"SECRET_PROOF_CANARY"}})
			assert.Contains(t, []int{400, 403}, s)
		}
		log := f.logs.snapshot()
		for _, word := range []string{"SECRET_SELECTOR_CANARY", "SECRET_ACCESS_CANARY", "SECRET_PATH_CANARY", "SECRET_AUTH_CANARY", "SECRET_COOKIE_CANARY", "SECRET_UA_CANARY", "SECRET_PROOF_CANARY"} {
			assert.NotContains(t, log, word)
		}
	})
}

func TestOrganizationPersonalCompatibility(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	tokens := map[string]*model.Token{}
	for _, actor := range []string{"owner", "foreign"} {
		suffix, err := common.GenerateRandomCharsKey(40)
		require.NoError(t, err)
		row := &model.Token{UserId: f.users[actor].Id, Key: suffix, Name: "personal-" + actor, Status: common.TokenStatusEnabled, ExpiredTime: -1}
		require.NoError(t, f.db.Create(row).Error)
		tokens[actor] = row
	}
	for _, query := range []string{"", "?org_id=0"} {
		s, _, d := f.request(t, "GET", "/api/token/"+query, "owner", "", nil)
		require.Equal(t, 200, s)
		raw, err := common.Marshal(d)
		require.NoError(t, err)
		assert.Contains(t, string(raw), "personal-owner")
		assert.NotContains(t, string(raw), "personal-foreign")
		s, _, d = f.request(t, "GET", fmt.Sprintf("/api/token/%d%s", tokens["foreign"].Id, query), "owner", "", nil)
		require.Equal(t, 200, s)
		assert.Equal(t, false, d["success"])
		s, _, d = f.request(t, "POST", "/api/token/batch/keys"+query, "owner", fmt.Sprintf(`{"ids":[%d,%d]}`, tokens["owner"].Id, tokens["foreign"].Id), http.Header{"Content-Type": {"application/json"}})
		require.Equal(t, 200, s)
		encoded, err := common.Marshal(d)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), tokens["foreign"].Key)
		s, _, _ = f.request(t, "GET", "/api/channel/"+query, "owner", "", nil)
		assert.Equal(t, 403, s)
	}
	// A syntactically valid opaque relay key is still not a dashboard session.
	s, h, d := f.request(t, "GET", "/api/organizations", "sk-"+tokens["owner"].Key, "", nil)
	assert.Equal(t, 401, s)
	assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
	assert.NotContains(t, slices.Collect(maps.Keys(d)), "data")
}

func TestOrganizationRateLimitContract(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	oldEnabled, oldNum, oldDuration := common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration
	t.Cleanup(func() {
		common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = oldEnabled, oldNum, oldDuration
	})
	common.GlobalApiRateLimitEnable = true
	common.GlobalApiRateLimitNum = 1
	common.GlobalApiRateLimitDuration = 60
	e := gin.New()
	SetRouter(e, WebAssets{IndexPage: []byte("fallback")})
	srv := httptest.NewServer(e)
	defer srv.Close()
	for i := range 2 {
		req, err := http.NewRequest("GET", srv.URL+"/api/organization-context", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+f.bearer["owner"])
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		if i == 0 {
			assert.Equal(t, 200, resp.StatusCode)
		} else {
			assert.Equal(t, 429, resp.StatusCode)
			assert.Empty(t, body)
			if v := resp.Header.Get("Retry-After"); v != "" {
				seconds, err := strconv.Atoi(v)
				require.NoError(t, err)
				assert.Positive(t, seconds)
			}
		}
		assert.Equal(t, "private, no-store", resp.Header.Get("Cache-Control"))
	}
	if common.RedisEnabled {
		old := common.RDB
		common.RDB = nil
		req, err := http.NewRequest("GET", srv.URL+"/api/organization-context", nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		common.RDB = old
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, 500, resp.StatusCode)
		assert.Empty(t, body)
	}
}

func TestOrganizationLegacyCapabilityCompatibility(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	oldSecret := common.CryptoSecret
	common.CryptoSecret = common.SessionSecret
	t.Cleanup(func() { common.CryptoSecret = oldSecret })
	task := &model.Task{TaskID: "s2-legacy-video", UserId: f.users["member"].Id, Platform: "document", Action: constant.TaskActionTextToVideo, Status: model.TaskStatusSuccess, FailReason: "data:video/mp4;base64,YWJj"}
	require.NoError(t, f.db.Create(task).Error)
	capability, err := service.IssueTaskArtifactAccess(task.TaskID, "video")
	require.NoError(t, err)
	path := "/v1/tasks/" + task.TaskID + "/artifacts/video/content?access=" + url.QueryEscape(capability)
	for _, removed := range []bool{false, true} {
		if removed {
			require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("user_id = ?", f.users["member"].Id).Update("removed_at", time.Now().Unix()).Error)
		}
		for _, method := range []string{"GET", "HEAD"} {
			req, err := http.NewRequest(method, f.server.URL+path, nil)
			require.NoError(t, err)
			resp, err := f.client.Do(req)
			require.NoError(t, err)
			raw, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, 200, resp.StatusCode)
			if method == "GET" {
				assert.Equal(t, "abc", string(raw))
			} else {
				assert.Empty(t, raw)
			}
		}
	}
	s, _, d := f.request(t, "GET", path+"&org_id=1", "", "", nil)
	assert.Equal(t, 403, s)
	assert.Equal(t, "organization_scope_unsupported", d["error"].(map[string]any)["code"])
	s, _, _ = f.request(t, "GET", "/v1/tasks/"+task.TaskID+"/artifacts/video/content?access=invalid", "", "", nil)
	assert.Equal(t, 404, s)
	// No positive cache here: original policy checks owner enabled, not membership.
	oldRedis := common.RedisEnabled
	common.RedisEnabled = false
	defer func() { common.RedisEnabled = oldRedis }()
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["member"].Id).Update("status", common.UserStatusDisabled).Error)
	s, _, _ = f.request(t, "GET", path, "", "", nil)
	assert.Equal(t, 404, s)
	require.NoError(t, f.db.Unscoped().Delete(f.users["member"]).Error)
	s, _, _ = f.request(t, "GET", path, "", "", nil)
	assert.Equal(t, 404, s)
	assert.NotContains(t, f.logs.snapshot(), capability)
}

// Organization-owned tasks are reachable only through the selected task view;
// personal, platform-administrator and capability lookups never resolve them.
func TestOrganizationTaskAccess(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	oldSecret := common.CryptoSecret
	common.CryptoSecret = common.SessionSecret
	t.Cleanup(func() { common.CryptoSecret = oldSecret })
	a, b := strconv.FormatInt(f.orgA, 10), strconv.FormatInt(f.orgB, 10)
	now := time.Now().Unix()
	for i, seed := range []struct {
		taskID, user string
		org          int64
	}{
		{"s2-p-owner", "owner", 0}, {"s2-p-member", "member", 0},
		{"s2-a-owner", "owner", f.orgA}, {"s2-a-member", "member", f.orgA}, {"s2-a-revoked", "revoked", f.orgA},
		{"s2-b-member", "member", f.orgB}, {"s2-b-foreign", "foreign", f.orgB},
	} {
		require.NoError(t, f.db.Create(&model.Task{TaskID: seed.taskID, UserId: f.users[seed.user].Id, OrganizationID: seed.org, Platform: "document", Action: constant.TaskActionTextToVideo, Status: model.TaskStatusSuccess, FailReason: "data:video/mp4;base64,YWJj", SubmitTime: now + int64(i), ChannelId: 7, Data: []byte(`{"upstream":"s2-snapshot-canary"}`)}).Error)
	}
	list := func(t *testing.T, actor, query string, headers http.Header) ([]string, map[string]any) {
		t.Helper()
		s, _, d := f.request(t, "GET", "/api/task/self"+query, actor, "", headers)
		require.Equal(t, 200, s, "%v", d)
		raw, err := common.Marshal(d)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "s2-snapshot-canary")
		data := d["data"].(map[string]any)
		ids := []string{}
		for _, item := range data["items"].([]any) {
			task := item.(map[string]any)
			assert.EqualValues(t, 0, task["channel_id"], "task lists never expose the channel")
			ids = append(ids, task["task_id"].(string))
		}
		return ids, data
	}

	t.Run("personal_view_excludes_organization_rows", func(t *testing.T) {
		for _, query := range []string{"", "?org_id=0"} {
			ids, _ := list(t, "owner", query, nil)
			assert.Equal(t, []string{"s2-p-owner"}, ids)
			ids, _ = list(t, "member", query, nil)
			assert.Equal(t, []string{"s2-p-member"}, ids)
			// Organization request hardening applies only to a positive selector.
			s, h, d := f.request(t, "GET", "/api/task/self"+query, "owner", "", http.Header{"Idempotency-Key": {"s2-key"}, "Origin": {"https://a.example", "https://b.example"}})
			require.Equal(t, 200, s, "%v", d)
			assert.Empty(t, h.Get("Cache-Control"))
		}
	})
	t.Run("organization_roles", func(t *testing.T) {
		orgA := []string{"s2-a-revoked", "s2-a-member", "s2-a-owner"}
		for _, tc := range []struct {
			actor, org string
			want       []string
		}{
			{"owner", a, orgA},
			{"admin", a, orgA},
			{"member", a, []string{"s2-a-member"}},
			{"member", b, []string{"s2-b-member"}},
			{"foreign", b, []string{"s2-b-foreign", "s2-b-member"}},
		} {
			ids, data := list(t, tc.actor, "?org_id="+tc.org, nil)
			assert.Equal(t, tc.want, ids, "%s in %s", tc.actor, tc.org)
			assert.EqualValues(t, len(tc.want), data["total"])
		}
		ids, _ := list(t, "owner", "", http.Header{"X-Organization-Id": {a}})
		assert.Equal(t, orgA, ids)
	})
	t.Run("cross_organization_and_platform_roles_are_not_found", func(t *testing.T) {
		for _, tc := range []struct{ actor, org string }{{"owner", b}, {"admin", b}, {"foreign", a}, {"root", a}, {"empty", a}} {
			s, h, d := f.request(t, "GET", "/api/task/self?org_id="+tc.org, tc.actor, "", nil)
			organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
		}
		ids, data := list(t, "owner", "?org_id="+a+"&task_id=s2-b-member", nil)
		assert.Empty(t, ids)
		assert.EqualValues(t, 0, data["total"])
		ids, _ = list(t, "member", "?org_id="+a+"&task_id=s2-a-owner", nil)
		assert.Empty(t, ids)
	})
	t.Run("strict_bounded_query", func(t *testing.T) {
		ids, data := list(t, "owner", "?org_id="+a+"&p=2&page_size=2", nil)
		assert.Equal(t, []string{"s2-a-owner"}, ids)
		assert.EqualValues(t, 3, data["total"])
		assert.EqualValues(t, 2, data["page"])
		assert.EqualValues(t, 2, data["page_size"])
		ids, _ = list(t, "owner", "?org_id="+a+"&page_size=100&start_timestamp=&end_timestamp=&status=SUCCESS&platform=document", nil)
		assert.Len(t, ids, 3)
		ids, _ = list(t, "owner", fmt.Sprintf("?org_id=%s&start_timestamp=%d&end_timestamp=%d", a, now+3, now+4), nil)
		assert.Equal(t, []string{"s2-a-revoked", "s2-a-member"}, ids)
		for _, query := range []string{"page_size=0", "page_size=101", "page_size=-1", "page_size=01", "p=0", "p=101", "p=x", "p=1&p=2", "size=10", "ps=10", "user_id=1", "start_timestamp=-1", "task_id=a&task_id=b"} {
			s, h, d := f.request(t, "GET", "/api/task/self?org_id="+a+"&"+query, "owner", "", nil)
			organizationError(t, s, h, d, 400, "ORG_REQUEST_INVALID")
		}
		for _, extra := range []struct {
			body    string
			headers http.Header
		}{{"", http.Header{"X-Security-Proof": {"s2-proof"}}}, {"{}", nil}} {
			s, h, d := f.request(t, "GET", "/api/task/self?org_id="+a, "owner", extra.body, extra.headers)
			organizationError(t, s, h, d, 400, "ORG_REQUEST_INVALID")
		}
	})
	t.Run("credentials", func(t *testing.T) {
		suffix, err := common.GenerateRandomCharsKey(43)
		require.NoError(t, err)
		pat := model.AccessTokenPrefix + suffix
		row := &model.UserAccessToken{Name: "s2-task-scope", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
		require.NoError(t, row.SetScopes([]string{"usage:read"}))
		require.NoError(t, model.CreateUserAccessToken(f.users["owner"].Id, row, service.AccessTokenMaxPerUser))
		s, h, d := f.request(t, "GET", "/api/task/self?org_id="+a, pat, "", nil)
		organizationError(t, s, h, d, 403, "AUTH_SESSION_REQUIRED")
		ids, _ := list(t, pat, "", nil)
		assert.Equal(t, []string{"s2-p-owner"}, ids)
		s, h, d = f.request(t, "GET", "/api/task/self?org_id="+a, "relay", "", nil)
		organizationError(t, s, h, d, 401, "AUTH_UNAUTHORIZED")
	})
	t.Run("artifacts_and_capabilities_exclude_organization_rows", func(t *testing.T) {
		for _, actor := range []string{"owner", "root"} {
			s, _, d := f.request(t, "GET", "/api/task/s2-a-owner/artifacts", actor, "", nil)
			assert.Equal(t, 404, s, actor)
			assert.Equal(t, "artifact_not_found", d["code"], actor)
		}
		s, _, _ := f.request(t, "GET", "/api/task/s2-p-owner/artifacts", "owner", "", nil)
		assert.Equal(t, 200, s)
		s, h, d := f.request(t, "GET", "/api/task/s2-a-owner/artifacts?org_id="+a, "owner", "", nil)
		organizationError(t, s, h, d, 403, "ORG_RESOURCE_UNSUPPORTED")
		for taskID, want := range map[string]int{"s2-a-owner": 404, "s2-p-owner": 200} {
			capability, err := service.IssueTaskArtifactAccess(taskID, "video")
			require.NoError(t, err)
			resp, err := f.client.Get(f.server.URL + "/v1/tasks/" + taskID + "/artifacts/video/content?access=" + url.QueryEscape(capability))
			require.NoError(t, err)
			raw, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, want, resp.StatusCode, taskID)
			if want == 200 {
				assert.Equal(t, "abc", string(raw))
			}
		}
	})
	t.Run("revocation_is_observed_by_the_next_read", func(t *testing.T) {
		// Warm the caches so cached session and user state cannot mask revocation.
		for _, actor := range []string{"member", "revoked", "admin"} {
			_, err := model.GetUserCache(f.users[actor].Id)
			require.NoError(t, err)
			_, err = model.GetUserSessionCached(f.sids[actor])
			require.NoError(t, err)
		}
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, f.users["member"].Id).Update("removed_at", time.Now().Unix()).Error)
		s, h, d := f.request(t, "GET", "/api/task/self?org_id="+a, "member", "", nil)
		organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
		ids, _ := list(t, "member", "", nil)
		assert.Equal(t, []string{"s2-p-member"}, ids)
		ids, _ = list(t, "member", "?org_id="+b, nil)
		assert.Equal(t, []string{"s2-b-member"}, ids)
		ids, _ = list(t, "owner", "?org_id="+a, nil)
		assert.Contains(t, ids, "s2-a-member", "a departed member's submissions stay with the organization")

		require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["revoked"]).Update("status", model.UserSessionStatusRevoked).Error)
		for _, org := range []string{a, "999999"} {
			// A revoked session is refused before any organization lookup.
			s, h, d = f.request(t, "GET", "/api/task/self?org_id="+org, "revoked", "", nil)
			organizationError(t, s, h, d, 401, "AUTH_SESSION_REVOKED")
		}

		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["admin"].Id).Update("status", common.UserStatusDisabled).Error)
		s, h, d = f.request(t, "GET", "/api/task/self?org_id="+a, "admin", "", nil)
		organizationError(t, s, h, d, 401, "AUTH_SESSION_REVOKED")

		require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.orgA).Update("platform_disabled_at", time.Now().Unix()).Error)
		s, h, d = f.request(t, "GET", "/api/task/self?org_id="+a, "owner", "", nil)
		organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
		ids, _ = list(t, "owner", "", nil)
		assert.Equal(t, []string{"s2-p-owner"}, ids)
	})
}

func TestOrganizationPersonalLogExport(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	now := time.Now().Unix()
	for _, actor := range []string{"owner", "foreign"} {
		entry := model.Log{UserId: f.users[actor].Id, Username: f.users[actor].Username, CreatedAt: now, Type: model.LogTypeSystem, RequestId: "s2-log-" + actor, Content: "s2-system-" + actor}
		require.NoError(t, model.LOG_DB.Create(&entry).Error)
	}
	for _, scope := range []string{"", "&org_id=0"} {
		q := fmt.Sprintf("?type=4&start_timestamp=%d&end_timestamp=%d", now-60, now+60) + scope
		s, _, d := f.request(t, "GET", "/api/log/self"+q, "owner", "", nil)
		require.Equal(t, 200, s)
		raw, err := common.Marshal(d)
		require.NoError(t, err)
		assert.Contains(t, string(raw), "s2-system-owner")
		assert.NotContains(t, string(raw), "s2-system-foreign")
		req, err := http.NewRequest("GET", f.server.URL+"/api/log/self/export"+q, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+f.bearer["owner"])
		resp, err := f.client.Do(req)
		require.NoError(t, err)
		raw, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, 200, resp.StatusCode)
		assert.Contains(t, string(raw), "s2-system-owner")
		assert.NotContains(t, string(raw), "s2-system-foreign")
	}
}

func TestOrganizationDatabaseLockWait(t *testing.T) {
	kind := os.Getenv("NEWAPI_S2_MAIN")
	if kind != "mysql" && kind != "postgres" {
		return
	} // SQLite has the barrier/snapshot test, not row locks.
	for _, tc := range []struct {
		name, actor, path string
		want              int
	}{
		{"session_expiry", "owner", "/api/organizations/%d", 401},
		{"member_removal_task_view", "member", "/api/task/self?org_id=%d", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			path := fmt.Sprintf(tc.path, f.orgA)
			actorID := f.users[tc.actor].Id
			s, _, _ := f.request(t, "GET", path, tc.actor, "", nil)
			require.Equal(t, 200, s)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			holder := f.db.WithContext(ctx).Begin()
			require.NoError(t, holder.Error)
			defer holder.Rollback()
			var holderID int64
			idSQL := "SELECT CONNECTION_ID()"
			if kind == "postgres" {
				idSQL = "SELECT pg_backend_pid()"
			}
			require.NoError(t, holder.Raw(idSQL).Scan(&holderID).Error)
			require.NoError(t, holder.Model(&model.User{}).Where("id = ?", actorID).UpdateColumn("auth_version", gorm.Expr("auth_version")).Error)
			done := make(chan int, 1)
			go func() {
				req, err := http.NewRequestWithContext(ctx, "GET", f.server.URL+path, nil)
				if err != nil {
					done <- 0
					return
				}
				req.Header.Set("Authorization", "Bearer "+f.bearer[tc.actor])
				resp, err := f.client.Do(req)
				if err != nil {
					done <- 0
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				done <- resp.StatusCode
			}()
			waitSQL := `SELECT EXISTS (SELECT 1 FROM performance_schema.data_lock_waits w JOIN performance_schema.threads blocker ON blocker.THREAD_ID=w.BLOCKING_THREAD_ID JOIN performance_schema.data_locks requested ON requested.ENGINE=w.ENGINE AND requested.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE blocker.PROCESSLIST_ID=? AND requested.OBJECT_SCHEMA=DATABASE() AND requested.OBJECT_NAME='users' AND requested.INDEX_NAME='PRIMARY' AND requested.LOCK_TYPE='RECORD' AND requested.LOCK_STATUS='WAITING' AND requested.LOCK_DATA=?)`
			args := []any{holderID, fmt.Sprint(actorID)}
			if kind == "postgres" {
				waitSQL = `SELECT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.wait_event_type='Lock' AND ? = ANY(pg_blocking_pids(a.pid)) AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.relation='users'::regclass AND l.mode='RowShareLock' AND l.granted))`
				args = []any{holderID}
			}
			observed := false
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for !observed {
				require.NoError(t, f.db.WithContext(ctx).Raw(waitSQL, args...).Scan(&observed).Error)
				if observed {
					break
				}
				select {
				case <-ticker.C:
				case status := <-done:
					t.Fatalf("request completed before actual lock wait: %d", status)
				case <-ctx.Done():
					t.Fatal("actual row lock wait not observed")
				}
			}
			t.Logf("server lock metadata confirmed engine=%s holder=%d table=users", kind, holderID)
			if tc.want == 401 {
				require.NoError(t, holder.Model(&model.UserSession{}).Where("sid = ?", f.sids[tc.actor]).Update("expires_at", int64(1)).Error)
			} else {
				require.NoError(t, holder.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, actorID).Update("removed_at", time.Now().Unix()).Error)
			}
			require.NoError(t, holder.Commit().Error)
			select {
			case status := <-done:
				assert.Equal(t, tc.want, status)
			case <-ctx.Done():
				t.Fatal("waiter failed to finish after committed revocation")
			}
		})
	}
	// The organization task read runs inside the transaction that holds the
	// membership locks, so a removal cannot commit between the check and the read.
	t.Run("task_read_holds_membership_lock", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		path := fmt.Sprintf("/api/task/self?org_id=%d", f.orgA)
		memberID := f.users["member"].Id
		require.NoError(t, f.db.Create(&model.Task{TaskID: "s2-lock-member", UserId: memberID, OrganizationID: f.orgA, Platform: "document", Status: model.TaskStatusSuccess}).Error)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		reached, release := make(chan struct{}), make(chan struct{})
		releaseRead := sync.OnceFunc(func() { close(release) })
		defer releaseRead()
		var paused atomic.Bool
		require.NoError(t, f.db.Callback().Query().After("gorm:query").Register("s2:task_read_lock", func(tx *gorm.DB) {
			// Pause on the item read itself, not the preceding count.
			if _, items := tx.Statement.Dest.(*[]*model.Task); items && tx.Statement.Table == "tasks" && paused.CompareAndSwap(false, true) {
				close(reached)
				select {
				case <-release:
				case <-time.After(10 * time.Second):
					tx.AddError(fmt.Errorf("task read barrier deadline"))
				}
			}
		}))
		defer f.db.Callback().Query().Remove("s2:task_read_lock")
		done := make(chan int, 1)
		go func() {
			req, err := http.NewRequestWithContext(ctx, "GET", f.server.URL+path, nil)
			if err != nil {
				done <- 0
				return
			}
			req.Header.Set("Authorization", "Bearer "+f.bearer["member"])
			resp, err := f.client.Do(req)
			if err != nil {
				done <- 0
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			done <- resp.StatusCode
		}()
		select {
		case <-reached:
		case status := <-done:
			t.Fatalf("request completed without reaching the task read: %d", status)
		case <-ctx.Done():
			t.Fatal("task read barrier not reached")
		}
		revoker := f.db.WithContext(ctx).Begin()
		require.NoError(t, revoker.Error)
		defer revoker.Rollback()
		var revokerID int64
		idSQL, waitSQL := "SELECT CONNECTION_ID()", "SELECT EXISTS (SELECT 1 FROM information_schema.innodb_trx WHERE trx_mysql_thread_id = ? AND trx_state = 'LOCK WAIT')"
		if kind == "postgres" {
			idSQL, waitSQL = "SELECT pg_backend_pid()", "SELECT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.pid = ? AND cardinality(pg_blocking_pids(a.pid)) > 0)"
		}
		require.NoError(t, revoker.Raw(idSQL).Scan(&revokerID).Error)
		removed := make(chan error, 1)
		go func() {
			removed <- revoker.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, memberID).Update("removed_at", time.Now().Unix()).Error
		}()
		observed := false
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !observed {
			require.NoError(t, f.db.WithContext(ctx).Raw(waitSQL, revokerID).Scan(&observed).Error)
			if observed {
				break
			}
			select {
			case <-ticker.C:
			case err := <-removed:
				t.Fatalf("member removal committed during the organization task read: %v", err)
			case <-ctx.Done():
				t.Fatal("member removal never waited on the task read")
			}
		}
		t.Logf("server lock wait confirmed engine=%s waiter=%d (member removal blocked by the open task read)", kind, revokerID)
		releaseRead()
		select {
		case status := <-done:
			assert.Equal(t, 200, status)
		case <-ctx.Done():
			t.Fatal("task read did not finish after release")
		}
		select {
		case err := <-removed:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal("member removal did not finish after the read")
		}
		require.NoError(t, revoker.Commit().Error)
		s, h, d := f.request(t, "GET", path, "member", "", nil)
		organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
	})
}

// F01: the role read must not establish the discovery JOIN's snapshot.
func TestOrganizationDiscoveryJoinLinearization(t *testing.T) {
	if os.Getenv("NEWAPI_S2_MAIN") != "mysql" {
		t.Skip("requires dedicated MySQL REPEATABLE READ")
	}
	f := newOrganizationHTTPFixture(t)
	var isolation string
	require.NoError(t, f.db.Raw("SELECT @@transaction_isolation").Scan(&isolation).Error)
	require.Equal(t, "REPEATABLE-READ", isolation)
	reached, release := make(chan struct{}), make(chan struct{})
	releaseDiscovery := sync.OnceFunc(func() { close(release) })
	defer releaseDiscovery()
	var paused atomic.Bool
	require.NoError(t, f.db.Callback().Query().After("gorm:query").Register("s2:discovery_role_barrier", func(tx *gorm.DB) {
		if tx.Statement.Table == "users" && len(tx.Statement.Selects) == 1 && tx.Statement.Selects[0] == "role" && paused.CompareAndSwap(false, true) {
			close(reached)
			select {
			case <-release:
			case <-time.After(10 * time.Second):
				tx.AddError(fmt.Errorf("discovery barrier deadline"))
			}
		}
	}))
	defer f.db.Callback().Query().Remove("s2:discovery_role_barrier")
	type response struct {
		status int
		body   []byte
		err    error
	}
	result := make(chan response, 1)
	done := make(chan struct{})
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	defer func() {
		releaseDiscovery()
		cancelRequest()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("discovery request did not stop during cleanup")
		}
	}()
	go func() {
		defer close(done)
		req, err := http.NewRequestWithContext(requestCtx, "GET", f.server.URL+"/api/organizations", nil)
		if err != nil {
			result <- response{err: err}
			return
		}
		req.Header.Set("Authorization", "Bearer "+f.bearer["member"])
		resp, err := f.client.Do(req)
		if err != nil {
			result <- response{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		result <- response{resp.StatusCode, body, err}
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("role read barrier absent")
	}
	// Fixture-only state change isolates discovery snapshot interleaving. It does
	// not exercise sensitive lifecycle authorization or lock member/session rows.
	mutationCtx, cancelMutation := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelMutation()
	tx := f.db.WithContext(mutationCtx).Begin()
	require.NoError(t, tx.Error)
	defer tx.Rollback()
	updated := tx.Model(&model.Organization{}).
		Where("id = ? AND revision = ? AND self_disabled_at = ? AND platform_disabled_at = ? AND dissolved_at = ?", f.orgA, int64(9007199254740993), 0, 0, 0).
		Update("self_disabled_at", time.Now().Unix())
	require.NoError(t, updated.Error)
	require.Equal(t, int64(1), updated.RowsAffected)
	require.NoError(t, tx.Commit().Error)
	releaseDiscovery()
	select {
	case got := <-result:
		require.NoError(t, got.err)
		require.Equal(t, 200, got.status)
		var body struct {
			Success bool `json:"success"`
			Data    struct {
				Items []struct {
					ID string `json:"org_id"`
				} `json:"items"`
			} `json:"data"`
		}
		require.NoError(t, common.Unmarshal(got.body, &body))
		require.True(t, body.Success)
		require.NotEmpty(t, body.Data.Items, "other active organization remains visible")
		ids := make([]string, 0, len(body.Data.Items))
		for _, item := range body.Data.Items {
			require.NotEmpty(t, item.ID)
			assert.NotEqual(t, strconv.FormatInt(f.orgA, 10), item.ID)
			ids = append(ids, item.ID)
		}
		assert.Contains(t, ids, strconv.FormatInt(f.orgB, 10))
	case <-time.After(10 * time.Second):
		t.Fatal("discovery failed to complete")
	}
}

func TestOrganizationAuthorityTransitions(t *testing.T) {
	t.Run("signed_expired_and_recognized_invalid", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(f.bearer["owner"], claims)
		require.NoError(t, err)
		claims["exp"] = time.Now().Unix() - 60
		mac := hmac.New(sha256.New, []byte(common.SessionSecret))
		_, err = mac.Write([]byte("new-api/auth/access/v1"))
		require.NoError(t, err)
		expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(mac.Sum(nil))
		require.NoError(t, err)
		_, internal, err := service.ParseDashboardAccessToken(expired)
		require.True(t, internal)
		require.ErrorIs(t, err, service.ErrAuthTokenExpired)
		s, h, d := f.request(t, "GET", "/api/organization-context", expired, "", nil)
		organizationError(t, s, h, d, 401, "AUTH_TOKEN_EXPIRED")
		invalid, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("wrong-test-key"))
		require.NoError(t, err)
		_, internal, err = service.ParseDashboardAccessToken(invalid)
		require.True(t, internal)
		require.Error(t, err)
		s, h, d = f.request(t, "GET", "/api/organization-context", invalid, "", nil)
		organizationError(t, s, h, d, 401, "AUTH_UNAUTHORIZED")
	})
	for _, mutation := range []string{"deleted_user", "user_version", "session_version"} {
		t.Run(mutation, func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			_, err := model.GetUserCache(f.users["empty"].Id)
			require.NoError(t, err)
			_, err = model.GetUserSessionCached(f.sids["empty"])
			require.NoError(t, err)
			switch mutation {
			case "deleted_user":
				require.NoError(t, f.db.Delete(f.users["empty"]).Error)
			case "user_version":
				require.NoError(t, f.db.Model(f.users["empty"]).Update("auth_version", 2).Error)
			case "session_version":
				require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["empty"]).Update("version", 2).Error)
			}
			for _, path := range []string{"/api/organization-context?org_id=0", "/api/organizations", "/api/organizations/9223372036854775807"} {
				s, h, d := f.request(t, "GET", path, "empty", "", nil)
				require.Equal(t, 401, s)
				assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
				assert.NotContains(t, slices.Collect(maps.Keys(d)), "data")
			}
		})
	}
	t.Run("remove_rejoin_lower_role", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		path := "/api/organizations/" + strconv.FormatInt(f.orgA, 10)
		s, _, _ := f.request(t, "GET", path+"/events", "admin", "", nil)
		require.Equal(t, 200, s)
		member := f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, f.users["admin"].Id)
		require.NoError(t, member.Updates(map[string]any{"removed_at": time.Now().Unix(), "revision": 9007199254740994}).Error)
		s, h, d := f.request(t, "GET", path+"/events", "admin", "", nil)
		organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
		require.NoError(t, member.Updates(map[string]any{"removed_at": 0, "role": "member", "revision": 9007199254740995}).Error)
		s, h, d = f.request(t, "GET", path+"/events", "admin", "", nil)
		organizationError(t, s, h, d, 403, "ORG_FORBIDDEN")
		s, _, d = f.request(t, "GET", path, "admin", "", nil)
		require.Equal(t, 200, s)
		view := d["data"].(map[string]any)
		assert.Equal(t, "member", view["my_role"])
		assert.Equal(t, "9007199254740995", view["my_member_revision"])
	})
	for _, column := range []string{"self_disabled_at", "platform_disabled_at", "dissolved_at"} {
		t.Run(column, func(t *testing.T) {
			f := newOrganizationHTTPFixture(t)
			a := strconv.FormatInt(f.orgA, 10)
			require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.orgA).Update(column, time.Now().Unix()).Error)
			for _, path := range []string{"/api/organizations/" + a, "/api/organizations/" + a + "/events"} {
				s, h, d := f.request(t, "GET", path, "owner", "", nil)
				organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
			}
			s, _, d := f.request(t, "GET", "/api/organizations", "owner", "", nil)
			require.Equal(t, 200, s)
			assert.Empty(t, d["data"].(map[string]any)["items"])
		})
	}
	t.Run("invitation_and_platform_role_do_not_grant_membership", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		require.NoError(t, f.db.Create(&model.OrganizationInvitation{OrganizationID: f.orgA, TargetUserID: f.users["empty"].Id, InviterUserID: f.users["owner"].Id, Role: "admin", Generation: 1, Status: model.OrganizationPending, ExpiresAt: time.Now().Unix() + 3600}).Error)
		require.NoError(t, f.db.Model(f.users["empty"]).Update("role", common.RoleAdminUser).Error)
		for _, actor := range []string{"empty", "root"} {
			s, h, d := f.request(t, "GET", "/api/organizations/"+strconv.FormatInt(f.orgA, 10), actor, "", nil)
			organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
		}
	})
}

func TestOrganizationSelectorCanonicalForms(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	a := strconv.FormatInt(f.orgA, 10)
	for _, value := range []string{" ", "+1", "1.0", "１", "1,2", "01", "-1", "9223372036854775808"} {
		t.Run("invalid_"+url.QueryEscape(value), func(t *testing.T) {
			s, h, d := f.request(t, "GET", "/api/organization-context?org_id="+url.QueryEscape(value), "owner", "", nil)
			organizationError(t, s, h, d, 400, "ORG_SELECTOR_INVALID")
		})
	}
	for _, selected := range []string{"0", a} {
		t.Run("header_"+selected, func(t *testing.T) {
			s, _, d := f.request(t, "GET", "/api/organization-context", "owner", "", http.Header{"x-organization-id": {selected}})
			require.Equal(t, 200, s)
			assert.Equal(t, selected, d["data"].(map[string]any)["org_id"])
		})
	}
	s, _, _ := f.request(t, "GET", "/api/organizations/"+a, "owner", "", http.Header{"X-Organization-Id": {a}})
	require.Equal(t, 200, s)
	s, _, d := f.request(t, "GET", "/api/organization-context?%6frg_id=%30", "owner", "", nil)
	require.Equal(t, 200, s)
	assert.Equal(t, "0", d["data"].(map[string]any)["org_id"])
	for _, tc := range []struct {
		query, code string
		messages    map[string]string
	}{
		{"org_id=bad", "organization_selector_invalid", map[string]string{"en": "Invalid organization selector.", "zh-CN": "组织选择参数无效。", "zh-TW": "組織選擇參數無效。"}},
		{"org_id=1", "organization_selector_conflict", map[string]string{"en": "Organization selectors conflict.", "zh-CN": "组织选择参数冲突。", "zh-TW": "組織選擇參數衝突。"}},
	} {
		for lang, message := range tc.messages {
			headers := http.Header{"Accept-Language": {lang}}
			if tc.code == "organization_selector_conflict" {
				headers.Set("X-Organization-Id", "1")
			}
			s, _, d := f.request(t, "GET", "/v1/models?"+tc.query, "", "", headers)
			require.Equal(t, 400, s)
			errBody := d["error"].(map[string]any)
			assert.Equal(t, tc.code, errBody["code"])
			assert.Equal(t, message, errBody["message"])
		}
	}
}

func TestOrganizationCredentialScopeIntersection(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	for _, actor := range []string{"owner", "root"} {
		for _, scopes := range [][]string{{"*"}, {"profile:read"}, {"api_key:read", "usage:read"}} {
			suffix, err := common.GenerateRandomCharsKey(43)
			require.NoError(t, err)
			pat := model.AccessTokenPrefix + suffix
			row := &model.UserAccessToken{Name: "scope-boundary", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
			require.NoError(t, row.SetScopes(scopes))
			require.NoError(t, model.CreateUserAccessToken(f.users[actor].Id, row, service.AccessTokenMaxPerUser))
			for _, path := range []string{"/api/organizations", "/api/organization-context", "/api/organizations/" + strconv.FormatInt(f.orgA, 10), "/api/organizations/" + strconv.FormatInt(f.orgA, 10) + "/members", "/api/organizations/" + strconv.FormatInt(f.orgA, 10) + "/events"} {
				s, h, d := f.request(t, "GET", path, pat, "", nil)
				organizationError(t, s, h, d, 403, "AUTH_SESSION_REQUIRED")
			}
			if actor == "root" && len(scopes) == 1 && scopes[0] == "profile:read" {
				s, _, _ := f.request(t, "GET", "/api/token/", pat, "", nil)
				assert.Equal(t, 403, s)
			}
			for _, credential := range []string{pat, actor, "relay"} {
				for _, path := range []string{"/api/token/", "/api/log/self", "/v1/models", "/s2alias/jobs/missing", "/v1/videos/missing/content"} {
					s, _, _ := f.request(t, "GET", path+"?org_id=1", credential, "", nil)
					assert.Equal(t, 403, s)
				}
			}
			// The organization task view is session-only: a PAT that passes the
			// route scope is still refused, a session reaches membership (unknown
			// organization), and a relay key is not a dashboard credential.
			patCode := "ACCESS_TOKEN_SCOPE_DENIED"
			if slices.Contains(scopes, "usage:read") {
				patCode = "AUTH_SESSION_REQUIRED"
			}
			s, h, d := f.request(t, "GET", "/api/task/self?org_id=1", pat, "", nil)
			organizationError(t, s, h, d, 403, patCode)
			s, h, d = f.request(t, "GET", "/api/task/self?org_id=1", actor, "", nil)
			organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
			s, h, d = f.request(t, "GET", "/api/task/self?org_id=1", "relay", "", nil)
			organizationError(t, s, h, d, 401, "AUTH_UNAUTHORIZED")
		}
	}
}

func TestOrganizationRedirectSelection(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	client := *f.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, method := range []string{"GET", "POST"} {
		for _, header := range []bool{false, true} {
			path := "/api/token"
			if !header {
				path += "?org_id=1"
			}
			req, err := http.NewRequest(method, f.server.URL+path, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+f.bearer["owner"])
			if header {
				req.Header.Set("X-Organization-Id", "1")
			}
			resp, err := client.Do(req)
			require.NoError(t, err)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if method == "GET" {
				require.Equal(t, 301, resp.StatusCode)
			} else {
				require.Equal(t, 307, resp.StatusCode)
			}
			location := resp.Header.Get("Location")
			require.NotEmpty(t, location)
			if !header {
				assert.Contains(t, location, "org_id=1")
			}
			follow, err := http.NewRequest(method, f.server.URL+location, nil)
			require.NoError(t, err)
			follow.Header = req.Header.Clone()
			resp, err = client.Do(follow)
			require.NoError(t, err)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			assert.Equal(t, 403, resp.StatusCode)
			assert.Equal(t, "private, no-store", resp.Header.Get("Cache-Control"))
		}
	}
}

// This boundary is after the production handler has produced its bounded body,
// hence after domain authorization, data reads, and transaction completion. It
// delays delivery only; it does not replace a production handler or grant access.
type organizationDeliveryBarrier struct {
	http.ResponseWriter
	ctx     context.Context
	ready   chan<- []byte
	release <-chan struct{}
	once    sync.Once
}

func (w *organizationDeliveryBarrier) Write(body []byte) (int, error) {
	w.once.Do(func() {
		w.ready <- bytes.Clone(body)
		select {
		case <-w.release:
		case <-w.ctx.Done():
		}
	})
	return w.ResponseWriter.Write(body)
}

type organizationAsyncResponse struct {
	status int
	body   []byte
	err    error
}

func organizationGetAsync(ctx context.Context, client *http.Client, endpoint, credential string) <-chan organizationAsyncResponse {
	result := make(chan organizationAsyncResponse, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			result <- organizationAsyncResponse{err: err}
			return
		}
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := client.Do(req)
		if err != nil {
			result <- organizationAsyncResponse{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		result <- organizationAsyncResponse{resp.StatusCode, body, err}
	}()
	return result
}

func TestOrganizationRemainingContracts(t *testing.T) {
	t.Run("post_grant_delivery_after_revocation", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ready, release := make(chan []byte, 1), make(chan struct{})
		var unblock sync.Once
		defer unblock.Do(func() { close(release) })
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.engine.ServeHTTP(&organizationDeliveryBarrier{ResponseWriter: w, ctx: ctx, ready: ready, release: release}, r)
		}))
		defer server.Close()
		first := organizationGetAsync(ctx, server.Client(), server.URL+"/api/organizations/"+strconv.FormatInt(f.orgA, 10), f.bearer["member"])
		var granted map[string]any
		select {
		case body := <-ready:
			require.NoError(t, common.Unmarshal(body, &granted))
		case <-ctx.Done():
			t.Fatal("bounded successful read never reached delivery boundary")
		}
		require.Equal(t, true, granted["success"])
		require.Equal(t, strconv.FormatInt(f.orgA, 10), granted["data"].(map[string]any)["org_id"])
		// The read transaction is already complete: this committed removal must not
		// block behind it and must affect a new request even while delivery is held.
		require.NoError(t, f.db.WithContext(ctx).Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, f.users["member"].Id).Updates(map[string]any{"removed_at": time.Now().Unix(), "revision": 9007199254740994}).Error)
		s, h, d := f.request(t, "GET", "/api/organizations/"+strconv.FormatInt(f.orgA, 10), "member", "", nil)
		organizationError(t, s, h, d, 404, "ORG_NOT_FOUND")
		unblock.Do(func() { close(release) })
		select {
		case got := <-first:
			require.NoError(t, got.err)
			require.Equal(t, 200, got.status)
			var delivered map[string]any
			require.NoError(t, common.Unmarshal(got.body, &delivered))
			assert.Equal(t, granted, delivered)
		case <-ctx.Done():
			t.Fatal("bounded granted read failed to finish")
		}
	})
	t.Run("controlled_tab_response_reorder", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		a, b := strconv.FormatInt(f.orgA, 10), strconv.FormatInt(f.orgB, 10)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ready, release := make(chan []byte, 1), make(chan struct{})
		var unblock sync.Once
		defer unblock.Do(func() { close(release) })
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("org_id") == a {
				f.engine.ServeHTTP(&organizationDeliveryBarrier{ResponseWriter: w, ctx: ctx, ready: ready, release: release}, r)
			} else {
				f.engine.ServeHTTP(w, r)
			}
		}))
		defer server.Close()
		first := organizationGetAsync(ctx, server.Client(), server.URL+"/api/organization-context?org_id="+a, f.bearer["member"])
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("A response not held")
		}
		for _, id := range []string{b, "0"} {
			later := organizationGetAsync(ctx, server.Client(), server.URL+"/api/organization-context?org_id="+id, f.bearer["member"])
			select {
			case got := <-later:
				require.NoError(t, got.err)
				require.Equal(t, 200, got.status)
				var body map[string]any
				require.NoError(t, common.Unmarshal(got.body, &body))
				assert.Equal(t, id, body["data"].(map[string]any)["org_id"])
			case <-ctx.Done():
				t.Fatal("later tab failed to finish before A")
			}
		}
		select {
		case <-first:
			t.Fatal("A completed before explicit release")
		default:
		}
		unblock.Do(func() { close(release) })
		select {
		case got := <-first:
			require.NoError(t, got.err)
			require.Equal(t, 200, got.status)
			var body map[string]any
			require.NoError(t, common.Unmarshal(got.body, &body))
			assert.Equal(t, a, body["data"].(map[string]any)["org_id"])
		case <-ctx.Done():
			t.Fatal("A response failed to finish")
		}
		s, _, d := f.request(t, "GET", "/api/organization-context?org_id="+b, "member", "", nil)
		require.Equal(t, 200, s)
		assert.Equal(t, b, d["data"].(map[string]any)["org_id"])
	})
	t.Run("limit100_exact_second_page_cursor", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		organizations := make([]model.Organization, 101)
		members := make([]model.OrganizationMember, 101)
		for i := range 101 {
			id := int64(10000 + i)
			organizations[i] = model.Organization{ID: id, Name: fmt.Sprintf("page-%d", i), OwnerUserID: f.users["owner"].Id, CreatedByUserID: f.users["owner"].Id, Revision: 1, OwnershipVersion: 1}
			members[i] = model.OrganizationMember{OrganizationID: id, UserID: f.users["empty"].Id, Role: "member", Revision: 1, JoinedAt: 1}
		}
		require.NoError(t, f.db.Create(&organizations).Error)
		require.NoError(t, f.db.Create(&members).Error)
		s, _, d := f.request(t, "GET", "/api/organizations?limit=100", "empty", "", nil)
		require.Equal(t, 200, s)
		page := d["data"].(map[string]any)
		items := page["items"].([]any)
		require.Len(t, items, 100)
		assert.Equal(t, float64(100), page["limit"])
		require.Equal(t, "10099", page["next_after_id"])
		for i, item := range items {
			assert.Equal(t, strconv.Itoa(10000+i), item.(map[string]any)["org_id"])
		}
		s, _, d = f.request(t, "GET", "/api/organizations?limit=100&after_id="+page["next_after_id"].(string), "empty", "", nil)
		require.Equal(t, 200, s)
		page = d["data"].(map[string]any)
		items = page["items"].([]any)
		require.Len(t, items, 1)
		assert.Equal(t, "10100", items[0].(map[string]any)["org_id"])
		assert.Nil(t, page["next_after_id"])
		s, _, d = f.request(t, "GET", "/api/organizations?limit=100&after_id=10100", "empty", "", nil)
		require.Equal(t, 200, s)
		page = d["data"].(map[string]any)
		require.Equal(t, []any{}, page["items"])
		assert.Nil(t, page["next_after_id"])
	})
	t.Run("legacy_malformed_query_and_body_bytes", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		for _, selection := range []string{"", "&org_id=0"} {
			rawQuery := "unrelated=%ZZ&literal=a+b&opaque=x;y" + selection
			body := []byte("old-client-body\x00\xff\r\n%2F&raw=+;{}")
			request := httptest.NewRequest("GET", "/api/token/?"+rawQuery, bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+f.bearer["owner"])
			recorder := httptest.NewRecorder()
			f.engine.ServeHTTP(recorder, request)
			require.Equal(t, 200, recorder.Code)
			assert.Equal(t, rawQuery, request.URL.RawQuery)
			remaining, err := io.ReadAll(request.Body)
			require.NoError(t, err)
			assert.Equal(t, body, remaining, "legacy handler must receive untouched request body")
		}
	})
	t.Run("artifact_capability_never_authenticates_organization", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		old := common.CryptoSecret
		common.CryptoSecret = common.SessionSecret
		defer func() { common.CryptoSecret = old }()
		task := &model.Task{TaskID: "capability-org-boundary", UserId: f.users["member"].Id, Platform: "document", Action: constant.TaskActionTextToVideo, Status: model.TaskStatusSuccess, FailReason: "data:video/mp4;base64,YWJj"}
		require.NoError(t, f.db.Create(task).Error)
		capability, err := service.IssueTaskArtifactAccess(task.TaskID, "video")
		require.NoError(t, err)
		resp, err := f.client.Get(f.server.URL + "/v1/tasks/" + task.TaskID + "/artifacts/video/content?access=" + url.QueryEscape(capability))
		require.NoError(t, err)
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, 200, resp.StatusCode)
		require.Equal(t, "abc", string(raw))
		for _, path := range []string{"/api/organizations", "/api/organization-context", "/api/organizations/" + strconv.FormatInt(f.orgA, 10), "/api/organizations/" + strconv.FormatInt(f.orgA, 10) + "/members", "/api/organizations/" + strconv.FormatInt(f.orgA, 10) + "/events"} {
			s, h, d := f.request(t, "GET", path, capability, "", nil)
			organizationError(t, s, h, d, 401, "AUTH_UNAUTHORIZED")
		}
	})
	t.Run("task_lookup_dispatch_attempt_counter", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		var attempts atomic.Int64
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("s2:task_attempt", func(tx *gorm.DB) {
			if tx.Statement.Table == "tasks" {
				attempts.Add(1)
			}
		}))
		defer f.db.Callback().Query().Remove("s2:task_attempt")
		// Positive control: the production task artifact handler actually reaches its
		// task lookup, so zero under selected requests is not an inert sentinel.
		oldSecret := common.CryptoSecret
		common.CryptoSecret = common.SessionSecret
		defer func() { common.CryptoSecret = oldSecret }()
		capability, err := service.IssueTaskArtifactAccess("task-counter-missing", "video")
		require.NoError(t, err)
		status, _, _ := f.request(t, "GET", "/v1/tasks/task-counter-missing/artifacts/video/content?access="+url.QueryEscape(capability), "", "", nil)
		require.Equal(t, 404, status)
		require.Positive(t, attempts.Load(), "task lookup sentinel was not exercised by production handler")
		before := attempts.Load()
		for _, path := range []string{"/v1/tasks/task-counter-missing/artifacts/video/content", "/v1/videos/task-counter-missing/content", "/s2alias/jobs/task-counter-missing"} {
			for _, actor := range []string{"", "relay", "owner", "root"} {
				s, _, _ := f.request(t, "GET", path+"?org_id=1", actor, "", nil)
				require.Equal(t, 403, s)
			}
		}
		status, _, _ = f.request(t, "GET", "/v1/tasks/task-counter-missing/artifacts/video/content?access="+url.QueryEscape(capability)+"&org_id=1", "", "", nil)
		require.Equal(t, 403, status)
		assert.Equal(t, before, attempts.Load(), "selected task requests must not attempt task retrieval")
	})
}

// The gateway still uses SetRouter, normal token auth, selection and settlement.
// Only the downstream writer fails; the completed upstream outcome is unchanged.
type toolsSearchRejectedWriter struct{ *httptest.ResponseRecorder }

func (w *toolsSearchRejectedWriter) Write([]byte) (int, error) {
	return 0, errors.New("test downstream closed")
}

// Observe the real outbound request before the ordinary loopback transport.
// No request body/header is logged or altered by this test-only boundary.
type toolsSearchRequestBoundary struct {
	next  http.RoundTripper
	t     *testing.T
	calls atomic.Int64
}

func (b *toolsSearchRequestBoundary) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/v1/tools/search" {
		b.calls.Add(1)
		assert.NotNil(b.t, req.Body)
		assert.Greater(b.t, req.ContentLength, int64(0))
		assert.Nil(b.t, req.GetBody, "sent search must not be replayable by net/http")
	}
	return b.next.RoundTrip(req)
}

func TestToolsSearchRelayHTTP(t *testing.T) {
	require.Equal(t, "g19-tools-search", os.Getenv("NEWAPI_S2_OWNED"))
	if service.GetHttpClient() == nil {
		service.InitHttpClient()
	}
	f := newOrganizationHTTPFixture(t)
	common.OptionMapRWMutex.Lock()
	previousOptions := common.OptionMap
	common.OptionMap = map[string]string{}
	common.OptionMapRWMutex.Unlock()
	t.Cleanup(func() {
		common.OptionMapRWMutex.Lock()
		common.OptionMap = previousOptions
		common.OptionMapRWMutex.Unlock()
	})
	outbound := service.GetHttpClient()
	previousTransport := outbound.Transport
	boundary := &toolsSearchRequestBoundary{next: previousTransport, t: t}
	outbound.Transport = boundary
	t.Cleanup(func() { outbound.Transport = previousTransport })
	require.NoError(t, f.db.AutoMigrate(&model.Channel{}, &model.Ability{}))
	oldCount, oldBatch, oldExport, oldLog, oldUnit := constant.CountToken, common.BatchUpdateEnabled, common.DataExportEnabled, common.LogConsumeEnabled, common.QuotaPerUnit
	constant.CountToken, common.BatchUpdateEnabled, common.DataExportEnabled, common.LogConsumeEnabled, common.QuotaPerUnit = false, false, false, true, 500000
	oldQuotaSetting := *operation_setting.GetQuotaSetting()
	*operation_setting.GetQuotaSetting() = operation_setting.QuotaSetting{EnableFreeModelPreConsume: false, TrustQuotaUSD: 0, PreConsumeMultiplier: 1}
	t.Cleanup(func() {
		constant.CountToken, common.BatchUpdateEnabled, common.DataExportEnabled, common.LogConsumeEnabled, common.QuotaPerUnit = oldCount, oldBatch, oldExport, oldLog, oldUnit
		*operation_setting.GetQuotaSetting() = oldQuotaSetting
	})
	oldPolicy := maps.Clone(model.CurrentRequestPolicy().Options)
	require.NoError(t, model.UpdateRequestPolicyOptions(map[string]string{"RetryTimes": "2", "AutomaticRetryStatusCodes": "408,429,500-599", "AutomaticDisableChannelEnabled": "false", "CheckSensitiveOnPromptEnabled": "false"}))
	t.Cleanup(func() { require.NoError(t, model.UpdateRequestPolicyOptions(oldPolicy)) })
	for _, snapshot := range []struct {
		before string
		write  func(string) error
		next   string
	}{
		{setting.UserUsableGroups2JSONString(), setting.UpdateUserUsableGroupsByJSONString, `{"default":"Default","free":"Free","paid":"Paid","auto":"Auto"}`},
		{setting.AutoGroups2JsonString(), setting.UpdateAutoGroupsByJsonString, `["free","paid"]`},
		{ratio_setting.GroupRatio2JSONString(), ratio_setting.UpdateGroupRatioByJSONString, `{"default":1,"free":0,"paid":2}`},
		{ratio_setting.GroupGroupRatio2JSONString(), ratio_setting.UpdateGroupGroupRatioByJSONString, `{}`},
		{ratio_setting.ModelPrice2JSONString(), ratio_setting.UpdateModelPriceByJSONString, `{}`},
		{ratio_setting.ModelRatio2JSONString(), ratio_setting.UpdateModelRatioByJSONString, `{}`},
	} {
		require.NoError(t, snapshot.write(snapshot.next))
		t.Cleanup(func() { require.NoError(t, snapshot.write(snapshot.before)) })
	}
	cfg := config.GlobalConfig.Get("billing_setting").(*billing_setting.BillingSetting)
	oldModes, oldExpressions := cfg.BillingMode, cfg.BillingExpr
	cfg.BillingMode, cfg.BillingExpr = map[string]string{}, map[string]string{}
	t.Cleanup(func() { cfg.BillingMode, cfg.BillingExpr = oldModes, oldExpressions })
	var tokens [2]model.Token
	require.NoError(t, f.db.Where("user_id = ?", f.users["owner"].Id).Take(&tokens[0]).Error)
	tokens[1] = model.Token{UserId: f.users["foreign"].Id, Key: "toolssearchotherownedkey00000000000000001", Status: common.TokenStatusEnabled, ExpiredTime: -1, RemainQuota: 1000000}
	require.NoError(t, f.db.Create(&tokens[1]).Error)
	for _, token := range tokens {
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", token.UserId).Updates(map[string]any{"quota": 1000000, "setting": `{"billing_preference":"wallet_only"}`}).Error)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Update("remain_quota", 1000000).Error)
	}
	const good = `{"results":[{"title":"Owned result","url":"https://example.invalid/result","snippet":"snippet","summary":"summary","content":"body","rerank_score":2.5,"authority":-1,"site_name":null,"site_icon":null,"date":null,"extension":{"kept":true}}],"extension":null}`
	type scenario struct {
		status      int
		body        string
		firstStatus int
		mode        string
		entered     chan struct{}
		release     chan struct{}
		cancelled   chan struct{}
		before      func(int, *http.Request)
		calls       atomic.Int64
		mu          sync.Mutex
		requests    []map[string]any
		paths       []string
		connections []string
		protocols   []int
		idempotency []string
	}
	var scenarios sync.Map
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		var body map[string]any
		if !assert.NoError(t, common.Unmarshal(raw, &body)) {
			return
		}
		query, _ := body["query"].(string)
		if r.URL.Path == "/v1/alpha/search" {
			query = "alpha-control"
		}
		item, ok := scenarios.Load(query)
		if !assert.True(t, ok, "unexpected synthetic upstream query") {
			w.WriteHeader(500)
			return
		}
		sc := item.(*scenario)
		attempt := int(sc.calls.Add(1))
		sc.mu.Lock()
		sc.requests = append(sc.requests, body)
		sc.paths = append(sc.paths, r.URL.Path)
		sc.connections = append(sc.connections, r.RemoteAddr)
		sc.protocols = append(sc.protocols, r.ProtoMajor)
		sc.idempotency = append(sc.idempotency, r.Header.Get("Idempotency-Key")+r.Header.Get("X-Idempotency-Key"))
		sc.mu.Unlock()
		if sc.before != nil {
			sc.before(attempt, r)
		}
		if sc.mode == "transport" {
			conn, _, hijackErr := w.(http.Hijacker).Hijack()
			if assert.NoError(t, hijackErr) {
				conn.Close()
			}
			return
		}
		if sc.mode == "partial" {
			w.Header().Set("Content-Length", "1000")
			io.WriteString(w, `{"results":[`)
			return
		}
		if sc.entered != nil {
			if sc.mode == "body-cancel" {
				io.WriteString(w, `{"results":[`)
				w.(http.Flusher).Flush()
			}
			close(sc.entered)
			select {
			case <-sc.release:
			case <-r.Context().Done():
				if sc.cancelled != nil {
					close(sc.cancelled)
				}
				return
			}
		}
		status := sc.status
		if status == 0 {
			status = 200
		}
		if attempt == 1 && sc.firstStatus != 0 {
			status = sc.firstStatus
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		bodyText := sc.body
		if bodyText == "" {
			bodyText = good
		}
		io.WriteString(w, bodyText)
	}))
	t.Cleanup(provider.Close)
	var channels []*model.Channel
	for _, entry := range []struct {
		group, models string
		kind          int
	}{{"default", "deepseek-search", constant.ChannelTypeDeepSeek}, {"free", "deepseek-search", constant.ChannelTypeDeepSeek}, {"paid", "deepseek-search", constant.ChannelTypeDeepSeek}, {"default", "alpha-control", constant.ChannelTypeNewAPI}} {
		base := provider.URL
		priority := int64(0)
		weight := uint(100)
		autoBan := 0
		ch := &model.Channel{Type: entry.kind, Name: "owned-tools-" + entry.group, Key: "owned-upstream-placeholder", Status: common.ChannelStatusEnabled, BaseURL: &base, Models: entry.models, Group: entry.group, Priority: &priority, Weight: &weight, AutoBan: &autoBan}
		require.NoError(t, ch.Insert())
		channels = append(channels, ch)
	}
	type accounting struct {
		quota, used, requests, remaining, tokenUsed int
		channelQuota, logQuota, logs                int64
	}
	snapshot := func(t *testing.T, index int) accounting {
		t.Helper()
		var user model.User
		var token model.Token
		require.NoError(t, f.db.First(&user, tokens[index].UserId).Error)
		require.NoError(t, f.db.First(&token, tokens[index].Id).Error)
		var all []model.Channel
		require.NoError(t, f.db.Find(&all).Error)
		state := accounting{quota: user.Quota, used: user.UsedQuota, requests: user.RequestCount, remaining: token.RemainQuota, tokenUsed: token.UsedQuota}
		for _, channel := range all {
			state.channelQuota += channel.UsedQuota
		}
		var logs []model.Log
		require.NoError(t, model.LOG_DB.Where("user_id = ? AND type = ?", user.Id, model.LogTypeConsume).Find(&logs).Error)
		state.logs = int64(len(logs))
		for _, log := range logs {
			state.logQuota += int64(log.Quota)
		}
		return state
	}
	expectAccounting := func(t *testing.T, index int, before accounting, cost, successful int, globalCost int) {
		t.Helper()
		require.Eventually(t, func() bool {
			var user model.User
			var token model.Token
			return f.db.First(&user, tokens[index].UserId).Error == nil && f.db.First(&token, tokens[index].Id).Error == nil && user.Quota == before.quota-cost && token.RemainQuota == before.remaining-cost
		}, 5*time.Second, 10*time.Millisecond, "reservation must settle/refund completely")
		after := snapshot(t, index)
		assert.Equal(t, before.used+cost, after.used)
		assert.Equal(t, before.tokenUsed+cost, after.tokenUsed)
		assert.Equal(t, before.requests+successful, after.requests)
		assert.Equal(t, before.logs+int64(successful), after.logs)
		assert.Equal(t, before.logQuota+int64(cost), after.logQuota)
		assert.Equal(t, before.channelQuota+int64(globalCost), after.channelQuota)
	}
	request := func(t *testing.T, index int, path, body string) (int, http.Header, []byte) {
		t.Helper()
		req, err := http.NewRequest("POST", f.server.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer sk-"+tokens[index].Key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, resp.Header, raw
	}
	t.Run("admission_and_fixed_routing", func(t *testing.T) {
		// Source-compatible RED: the baseline route produces404 before this provider.
		sc := &scenario{}
		scenarios.Store("route-presence", sc)
		before := snapshot(t, 0)
		status, headers, raw := request(t, 0, "/v1/tools/search", `{"query":"route-presence"}`)
		require.Equal(t, 200, status, "baseline route absence must be observable, body=%s", raw)
		assert.Contains(t, headers.Get("Content-Type"), "application/json")
		assert.JSONEq(t, good, string(raw))
		assert.Equal(t, int64(1), sc.calls.Load())
		assert.Positive(t, boundary.calls.Load(), "inspect the actual provider request boundary")
		expectAccounting(t, 0, before, 375, 1, 375)
		for _, actor := range []string{"", "owner", "invalid-key"} {
			status, _, _ := f.request(t, "POST", "/v1/tools/search", actor, `{"query":"unauthorized"}`, http.Header{"Content-Type": {"application/json"}})
			assert.Contains(t, []int{401, 403}, status)
		}
		var originalAuth model.Token
		var originalUser model.User
		require.NoError(t, f.db.Select("id", "status", "expired_time", "allow_ips", "model_limits_enabled", "model_limits").First(&originalAuth, tokens[0].Id).Error)
		require.NoError(t, f.db.Select("id", "status").First(&originalUser, tokens[0].UserId).Error)
		t.Cleanup(func() {
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Updates(map[string]any{
				"status": originalAuth.Status, "expired_time": originalAuth.ExpiredTime, "allow_ips": originalAuth.AllowIps,
				"model_limits_enabled": originalAuth.ModelLimitsEnabled, "model_limits": originalAuth.ModelLimits,
			}).Error)
			require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", tokens[0].UserId).Update("status", originalUser.Status).Error)
		})
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Updates(map[string]any{"model_limits_enabled": true, "model_limits": "body-spoof"}).Error)
		status, _, _ = request(t, 0, "/v1/tools/search", `{"query":"denied-model","model":"body-spoof","group":"paid"}`)
		assert.Equal(t, 403, status)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Update("model_limits", "deepseek-search").Error)
		mapped, override := `{"deepseek-search":"body-spoof","body-spoof":"another-model"}`, `{"model":"override-spoof","group":"paid","count":1}`
		require.NoError(t, f.db.Model(channels[0]).Updates(map[string]any{"model_mapping": mapped, "param_override": override}).Error)
		sc = &scenario{}
		scenarios.Store("fixed-subject", sc)
		before = snapshot(t, 0)
		status, _, raw = request(t, 0, "/v1/tools/search", `{"query":"fixed-subject","model":{"ignored":true},"group":{"ignored":true},"count":50,"need_content":false,"ori_question":null,"localization":"","extension":null}`)
		require.Equal(t, 200, status, "%s", raw)
		expectAccounting(t, 0, before, 375, 1, 375)
		require.Equal(t, int64(1), sc.calls.Load())
		assert.Equal(t, "/v1/tools/search", sc.paths[0])
		assert.Equal(t, false, sc.requests[0]["need_content"])
		assert.Contains(t, sc.requests[0], "extension")
		assert.Nil(t, sc.requests[0]["ori_question"])
		var entry model.Log
		require.NoError(t, model.LOG_DB.Where("user_id = ? AND type = ?", tokens[0].UserId, model.LogTypeConsume).Order("id DESC").First(&entry).Error)
		assert.Equal(t, "deepseek-search", entry.ModelName)
		assert.Equal(t, "default", entry.Group)
		assert.Equal(t, channels[0].Id, entry.ChannelId)
		require.NoError(t, f.db.Model(channels[0]).Updates(map[string]any{"model_mapping": "", "param_override": ""}).Error)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Update("model_limits_enabled", false).Error)
		before = snapshot(t, 0)
		for _, tc := range []struct {
			name    string
			status  int
			expires int64
			ips     string
			want    int
		}{
			{"disabled", common.TokenStatusDisabled, -1, "", 401},
			{"expired", common.TokenStatusEnabled, time.Now().Unix() - 1, "", 401},
			{"ip_policy", common.TokenStatusEnabled, -1, "192.0.2.1", 403},
		} {
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Updates(map[string]any{
				"status": tc.status, "expired_time": tc.expires, "allow_ips": tc.ips,
			}).Error)
			var current model.Token
			require.NoError(t, f.db.Select("id", "status", "expired_time", "allow_ips").First(&current, tokens[0].Id).Error)
			require.Equal(t, tc.status, current.Status, tc.name)
			require.Equal(t, tc.expires, current.ExpiredTime, tc.name)
			require.NotNil(t, current.AllowIps, tc.name)
			require.Equal(t, tc.ips, *current.AllowIps, tc.name)
			status, _, _ = request(t, 0, "/v1/tools/search", `{"query":"token-denied"}`)
			assert.Equal(t, tc.want, status, tc.name)
			if tc.name == "expired" {
				require.NoError(t, f.db.Select("id", "status").First(&current, tokens[0].Id).Error)
				assert.Equal(t, common.TokenStatusExpired, current.Status)
			}
		}
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Updates(map[string]any{
			"status": common.TokenStatusEnabled, "expired_time": int64(-1), "allow_ips": "",
		}).Error)
		var restored model.Token
		require.NoError(t, f.db.Select("id", "status", "expired_time", "allow_ips").First(&restored, tokens[0].Id).Error)
		require.Equal(t, common.TokenStatusEnabled, restored.Status)
		require.Equal(t, int64(-1), restored.ExpiredTime)
		require.NotNil(t, restored.AllowIps)
		require.Empty(t, *restored.AllowIps)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", tokens[0].UserId).Update("status", common.UserStatusDisabled).Error)
		status, _, _ = request(t, 0, "/v1/tools/search", `{"query":"disabled-user"}`)
		assert.Equal(t, 403, status)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", tokens[0].UserId).Update("status", common.UserStatusEnabled).Error)
		require.NoError(t, f.db.Model(&model.Ability{}).Where("channel_id = ?", channels[0].Id).Update("enabled", false).Error)
		status, _, raw = request(t, 0, "/v1/tools/search", `{"query":"no-channel","model":"body-spoof"}`)
		assert.Equal(t, 503, status)
		var failure map[string]any
		require.NoError(t, common.Unmarshal(raw, &failure))
		detail := failure["error"].(map[string]any)
		assert.Equal(t, "no_available_channel", detail["code_detail"])
		assert.Equal(t, "deepseek-search", detail["model"])
		assert.Equal(t, "default", detail["group"])
		require.NoError(t, f.db.Model(&model.Ability{}).Where("channel_id = ?", channels[0].Id).Update("enabled", true).Error)
		require.NoError(t, f.db.Model(channels[0]).Update("type", constant.ChannelTypeOpenAI).Error)
		unsupported := &scenario{}
		scenarios.Store("unsupported-channel", unsupported)
		status, _, _ = request(t, 0, "/v1/tools/search", `{"query":"unsupported-channel"}`)
		assert.Equal(t, 500, status)
		assert.Zero(t, unsupported.calls.Load(), "unsupported native channel must fail before I/O")
		require.NoError(t, f.db.Model(channels[0]).Update("type", constant.ChannelTypeDeepSeek).Error)
		expectAccounting(t, 0, before, 0, 0, 0)
	})
	t.Run("structured_response_and_request_settlement", func(t *testing.T) {
		var traceActive atomic.Bool
		var traceMu sync.Mutex
		var balances []int
		callback := "tools_search_legacy_reservation"
		require.NoError(t, f.db.Callback().Update().After("gorm:commit_or_rollback_transaction").Register(callback, func(tx *gorm.DB) {
			if !traceActive.Load() || tx.Statement.Table != "users" || tx.Error != nil {
				return
			}
			var user model.User
			if assert.NoError(t, f.db.First(&user, tokens[0].UserId).Error) {
				traceMu.Lock()
				balances = append(balances, user.Quota)
				traceMu.Unlock()
			}
		}))
		defer func() { require.NoError(t, f.db.Callback().Update().Remove(callback)) }()
		for _, tc := range []struct {
			query, body, expr, legacy, group string
			cost                             int
		}{
			{"count-one", `{"query":"count-one","count":1}`, "", "", "", 375},
			{"count-fifty", `{"query":"count-fifty","count":50,"need_content":false,"ori_question":"source query","localization":"2001:db8::1","future":{"x":1}}`, "", "", "", 375},
			{"admin-expr", `{"query":"admin-expr"}`, `tier("request", fixed(0.001))`, "", "", 500},
			{"admin-zero", `{"query":"admin-zero"}`, `tier("request", fixed(0))`, "", "", 0},
			{"legacy-price", `{"query":"legacy-price"}`, "", `{"deepseek-search":0.002}`, "", 1000},
			{"legacy-zero", `{"query":"legacy-zero"}`, "", `{"deepseek-search":0}`, "", 0},
			{"legacy-fraction", `{"query":"legacy-fraction"}`, "", `{"deepseek-search":0.000751}`, "", 376},
			{"paid-group", `{"query":"paid-group"}`, "", "", "paid", 750},
		} {
			cfg.BillingMode, cfg.BillingExpr = map[string]string{}, map[string]string{}
			if tc.expr != "" {
				cfg.BillingMode["deepseek-search"] = "tiered_expr"
				cfg.BillingExpr["deepseek-search"] = tc.expr
			}
			prices := tc.legacy
			if prices == "" {
				prices = `{}`
			}
			require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(prices))
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Update("group", tc.group).Error)
			sc := &scenario{}
			scenarios.Store(tc.query, sc)
			before := snapshot(t, 0)
			sc.before = func(_ int, _ *http.Request) {
				var user model.User
				var token model.Token
				assert.NoError(t, f.db.First(&user, tokens[0].UserId).Error)
				assert.NoError(t, f.db.First(&token, tokens[0].Id).Error)
				assert.Equal(t, before.quota-tc.cost, user.Quota, "reservation before provider, %s", tc.query)
				assert.Equal(t, before.remaining-tc.cost, token.RemainQuota)
			}
			traceActive.Store(tc.query == "legacy-fraction")
			status, headers, raw := request(t, 0, "/v1/tools/search", tc.body)
			traceActive.Store(false)
			if tc.query == "legacy-fraction" {
				traceMu.Lock()
				assert.Contains(t, balances, before.quota-375, "initial legacy reservation truncates")
				assert.Contains(t, balances, before.quota-376, "fixed target reserves the rounded top-up")
				traceMu.Unlock()
			}
			require.Equal(t, 200, status, "query=%s response=%s", tc.query, raw)
			assert.Contains(t, headers.Get("Content-Type"), "application/json")
			assert.JSONEq(t, good, string(raw))
			assert.Equal(t, int64(1), sc.calls.Load())
			expectAccounting(t, 0, before, tc.cost, 1, tc.cost)
			var logged model.Log
			require.NoError(t, model.LOG_DB.Where("user_id = ? AND type = ?", tokens[0].UserId, model.LogTypeConsume).Order("id DESC").First(&logged).Error)
			assert.Zero(t, logged.PromptTokens)
			assert.Zero(t, logged.CompletionTokens)
			assert.Equal(t, tc.cost, logged.Quota)
		}
		cfg.BillingMode, cfg.BillingExpr = map[string]string{}, map[string]string{}
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"deepseek-search":0}`))
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Update("group", "").Error)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", tokens[0].UserId).Update("quota", 0).Error)
		free := &scenario{}
		scenarios.Store("legacy-free-no-wallet", free)
		freeBefore := snapshot(t, 0)
		status, _, _ := request(t, 0, "/v1/tools/search", `{"query":"legacy-free-no-wallet"}`)
		require.Equal(t, 200, status)
		assert.Equal(t, int64(1), free.calls.Load())
		expectAccounting(t, 0, freeBefore, 0, 1, 0)
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"deepseek-search":0.000751}`))
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Update("group", "").Error)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", tokens[0].UserId).Update("quota", 375).Error)
		topUp := &scenario{}
		scenarios.Store("legacy-top-up-insufficient", topUp)
		limited := snapshot(t, 0)
		status, _, _ = request(t, 0, "/v1/tools/search", `{"query":"legacy-top-up-insufficient"}`)
		assert.Equal(t, 403, status)
		assert.Zero(t, topUp.calls.Load(), "375 initial funds cannot fund the rounded376 target")
		expectAccounting(t, 0, limited, 0, 0, 0)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", tokens[0].UserId).Update("quota", 1000000).Error)
		for _, query := range []string{"legacy-empty-refund", "legacy-error-refund", "legacy-token-top-up-insufficient"} {
			sc := &scenario{body: `{"results":[]}`}
			want, calls := 200, int64(1)
			if query == "legacy-error-refund" {
				sc.status = 400
				sc.body = `{"error":"safe synthetic failure"}`
				want = 400
			}
			if query == "legacy-token-top-up-insufficient" {
				require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Update("remain_quota", 375).Error)
				want, calls = 403, 0
			}
			scenarios.Store(query, sc)
			before := snapshot(t, 0)
			status, _, _ := request(t, 0, "/v1/tools/search", `{"query":"`+query+`"}`)
			assert.Equal(t, want, status)
			assert.Equal(t, calls, sc.calls.Load())
			expectAccounting(t, 0, before, 0, 0, 0)
		}
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Update("remain_quota", 1000000).Error)
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{}`))
		for _, body := range []string{`{}`, `{"query":"  "}`, `{"query":null}`, `{"query":"x","query":"y"}`, `{"query":"x","count":0}`, `{"query":"x","count":51}`, `{"query":"x","count":1.5}`, `{"query":"x","need_content":0}`, `{"query":"x","ori_question":""}`, `{"query":"x","localization":"not-an-ip"}`, `{"query":"` + strings.Repeat("界", 129) + `"}`} {
			before := snapshot(t, 0)
			status, _, _ := request(t, 0, "/v1/tools/search", body)
			assert.Equal(t, 400, status)
			expectAccounting(t, 0, before, 0, 0, 0)
		}
		invalidOverride := `{"count":0}`
		require.NoError(t, f.db.Model(channels[0]).Update("param_override", invalidOverride).Error)
		before := snapshot(t, 0)
		status, _, _ = request(t, 0, "/v1/tools/search", `{"query":"override-invalid"}`)
		assert.Equal(t, 400, status)
		expectAccounting(t, 0, before, 0, 0, 0)
		require.NoError(t, f.db.Model(channels[0]).Update("param_override", "").Error)
		sc := &scenario{body: `{"alpha":"unchanged"}`}
		scenarios.Store("alpha-control", sc)
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"alpha-control":0}`))
		status, _, raw := request(t, 0, "/v1/alpha/search", `{"model":"alpha-control","commands":{"search_query":[{"q":"owned"}]}}`)
		require.Equal(t, 200, status)
		assert.JSONEq(t, sc.body, string(raw))
		assert.Equal(t, []string{"/v1/alpha/search"}, sc.paths)
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{}`))
	})
	t.Run("upstream_failures_and_refunds", func(t *testing.T) {
		for _, tc := range []struct {
			query, body, mode   string
			status, want, calls int
		}{
			{"empty", `{"results":[],"future":null}`, "", 200, 200, 1},
			{"missing", `{"message":"provider-cause-canary"}`, "", 200, 502, 1},
			{"null-results", `{"results":null}`, "", 200, 502, 1},
			{"duplicate-results", `{"results":[],"results":[]}`, "", 200, 502, 1},
			{"invalid-score", strings.Replace(good, `2.5`, `3.1`, 1), "", 200, 502, 1},
			{"invalid-date", strings.Replace(good, `"date":null`, `"date":"yesterday"`, 1), "", 200, 502, 1},
			{"trailing", good + `{}`, "", 200, 502, 1},
			{"oversized", `{"results":[],"padding":"` + strings.Repeat("x", 16*1024*1024) + `"}`, "", 200, 502, 1},
			{"partial", "", "partial", 200, 502, 1},
			{"transport", "", "transport", 200, 502, 1},
			{"other-success", good, "", 201, 502, 1},
			{"bad-request", `{"error":"provider-cause-canary"}`, "", 400, 400, 1},
		} {
			sc := &scenario{body: tc.body, mode: tc.mode, status: tc.status}
			scenarios.Store(tc.query, sc)
			before := snapshot(t, 0)
			status, headers, raw := request(t, 0, "/v1/tools/search", `{"query":"`+tc.query+`"}`)
			require.Equal(t, tc.want, status, "query=%s response=%s", tc.query, raw)
			assert.Equal(t, int64(tc.calls), sc.calls.Load())
			if status == 200 {
				assert.JSONEq(t, tc.body, string(raw))
				assert.Contains(t, headers.Get("Content-Type"), "application/json")
			} else {
				assert.NotContains(t, string(raw), "provider-cause-canary")
				assert.NotContains(t, string(raw), "padding")
			}
			expectAccounting(t, 0, before, 0, 0, 0)
		}
		// Dedicated HTTP/1 hosts guarantee each pair uses its one idle
		// connection. The second POST is fully read before that connection closes.
		for index, header := range []string{"Idempotency-Key", "X-Idempotency-Key"} {
			replayProvider := httptest.NewServer(provider.Config.Handler)
			defer replayProvider.Close()
			override := `{"` + header + `":"owned-no-provider-idempotency"}`
			require.NoError(t, f.db.Model(channels[0]).Updates(map[string]any{"base_url": replayProvider.URL, "header_override": override}).Error)
			warmQuery := fmt.Sprintf("replay-warm-up-%d", index)
			warm := &scenario{}
			scenarios.Store(warmQuery, warm)
			warmBefore := snapshot(t, 0)
			status, _, raw := request(t, 0, "/v1/tools/search", `{"query":"`+warmQuery+`"}`)
			require.Equal(t, 200, status, "%s", raw)
			expectAccounting(t, 0, warmBefore, 375, 1, 375)
			lostQuery := fmt.Sprintf("reused-connection-lost-response-%d", index)
			lost := &scenario{mode: "transport"}
			scenarios.Store(lostQuery, lost)
			lostBefore := snapshot(t, 0)
			status, _, _ = request(t, 0, "/v1/tools/search", `{"query":"`+lostQuery+`"}`)
			assert.Equal(t, 502, status)
			require.Equal(t, int64(1), lost.calls.Load(), "idempotency headers must not enable hidden transport replay")
			require.Len(t, warm.connections, 1)
			require.Len(t, lost.connections, 1)
			assert.Equal(t, warm.connections[0], lost.connections[0], "failure must use the actual reused connection")
			assert.Equal(t, []int{1}, lost.protocols)
			assert.Equal(t, []string{"owned-no-provider-idempotency"}, lost.idempotency)
			expectAccounting(t, 0, lostBefore, 0, 0, 0)
			require.NoError(t, f.db.Model(channels[0]).Updates(map[string]any{"base_url": provider.URL, "header_override": ""}).Error)
		}
		for _, code := range []int{408, 429, 503} {
			query := fmt.Sprintf("retry-%d", code)
			sc := &scenario{firstStatus: code}
			scenarios.Store(query, sc)
			before := snapshot(t, 0)
			status, _, raw := request(t, 0, "/v1/tools/search", `{"query":"`+query+`"}`)
			require.Equal(t, 200, status, "%s", raw)
			require.Equal(t, int64(2), sc.calls.Load())
			assert.Equal(t, sc.requests[0], sc.requests[1], "allowed retry must rebuild the complete original body")
			expectAccounting(t, 0, before, 375, 1, 375)
		}
		freeSelector := map[string]any{"channel_id": channels[1].Id, "model": "deepseek-search", "group": "free"}
		setFreeEligible := func(enabled bool) {
			var current model.Ability
			if !assert.NoError(t, f.db.Where(freeSelector).Take(&current).Error) {
				return
			}
			if current.Enabled != enabled {
				updated := f.db.Model(&model.Ability{}).Where(freeSelector).Update("enabled", enabled)
				assert.NoError(t, updated.Error)
				assert.Equal(t, int64(1), updated.RowsAffected, "only the owned free ability changes")
			}
			var actual model.Ability
			if assert.NoError(t, f.db.Where(freeSelector).Take(&actual).Error) {
				assert.Equal(t, enabled, actual.Enabled)
			}
		}
		t.Cleanup(func() { setFreeEligible(true) })
		// Only the selected owned channel supplies these provider-visible markers.
		for _, channel := range []*model.Channel{channels[1], channels[2]} {
			previous := channel.HeaderOverride
			t.Cleanup(func() {
				require.NoError(t, f.db.Model(&model.Channel{}).Where("id = ?", channel.Id).Update("header_override", previous).Error)
			})
			markers, err := common.Marshal(map[string]string{"X-Owned-Channel": strconv.Itoa(channel.Id), "X-Owned-Group": channel.Group})
			require.NoError(t, err)
			require.NoError(t, f.db.Model(&model.Channel{}).Where("id = ?", channel.Id).Update("header_override", string(markers)).Error)
		}
		setFreeEligible(true)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Updates(map[string]any{"group": "auto", "auto_groups": `["free","paid"]`, "cross_group_retry": true}).Error)
		sc := &scenario{firstStatus: 503}
		// Use exact snapshots, not elapsed time, to prove paid reservation precedes I/O.
		before := snapshot(t, 0)
		sc.before = func(attempt int, outgoing *http.Request) {
			selected := channels[1]
			if attempt == 2 {
				selected = channels[2]
			}
			assert.Equal(t, selected.Group, outgoing.Header.Get("X-Owned-Group"))
			assert.Equal(t, strconv.Itoa(selected.Id), outgoing.Header.Get("X-Owned-Channel"))
			var user model.User
			var token model.Token
			assert.NoError(t, f.db.First(&user, tokens[0].UserId).Error)
			assert.NoError(t, f.db.First(&token, tokens[0].Id).Error)
			reserved := 0
			if attempt == 2 {
				reserved = 750
			}
			assert.Equal(t, before.quota-reserved, user.Quota)
			assert.Equal(t, before.remaining-reserved, token.RemainQuota)
			if attempt == 1 {
				setFreeEligible(false)
			}
		}
		scenarios.Store("free-to-paid", sc)
		status, _, raw := request(t, 0, "/v1/tools/search", `{"query":"free-to-paid"}`)
		setFreeEligible(true)
		require.Equal(t, 200, status, "%s", raw)
		assert.Equal(t, int64(2), sc.calls.Load())
		expectAccounting(t, 0, before, 750, 1, 750)
		var paidLog model.Log
		require.NoError(t, model.LOG_DB.Where("user_id = ? AND type = ?", tokens[0].UserId, model.LogTypeConsume).Order("id DESC").First(&paidLog).Error)
		assert.Equal(t, "paid", paidLog.Group)
		assert.Equal(t, channels[2].Id, paidLog.ChannelId)
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"deepseek-search":0.001}`))
		legacy := &scenario{firstStatus: 503}
		scenarios.Store("legacy-free-to-paid", legacy)
		legacyBefore := snapshot(t, 0)
		legacy.before = func(attempt int, outgoing *http.Request) {
			selected := channels[1]
			if attempt == 2 {
				selected = channels[2]
			}
			assert.Equal(t, selected.Group, outgoing.Header.Get("X-Owned-Group"))
			assert.Equal(t, strconv.Itoa(selected.Id), outgoing.Header.Get("X-Owned-Channel"))
			var user model.User
			var token model.Token
			assert.NoError(t, f.db.First(&user, tokens[0].UserId).Error)
			assert.NoError(t, f.db.First(&token, tokens[0].Id).Error)
			reserved := 0
			if attempt == 2 {
				reserved = 1000
			}
			assert.Equal(t, legacyBefore.quota-reserved, user.Quota)
			assert.Equal(t, legacyBefore.remaining-reserved, token.RemainQuota)
			if attempt == 1 {
				setFreeEligible(false)
			}
		}
		status, _, raw = request(t, 0, "/v1/tools/search", `{"query":"legacy-free-to-paid"}`)
		setFreeEligible(true)
		require.Equal(t, 200, status, "%s", raw)
		assert.Equal(t, int64(2), legacy.calls.Load())
		expectAccounting(t, 0, legacyBefore, 1000, 1, 1000)
		paidLog = model.Log{}
		require.NoError(t, model.LOG_DB.Where("user_id = ? AND type = ?", tokens[0].UserId, model.LogTypeConsume).Order("id DESC").First(&paidLog).Error)
		assert.Equal(t, "paid", paidLog.Group)
		assert.Equal(t, channels[2].Id, paidLog.ChannelId)
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{}`))
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", tokens[0].UserId).Update("quota", 100).Error)
		sc = &scenario{firstStatus: 503, before: func(attempt int, outgoing *http.Request) {
			assert.Equal(t, 1, attempt, "insufficient paid reserve must prevent a second call")
			assert.Equal(t, "free", outgoing.Header.Get("X-Owned-Group"))
			assert.Equal(t, strconv.Itoa(channels[1].Id), outgoing.Header.Get("X-Owned-Channel"))
			setFreeEligible(false)
		}}
		scenarios.Store("insufficient-retry", sc)
		before = snapshot(t, 0)
		status, _, _ = request(t, 0, "/v1/tools/search", `{"query":"insufficient-retry"}`)
		setFreeEligible(true)
		assert.Equal(t, 403, status)
		assert.Equal(t, int64(1), sc.calls.Load())
		expectAccounting(t, 0, before, 0, 0, 0)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", tokens[0].UserId).Update("quota", 1000000).Error)
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", tokens[0].Id).Updates(map[string]any{"group": "", "cross_group_retry": false}).Error)
		for _, mode := range []string{"header-cancel", "body-cancel", "parent-deadline"} {
			sc = &scenario{mode: mode, entered: make(chan struct{}), release: make(chan struct{}), cancelled: make(chan struct{})}
			scenarios.Store(mode, sc)
			before = snapshot(t, 0)
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "parent-deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			}
			req, err := http.NewRequestWithContext(ctx, "POST", f.server.URL+"/v1/tools/search", strings.NewReader(`{"query":"`+mode+`"}`))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer sk-"+tokens[0].Key)
			req.Header.Set("Content-Type", "application/json")
			finished := make(chan error, 1)
			go func() {
				resp, err := f.client.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				finished <- err
			}()
			select {
			case <-sc.entered:
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("upstream barrier not reached")
			}
			if mode != "parent-deadline" {
				cancel()
			}
			select {
			case err := <-finished:
				assert.Error(t, err)
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("caller cancellation not observed")
			}
			select {
			case <-sc.cancelled:
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("outgoing context not cancelled")
			}
			cancel()
			assert.Equal(t, int64(1), sc.calls.Load())
			expectAccounting(t, 0, before, 0, 0, 0)
		}
		// Distinct actors interleave one complete success with one lost response.
		success := &scenario{entered: make(chan struct{}), release: make(chan struct{})}
		failure := &scenario{entered: make(chan struct{}), release: make(chan struct{}), mode: "body-cancel", cancelled: make(chan struct{})}
		scenarios.Store("concurrent-success", success)
		scenarios.Store("concurrent-failure", failure)
		ownBefore, otherBefore := snapshot(t, 0), snapshot(t, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type outcome struct {
			status int
			err    error
		}
		done := make(chan outcome, 2)
		for index, query := range []string{"concurrent-success", "concurrent-failure"} {
			go func() {
				requestCtx := context.Background()
				if index == 1 {
					requestCtx = ctx
				}
				req, err := http.NewRequestWithContext(requestCtx, "POST", f.server.URL+"/v1/tools/search", strings.NewReader(`{"query":"`+query+`"}`))
				if err != nil {
					done <- outcome{err: err}
					return
				}
				req.Header.Set("Authorization", "Bearer sk-"+tokens[index].Key)
				req.Header.Set("Content-Type", "application/json")
				resp, err := f.client.Do(req)
				status := 0
				if resp != nil {
					status = resp.StatusCode
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				done <- outcome{status, err}
			}()
		}
		for _, sc := range []*scenario{success, failure} {
			select {
			case <-sc.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("concurrent barrier not reached")
			}
		}
		cancel()
		close(success.release)
		for range 2 {
			select {
			case result := <-done:
				if result.err == nil {
					assert.Equal(t, 200, result.status)
				} else {
					assert.ErrorIs(t, result.err, context.Canceled)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("concurrent request did not finish")
			}
		}
		select {
		case <-failure.cancelled:
		case <-time.After(5 * time.Second):
			t.Fatal("failed actor provider not cancelled")
		}
		assert.Equal(t, int64(1), success.calls.Load())
		assert.Equal(t, int64(1), failure.calls.Load())
		expectAccounting(t, 0, ownBefore, 375, 1, 375)
		expectAccounting(t, 1, otherBefore, 0, 0, 375)
		// A client delivery error happens after settlement; it is never a replay/refund.
		sc = &scenario{}
		scenarios.Store("downstream-closed", sc)
		before = snapshot(t, 0)
		req := httptest.NewRequest("POST", "/v1/tools/search", strings.NewReader(`{"query":"downstream-closed"}`))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Authorization", "Bearer sk-"+tokens[0].Key)
		req.Header.Set("Content-Type", "application/json")
		writer := &toolsSearchRejectedWriter{httptest.NewRecorder()}
		f.engine.ServeHTTP(writer, req)
		assert.Empty(t, writer.Body.Bytes())
		assert.Equal(t, int64(1), sc.calls.Load())
		expectAccounting(t, 0, before, 375, 1, 375)
	})
}
