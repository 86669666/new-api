package router

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
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
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	sqlmysql "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/clickhouse"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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
	boundedSuite := slices.Contains([]string{"g10-organization-identity", "g10-organization-task-read", "g11-organization-invitation-presentation", "g12-organization-task-batch", "g13-organization-task-export", "g14-organization-task-list-revocation", "g15-organization-task-funding-isolation", "g16-organization-capabilities", "g17-organization-wallet"}, owner)
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
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.UserAccessToken{}, &model.Option{}, &model.Token{}, &model.Task{}, &model.Log{}, &model.CasbinRule{}, &model.AuthzRole{}, &model.Organization{}, &model.OrganizationMember{}, &model.OrganizationInvitation{}, &model.OrganizationOwnershipTransfer{}, &model.OrganizationEvent{}, &model.OrganizationWallet{}, &model.OrganizationWalletEntry{}))
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
