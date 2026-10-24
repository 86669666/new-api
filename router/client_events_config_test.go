package router

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// A separate application process shares only the owned test database. It runs
// the production SyncOptions poll and exposes the production authenticated API.
func TestClientEventsConfigProcess(t *testing.T) {
	if os.Getenv("CLIENT_CONFIG_TEST_CHILD") != "1" {
		t.Skip("subprocess fixture only")
	}
	kind, dsn := os.Getenv("NEWAPI_S2_MAIN"), os.Getenv("CLIENT_CONFIG_TEST_DSN")
	if os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") != "" {
		kind = os.Getenv("CLIENT_CONFIG_TEST_ENGINE")
		require.Equal(t, "sqlite", kind)
		organizationTrustedSQLitePath(t, dsn, os.Getenv("CLIENT_CONFIG_TEST_ROOT"))
	}
	var dial gorm.Dialector
	switch kind {
	case "mysql":
		dial = mysql.Open(dsn)
	case "postgres":
		dial = postgres.New(postgres.Config{DSN: dsn, PreferSimpleProtocol: true})
	case "sqlite":
		dial = sqlite.Open(dsn)
	default:
		t.Fatal("unsupported child engine")
	}
	db, err := gorm.Open(dial, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	pool, err := db.DB()
	require.NoError(t, err)
	defer pool.Close()
	model.DB, model.LOG_DB = db, db
	if os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") != "" {
		require.NoError(t, model.ValidateOAuthDerivedTokenStore(t.Context()))
		common.SQLitePath = dsn
	}
	common.SetDatabaseTypes(common.DatabaseType(kind), common.DatabaseType(kind))
	common.SessionSecret = os.Getenv("CLIENT_CONFIG_TEST_SECRET")
	common.RedisEnabled = false
	common.MemoryCacheEnabled = false
	common.GlobalApiRateLimitEnable = false
	common.IsMasterNode = false
	require.NoError(t, model.InitLogDB())
	require.NoError(t, i18n.Init())
	require.NoError(t, service.InitClientEventsConfig())
	model.InitOptionMap()
	gin.SetMode(gin.TestMode)
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard
	engine := gin.New()
	SetRouter(engine, WebAssets{IndexPage: []byte("config-fixture")})
	server := httptest.NewServer(engine)
	defer server.Close()
	go model.SyncOptions(1)
	fmt.Println("CLIENT_CONFIG_READY " + server.URL)
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)
}

func TestClientEventsConfigHTTP(t *testing.T) {
	t.Setenv("CLIENT_EVENTS_ENABLED", "true")
	t.Setenv("CLIENT_EVENTS_RETENTION_DAYS", "45")
	t.Setenv("CLIENT_EVENTS_RATE_LIMIT", "90")
	require.NoError(t, service.InitClientEventsConfig())
	assert.False(t, operation_setting.CurrentClientEventsSnapshot().Valid)
	assert.False(t, service.CurrentClientEventsConfig().Enabled)
	f := newOrganizationProfileFixture(t, "g1-W03-09-client-config")
	require.NoError(t, f.db.AutoMigrate(&model.ClientEvent{}, &model.SystemTask{}, &model.SystemTaskLock{}))
	require.NoError(t, model.ReloadClientEventsConfig())
	require.NoError(t, f.db.Model(f.users["admin"]).Update("role", common.RoleAdminUser).Error)
	encode := func(v any) string { data, err := common.Marshal(v); require.NoError(t, err); return string(data) }
	write := func(key string, value any, actor string, want int) {
		s, _, body := f.request(t, "PUT", "/api/option/", actor, encode(map[string]any{"key": key, "value": value}), http.Header{"Content-Type": {"application/json"}})
		require.Equal(t, want, s, "%v", body)
		assert.Equal(t, want == 200, body["success"])
	}
	read := func(actor string, want int) operation_setting.ClientEventsSnapshot {
		s, _, body := f.request(t, "GET", "/api/option/", actor, "", nil)
		require.Equal(t, want, s)
		var value operation_setting.ClientEventsSnapshot
		if want != 200 {
			return value
		}
		count := 0
		for _, v := range body["data"].([]any) {
			option := v.(map[string]any)
			if option["key"] == operation_setting.ClientEventsConfigKey {
				count++
				require.NoError(t, common.UnmarshalJsonStr(option["value"].(string), &value))
			}
		}
		require.Equal(t, 1, count)
		return value
	}
	valid := `{"enabled":true,"retention_days":30,"rate_limit":60}`
	t.Run("startup_precedence_and_root_boundary", func(t *testing.T) {
		state := read("root", 200)
		assert.True(t, state.Valid)
		assert.True(t, state.Enabled)
		assert.Equal(t, 45, state.RetentionDays)
		assert.Equal(t, "environment", state.Source)
		for _, actor := range []string{"admin", "owner", "relay", ""} {
			want := 403
			if actor == "relay" || actor == "" {
				want = 401
			}
			read(actor, want)
			write(operation_setting.ClientEventsConfigKey, valid, actor, want)
		}
		for _, scope := range []string{"option:read", "option:write"} {
			raw := "nap_" + common.NewRequestId() + common.NewRequestId()
			token := model.UserAccessToken{UserId: f.users["root"].Id, TokenHash: model.AccessTokenFingerprint(raw)}
			require.NoError(t, token.SetScopes([]string{scope}))
			require.NoError(t, f.db.Create(&token).Error)
			if scope == "option:read" {
				read(raw, 200)
				write(operation_setting.ClientEventsConfigKey, valid, raw, 403)
			} else {
				read(raw, 403)
				write(operation_setting.ClientEventsConfigKey, valid, raw, 200)
			}
		}
		write(operation_setting.ClientEventsConfigKey, valid, "root", 200)
		state = read("root", 200)
		assert.Equal(t, "option", state.Source)
		assert.Equal(t, 30, state.RetentionDays)
		t.Setenv("CLIENT_EVENTS_ENABLED", "false")
		t.Setenv("CLIENT_EVENTS_RETENTION_DAYS", "365")
		require.NoError(t, service.InitClientEventsConfig())
		assert.False(t, service.CurrentClientEventsConfig().Enabled)
		require.NoError(t, model.ReloadClientEventsConfig())
		state = read("root", 200)
		assert.True(t, state.Enabled)
		assert.Equal(t, 30, state.RetentionDays)
		require.NoError(t, f.db.Where(map[string]any{"key": operation_setting.ClientEventsConfigKey}).Delete(&model.Option{}).Error)
		require.NoError(t, model.ReloadClientEventsConfig())
		state = read("root", 200)
		assert.False(t, state.Enabled)
		assert.Equal(t, 365, state.RetentionDays)
		assert.Equal(t, "environment", state.Source)
	})
	t.Run("strict_complete_json_and_key_identity", func(t *testing.T) {
		write(operation_setting.ClientEventsConfigKey, valid, "root", 200)
		before := read("root", 200)
		invalid := []any{nil, true, 42, map[string]any{"enabled": true, "retention_days": 30, "rate_limit": 60}, "null", "[]", "{}", `{"enabled":null,"retention_days":30,"rate_limit":60}`, `{"enabled":true,"retention_days":30}`, `{"enabled":true,"retention_days":30,"rate_limit":60,"extra":1}`, `{"enabled":true,"enabled":false,"retention_days":30,"rate_limit":60}`, `{"Enabled":true,"retention_days":30,"rate_limit":60}`, `{"enabled":true,"retention_days":30.0,"rate_limit":60}`, `{"enabled":true,"retention_days":3e1,"rate_limit":60}`, `{"enabled":true,"retention_days":"30","rate_limit":60}`, `{"enabled":true,"retention_days":7,"rate_limit":60}`, `{"enabled":true,"retention_days":366,"rate_limit":60}`, `{"enabled":true,"retention_days":30,"rate_limit":0}`, `{"enabled":true,"retention_days":30,"rate_limit":601}`, valid + strings.Repeat(" ", 4096)}
		for _, value := range invalid {
			write(operation_setting.ClientEventsConfigKey, value, "root", 400)
			assert.Equal(t, before, read("root", 200))
		}
		for _, key := range []string{"clienteventsconfig", "CLIENTEVENTSCONFIG", "ClientEventsConfig "} {
			write(key, valid, "root", 400)
		}
		if f.mainKind == "mysql" {
			write("ClïentEventsConfig", valid, "root", 400)
		}
		for _, value := range []string{`{"enabled":false,"retention_days":8,"rate_limit":1}`, `{"enabled":true,"retention_days":365,"rate_limit":600}`} {
			write(operation_setting.ClientEventsConfigKey, value, "root", 200)
		}
		write(operation_setting.ClientEventsConfigKey, valid, "root", 200)
		require.NoError(t, f.db.Model(&model.Option{}).Where(map[string]any{"key": operation_setting.ClientEventsConfigKey}).Update("key", "clienteventsconfig").Error)
		require.Error(t, model.ReloadClientEventsConfig())
		assert.False(t, read("root", 200).Valid)
		write(operation_setting.ClientEventsConfigKey, valid, "root", 400)
		require.NoError(t, f.db.Where(map[string]any{"key": "clienteventsconfig"}).Delete(&model.Option{}).Error)
		write(operation_setting.ClientEventsConfigKey, valid, "root", 200)
	})
	t.Run("mixed_passkey_bulk_cannot_change_client_configuration", func(t *testing.T) {
		require.NoError(t, f.db.AutoMigrate(&model.PasskeyCredential{}))
		keys := []string{operation_setting.ClientEventsConfigKey}
		if f.mainKind == "mysql" {
			keys = append(keys, "CliéntEventsConfig")
		}
		for _, key := range keys {
			for _, writer := range []string{"bulk", "passkey"} {
				t.Run(writer+"_"+key, func(t *testing.T) {
					write(operation_setting.ClientEventsConfigKey, valid, "root", 200)
					before := read("root", 200)
					var optionsBefore []model.Option
					require.NoError(t, f.db.Find(&optionsBefore).Error)
					values := map[string]string{"ServerAddress": "https://localhost", key: "not-json"}
					var err error
					if writer == "bulk" {
						err = model.UpdateOptionsBulk(values)
					} else {
						_, err = model.UpdatePasskeyDomainOptions(values, false, "")
					}
					assert.ErrorIs(t, err, operation_setting.ErrClientEventsConfig)
					var optionsAfter []model.Option
					require.NoError(t, f.db.Find(&optionsAfter).Error)
					assert.ElementsMatch(t, optionsBefore, optionsAfter, "the entire mixed write must roll back")
					assert.Equal(t, before, read("root", 200), "rejected writes must not publish settings")
				})
			}
		}
	})
	t.Run("storage_failure_does_not_publish_and_reload_preserves_state", func(t *testing.T) {
		before := read("root", 200)
		require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register("config:write-fail", func(tx *gorm.DB) {
			if tx.Statement.Table == "options" {
				tx.AddError(errors.New("fixture unavailable"))
			}
		}))
		write(operation_setting.ClientEventsConfigKey, `{"enabled":false,"retention_days":8,"rate_limit":1}`, "root", 503)
		require.NoError(t, f.db.Callback().Update().Remove("config:write-fail"))
		assert.Equal(t, before, read("root", 200))
		require.NoError(t, model.ReloadClientEventsConfig())
		assert.Equal(t, before, read("root", 200))
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("config:read-fail", func(tx *gorm.DB) {
			if tx.Statement.Table == "options" {
				tx.AddError(errors.New("fixture unavailable"))
			}
		}))
		require.Error(t, model.ReloadClientEventsConfig())
		assert.Equal(t, before, read("root", 200))
		require.NoError(t, service.InitClientEventsConfig())
		require.Error(t, model.ReloadClientEventsConfig())
		state := read("root", 200)
		assert.False(t, state.Valid)
		assert.False(t, state.Enabled)
		assert.False(t, (service.ClientEventsCleanupHandler{}).Enabled())
		require.NoError(t, f.db.Callback().Query().Remove("config:read-fail"))
		require.NoError(t, model.ReloadClientEventsConfig())
		assert.Equal(t, before, read("root", 200))
	})
	t.Run("invalid_persistence_pauses_cleanup_and_repair_restores", func(t *testing.T) {
		require.NoError(t, f.db.Model(&model.Option{}).Where(map[string]any{"key": operation_setting.ClientEventsConfigKey}).Update("value", "null").Error)
		require.Error(t, model.ReloadClientEventsConfig())
		state := read("root", 200)
		assert.False(t, state.Valid)
		assert.False(t, state.Enabled)
		assert.Equal(t, 30, state.RetentionDays)
		assert.False(t, (service.ClientEventsCleanupHandler{}).Enabled())
		old := model.ClientEvent{Fingerprint: strings.Repeat("a", 64), ReceivedAt: time.Now().Add(-100 * 24 * time.Hour).Unix()}
		require.NoError(t, f.db.Create(&old).Error)
		// Even a scheduler admission made before invalidation must not delete now.
		(service.ClientEventsCleanupHandler{}).Run(context.Background(), &model.SystemTask{TaskID: "missing-fixture-task"}, "fixture")
		var count int64
		require.NoError(t, f.db.Model(&model.ClientEvent{}).Count(&count).Error)
		assert.Equal(t, int64(1), count)
		write(operation_setting.ClientEventsConfigKey, `{"enabled":false,"retention_days":30,"rate_limit":60}`, "root", 200)
		assert.True(t, (service.ClientEventsCleanupHandler{}).Enabled())
		assert.False(t, read("root", 200).Enabled)
	})
	t.Run("running_cleanup_retains_captured_policy", func(t *testing.T) {
		require.NoError(t, f.db.Where("id > ?", 0).Delete(&model.ClientEvent{}).Error)
		write(operation_setting.ClientEventsConfigKey, valid, "root", 200)
		for i, days := range []int{50, 20} {
			require.NoError(t, f.db.Create(&model.ClientEvent{Fingerprint: fmt.Sprintf("%064x", i+10), ReceivedAt: time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()}).Error)
		}
		job := model.SystemTask{TaskID: "config-old-policy", Type: "client_events_cleanup", Status: model.SystemTaskStatusRunning, LockedBy: "fixture"}
		require.NoError(t, f.db.Create(&job).Error)
		require.NoError(t, f.db.Create(&model.SystemTaskLock{Type: job.Type, TaskID: job.TaskID, LockedBy: "fixture", LockedUntil: time.Now().Unix() + 60}).Error)
		var once sync.Once
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("config:cleanup-change", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				once.Do(func() {
					tx.AddError(model.UpdateClientEventsConfigOption(`{"enabled":false,"retention_days":8,"rate_limit":60}`))
				})
			}
		}))
		(service.ClientEventsCleanupHandler{}).Run(context.Background(), &job, "fixture")
		require.NoError(t, f.db.Callback().Query().Remove("config:cleanup-change"))
		var count int64
		require.NoError(t, f.db.Model(&model.ClientEvent{}).Count(&count).Error)
		assert.Equal(t, int64(1), count)
		require.NoError(t, f.db.Where("task_id = ?", job.TaskID).First(&job).Error)
		assert.Equal(t, model.SystemTaskStatusSucceeded, job.Status)
		next := model.SystemTask{TaskID: "config-new-policy", Type: "client_events_cleanup", Status: model.SystemTaskStatusRunning, LockedBy: "fixture"}
		require.NoError(t, f.db.Create(&next).Error)
		require.NoError(t, f.db.Create(&model.SystemTaskLock{Type: next.Type, TaskID: next.TaskID, LockedBy: "fixture", LockedUntil: time.Now().Unix() + 60}).Error)
		(service.ClientEventsCleanupHandler{}).Run(context.Background(), &next, "fixture")
		require.NoError(t, f.db.Model(&model.ClientEvent{}).Count(&count).Error)
		assert.Zero(t, count)
	})
	t.Run("reload_and_save_serialize_from_read_to_publication", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		require.NoError(t, f.db.Callback().Query().After("gorm:query").Register("config:reload-barrier", func(tx *gorm.DB) {
			if tx.Statement.Table == "options" {
				once.Do(func() { close(entered); <-release })
			}
		}))
		reloadDone := make(chan error, 1)
		go func() { reloadDone <- model.ReloadClientEventsConfig() }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("reload did not reach barrier")
		}
		writeDone := make(chan error, 1)
		go func() {
			writeDone <- model.UpdateClientEventsConfigOption(`{"enabled":true,"retention_days":90,"rate_limit":120}`)
		}()
		close(release)
		require.NoError(t, <-reloadDone)
		require.NoError(t, <-writeDone)
		require.NoError(t, f.db.Callback().Query().Remove("config:reload-barrier"))
		state := read("root", 200)
		assert.Equal(t, 90, state.RetentionDays)
		assert.Equal(t, 120, state.RateLimit)
	})
	t.Run("rate_change_preserves_the_existing_bucket", func(t *testing.T) {
		write(operation_setting.ClientEventsConfigKey, `{"enabled":true,"retention_days":30,"rate_limit":1}`, "root", 200)
		body := `{"client_id":"8a6c0e0e-6f3b-4c55-9d0e-2a1f7c9b1e11","channel":"cherry","events":[{"event_type":"app_launch","data":{"version":"1","os":"linux"}}]}`
		post := func(want int) {
			s, _, _ := f.request(t, "POST", "/api/events", "relay", body, http.Header{"Content-Type": {"application/json"}})
			require.Equal(t, want, s)
		}
		post(200)
		post(429)
		write(operation_setting.ClientEventsConfigKey, `{"enabled":true,"retention_days":30,"rate_limit":2}`, "root", 200)
		post(200)
		post(429)
		write(operation_setting.ClientEventsConfigKey, `{"enabled":false,"retention_days":30,"rate_limit":2}`, "root", 200)
		post(404)
		write(operation_setting.ClientEventsConfigKey, `{"enabled":true,"retention_days":30,"rate_limit":2}`, "root", 200)
		post(429)
	})
	t.Run("independent_instance_poll_and_restart", func(t *testing.T) {
		startChild := func() (*exec.Cmd, io.WriteCloser, string) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestClientEventsConfigProcess$", "-test.v")
			cmd.Env = append(os.Environ(), "CLIENT_CONFIG_TEST_CHILD=1", "CLIENT_CONFIG_TEST_DSN="+f.mainDSN, "CLIENT_CONFIG_TEST_SECRET="+common.SessionSecret, "CLIENT_CONFIG_TEST_ENGINE="+f.mainKind, "CLIENT_CONFIG_TEST_ROOT="+filepath.Dir(f.mainDSN))
			input, e := cmd.StdinPipe()
			require.NoError(t, e)
			output, e := cmd.StdoutPipe()
			require.NoError(t, e)
			cmd.Stderr = io.Discard
			require.NoError(t, cmd.Start())
			found := make(chan string, 1)
			go func() {
				scanner := bufio.NewScanner(output)
				for scanner.Scan() {
					if value, ok := strings.CutPrefix(scanner.Text(), "CLIENT_CONFIG_READY "); ok {
						found <- value
						break
					}
				}
				io.Copy(io.Discard, output)
			}()
			select {
			case address := <-found:
				return cmd, input, address
			case <-time.After(15 * time.Second):
				cmd.Process.Kill()
				cmd.Wait()
				t.Fatal("child did not start")
			}
			return nil, nil, ""
		}
		childRead := func(address string) (operation_setting.ClientEventsSnapshot, error) {
			var snapshot operation_setting.ClientEventsSnapshot
			req, e := http.NewRequest("GET", address+"/api/option/", nil)
			if e != nil {
				return snapshot, e
			}
			req.Header.Set("Authorization", "Bearer "+f.bearer["root"])
			resp, e := f.client.Do(req)
			if e != nil {
				return snapshot, e
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return snapshot, fmt.Errorf("child HTTP %d", resp.StatusCode)
			}
			var body struct {
				Data []model.Option `json:"data"`
			}
			if e := common.DecodeJson(resp.Body, &body); e != nil {
				return snapshot, e
			}
			for _, option := range body.Data {
				if option.Key == operation_setting.ClientEventsConfigKey {
					return snapshot, common.UnmarshalJsonStr(option.Value, &snapshot)
				}
			}
			return snapshot, errors.New("missing effective option")
		}
		cmd, input, address := startChild()
		stopped := false
		t.Cleanup(func() {
			if !stopped {
				input.Write([]byte("stop\n"))
				input.Close()
				cmd.Wait()
			}
		})
		state, err := childRead(address)
		require.NoError(t, err)
		assert.Equal(t, 2, state.RateLimit)
		write(operation_setting.ClientEventsConfigKey, `{"enabled":false,"retention_days":77,"rate_limit":17}`, "root", 200)
		require.Eventually(t, func() bool {
			state, err := childRead(address)
			return err == nil && state.Valid && !state.Enabled && state.RetentionDays == 77 && state.RateLimit == 17
		}, 5*time.Second, 25*time.Millisecond, "second process must observe the shared database through SyncOptions")
		_, err = input.Write([]byte("stop\n"))
		require.NoError(t, err)
		input.Close()
		require.NoError(t, cmd.Wait())
		stopped = true
		cmd2, input2, address2 := startChild()
		defer func() { input2.Write([]byte("stop\n")); input2.Close(); require.NoError(t, cmd2.Wait()) }()
		state, err = childRead(address2)
		require.NoError(t, err)
		assert.Equal(t, 77, state.RetentionDays)
		assert.False(t, state.Enabled)
		assert.Equal(t, "option", state.Source)
	})
}
