package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// A controlled Redis transport barrier holds real requests after slot admission;
// commands still execute against the real Redis server once released.
type clientEventRedisBarrier struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (h clientEventRedisBarrier) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	args := cmd.Args()
	if len(args) > 3 && args[0] == "eval" && args[3] == "rateLimit:v2:client-events:anonymous:site" {
		h.entered <- struct{}{}
		select {
		case <-h.release:
		case <-ctx.Done():
			return ctx, ctx.Err()
		}
	}
	return ctx, nil
}
func (clientEventRedisBarrier) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (clientEventRedisBarrier) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (clientEventRedisBarrier) AfterProcessPipeline(context.Context, []redis.Cmder) error { return nil }

// Real router/HTTP, real owned SQL and real Redis. No fake auth reader or
// response handler. The runner must provision an exclusive Redis Unix socket.
func TestClientEventsAnonymousHTTP(t *testing.T) {
	t.Setenv("CLIENT_EVENTS_ENABLED", "false")
	require.NoError(t, service.InitClientEventsConfig())
	f := newOrganizationProfileFixture(t, "g4-issue25-anonymous")
	require.NoError(t, f.db.AutoMigrate(&model.ClientEvent{}))
	t.Setenv("TRUSTED_PROXIES", "none")
	require.NoError(t, f.engine.SetTrustedProxies(nil))
	socket := os.Getenv("ISSUE25_REDIS_SOCKET")
	require.NotEmpty(t, socket, "exclusive real Redis required, never miniredis")
	rdb := redis.NewClient(&redis.Options{Network: "unix", Addr: socket, MaxRetries: -1})
	require.NoError(t, rdb.Ping(t.Context()).Err())
	info, err := rdb.Info(t.Context(), "server").Result()
	require.NoError(t, err)
	t.Log(strings.Split(info, "\r\n")[1])
	common.RDB = rdb
	common.RedisEnabled = true
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	oldSearch := common.SearchRateLimitEnable
	common.SearchRateLimitEnable = false
	t.Cleanup(func() { common.SearchRateLimitEnable = oldSearch })
	var requests atomic.Int64
	stamp := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	payload := fmt.Sprintf(`{"client_id":"8a6c0e0e-6f3b-4c55-9d0e-2a1f7c9b1e11","channel":"issue25","user_id":999,"token_id":999,"events":[{"event_type":"app_launch","timestamp":%q,"data":{"version":"1","os":"linux","secret":"discard-me"}}]}`, stamp)
	post := func(t *testing.T, actor, body string, extra http.Header, want int, wantCount int) {
		t.Helper()
		requests.Add(1)
		h := http.Header{"Content-Type": {"application/json"}}
		for k, v := range extra {
			h[k] = v
		}
		s, headers, result := f.request(t, "POST", "/api/events", actor, body, h)
		require.Equal(t, want, s, "%v", result)
		assert.Contains(t, headers.Get("Cache-Control"), "no-store")
		if want == 200 {
			assert.Equal(t, float64(wantCount), result["count"])
		} else {
			assert.NotContains(t, result, "count")
		}
		if want == 429 {
			assert.NotEmpty(t, headers.Get("Retry-After"))
		}
	}
	config := func(enabled, anon bool, rate int) string {
		return fmt.Sprintf(`{"enabled":%t,"allow_anonymous":%t,"retention_days":30,"rate_limit":%d}`, enabled, anon, rate)
	}
	save := func(t *testing.T, value string) {
		t.Helper()
		require.NoError(t, model.UpdateClientEventsConfigOption(value))
	}
	reset := func(t *testing.T) {
		t.Helper()
		require.NoError(t, f.db.Where("id > 0").Delete(&model.ClientEvent{}).Error)
		keys, err := rdb.Keys(t.Context(), "rateLimit:v2:client-events:anonymous:*").Result()
		require.NoError(t, err)
		if len(keys) > 0 {
			require.NoError(t, rdb.Del(t.Context(), keys...).Err())
		}
		common.RedisEnabled = true
		common.RDB = rdb
		save(t, config(true, false, 600))
		save(t, config(true, true, 600))
	}
	t.Cleanup(func() { t.Logf("ISSUE25_GATEWAY_POST_REQUESTS=%d", requests.Load()) })
	t.Run("default_and_strict_legacy_configuration", func(t *testing.T) {
		require.NoError(t, model.ReloadClientEventsConfig())
		assert.False(t, service.CurrentClientEventsConfig().AllowAnonymous)
		post(t, "", payload, nil, 404, 0)
		legacy := `{"enabled":true,"retention_days":30,"rate_limit":60}`
		save(t, legacy)
		post(t, "", payload, nil, 401, 0)
		assert.False(t, service.CurrentClientEventsConfig().AllowAnonymous)
		save(t, config(true, true, 600))
		assert.ErrorIs(t, model.UpdateClientEventsConfigOption(legacy), operation_setting.ErrClientEventsConfig)
		assert.True(t, service.CurrentClientEventsConfig().AllowAnonymous)
		// The real root-only settings entry returns/preserves the fourth field.
		for _, value := range []string{config(true, false, 600), legacy, config(true, true, 600)} {
			body, err := common.Marshal(map[string]any{"key": operation_setting.ClientEventsConfigKey, "value": value})
			require.NoError(t, err)
			status, _, response := f.request(t, "PUT", "/api/option/", "root", string(body), http.Header{"Content-Type": {"application/json"}})
			require.Equal(t, 200, status, "%v", response)
		}
		status, _, response := f.request(t, "GET", "/api/option/", "root", "", nil)
		require.Equal(t, 200, status)
		var saved operation_setting.ClientEventsSnapshot
		for _, raw := range response["data"].([]any) {
			option := raw.(map[string]any)
			if option["key"] == operation_setting.ClientEventsConfigKey {
				require.NoError(t, common.UnmarshalJsonStr(option["value"].(string), &saved))
			}
		}
		assert.True(t, saved.AllowAnonymous)
		assert.True(t, saved.Valid)
		body, err := common.Marshal(map[string]any{"key": operation_setting.ClientEventsConfigKey, "value": legacy})
		require.NoError(t, err)
		status, _, _ = f.request(t, "PUT", "/api/option/", "root", string(body), http.Header{"Content-Type": {"application/json"}})
		assert.Equal(t, 400, status)

		for _, value := range []string{`{"enabled":true,"allow_anonymous":null,"retention_days":30,"rate_limit":60}`, `{"enabled":true,"allow_anonymous":true,"allow_anonymous":false,"retention_days":30,"rate_limit":60}`, `{"enabled":true,"allow_anonymous":true,"retention_days":30,"rate_limit":60,"other":1}`, `{"enabled":true,"allow_anonymous":1,"retention_days":30,"rate_limit":60}`} {
			assert.ErrorIs(t, model.UpdateClientEventsConfigOption(value), operation_setting.ErrClientEventsConfig)
		}
		// Unknown historic zero rows fail closed, without silently relabelling.
		save(t, config(true, false, 600))
		bad := model.ClientEvent{Fingerprint: strings.Repeat("b", 64)}
		require.NoError(t, f.db.Create(&bad).Error)
		assert.Error(t, model.UpdateClientEventsConfigOption(config(true, true, 600)))
		assert.False(t, service.CurrentClientEventsConfig().AllowAnonymous)
		require.NoError(t, f.db.Delete(&bad).Error)
	})
	t.Run("anonymous_success_retry_and_whitelist", func(t *testing.T) {
		reset(t)
		post(t, "", payload, nil, 200, 1)
		post(t, "", payload, nil, 200, 0)
		var rows []model.ClientEvent
		require.NoError(t, f.db.Find(&rows).Error)
		require.Len(t, rows, 1)
		assert.Zero(t, rows[0].UserID)
		assert.Zero(t, rows[0].TokenID)
		assert.Equal(t, "issue25", rows[0].Channel)
		post(t, "", strings.Replace(payload, `"os":"linux"`, `"os":"unknown"`, 1), nil, 200, 0)
		post(t, "", payload, http.Header{"X-Client-Id": {"not-uuid"}}, 400, 0)
		post(t, "", strings.Repeat("x", 256*1024+1), nil, 413, 0)
	})
	t.Run("credentials_never_downgrade_and_auth_independent", func(t *testing.T) {
		reset(t)
		for _, header := range []http.Header{{"Authorization": {""}}, {"Authorization": {"Basic nope"}}, {"Authorization": {"Bearer sk-unknown"}}, {"Authorization": {"Bearer sk-a", "Bearer sk-b"}}} {
			want := 401
			if len(header["Authorization"]) > 1 {
				want = 400
			}
			post(t, "", payload, header, want, 0)
		}
		var token model.Token
		require.NoError(t, f.db.Where(map[string]any{"key": f.bearer["relay"][3:]}).First(&token).Error)
		for _, change := range []map[string]any{{"status": common.TokenStatusDisabled}, {"status": common.TokenStatusEnabled, "expired_time": time.Now().Unix() - 1}} {
			require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Updates(change).Error)
			post(t, "relay", payload, nil, 401, 0)
		}
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", token.Id).Updates(map[string]any{"status": common.TokenStatusEnabled, "expired_time": -1}).Error)
		common.RedisEnabled = false
		t.Setenv("TRUSTED_PROXIES", "")
		post(t, "relay", payload, nil, 200, 1)
		post(t, "", payload, nil, 503, 0)
		common.RedisEnabled = true
		t.Setenv("TRUSTED_PROXIES", "none")
	})
	t.Run("identity_and_sql_cohort_isolation", func(t *testing.T) {
		reset(t)
		post(t, "relay", payload, nil, 200, 1)
		post(t, "", payload, nil, 200, 1)
		// Same normalized report, independent identity and namespace.
		var rows []model.ClientEvent
		require.NoError(t, f.db.Order("id").Find(&rows).Error)
		require.Len(t, rows, 2)
		assert.NotEqual(t, rows[0].Fingerprint, rows[1].Fingerprint)
		path := fmt.Sprintf("/api/events/clients?start_time=%d&end_time=%d", time.Now().Unix()-30, time.Now().Unix()+30)
		var versions []any
		for _, cohort := range []string{"authenticated", "anonymous"} {
			s, _, body := f.request(t, "GET", path+"&authentication="+cohort, "root", "", nil)
			require.Equal(t, 200, s, "%v", body)
			data := body["data"].(map[string]any)
			assert.Equal(t, cohort, data["authentication"])
			versions = append(versions, data["result_version"])
			require.Len(t, data["items"], 1)
			if cohort == "anonymous" {
				assert.Equal(t, "unverified_channel_client", data["identity_basis"])
				assert.Equal(t, "claimed_client_identifiers", data["count_basis"])
			}
		}
		assert.NotEqual(t, versions[0], versions[1])
		s, _, body := f.request(t, "GET", path, "root", "", nil)
		require.Equal(t, 200, s)
		assert.Equal(t, "authenticated", body["data"].(map[string]any)["authentication"])
		s, _, _ = f.request(t, "GET", path+"&authentication=all", "root", "", nil)
		assert.Equal(t, 400, s)
		s, _, _ = f.request(t, "GET", path+"&authentication=anonymous", "owner", "", nil)
		assert.Equal(t, 403, s)
	})
	t.Run("layered_redis_limits_and_no_fallback", func(t *testing.T) {
		reset(t)
		save(t, config(true, true, 1))
		post(t, "", payload, nil, 200, 1)
		post(t, "", strings.Replace(payload, "8a6c0e0e", "7a6c0e0e", 1), http.Header{"X-Forwarded-For": {"203.0.113.44"}}, 429, 0)
		ttl, err := rdb.TTL(t.Context(), "rateLimit:v2:client-events:anonymous:site").Result()
		require.NoError(t, err)
		assert.Greater(t, ttl, time.Duration(0))
		assert.LessOrEqual(t, ttl, time.Minute)
		reset(t)
		require.NoError(t, rdb.Set(t.Context(), "rateLimit:v2:client-events:anonymous:site", 600, time.Minute).Err())
		before, err := rdb.Keys(t.Context(), "rateLimit:v2:client-events:anonymous:*").Result()
		require.NoError(t, err)
		post(t, "", payload, nil, 429, 0)
		after, err := rdb.Keys(t.Context(), "rateLimit:v2:client-events:anonymous:*").Result()
		require.NoError(t, err)
		assert.ElementsMatch(t, before, after)

		reset(t)
		pair := "rateLimit:v2:client-events:anonymous:pair:127.0.0.1:8a6c0e0e-6f3b-4c55-9d0e-2a1f7c9b1e11"
		require.NoError(t, rdb.Set(t.Context(), pair, 600, time.Minute).Err())
		post(t, "", payload, nil, 429, 0)
		reset(t)
		entered, release := make(chan struct{}, 8), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		held := redis.NewClient(&redis.Options{Network: "unix", Addr: socket, MaxRetries: -1})
		defer held.Close()
		held.AddHook(clientEventRedisBarrier{entered: entered, release: release})
		common.RDB = held
		results := make(chan error, 8)
		for range 8 {
			requests.Add(1)
			go func() {
				req, err := http.NewRequest("POST", f.server.URL+"/api/events", strings.NewReader(payload))
				if err != nil {
					results <- err
					return
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := f.client.Do(req)
				if err != nil {
					results <- err
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					results <- fmt.Errorf("held request HTTP %d", resp.StatusCode)
					return
				}
				results <- nil
			}()
		}
		for range 8 {
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("eight owned requests did not occupy slots")
			}
		}
		post(t, "", payload, nil, 503, 0)
		unblock()
		for range 8 {
			require.NoError(t, <-results)
		}
		common.RDB = rdb
		broken := redis.NewClient(&redis.Options{Network: "unix", Addr: socket + "-absent", MaxRetries: -1})
		defer broken.Close()
		common.RDB = broken
		post(t, "", payload, nil, 503, 0)
		common.RDB = rdb
		common.RedisEnabled = false
		post(t, "", payload, nil, 503, 0)
		common.RedisEnabled = true
	})
	t.Run("capacity_dedup_concurrency_and_atomic_rollback", func(t *testing.T) {
		reset(t)
		event := model.ClientEvent{ClientID: "8a6c0e0e-6f3b-4c55-9d0e-2a1f7c9b1e11", Channel: "concurrent", EventType: "app_launch", EventTimeMS: time.Now().UnixMilli(), ReceivedAt: time.Now().Unix(), OS: "linux"}
		// Ordinary independent concurrent transactions, not a distributed rollout claim.
		counts := make(chan int, 2)
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				n, err := model.ReceiveAnonymousClientEvents(context.Background(), []model.ClientEvent{event})
				counts <- n
				errs <- err
			})
		}
		wg.Wait()
		close(counts)
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		sum := 0
		for n := range counts {
			sum += n
		}
		assert.Equal(t, 1, sum)
		var created atomic.Int32
		require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("issue25:batch-failure", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" && created.Add(1) == 2 {
				tx.AddError(errors.New("owned fixture insert failure"))
			}
		}))
		a, b := event, event
		a.Channel = "rollback-a"
		b.Channel = "rollback-b"
		n, err := model.ReceiveAnonymousClientEvents(t.Context(), []model.ClientEvent{a, b})
		assert.Error(t, err)
		assert.Zero(t, n)
		require.NoError(t, f.db.Callback().Create().Remove("issue25:batch-failure"))
		var count int64
		require.NoError(t, f.db.Model(&model.ClientEvent{}).Where("channel IN ?", []string{a.Channel, b.Channel}).Count(&count).Error)
		assert.Zero(t, count)
		// Deliberately synthetic retained rows only exercise the exact SQL capacity
		// boundary; they are not claimed to be valid historical anonymous reports.
		batch := make([]model.ClientEvent, 99999)
		for i := range batch {
			batch[i] = model.ClientEvent{Fingerprint: fmt.Sprintf("%064x", i+1), ReceivedAt: time.Now().Unix()}
		}
		require.NoError(t, f.db.CreateInBatches(batch, 500).Error)
		n, err = model.ReceiveAnonymousClientEvents(t.Context(), []model.ClientEvent{event})
		require.NoError(t, err)
		assert.Zero(t, n)
		n, err = model.ReceiveAnonymousClientEvents(t.Context(), []model.ClientEvent{a, event})
		assert.Error(t, err)
		assert.Zero(t, n)
		require.NoError(t, f.db.Model(&model.ClientEvent{}).Count(&count).Error)
		assert.Equal(t, int64(100000), count)
		require.NoError(t, f.db.Delete(&batch[0]).Error)
		n, err = model.ReceiveAnonymousClientEvents(t.Context(), []model.ClientEvent{a})
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		// An anonymous flood cannot consume the authenticated query candidate
		// limit or the authenticated writer's storage allowance.
		post(t, "relay", payload, nil, 200, 1)
		path := fmt.Sprintf("/api/events/clients?start_time=%d&end_time=%d", time.Now().Unix()-30, time.Now().Unix()+30)
		status, _, body := f.request(t, "GET", path, "root", "", nil)
		require.Equal(t, 200, status, "%v", body)
		data := body["data"].(map[string]any)
		assert.Equal(t, "authenticated", data["authentication"])
		require.Len(t, data["items"], 1)
		status, _, body = f.request(t, "GET", path+"&authentication=anonymous", "root", "", nil)
		assert.Equal(t, 422, status, "%v", body)
	})
	t.Run("disable_ordering_and_no_billing_or_sensitive_payload", func(t *testing.T) {
		reset(t)
		var beforeUser, afterUser model.User
		var beforeToken, afterToken model.Token
		require.NoError(t, f.db.First(&beforeUser, f.users["owner"].Id).Error)
		require.NoError(t, f.db.Where(map[string]any{"key": f.bearer["relay"][3:]}).First(&beforeToken).Error)
		var logBefore, logAfter int64
		require.NoError(t, model.LOG_DB.Model(&model.Log{}).Count(&logBefore).Error)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("issue25:hold-write", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				once.Do(func() { close(entered); <-release })
			}
		}))
		done := make(chan error, 1)
		go func() {
			_, err := model.ReceiveAnonymousClientEvents(context.Background(), []model.ClientEvent{{ClientID: "bounded", Channel: "ordering", EventType: "app_launch", EventTimeMS: time.Now().UnixMilli(), ReceivedAt: time.Now().Unix(), OS: "linux"}})
			done <- err
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("writer did not reach held insert")
		}
		disabled := make(chan error, 1)
		go func() { disabled <- model.UpdateClientEventsConfigOption(config(true, false, 600)) }()
		close(release)
		require.NoError(t, <-done)
		require.NoError(t, <-disabled)
		require.NoError(t, f.db.Callback().Create().Remove("issue25:hold-write"))
		_, err := model.ReceiveAnonymousClientEvents(t.Context(), nil)
		assert.ErrorIs(t, err, model.ErrClientEventDisabled)
		post(t, "", payload, nil, 401, 0)
		save(t, config(true, true, 600))
		post(t, "", payload, nil, 200, 1)
		require.NoError(t, f.db.First(&afterUser, beforeUser.Id).Error)
		require.NoError(t, f.db.First(&afterToken, beforeToken.Id).Error)
		assert.Equal(t, beforeUser.Quota, afterUser.Quota)
		assert.Equal(t, beforeUser.UsedQuota, afterUser.UsedQuota)
		assert.Equal(t, beforeUser.RequestCount, afterUser.RequestCount)
		assert.Equal(t, beforeToken.RemainQuota, afterToken.RemainQuota)
		assert.Equal(t, beforeToken.UsedQuota, afterToken.UsedQuota)
		require.NoError(t, model.LOG_DB.Model(&model.Log{}).Count(&logAfter).Error)
		assert.Equal(t, logBefore, logAfter)
		assert.NotContains(t, f.logs.snapshot(), "discard-me")
		assert.NotContains(t, f.logs.snapshot(), f.bearer["relay"])
	})
}
