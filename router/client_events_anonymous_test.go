package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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

// This hook controls only transport timing/errors for the original GA script.
// Unblocked commands use the real exclusive Redis instance, never canned replies.
type clientEventGlobalRedisProbe struct {
	calls     atomic.Int32
	entered   chan time.Time
	cancelled chan struct{}
	release   <-chan struct{}
	err       error
}

func (h *clientEventGlobalRedisProbe) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	args := cmd.Args()
	if len(args) <= 3 || args[0] != "eval" || !strings.HasPrefix(fmt.Sprint(args[3]), "rateLimit:v2:ip:GA:") {
		return ctx, nil
	}
	h.calls.Add(1)
	deadline, _ := ctx.Deadline()
	h.entered <- deadline
	if h.release != nil {
		select {
		case <-ctx.Done():
			h.cancelled <- struct{}{}
			return ctx, ctx.Err()
		case <-h.release:
		}
	}
	return ctx, h.err
}
func (*clientEventGlobalRedisProbe) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (*clientEventGlobalRedisProbe) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (*clientEventGlobalRedisProbe) AfterProcessPipeline(context.Context, []redis.Cmder) error {
	return nil
}

func TestClientEventsAnonymousEntryOrder(t *testing.T) {
	t.Setenv("CLIENT_EVENTS_ENABLED", "false")
	require.NoError(t, service.InitClientEventsConfig())
	f := newOrganizationProfileFixture(t, "g4-issue25-anonymous-rework02")
	require.NoError(t, f.db.AutoMigrate(&model.ClientEvent{}))
	t.Setenv("TRUSTED_PROXIES", "none")
	require.NoError(t, f.engine.SetTrustedProxies(nil))
	socket := os.Getenv("ISSUE25_REDIS_SOCKET")
	require.NotEmpty(t, socket, "exclusive real Redis required")
	rdb := redis.NewClient(&redis.Options{Network: "unix", Addr: socket, MaxRetries: -1})
	defer rdb.Close()
	require.NoError(t, rdb.Ping(t.Context()).Err())
	version, err := rdb.Info(t.Context(), "server").Result()
	require.NoError(t, err)
	t.Log(strings.Split(version, "\r\n")[1])
	probe := &clientEventGlobalRedisProbe{entered: make(chan time.Time, 64)}
	rdb.AddHook(probe)
	common.RDB, common.RedisEnabled = rdb, true
	oldNum, oldDuration := common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration
	t.Cleanup(func() {
		common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = oldNum, oldDuration
	})
	common.GlobalApiRateLimitEnable = true
	common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = 100, 60
	require.NoError(t, model.UpdateClientEventsConfigOption(`{"enabled":true,"allow_anonymous":true,"retention_days":30,"rate_limit":600}`))
	payload := fmt.Sprintf(`{"client_id":"8a6c0e0e-6f3b-4c55-9d0e-2a1f7c9b1e11","channel":"issue25-order","events":[{"event_type":"app_launch","timestamp":%q,"data":{"version":"1","os":"linux"}}]}`, time.Now().UTC().Truncate(time.Second).Format(time.RFC3339))
	// Observe real completion/peers and control request-context cancellation.
	// HTTP/1 disconnect detection can wait for body reads while GA is blocked;
	// cancel the server request explicitly, never replace the gateway response.
	completed := make(chan string, 64)
	serverCancels := make(chan context.CancelFunc, 64)
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		serverCancels <- cancel
		f.engine.ServeHTTP(w, r.WithContext(ctx))
		completed <- r.RemoteAddr
	})
	type response struct {
		status int
		body   string
		err    error
	}
	var requests atomic.Int32
	send := func(ctx context.Context, client *http.Client, headers http.Header) response {
		requests.Add(1)
		req, err := http.NewRequestWithContext(ctx, "POST", f.server.URL+"/api/events", strings.NewReader(payload))
		if err != nil {
			return response{err: err}
		}
		req.Header.Set("Content-Type", "application/json")
		for key, values := range headers {
			req.Header[key] = append([]string(nil), values...)
		}
		resp, err := client.Do(req)
		if err != nil {
			return response{err: err}
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return response{status: resp.StatusCode, body: string(raw), err: err}
	}
	check := func(t *testing.T, result response, status int) {
		t.Helper()
		t.Logf("HTTP status=%d body=%s error=%v", result.status, result.body, result.err)
		require.NoError(t, result.err)
		require.Equal(t, status, result.status, "%s", result.body)
		var body map[string]any
		require.NoError(t, common.UnmarshalJsonStr(result.body, &body))
		if status != 200 {
			assert.Equal(t, map[int]string{400: "CLIENT_EVENTS_INVALID", 401: "CLIENT_EVENTS_UNAUTHORIZED", 429: "CLIENT_EVENTS_RATE_LIMIT", 503: "CLIENT_EVENTS_UNAVAILABLE"}[status], body["code"])
		}
	}
	peerClient := func(ip string) *http.Client {
		transport := &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}).DialContext}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	clearBudgets := func(t *testing.T) {
		t.Helper()
		keys, err := rdb.Keys(t.Context(), "rateLimit:v2:*").Result()
		require.NoError(t, err)
		if len(keys) > 0 {
			require.NoError(t, rdb.Del(t.Context(), keys...).Err())
		}
	}
	t.Cleanup(func() { t.Logf("ISSUE25_REWORK02_HTTP_POST_REQUESTS=%d", requests.Load()) })
	t.Run("full_site_precedes_every_global_peer_key", func(t *testing.T) {
		require.NoError(t, rdb.Set(t.Context(), "rateLimit:v2:client-events:anonymous:site", 600, time.Minute).Err())
		before, err := rdb.Keys(t.Context(), "*").Result()
		require.NoError(t, err)
		for _, ip := range []string{"127.0.0.31", "127.0.0.32", "127.0.0.33"} {
			check(t, send(t.Context(), peerClient(ip), nil), 429)
			peer := <-completed
			host, _, err := net.SplitHostPort(peer)
			require.NoError(t, err)
			assert.Equal(t, ip, host, "actual RemoteAddr, not a forwarding header")
			t.Logf("actual_transport_peer=%s", peer)
		}
		after, err := rdb.Keys(t.Context(), "*").Result()
		require.NoError(t, err)
		assert.ElementsMatch(t, before, after, "all Redis keys, including GA, remain bounded by fixed site rejection")
		assert.Zero(t, probe.calls.Load())
	})
	t.Run("admitted_global_once_and_header_present_unchanged", func(t *testing.T) {
		clearBudgets(t)
		common.GlobalApiRateLimitNum = 1
		before := probe.calls.Load()
		for _, status := range []int{200, 429} {
			check(t, send(t.Context(), f.client, nil), status)
		}
		assert.Equal(t, before+2, probe.calls.Load())
		count, err := rdb.Get(t.Context(), "rateLimit:v2:ip:GA:127.0.0.1").Int()
		require.NoError(t, err)
		assert.Equal(t, 2, count, "original global limiter executed exactly once per admission")
		common.GlobalApiRateLimitNum = 100
		require.NoError(t, rdb.Set(t.Context(), "rateLimit:v2:client-events:anonymous:site", 600, time.Minute).Err())
		for _, tc := range []struct {
			header http.Header
			status int
		}{{http.Header{"Authorization": {""}}, 401}, {http.Header{"Authorization": {"Bearer sk-a", "Bearer sk-b"}}, 400}, {http.Header{"Authorization": {"Basic invalid"}}, 401}} {
			before := probe.calls.Load()
			check(t, send(t.Context(), f.client, tc.header), tc.status)
			assert.Equal(t, before+1, probe.calls.Load(), "header presence keeps original global-first path even with full anonymous site")
		}
		common.RedisEnabled = false
		t.Setenv("TRUSTED_PROXIES", "")
		check(t, send(t.Context(), f.client, http.Header{"Authorization": {"Bearer " + f.bearer["relay"]}}), 200)
		common.RedisEnabled = true
		t.Setenv("TRUSTED_PROXIES", "none")
	})
	t.Run("slots_and_deadline_precede_blocked_global_and_release_on_error_cancel", func(t *testing.T) {
		clearBudgets(t)
		// Drain completion observations from the preceding synchronous requests.
		for len(completed) > 0 {
			<-completed
		}
		for len(serverCancels) > 0 {
			<-serverCancels
		}
		for batch := range 2 {
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			hook := &clientEventGlobalRedisProbe{entered: make(chan time.Time, 16), cancelled: make(chan struct{}, 8), release: release}
			if batch == 0 {
				hook.err = errors.New("owned GA transport failure")
			}
			held := redis.NewClient(&redis.Options{Network: "unix", Addr: socket, MaxRetries: -1})
			held.AddHook(hook)
			common.RDB = held
			results := make(chan response, 8)
			cancels := make([]context.CancelFunc, 8)
			var wg sync.WaitGroup
			defer func() {
				for _, cancel := range cancels {
					cancel()
				}
				unblock()
				wg.Wait()
				held.Close()
				common.RDB = rdb
			}()
			for i := range 8 {
				ctx, cancel := context.WithCancel(t.Context())
				cancels[i] = cancel
				wg.Go(func() { results <- send(ctx, f.client, nil) })
			}
			for range 8 {
				select {
				case deadline := <-hook.entered:
					require.False(t, deadline.IsZero(), "anonymous deadline must already exist at GA transport")
					assert.WithinRange(t, deadline, time.Now(), time.Now().Add(10*time.Second))
				case <-time.After(5 * time.Second):
					t.Fatal("eight requests did not reach GA with eight admitted slots")
				}
			}
			if batch == 0 {
				check(t, send(t.Context(), peerClient("127.0.0.39"), nil), 503)
				assert.Equal(t, int32(8), hook.calls.Load(), "ninth request never enters blocked GA")
				for i := range 9 {
					cancel := <-serverCancels
					if i < 4 {
						cancel()
					}
				}
				for range 4 {
					select {
					case <-hook.cancelled:
					case <-time.After(5 * time.Second):
						t.Fatal("GA transport did not observe request cancellation")
					}
				}
				t.Log("controlled_server_request_context_cancellations=4; real TCP-disconnect propagation is not asserted")
			}
			unblock()
			for range 8 {
				result := <-results
				if batch == 0 {
					check(t, result, 503)
				} else {
					check(t, result, 200)
				}
			}
			completions := 8
			if batch == 0 {
				completions++
			}
			for range completions {
				select {
				case <-completed:
				case <-time.After(5 * time.Second):
					t.Fatal("server did not complete and release anonymous admission")
				}
			}
			wg.Wait()
			common.RDB = rdb
			assert.Equal(t, int32(8), hook.calls.Load())
		}
		count, err := rdb.Get(t.Context(), "rateLimit:v2:ip:GA:127.0.0.1").Int()
		require.NoError(t, err)
		assert.Equal(t, 8, count, "only second-batch admitted GA calls reach real Redis")
		missing, err := rdb.Exists(t.Context(), "rateLimit:v2:ip:GA:127.0.0.39").Result()
		require.NoError(t, err)
		assert.Zero(t, missing)
		check(t, send(t.Context(), f.client, nil), 200)
	})
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
