package router

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func clientStatsData(t *testing.T, f *organizationHTTPFixture, path, actor string) map[string]any {
	t.Helper()
	status, h, body := f.request(t, "GET", path, actor, "", nil)
	require.Equal(t, 200, status, "%v", body)
	require.Equal(t, true, body["success"])
	assert.Contains(t, h.Get("Cache-Control"), "no-store")
	assert.Contains(t, h.Get("Cache-Control"), "private")
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "client_self_reported", data["provenance"])
	assert.Equal(t, "retained_events", data["coverage"])
	assert.Equal(t, false, data["data_complete"])
	raw, err := common.Marshal(data)
	require.NoError(t, err)
	for _, key := range []string{"user_id", "client_id", "token_id", "fingerprint", "quota", "raw_event"} {
		assert.NotContains(t, string(raw), `"`+key+`"`)
	}
	return data
}

func clientStatsFailure(t *testing.T, f *organizationHTTPFixture, path, actor string, want int, code string) {
	t.Helper()
	status, h, body := f.request(t, "GET", path, actor, "", nil)
	require.Equal(t, want, status, "%v", body)
	assert.Equal(t, false, body["success"])
	if code != "" {
		assert.Equal(t, code, body["code"])
	}
	assert.NotContains(t, body, "data")
	assert.NotContains(t, body, "items")
	assert.Contains(t, h.Get("Cache-Control"), "no-store")
	assert.Contains(t, h.Get("Cache-Control"), "private")
}

// Uses the existing full-router fixture and only its collision-failing databases.
// The runner must select each real engine explicitly; there is no SQLite fallback.
func TestClientEventsQueryHTTP(t *testing.T) {
	require.Equal(t, "g1-W03-08-client-stats", os.Getenv("NEWAPI_S2_OWNED"))
	require.Contains(t, []string{"sqlite", "mysql", "postgres"}, os.Getenv("NEWAPI_S2_MAIN"))
	oldSearch := common.SearchRateLimitEnable
	common.SearchRateLimitEnable = false
	t.Cleanup(func() { common.SearchRateLimitEnable = oldSearch })
	t.Setenv("CLIENT_EVENTS_ENABLED", "true")
	t.Setenv("CLIENT_EVENTS_RATE_LIMIT", "600")
	t.Setenv("CLIENT_EVENTS_RETENTION_DAYS", "30")
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
	require.NoError(t, f.db.Model(f.users["admin"]).Update("role", common.RoleAdminUser).Error)
	// A second pool performs real authoritative mutations after the event SELECT.
	var dial gorm.Dialector
	switch f.mainKind {
	case "mysql":
		dial = mysql.Open(f.mainDSN)
	case "postgres":
		dial = postgres.New(postgres.Config{DSN: f.mainDSN, PreferSimpleProtocol: true})
	default:
		dial = sqlite.Open(f.mainDSN)
	}
	independent, err := gorm.Open(dial, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	conn, err := independent.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	now := time.Now().UTC().Truncate(time.Second)
	start, end := now.Add(-48*time.Hour).Unix(), now.Add(time.Hour).Unix()
	window := fmt.Sprintf("start_time=%d&end_time=%d", start, end)
	usage := "/api/events/usage?" + window
	clients := "/api/events/clients?" + window
	encode := func(v any) string { b, e := common.Marshal(v); require.NoError(t, e); return string(b) }
	clear := func() { require.NoError(t, f.db.Where("id > ?", 0).Delete(&model.ClientEvent{}).Error) }
	var serial int64
	insert := func(rows []model.ClientEvent) {
		for i := range rows {
			serial++
			rows[i].Fingerprint = fmt.Sprintf("%064x", serial)
		}
		require.NoError(t, f.db.CreateInBatches(&rows, 500).Error)
	}
	number := int64(1)
	zero := int64(0)
	maxCounter := int64(9007199254740991)
	base := model.ClientEvent{UserID: f.users["owner"].Id, ClientID: "8a6c0e0e-6f3b-4c55-9d0e-2a1f7c9b1e11", Channel: "cherry", EventType: "token_usage", EventTimeMS: now.Add(-time.Hour).UnixMilli(), ReceivedAt: now.Unix(), Model: "Example", Provider: "new-api", Source: "chat", InputTokens: &number, OutputTokens: &zero}
	makePAT := func(user string, scopes []string) (string, *model.UserAccessToken) {
		raw := "nap_" + common.NewRequestId() + common.NewRequestId()
		token := &model.UserAccessToken{UserId: f.users[user].Id, Name: "stats fixture", TokenHash: model.AccessTokenFingerprint(raw), ExpiresAt: time.Now().Unix() + 3600}
		require.NoError(t, token.SetScopes(scopes))
		require.NoError(t, f.db.Create(token).Error)
		return raw, token
	}
	pat, patRow := makePAT("admin", []string{"log:read"})

	t.Run("receive_to_aggregate_and_activity_identity", func(t *testing.T) {
		clear()
		raw := "Events" + strings.Repeat("b", 34)
		token := model.Token{UserId: f.users["foreign"].Id, Key: raw, Status: common.TokenStatusEnabled, ExpiredTime: -1}
		require.NoError(t, f.db.Create(&token).Error)
		rotated := model.Token{UserId: f.users["owner"].Id, Key: "Events" + strings.Repeat("c", 34), Status: common.TokenStatusEnabled, ExpiredTime: -1}
		require.NoError(t, f.db.Create(&rotated).Error)
		stamp := now.Add(-time.Hour).In(time.FixedZone("test-offset", 8*3600)).Format(time.RFC3339)
		events := []any{map[string]any{"event_type": "token_usage", "timestamp": stamp, "data": map[string]any{"model": "Example", "provider": "new-api", "source": "chat", "input_tokens": maxCounter, "output_tokens": 0}}, map[string]any{"event_type": "app_launch", "timestamp": stamp, "data": map[string]any{"version": "2.1", "os": "linux"}}}
		body := map[string]any{"client_id": base.ClientID, "channel": "cherry", "events": events}
		for _, tc := range []struct {
			actor string
			count float64
		}{{"relay", 2}, {"relay", 0}, {"sk-" + rotated.Key, 0}, {"sk-" + raw, 2}} {
			s, _, b := f.request(t, "POST", "/api/events", tc.actor, encode(body), http.Header{"Content-Type": {"application/json"}})
			require.Equal(t, 200, s)
			assert.Equal(t, tc.count, b["count"])
		}
		d := clientStatsData(t, f, usage, "admin")
		items := d["items"].([]any)
		require.Len(t, items, 1)
		item := items[0].(map[string]any)
		assert.Equal(t, "18014398509481982", item["input_tokens"])
		assert.Equal(t, "0", item["output_tokens"])
		assert.Equal(t, float64(2), item["events"])
		launch := base
		launch.EventType = "app_launch"
		launch.InputTokens = nil
		launch.OutputTokens = nil
		launch.AppVersion = "2.1"
		launch.OS = "linux"
		same := launch
		same.EventTimeMS++
		otherChannel := launch
		otherChannel.Channel = "other"
		newVersion := launch
		newVersion.AppVersion = "2.2"
		unknown := launch
		unknown.AppVersion = ""
		update := launch
		update.EventType = "app_update"
		update.AppVersion = "not-activity"
		insert([]model.ClientEvent{same, otherChannel, newVersion, unknown, update})
		d = clientStatsData(t, f, clients, "root")
		assert.Equal(t, false, d["groups_additive"])
		assert.Equal(t, "app_launch", d["activity_basis"])
		assert.Equal(t, "user_channel_client", d["identity_basis"])
		assert.Equal(t, []any{map[string]any{"version": "", "os": "linux", "active_clients": float64(1)}, map[string]any{"version": "2.1", "os": "linux", "active_clients": float64(3)}, map[string]any{"version": "2.2", "os": "linux", "active_clients": float64(1)}}, d["items"])
		d = clientStatsData(t, f, clients+"&version=", pat)
		require.Len(t, d["items"], 1)
		// Historical reads remain available while the formal receiver is disabled.
		t.Setenv("CLIENT_EVENTS_ENABLED", "false")
		require.NoError(t, service.InitClientEventsConfig())
		require.NoError(t, model.ReloadClientEventsConfig())
		d = clientStatsData(t, f, usage, pat)
		assert.Equal(t, false, d["intake_enabled"])
		s, _, _ := f.request(t, "POST", "/api/events", "relay", encode(body), nil)
		assert.Equal(t, 404, s)
		t.Setenv("CLIENT_EVENTS_ENABLED", "true")
		require.NoError(t, service.InitClientEventsConfig())
		require.NoError(t, model.ReloadClientEventsConfig())
	})

	t.Run("null_precision_case_filters_and_utc", func(t *testing.T) {
		clear()
		// Deliberately use a non-UTC connection timezone where supported.
		pool, e := f.db.DB()
		require.NoError(t, e)
		pool.SetMaxOpenConns(1)
		defer pool.SetMaxOpenConns(8)
		if f.mainKind == "postgres" {
			require.NoError(t, f.db.Exec("SET TIME ZONE 'Pacific/Honolulu'").Error)
		}
		if f.mainKind == "mysql" {
			require.NoError(t, f.db.Exec("SET time_zone = '-10:00'").Error)
		}
		names := []string{"Model", "model", "model ", "é", "e\u0301"}
		rows := []model.ClientEvent{}
		for _, name := range names {
			row := base
			row.Model = name
			rows = append(rows, row)
		}
		for _, provider := range []string{"Provider", "provider", "provider "} {
			row := base
			row.Model, row.Provider = "provider-case", provider
			rows = append(rows, row)
		}
		filtered := base
		filtered.Model, filtered.Channel, filtered.Source = "filtered", "Cherry", "agent"
		rows = append(rows, filtered)
		partial := base
		partial.Model = "NULL-part"
		partial.InputTokens = nil
		partial.OutputTokens = nil
		known := partial
		known.InputTokens = &zero
		null := partial
		null.Model = "NULL-all"
		day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		before := base
		before.Model = "Midnight"
		before.EventTimeMS = day.UnixMilli() - 1
		after := before
		after.EventTimeMS++
		rows = append(rows, partial, known, null, before, after)
		insert(rows)
		d := clientStatsData(t, f, usage+"&model=NULL-part", "root")
		item := d["items"].([]any)[0].(map[string]any)
		assert.Equal(t, "0", item["input_tokens"])
		assert.Nil(t, item["output_tokens"])
		assert.Equal(t, float64(1), item["input_missing_events"])
		assert.Equal(t, float64(2), item["output_missing_events"])
		assert.Equal(t, false, item["counter_data_complete"])
		d = clientStatsData(t, f, usage+"&model=NULL-all", "root")
		item = d["items"].([]any)[0].(map[string]any)
		assert.Nil(t, item["input_tokens"])
		for _, name := range names {
			d = clientStatsData(t, f, usage+"&model="+url.QueryEscape(name), "root")
			require.Len(t, d["items"], 1)
			assert.Equal(t, name, d["items"].([]any)[0].(map[string]any)["model"])
		}
		for _, provider := range []string{"Provider", "provider", "provider "} {
			d = clientStatsData(t, f, usage+"&model=provider-case&provider="+url.QueryEscape(provider), "root")
			require.Len(t, d["items"], 1)
			assert.Equal(t, provider, d["items"].([]any)[0].(map[string]any)["provider"])
		}
		d = clientStatsData(t, f, usage+"&model=filtered&channel=Cherry&source=agent", "root")
		require.Len(t, d["items"], 1)
		assert.Empty(t, clientStatsData(t, f, usage+"&model=filtered&channel=cherry", "root")["items"])
		assert.Empty(t, clientStatsData(t, f, usage+"&model=filtered&source=chat", "root")["items"])
		d = clientStatsData(t, f, usage+"&model=Midnight", "root")
		items := d["items"].([]any)
		require.Len(t, items, 2)
		assert.Equal(t, day.Add(-24*time.Hour).Format("2006-01-02"), items[0].(map[string]any)["day"])
		assert.Equal(t, day.Format("2006-01-02"), items[1].(map[string]any)["day"])
		clear()
		a := base
		a.EventTimeMS = start * 1000
		a.ReceivedAt = start - 3600
		b := base
		b.EventTimeMS = end*1000 - 1
		b.ReceivedAt = end + 7*86400 - 1
		c := base
		c.EventTimeMS = start*1000 - 1
		eRow := base
		eRow.EventTimeMS = end * 1000
		insert([]model.ClientEvent{a, b, c, eRow})
		d = clientStatsData(t, f, usage, "root")
		count := float64(0)
		for _, v := range d["items"].([]any) {
			count += v.(map[string]any)["events"].(float64)
		}
		assert.Equal(t, float64(2), count)
		d = clientStatsData(t, f, fmt.Sprintf("/api/events/usage?start_time=%d&end_time=%d", start, start+1), "root")
		require.Len(t, d["items"], 1)
		clear()
		bad := base
		n := int64(-1)
		bad.InputTokens = &n
		insert([]model.ClientEvent{bad})
		clientStatsFailure(t, f, usage, "root", 503, "CLIENT_EVENTS_QUERY_UNAVAILABLE")
		clear()
		n = maxCounter + 1
		insert([]model.ClientEvent{bad})
		clientStatsFailure(t, f, usage, "root", 503, "CLIENT_EVENTS_QUERY_UNAVAILABLE")
	})

	t.Run("strict_parameters_and_pagination", func(t *testing.T) {
		clear()
		rows := []model.ClientEvent{}
		for _, name := range []string{"c", "a", "b"} {
			row := base
			row.Model = name
			rows = append(rows, row)
		}
		insert(rows)
		first := clientStatsData(t, f, usage+"&page_size=1", "root")
		version := first["result_version"].(string)
		same := clientStatsData(t, f, usage+"&page_size=2", pat)
		assert.Equal(t, version, same["result_version"])
		next := clientStatsData(t, f, usage+"&page=2&page_size=1&result_version="+version, pat)
		assert.Equal(t, "b", next["items"].([]any)[0].(map[string]any)["model"])
		empty := clientStatsData(t, f, usage+"&page=20&page_size=1&result_version="+version, "root")
		assert.Empty(t, empty["items"])
		assert.Equal(t, float64(3), empty["total"])
		row := base
		row.Model = "d"
		insert([]model.ClientEvent{row})
		clientStatsFailure(t, f, usage+"&result_version="+version, "root", 409, "CLIENT_EVENTS_QUERY_CHANGED")
		clear()
		clientStatsFailure(t, f, usage+"&page=2&result_version="+version, "root", 409, "CLIENT_EVENTS_QUERY_CHANGED")
		assert.Empty(t, clientStatsData(t, f, usage, "root")["items"])
		invalid := []string{"group_by=model", "page=01", "page=0", "page=-1", "page=%2B1", "page=1.0", "page=1e2", "page=2", "page_size=101", "page=2000&page_size=100", "page=1&page=1", "%70age=1&page=1", "page[]=1", "source=unknown", "source=", "channel=", "model=%00", "model=%FF", "model=%EF%BF%BD", "model=" + strings.Repeat("a", 256), "version=1", "os=linux", "result_version=sha256:" + strings.Repeat("A", 64), "result_version=", "a=%", "start_time=0", "start_time=0&end_time=2678401", fmt.Sprintf("start_time=%d&end_time=%d", end, end), fmt.Sprintf("start_time=%d&end_time=%d", end, end+3601), "model=" + strings.Repeat("x", 4097), "page=1;page_size=2"}
		for _, q := range invalid {
			clientStatsFailure(t, f, "/api/events/usage?"+q, "root", 400, "CLIENT_EVENTS_QUERY_INVALID")
		}
		for _, q := range []string{"model=a", "version=" + strings.Repeat("v", 33), "os=", "os=windows", "source=chat"} {
			clientStatsFailure(t, f, "/api/events/clients?"+q, "root", 400, "CLIENT_EVENTS_QUERY_INVALID")
		}
	})

	t.Run("credential_boundaries", func(t *testing.T) {
		clear()
		insert([]model.ClientEvent{base})
		commonPAT, _ := makePAT("owner", []string{"log:read"})
		missing, _ := makePAT("admin", []string{"profile:read"})
		for _, tc := range []struct {
			actor  string
			status int
		}{{"", 401}, {"owner", 403}, {commonPAT, 403}, {"relay", 401}, {missing, 403}} {
			for _, path := range []string{usage, clients} {
				clientStatsFailure(t, f, path, tc.actor, tc.status, "")
			}
		}
		for _, actor := range []string{"root", "admin", pat} {
			clientStatsData(t, f, usage, actor)
			clientStatsData(t, f, clients, actor)
		}
		s, _, b := f.request(t, "GET", usage, "root", "", http.Header{"X-Organization-Id": {fmt.Sprint(f.orgA)}})
		assert.Equal(t, 403, s)
		assert.Equal(t, "ORG_RESOURCE_UNSUPPORTED", b["code"])
		assert.NotContains(t, b, "data")
	})

	t.Run("authoritative_changes_after_event_select", func(t *testing.T) {
		clear()
		insert([]model.ClientEvent{base})
		legacy := strings.Repeat("L", 32)
		require.NoError(t, f.db.Model(f.users["admin"]).Update("access_token", legacy).Error)
		cases := []struct {
			name, actor      string
			table            any
			where            string
			id               any
			changes, restore map[string]any
			status           int
		}{
			{"role", "admin", &model.User{}, "id = ?", f.users["admin"].Id, map[string]any{"role": common.RoleCommonUser}, map[string]any{"role": common.RoleAdminUser}, 403},
			{"status", pat, &model.User{}, "id = ?", f.users["admin"].Id, map[string]any{"status": common.UserStatusDisabled}, map[string]any{"status": common.UserStatusEnabled}, 401},
			{"auth_version", pat, &model.User{}, "id = ?", f.users["admin"].Id, map[string]any{"auth_version": 2}, map[string]any{"auth_version": 1}, 401},
			{"user_deleted", "admin", &model.User{}, "id = ?", f.users["admin"].Id, map[string]any{"deleted_at": time.Now()}, map[string]any{"deleted_at": nil}, 401},
			{"session_revoked", "admin", &model.UserSession{}, "sid = ?", f.sids["admin"], map[string]any{"revoked_at": now.Unix()}, map[string]any{"revoked_at": 0}, 401},
			{"session_status", "admin", &model.UserSession{}, "sid = ?", f.sids["admin"], map[string]any{"status": "revoked"}, map[string]any{"status": "active"}, 401},
			{"session_version", "admin", &model.UserSession{}, "sid = ?", f.sids["admin"], map[string]any{"version": 2}, map[string]any{"version": 1}, 401},
			{"session_user_version", "admin", &model.UserSession{}, "sid = ?", f.sids["admin"], map[string]any{"user_auth_version": 2}, map[string]any{"user_auth_version": 1}, 401},
			{"session_expired", "admin", &model.UserSession{}, "sid = ?", f.sids["admin"], map[string]any{"expires_at": now.Unix() - 1}, map[string]any{"expires_at": now.Unix() + 3600}, 401},
			{"pat_scope", pat, &model.UserAccessToken{}, "id = ?", patRow.Id, map[string]any{"scopes": "[]"}, map[string]any{"scopes": patRow.Scopes}, 403},
			{"pat_hash", pat, &model.UserAccessToken{}, "id = ?", patRow.Id, map[string]any{"token_hash": strings.Repeat("0", 64)}, map[string]any{"token_hash": patRow.TokenHash}, 401},
			{"pat_expired", pat, &model.UserAccessToken{}, "id = ?", patRow.Id, map[string]any{"expires_at": now.Unix() - 1}, map[string]any{"expires_at": patRow.ExpiresAt}, 401},
			{"legacy_rotation", legacy, &model.User{}, "id = ?", f.users["admin"].Id, map[string]any{"access_token": ""}, map[string]any{"access_token": legacy}, 401},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var ran atomic.Bool
				name := "stats:authority-change"
				require.NoError(t, f.db.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
					if tx.Statement.Table == "client_events" && ran.CompareAndSwap(false, true) {
						tx.AddError(independent.Unscoped().Model(tc.table).Where(tc.where, tc.id).Updates(tc.changes).Error)
					}
				}))
				defer func() {
					require.NoError(t, f.db.Callback().Query().Remove(name))
					require.NoError(t, independent.Unscoped().Model(tc.table).Where(tc.where, tc.id).Updates(tc.restore).Error)
				}()
				clientStatsFailure(t, f, usage, tc.actor, tc.status, fmt.Sprint(map[int]string{401: "CLIENT_EVENTS_QUERY_UNAUTHORIZED", 403: "CLIENT_EVENTS_QUERY_FORBIDDEN"}[tc.status]))
				require.True(t, ran.Load())
			})
		}
		var ran atomic.Bool
		require.NoError(t, f.db.Callback().Query().After("gorm:query").Register("stats:pat-delete", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" && ran.CompareAndSwap(false, true) {
				tx.AddError(independent.Delete(&model.UserAccessToken{}, patRow.Id).Error)
			}
		}))
		clientStatsFailure(t, f, clients, pat, 401, "CLIENT_EVENTS_QUERY_UNAUTHORIZED")
		require.True(t, ran.Load())
		require.NoError(t, f.db.Callback().Query().Remove("stats:pat-delete"))
		require.NoError(t, f.db.Create(patRow).Error)
		var retired atomic.Bool
		require.NoError(t, f.db.Callback().Query().After("gorm:query").Register("stats:legacy-retired", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" && retired.CompareAndSwap(false, true) {
				err := independent.Model(&model.Option{}).Where(map[string]any{"key": "LegacyAccessTokenRetireAt"}).Update("value", fmt.Sprint(time.Now().Unix()-1)).Error
				if err == nil {
					err = model.EnsureLegacyAccessTokenRetireAt(time.Now().Unix())
				}
				tx.AddError(err)
			}
		}))
		clientStatsFailure(t, f, usage, legacy, 401, "CLIENT_EVENTS_QUERY_UNAUTHORIZED")
		require.True(t, retired.Load())
		require.NoError(t, f.db.Callback().Query().Remove("stats:legacy-retired"))
		require.NoError(t, independent.Model(&model.Option{}).Where(map[string]any{"key": "LegacyAccessTokenRetireAt"}).Update("value", fmt.Sprint(time.Now().Unix()+3600)).Error)
		require.NoError(t, model.EnsureLegacyAccessTokenRetireAt(time.Now().Unix()))

	})

	t.Run("candidate_and_group_limits_exact_sum", func(t *testing.T) {
		clear()
		rows := make([]model.ClientEvent, 50000)
		for i := range rows {
			rows[i] = base
			rows[i].InputTokens = &maxCounter
		}
		insert(rows)
		d := clientStatsData(t, f, usage, "root")
		item := d["items"].([]any)[0].(map[string]any)
		want := new(big.Int).Mul(big.NewInt(maxCounter), big.NewInt(50000)).String()
		assert.Equal(t, want, item["input_tokens"])
		assert.Equal(t, float64(50000), item["events"])
		extra := base
		extra.EventType = "app_update"
		insert([]model.ClientEvent{extra})
		for _, path := range []string{usage + "&model=nonexistent", clients + "&version=nonexistent"} {
			clientStatsFailure(t, f, path, "root", 422, "CLIENT_EVENTS_QUERY_TOO_LARGE")
		}
		clear()
		rows = make([]model.ClientEvent, 2000)
		for i := range rows {
			rows[i] = base
			rows[i].Model = fmt.Sprintf("m%04d", i)
		}
		insert(rows)
		d = clientStatsData(t, f, usage, "root")
		assert.Equal(t, float64(2000), d["total"])
		extra = base
		extra.Model = "extra"
		insert([]model.ClientEvent{extra})
		clientStatsFailure(t, f, usage, "root", 422, "CLIENT_EVENTS_QUERY_TOO_LARGE")
		clear()
		for i := range rows {
			rows[i] = base
			rows[i].EventType = "app_launch"
			rows[i].AppVersion = fmt.Sprintf("v%04d", i)
			rows[i].OS = "linux"
		}
		insert(rows)
		d = clientStatsData(t, f, clients, "root")
		assert.Equal(t, float64(2000), d["total"])
		extra = rows[0]
		extra.ID = 0
		extra.AppVersion = "extra"
		insert([]model.ClientEvent{extra})
		clientStatsFailure(t, f, clients, "root", 422, "CLIENT_EVENTS_QUERY_TOO_LARGE")
	})

	t.Run("engine_index_plan", func(t *testing.T) {
		// Retained reports outside this selective received range remain in the table.
		lower, upper := now.Add(60*24*time.Hour).Unix(), now.Add(61*24*time.Hour).Unix()
		row := base
		row.ReceivedAt = lower
		insert([]model.ClientEvent{row})
		query := "SELECT user_id,client_id,channel,event_type,event_time_ms,received_at,app_version,os,provider,model,source,input_tokens,output_tokens FROM client_events WHERE received_at >= ? AND received_at < ? ORDER BY received_at ASC LIMIT 50001"
		prefix := "EXPLAIN "
		if f.mainKind == "sqlite" {
			prefix = "EXPLAIN QUERY PLAN "
		}
		result, e := f.db.Raw(prefix+query, lower, upper).Rows()
		require.NoError(t, e)
		defer result.Close()
		columns, e := result.Columns()
		require.NoError(t, e)
		var lines []string
		for result.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			require.NoError(t, result.Scan(dest...))
			for _, v := range values {
				if b, ok := v.([]byte); ok {
					lines = append(lines, string(b))
				} else {
					lines = append(lines, fmt.Sprint(v))
				}
			}
		}
		require.NoError(t, result.Err())
		plan := strings.Join(lines, " ")
		t.Log("received-range plan:", plan)
		assert.Contains(t, strings.ToLower(plan), "idx_client_events_received_at")
	})

	t.Run("database_failure_capacity_and_cancel", func(t *testing.T) {
		clear()
		insert([]model.ClientEvent{base})
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("stats:db-failure", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				tx.AddError(errors.New("fixture database unavailable"))
			}
		}))
		clientStatsFailure(t, f, usage, "root", 503, "CLIENT_EVENTS_QUERY_UNAVAILABLE")
		require.NoError(t, f.db.Callback().Query().Remove("stats:db-failure"))
		var readEvents atomic.Bool
		require.NoError(t, f.db.Callback().Query().After("gorm:query").Register("stats:authority-db-failure", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				readEvents.Store(true)
			}
			if tx.Statement.Table == "users" && readEvents.Load() {
				tx.AddError(errors.New("fixture authority unavailable"))
			}
		}))
		clientStatsFailure(t, f, usage, "root", 503, "CLIENT_EVENTS_QUERY_UNAVAILABLE")
		require.True(t, readEvents.Load())
		require.NoError(t, f.db.Callback().Query().Remove("stats:authority-db-failure"))
		entered := make(chan struct{}, 2)
		release := make(chan struct{})
		exited := make(chan struct{}, 2)
		var closeOnce sync.Once
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("stats:bounded-wait", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				entered <- struct{}{}
				select {
				case <-release:
				case <-tx.Statement.Context.Done():
					tx.AddError(tx.Statement.Context.Err())
				}
				exited <- struct{}{}
			}
		}))
		defer func() {
			closeOnce.Do(func() { close(release) })
			require.NoError(t, f.db.Callback().Query().Remove("stats:bounded-wait"))
		}()
		var cancels []context.CancelFunc
		done := make(chan error, 2)
		for _, path := range []string{usage, clients} {
			ctx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)
			req, e := http.NewRequestWithContext(ctx, "GET", f.server.URL+path, nil)
			require.NoError(t, e)
			req.Header.Set("Authorization", "Bearer "+f.bearer["root"])
			go func() {
				resp, e := f.client.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				done <- e
			}()
		}
		for range 2 {
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("event query did not enter")
			}
		}
		status, h, body := f.request(t, "GET", usage, "root", "", nil)
		assert.Equal(t, 503, status)
		assert.Equal(t, "1", h.Get("Retry-After"))
		assert.NotContains(t, body, "data")
		for _, cancel := range cancels {
			cancel()
		}
		for range 2 {
			require.Error(t, <-done)
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
				t.Fatal("request cancellation did not reach database context")
			}
		}
		closeOnce.Do(func() { close(release) })
	})

	t.Run("real_engine_lock_deadline", func(t *testing.T) {
		lock, e := conn.Conn(context.Background())
		require.NoError(t, e)
		defer lock.Close()
		var held atomic.Bool
		require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("stats:engine-lock", func(tx *gorm.DB) {
			if tx.Statement.Table != "client_events" || !held.CompareAndSwap(false, true) {
				return
			}
			var e error
			switch f.mainKind {
			case "mysql":
				_, e = lock.ExecContext(context.Background(), "LOCK TABLES client_events WRITE")
			case "postgres":
				_, e = lock.ExecContext(context.Background(), "BEGIN")
				if e == nil {
					_, e = lock.ExecContext(context.Background(), "LOCK TABLE client_events IN ACCESS EXCLUSIVE MODE")
				}
			default:
				_, e = lock.ExecContext(context.Background(), "BEGIN EXCLUSIVE")
			}
			tx.AddError(e)
		}))
		defer func() {
			require.NoError(t, f.db.Callback().Query().Remove("stats:engine-lock"))
			command := "ROLLBACK"
			if f.mainKind == "mysql" {
				command = "UNLOCK TABLES"
			}
			_, e := lock.ExecContext(context.Background(), command)
			require.NoError(t, e)
		}()
		started := time.Now()
		clientStatsFailure(t, f, usage, "root", 503, "CLIENT_EVENTS_QUERY_UNAVAILABLE")
		elapsed := time.Since(started)
		require.True(t, held.Load())
		assert.Less(t, elapsed, 8*time.Second)
		t.Logf("real %s lock denied in %s", f.mainKind, elapsed)
	})

	t.Run("readonly_event_boundary", func(t *testing.T) {
		snapshot := func() map[string]any {
			state := map[string]any{}
			for table, columns := range map[string]string{"users": "id,quota,used_quota,request_count", "tokens": "id,user_id,remain_quota,used_quota,accessed_time"} {
				var rows []map[string]any
				require.NoError(t, f.db.Table(table).Select(columns).Order("id").Find(&rows).Error)
				state[table] = rows
			}
			var logs []model.Log
			require.NoError(t, model.LOG_DB.Order("id").Find(&logs).Error)
			state["consume_logs"] = logs
			var tasks []model.SystemTask
			require.NoError(t, f.db.Order("id").Find(&tasks).Error)
			state["cleanup_tasks"] = tasks
			return state
		}
		stateBefore := snapshot()
		var before, after []model.ClientEvent
		require.NoError(t, f.db.Order("id").Find(&before).Error)
		var writes atomic.Int64
		require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("stats:no-event-write", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				writes.Add(1)
			}
		}))
		require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register("stats:no-event-write", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				writes.Add(1)
			}
		}))
		require.NoError(t, f.db.Callback().Delete().Before("gorm:delete").Register("stats:no-event-write", func(tx *gorm.DB) {
			if tx.Statement.Table == "client_events" {
				writes.Add(1)
			}
		}))
		defer func() {
			f.db.Callback().Create().Remove("stats:no-event-write")
			f.db.Callback().Update().Remove("stats:no-event-write")
			f.db.Callback().Delete().Remove("stats:no-event-write")
		}()
		clientStatsData(t, f, usage, "root")
		clientStatsData(t, f, clients, pat)
		require.NoError(t, f.db.Order("id").Find(&after).Error)
		assert.Equal(t, before, after)
		assert.Zero(t, writes.Load())
		assert.Equal(t, stateBefore, snapshot())
	})
}
