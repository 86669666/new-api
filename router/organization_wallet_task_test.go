package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type organizationTaskWorkerFixture struct {
	Kind, DSN, Endpoint string
	Org                 int64
	Actor               int
}

func organizationTaskFixturePolicy(t *testing.T, cfg organizationTaskWorkerFixture) service.OrganizationTaskPolicy {
	t.Helper()
	endpoint, err := url.Parse(cfg.Endpoint)
	require.NoError(t, err)
	require.Equal(t, "http", endpoint.Scheme)
	require.Equal(t, "127.0.0.1", endpoint.Hostname())
	require.NotEmpty(t, endpoint.Port())
	require.Nil(t, endpoint.User)
	require.Empty(t, endpoint.Path)
	require.Empty(t, endpoint.RawQuery)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(ctx context.Context, path string, input, output any) error {
		raw, err := common.Marshal(input)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint+path, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return errors.New("synthetic upstream did not confirm request")
		}
		return common.DecodeJson(io.LimitReader(res.Body, 4096), output)
	}
	return service.OrganizationTaskPolicy{OrganizationID: cfg.Org, ActorUserID: cfg.Actor, AdapterID: "node-fixture/v1",
		Model: "synthetic-async", MaxUnits: 6, QuotaPerUnit: 10, Timeout: 5 * time.Second,
		Submit: func(ctx context.Context, dispatch service.OrganizationWalletSyncDispatch) (service.OrganizationTaskAcceptance, error) {
			var out service.OrganizationTaskAcceptance
			err := send(ctx, "/submit", dispatch, &out)
			return out, err
		},
		Poll: func(ctx context.Context, query service.OrganizationTaskQuery) (service.OrganizationTaskOutcome, error) {
			var out service.OrganizationTaskOutcome
			err := send(ctx, "/poll", query, &out)
			return out, err
		},
	}
}

// The child starts with no application state from the submit server. Its inputs
// (including owned database credentials) travel only over anonymous stdin.
func TestOrganizationWalletTaskPollProcess(t *testing.T) {
	if os.Getenv("NEWAPI_ORGANIZATION_TASK_POLL_CHILD") != "issue8-de-20261128" {
		return
	}
	var cfg organizationTaskWorkerFixture
	require.NoError(t, common.DecodeJson(io.LimitReader(os.Stdin, 16384), &cfg))
	var driver gorm.Dialector
	switch cfg.Kind {
	case "sqlite":
		require.True(t, filepath.IsAbs(cfg.DSN))
		require.Equal(t, "organization.db", filepath.Base(cfg.DSN))
		require.FileExists(t, cfg.DSN)
		driver = sqlite.Open(cfg.DSN + "?_pragma=busy_timeout(5000)")
	case "postgres", "mysql":
		require.Contains(t, cfg.DSN, "/newapi_s2_")
		require.NoError(t, organizationFixtureDSN(cfg.Kind, cfg.DSN, os.Getenv("NEWAPI_S2_"+strings.ToUpper(cfg.Kind)+"_PORT")))
		if cfg.Kind == "postgres" {
			driver = postgres.Open(cfg.DSN)
		} else {
			driver = mysql.Open(cfg.DSN)
		}
	default:
		t.Fatal("unowned database dialect")
	}
	db, err := gorm.Open(driver, &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	pool, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	model.DB = db
	common.SetDatabaseTypes(common.DatabaseType(cfg.Kind), common.DatabaseType(cfg.Kind))
	common.RedisEnabled = false
	err = service.PollOrganizationWalletTasks(t.Context(), organizationTaskFixturePolicy(t, cfg))
	if errors.Is(err, service.ErrOrganizationChargeUnconfirmed) {
		t.Log("POLL_RESULT=unconfirmed")
		return
	}
	require.NoError(t, err)
	t.Log("POLL_RESULT=ok")
}

func TestOrganizationWalletTask(t *testing.T) {
	f := newOrganizationHTTPFixture(t)
	actor := f.users["member"]
	require.NoError(t, f.db.AutoMigrate(&model.OrganizationCharge{}))
	require.NoError(t, f.db.Create(&model.OrganizationWallet{OrganizationID: f.orgA, Balance: 250}).Error)
	require.NoError(t, f.db.Create(&model.OrganizationWallet{OrganizationID: f.orgB, Balance: 80}).Error)
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", actor.Id).UpdateColumn("quota", 123).Error)
	oldOrigins := common.SessionCookieTrustedURLs
	common.SessionCookieTrustedURLs = []string{f.server.URL}
	t.Cleanup(func() { common.SessionCookieTrustedURLs = oldOrigins })

	var subjects sync.Map
	var submissions, polls, mode atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	reply := func(w http.ResponseWriter, value any) {
		raw, err := common.Marshal(value)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(raw)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/submit":
			var in service.OrganizationWalletSyncDispatch
			if common.DecodeJson(io.LimitReader(r.Body, 8192), &in) != nil || in.ChargeID <= 0 ||
				in.Model != "synthetic-async" || in.MaxUnits != 6 {
				w.WriteHeader(400)
				return
			}
			submissions.Add(1)
			handle := "upstream-" + strconv.FormatInt(in.ChargeID, 10)
			subjects.Store(handle, in.Text)
			switch in.Text {
			case "success":
				select {
				case entered <- struct{}{}:
				default:
				}
				<-release
			case "ack lost":
				w.WriteHeader(503)
				return
			}
			reply(w, service.OrganizationTaskAcceptance{ChargeID: in.ChargeID, UpstreamID: handle})
		case "/poll":
			var query service.OrganizationTaskQuery
			if common.DecodeJson(io.LimitReader(r.Body, 4096), &query) != nil || query.UpstreamID != "upstream-"+strconv.FormatInt(query.ChargeID, 10) {
				w.WriteHeader(400)
				return
			}
			actual, ok := subjects.Load(query.UpstreamID)
			if !ok || actual == "ack lost" {
				w.WriteHeader(400)
				return
			}
			polls.Add(1)
			if actual == "keep waiting" {
				reply(w, service.OrganizationTaskOutcome{ChargeID: query.ChargeID, UpstreamID: query.UpstreamID})
				return
			}
			units := int64(4)
			out := service.OrganizationTaskOutcome{ChargeID: query.ChargeID, UpstreamID: query.UpstreamID, Terminal: true, Units: &units}
			switch mode.Load() {
			case 1:
				if actual == "success" {
					out.UpstreamID = "wrong-handle"
				} else {
					out.Units = nil
				}
			case 2:
				if actual == "zero cost" {
					out.Units, out.NoCharge = nil, true
				}
			default:
				out.Terminal, out.Units = false, nil
			}
			reply(w, out)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); upstream.Close() })
	cfg := organizationTaskWorkerFixture{Kind: f.mainKind, DSN: f.mainDSN, Endpoint: upstream.URL, Org: f.orgA, Actor: actor.Id}
	f.engine.POST("/api/organizations/:org_id/wallet/task-fixture", middleware.UserAuth(), controller.OrganizationWalletTaskHandler(organizationTaskFixturePolicy(t, cfg)))
	path := fmt.Sprintf("/api/organizations/%d/wallet/task-fixture", f.orgA)
	key := func(n int) string { return fmt.Sprintf("92000000-0000-4000-8000-%012d", n) }
	headers := http.Header{"Content-Type": {"application/json"}, "Origin": {f.server.URL}}
	submit := func(t *testing.T, n int, text string) (int, map[string]any) {
		t.Helper()
		body, err := common.Marshal(map[string]string{"request_id": key(n), "text": text})
		require.NoError(t, err)
		status, _, data := f.request(t, "POST", path, "member", string(body), headers)
		return status, data
	}
	checkWallet := func(t *testing.T, balance, reserved int64) {
		t.Helper()
		var a, b model.OrganizationWallet
		require.NoError(t, f.db.Where("organization_id = ?", f.orgA).First(&a).Error)
		require.NoError(t, f.db.Where("organization_id = ?", f.orgB).First(&b).Error)
		assert.Equal(t, balance, a.Balance)
		assert.Equal(t, reserved, a.Reserved)
		assert.EqualValues(t, 80, b.Balance)
		assert.Zero(t, b.Reserved)
		var u model.User
		require.NoError(t, f.db.First(&u, actor.Id).Error)
		assert.EqualValues(t, 123, u.Quota)
	}
	restartPoller := func(t *testing.T, want string) {
		t.Helper()
		binary, err := os.Executable()
		require.NoError(t, err)
		input, err := common.Marshal(cfg)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "-test.run", "^TestOrganizationWalletTaskPollProcess$", "-test.v", "-test.timeout=15s")
		cmd.Env = append(os.Environ(), "NEWAPI_ORGANIZATION_TASK_POLL_CHILD=issue8-de-20261128")
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		// Avoid including fixture DSNs from nested driver diagnostics in output.
		require.NoError(t, err, "fresh poller failed")
		require.Contains(t, string(out), "POLL_RESULT="+want)
	}
	taskBinding := func(t *testing.T, id string) model.OrganizationTaskReceipt {
		t.Helper()
		rowID, err := strconv.ParseInt(id, 10, 64)
		require.NoError(t, err)
		var task model.Task
		require.NoError(t, f.db.First(&task, rowID).Error)
		require.NotNil(t, task.BillingRef)
		chargeID, err := strconv.ParseInt(strings.TrimPrefix(*task.BillingRef, "organization-charge-"), 10, 64)
		require.NoError(t, err)
		var charge model.OrganizationCharge
		require.NoError(t, f.db.Where("policy_hash = ? AND id = ?", task.BillingProgress, chargeID).First(&charge).Error)
		return model.OrganizationTaskReceipt{Charge: charge, TaskRowID: task.ID, PublicID: task.TaskID,
			UpstreamID: task.PrivateData.UpstreamTaskID, Status: task.Status}
	}
	var successID, zeroID string
	t.Run("atomic reserve and duplicate dispatch", func(t *testing.T) {
		body, err := common.Marshal(map[string]string{"request_id": key(1), "text": "success"})
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), "POST", f.server.URL+path, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header = headers.Clone()
		req.Header.Set("Authorization", "Bearer "+f.bearer["member"])
		type response struct {
			http *http.Response
			err  error
		}
		done := make(chan response, 1)
		go func() { res, err := f.client.Do(req); done <- response{res, err} }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("synthetic submit not reached")
		}
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
		checkWallet(t, 250, 60)
		status, replay := submit(t, 1, "success")
		require.Equal(t, 202, status)
		assert.EqualValues(t, 1, submissions.Load())
		status, changed := submit(t, 1, "different")
		assert.Equal(t, 409, status)
		assert.Equal(t, "ORG_IDEMPOTENCY_CONFLICT", changed["code"])
		releaseOnce.Do(func() { close(release) })
		res := <-done
		require.NoError(t, res.err)
		defer res.http.Body.Close()
		require.Equal(t, 202, res.http.StatusCode)
		var result map[string]any
		require.NoError(t, common.DecodeJson(res.http.Body, &result))
		data := result["data"].(map[string]any)
		assert.Equal(t, replay["data"].(map[string]any)["task_row_id"], data["task_row_id"])
		successID = data["task_row_id"].(string)
		assert.Equal(t, string(model.TaskStatusSubmitted), data["status"])
	})
	t.Run("durable acknowledgement and unknown send", func(t *testing.T) {
		status, result := submit(t, 2, "zero cost")
		require.Equal(t, 202, status)
		zeroID = result["data"].(map[string]any)["task_row_id"].(string)
		status, result = submit(t, 3, "ack lost")
		assert.Equal(t, 502, status)
		assert.Equal(t, "ORG_WALLET_OUTCOME_UNCONFIRMED", result["code"])
		status, _ = submit(t, 3, "ack lost")
		assert.Equal(t, 202, status)
		assert.EqualValues(t, 3, submissions.Load())
		checkWallet(t, 250, 180)
	})
	t.Run("restart preserves unconfirmed charges and transaction rollback", func(t *testing.T) {
		mode.Store(1)
		restartPoller(t, "unconfirmed")
		assert.EqualValues(t, 2, polls.Load())
		checkWallet(t, 250, 180)

		binding := taskBinding(t, successID)
		failure := errors.New("synthetic terminal write failure")
		require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register("fixture:abort-task-terminal", func(tx *gorm.DB) {
			if tx.Statement.Table == "tasks" {
				_ = tx.AddError(failure)
			}
		}))
		err := model.FinishOrganizationTask(t.Context(), binding, 40, false)
		require.NoError(t, f.db.Callback().Update().Remove("fixture:abort-task-terminal"))
		require.ErrorIs(t, err, failure)
		checkWallet(t, 250, 180)
		after := taskBinding(t, successID)
		assert.Equal(t, binding, after)
		assert.Equal(t, model.TaskStatus(model.TaskStatusSubmitted), after.Status)

		_, err = model.FinishOrganizationCharge(t.Context(), binding.Charge, 40, false)
		require.ErrorIs(t, err, model.ErrOrganizationConflict, "sync settlement cannot split a task transaction")
	})
	t.Run("revoked member, original wallet, and organization reads", func(t *testing.T) {
		identity := service.AuthIdentity{UserID: actor.Id, SessionID: f.sids["member"], UserAuthVersion: 1, SessionVersion: 1}
		req := model.OrganizationChargeRequest{OrganizationID: f.orgA, RequestKey: key(4), QuotaPerUnit: 10, Reserve: 60,
			PolicyHash: strings.Repeat("1", 64), RequestHash: strings.Repeat("2", 64)}
		unsent, err := model.ReserveOrganizationTask(t.Context(), identity, req)
		require.NoError(t, err)
		checkWallet(t, 250, 240)
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, actor.Id).
			UpdateColumn("removed_at", 1).Error)
		_, granted, err := model.DispatchOrganizationTask(t.Context(), identity, req)
		assert.False(t, granted)
		require.ErrorIs(t, err, model.ErrOrganizationNotFound)
		for range 2 {
			require.NoError(t, model.CancelUnsentOrganizationTask(t.Context(), unsent))
		}
		checkWallet(t, 250, 180)
		mode.Store(2)
		restartPoller(t, "ok")
		restartPoller(t, "ok")
		checkWallet(t, 210, 60)
		assert.EqualValues(t, 3, submissions.Load())
		assert.EqualValues(t, 4, polls.Load())

		settled := taskBinding(t, successID)
		refunded := taskBinding(t, zeroID)
		require.NoError(t, model.FinishOrganizationTask(t.Context(), settled, 40, false))
		require.NoError(t, model.FinishOrganizationTask(t.Context(), refunded, 0, true))
		require.ErrorIs(t, model.FinishOrganizationTask(t.Context(), settled, 50, false), model.ErrOrganizationConflict)
		require.ErrorIs(t, model.FinishOrganizationTask(t.Context(), settled, 0, true), model.ErrOrganizationConflict)
		assert.Equal(t, settled, taskBinding(t, successID))
		assert.Equal(t, refunded, taskBinding(t, zeroID))
		checkWallet(t, 210, 60)

		detail := func(t *testing.T, id, by string, org int64) (int, map[string]any) {
			t.Helper()
			status, _, body := f.request(t, "GET", fmt.Sprintf("/api/organizations/%d/tasks/%s", org, id), by, "", headers)
			return status, body
		}
		for _, tc := range []struct{ id, expected string }{{successID, string(model.TaskStatusSuccess)}, {zeroID, string(model.TaskStatusFailure)}} {
			status, result := detail(t, tc.id, "owner", f.orgA)
			require.Equal(t, 200, status)
			assert.Equal(t, tc.expected, result["data"].(map[string]any)["status"])
			status, _ = detail(t, tc.id, "member", f.orgA)
			assert.Equal(t, 404, status)
			status, _ = detail(t, tc.id, "foreign", f.orgB)
			assert.Equal(t, 404, status)
		}
		status, _, list := f.request(t, "GET", fmt.Sprintf("/api/task/self?org_id=%d", f.orgA), "owner", "", headers)
		require.Equal(t, 200, status)
		combined, err := common.Marshal(list)
		require.NoError(t, err)
		assert.Contains(t, string(combined), string(model.TaskStatusSuccess))
		assert.Contains(t, string(combined), string(model.TaskStatusFailure))
		status, _, list = f.request(t, "GET", "/api/task/self", "member", "", headers)
		require.Equal(t, 200, status)
		combined, err = common.Marshal(list)
		require.NoError(t, err)
		assert.NotContains(t, string(combined), "organization-task")
		status, _, _ = f.request(t, "GET", fmt.Sprintf("/api/organizations/%d/tasks/%s/artifacts", f.orgA, successID), "owner", "", headers)
		assert.Equal(t, 404, status)
	})
	t.Run("unconfirmed early tasks do not starve following pages", func(t *testing.T) {
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", f.orgA, actor.Id).
			UpdateColumn("removed_at", 0).Error)
		require.NoError(t, f.db.Model(&model.OrganizationWallet{}).Where("organization_id = ?", f.orgA).UpdateColumn("balance", 2000).Error)
		for index := range 20 {
			status, _ := submit(t, 100+index, "keep waiting")
			require.Equal(t, 202, status)
		}
		status, receipt := submit(t, 120, "later")
		require.Equal(t, 202, status)
		id := receipt["data"].(map[string]any)["task_row_id"].(string)
		before := polls.Load()
		restartPoller(t, "ok")
		assert.EqualValues(t, 21, polls.Load()-before)
		status, _, detail := f.request(t, "GET", fmt.Sprintf("/api/organizations/%d/tasks/%s", f.orgA, id), "owner", "", headers)
		require.Equal(t, 200, status)
		assert.Equal(t, string(model.TaskStatusSuccess), detail["data"].(map[string]any)["status"])
		checkWallet(t, 1960, 1260)
	})
}
