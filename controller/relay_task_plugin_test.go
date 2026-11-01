package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	pluginruntime "github.com/QuantumNous/new-api/pkg/jsplugin"
	builtinplugins "github.com/QuantumNous/new-api/plugins"
	"github.com/QuantumNous/new-api/relay"
	taskadaptor "github.com/QuantumNous/new-api/relay/channel/task/jsplugin"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	kitdto "github.com/QuantumNous/new-api/relaykit/dto"
	relaytypes "github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/config"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type taskSubmissionTestBilling struct {
	events     *[]string
	settleErr  error
	reserveErr error
	onSettle   func()
	refunds    int
}

func (b *taskSubmissionTestBilling) Settle(int) error {
	*b.events = append(*b.events, "settle")
	if b.onSettle != nil {
		b.onSettle()
	}
	return b.settleErr
}

func (b *taskSubmissionTestBilling) Refund(*gin.Context) {
	*b.events = append(*b.events, "refund")
	b.refunds++
}

func (b *taskSubmissionTestBilling) NeedsRefund() bool        { return b.refunds == 0 }
func (b *taskSubmissionTestBilling) GetPreConsumedQuota() int { return 0 }
func (b *taskSubmissionTestBilling) ReserveAcceptedTask(amount int) error {
	return b.Reserve(amount)
}

func (b *taskSubmissionTestBilling) Reserve(int) error {
	*b.events = append(*b.events, "reserve")
	return b.reserveErr
}

func TestPresentTaskSubmissionUsesNativePresenterAfterPersistence(t *testing.T) {
	plugin, err := pluginruntime.CompilePlugin(`
export const meta = {apiVersion:1,key:"presenter-test",name:"Presenter",version:"1.0.0",author:{name:"Test"},models:["model"],fetchMode:"per_task",routes:[{method:"POST",path:"/vendor/jobs",type:"submit",decode:"decode",render:"created"}]};
export const native = {decode:function(ctx){return {kind:"submit",model:"model",requestBody:ctx.body.value};},created:function(ctx,task){return {data:{task_id:task.task_id},upstream:task.data};}};
export function buildSubmitRequest(){return {}} export function parseSubmitResponse(){return {taskId:"upstream"}} export function buildQueryRequest(){return {}} export function parseTaskResult(){return {status:"SUCCESS"}}
`, pluginruntime.Options{})
	require.NoError(t, err)
	priceData := types.PriceData{}
	priceData.AddOtherRatio("seconds", 5)
	task := &model.Task{TaskID: "task_public", SubmitTime: 123}
	task.SetData(map[string]any{"task_id": "upstream_private"})
	outcome := &taskSubmissionOutcome{
		Result:    &relay.TaskSubmitResult{},
		Task:      task,
		RelayInfo: &relaycommon.RelayInfo{PriceData: priceData},
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/vendor/jobs", strings.NewReader(`{"model":"model"}`))
	c.Set(pluginruntime.ContextKeyPinnedRoute, pluginruntime.PinnedRoute{Plugin: plugin, Route: plugin.Meta.Routes[0]})
	c.Set(pluginruntime.ContextKeyRouteRequest, pluginruntime.RouteRequestContext{Path: "/vendor/jobs", Method: http.MethodPost, Body: map[string]any{"kind": "json", "value": map[string]any{"model": "model"}}})

	presentTaskSubmission(c, outcome)

	assert.JSONEq(t, `{
		"data":{"task_id":"task_public"},
		"upstream":{"task_id":"upstream_private"}
	}`, recorder.Body.String())
	assert.JSONEq(t, `{"seconds":5}`, recorder.Header().Get("X-New-Api-Other-Ratios"))
}

// The submit presenter may answer with the vendor's status; a native route that
// already relayed the vendor's event stream gets nothing more.
func TestPresentTaskSubmissionHonorsReplyWrapperAndRelayedStreams(t *testing.T) {
	plugin, err := pluginruntime.CompilePlugin(`
export const meta = {apiVersion:1,key:"accepted-test",name:"Accepted",version:"1.0.0",author:{name:"Test"},models:["model"],fetchMode:"per_task",routes:[{method:"POST",path:"/vendor/jobs",type:"submit",decode:"decode",render:"created"}]};
export const native = {decode:function(ctx){return {kind:"submit",model:"model",requestBody:ctx.body.value};},created:function(ctx,task){return {__status:202,__body:{id:task.task_id}};}};
export function buildSubmitRequest(){return {}} export function parseSubmitResponse(){return {taskId:"upstream"}} export function buildQueryRequest(){return {}} export function parseTaskResult(){return {status:"SUCCESS"}}
`, pluginruntime.Options{})
	require.NoError(t, err)
	present := func(recorder *httptest.ResponseRecorder, written bool) {
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/vendor/jobs", strings.NewReader(`{"model":"model"}`))
		c.Set(pluginruntime.ContextKeyPinnedRoute, pluginruntime.PinnedRoute{Plugin: plugin, Route: plugin.Meta.Routes[0]})
		c.Set(pluginruntime.ContextKeyRouteRequest, pluginruntime.RouteRequestContext{Path: "/vendor/jobs", Method: http.MethodPost, Body: map[string]any{"kind": "json", "value": map[string]any{"model": "model"}}})
		if written {
			_, _ = c.Writer.WriteString("data: {}\n\n")
		}
		presentTaskSubmission(c, &taskSubmissionOutcome{Result: &relay.TaskSubmitResult{}, Task: &model.Task{TaskID: "task_public"}, RelayInfo: &relaycommon.RelayInfo{}})
	}

	accepted := httptest.NewRecorder()
	present(accepted, false)
	assert.Equal(t, http.StatusAccepted, accepted.Code)
	assert.JSONEq(t, `{"id":"task_public"}`, accepted.Body.String())

	streamed := httptest.NewRecorder()
	present(streamed, true)
	assert.Equal(t, "data: {}\n\n", streamed.Body.String())
}

func TestPresentTaskSubmissionFallbackUsesPersistedPublicID(t *testing.T) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	outcome := &taskSubmissionOutcome{
		Result:    &relay.TaskSubmitResult{},
		Task:      &model.Task{TaskID: "task_persisted", SubmitTime: 456},
		RelayInfo: &relaycommon.RelayInfo{OriginModelName: "video-model"},
	}

	presentTaskSubmission(c, outcome)

	assert.JSONEq(t, `{
		"id":"task_persisted",
		"task_id":"task_persisted",
		"status":"queued",
		"model":"video-model",
		"created_at":456
	}`, recorder.Body.String())
}

func TestPresentTaskSubmissionUsesHostOpenAIVideoCreateReceipt(t *testing.T) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Set(pluginruntime.ContextKeyPinnedEndpoint, pluginruntime.PinnedEndpoint{
		Protocol:  "openai_video",
		Operation: pluginruntime.HostProtocolOperation{Name: "create"},
	})
	task := &model.Task{
		TaskID:     "task_public",
		Status:     model.TaskStatusSubmitted,
		Progress:   "0%",
		CreatedAt:  456,
		Properties: model.Properties{OriginModelName: "video-model"},
	}
	outcome := &taskSubmissionOutcome{Result: &relay.TaskSubmitResult{}, Task: task, RelayInfo: &relaycommon.RelayInfo{}}

	presentTaskSubmission(c, outcome)

	assert.JSONEq(t, `{"id":"task_public","object":"video","model":"video-model","status":"queued","progress":0,"created_at":456}`, recorder.Body.String())
	assert.NotContains(t, recorder.Body.String(), "task_id")
}

func TestExecuteTaskSubmissionAcceptedInsertFailureRetainsReservation(t *testing.T) {
	events := make([]string, 0, 3)
	database := setupTaskSubmissionDatabase(t, false, &events)
	_ = database
	billing := &taskSubmissionTestBilling{events: &events}
	c := taskSubmissionTestContext()
	info := taskSubmissionRelayInfo(billing)

	outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
		return &relay.TaskSubmitResult{
			UpstreamTaskID: "upstream_private",
			Platform:       constant.TaskPlatform("plugin"),
		}, nil
	})

	assert.Nil(t, outcome)
	require.NotNil(t, taskErr)
	assert.Equal(t, "task_insert_failed", taskErr.Code)
	assert.Equal(t, []string{"reserve", "insert"}, events)
	assert.Zero(t, billing.refunds)
	assert.False(t, c.Writer.Written())
}

func TestExecuteTaskSubmissionSettlementFailureStaysDurableAndWritesNothing(t *testing.T) {
	events := make([]string, 0, 3)
	database := setupTaskSubmissionDatabase(t, true, &events)
	billing := &taskSubmissionTestBilling{events: &events, settleErr: errors.New("settlement failed")}
	c := taskSubmissionTestContext()
	info := taskSubmissionRelayInfo(billing)

	outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
		return &relay.TaskSubmitResult{
			UpstreamTaskID: "upstream_private",
			Platform:       constant.TaskPlatform("plugin"),
		}, nil
	})

	assert.Nil(t, outcome)
	require.NotNil(t, taskErr)
	assert.Equal(t, "task_billing_settlement_failed", taskErr.Code)
	assert.Equal(t, []string{"reserve", "insert", "settle"}, events)
	assert.Zero(t, billing.refunds)
	var count int64
	require.NoError(t, database.Model(&model.Task{}).Where("task_id = ?", "task_public").Count(&count).Error)
	assert.Equal(t, int64(1), count)
	assert.False(t, c.Writer.Written())
}

func TestExecuteTaskSubmissionPersistsPinnedPluginProvenance(t *testing.T) {
	events := make([]string, 0, 3)
	database := setupTaskSubmissionDatabase(t, true, &events)
	previousLogConsumeEnabled := common.LogConsumeEnabled
	common.LogConsumeEnabled = false
	t.Cleanup(func() { common.LogConsumeEnabled = previousLogConsumeEnabled })

	c := taskSubmissionTestContext()
	c.Set(common.RequestIdKey, "request-public")
	c.Set(pluginruntime.ContextKeyPinnedPlugin, pluginruntime.PinnedPlugin{
		Generation: &pluginruntime.RoutingGeneration{Number: 42},
		Plugin: &pluginruntime.LoadedPlugin{Meta: pluginruntime.Meta{
			Key:        "document-parser",
			Name:       "Document Parser",
			Version:    "1.2.3",
			APIVersion: 1,
			Author: pluginruntime.AuthorMeta{
				Name: "Community Author",
				URL:  "https://plugins.example/author",
			},
		}},
	})
	billing := &taskSubmissionTestBilling{events: &events}
	info := taskSubmissionRelayInfo(billing)

	outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
		return &relay.TaskSubmitResult{
			UpstreamTaskID: "upstream-private",
			Platform:       constant.TaskPlatform("document-parser"),
		}, nil
	})

	require.Nil(t, taskErr)
	require.NotNil(t, outcome)
	require.NotNil(t, outcome.Task.PrivateData.Execution)
	require.NotNil(t, outcome.Task.PrivateData.Execution.TaskPlugin)
	assert.Equal(t, "request-public", outcome.Task.PrivateData.Execution.RequestID)
	assert.Equal(t, "/plugin/submit", outcome.Task.PrivateData.Execution.RequestPath)
	assert.Equal(t, "1.2.3", outcome.Task.PrivateData.Execution.TaskPlugin.Version)
	assert.Equal(t, uint64(42), outcome.Task.PrivateData.Execution.TaskPlugin.Generation)
	require.NotNil(t, outcome.Task.PrivateData.Execution.TaskPlugin.Author)
	assert.Equal(t, "Community Author", outcome.Task.PrivateData.Execution.TaskPlugin.Author.Name)
	assert.Equal(t, "https://plugins.example/author", outcome.Task.PrivateData.Execution.TaskPlugin.Author.URL)

	var stored model.Task
	require.NoError(t, database.Where("task_id = ?", "task_public").First(&stored).Error)
	require.NotNil(t, stored.PrivateData.Execution)
	require.NotNil(t, stored.PrivateData.Execution.TaskPlugin)
	assert.Equal(t, "document-parser", stored.PrivateData.Execution.TaskPlugin.Key)
	require.NotNil(t, stored.PrivateData.Execution.TaskPlugin.Author)
	assert.Equal(t, "Community Author", stored.PrivateData.Execution.TaskPlugin.Author.Name)
	assert.Equal(t, "upstream-private", stored.PrivateData.UpstreamTaskID)
}

// A submit route declaring retainResult: false persists the task row for
// billing but never writes the upstream snapshot for an immediate terminal
// result, while the in-memory task still carries it for the presenter. An
// asynchronous result on the same route is retained because polling and
// retrieval depend on it.
func TestExecuteTaskSubmissionHonorsRouteRetainResult(t *testing.T) {
	retainFalse := false
	for _, tc := range []struct {
		name          string
		immediate     *relaycommon.TaskInfo
		wantDiscarded bool
	}{
		{"immediate success is discarded", &relaycommon.TaskInfo{Status: model.TaskStatusSuccess, Progress: "100%"}, true},
		{"immediate failure is discarded", &relaycommon.TaskInfo{Status: model.TaskStatusFailure, Reason: "rejected"}, true},
		{"asynchronous result is retained", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := make([]string, 0, 3)
			database, _ := openTaskDialectDatabase(t, &model.Task{}, &model.User{}, &model.Channel{})
			previousDB := model.DB
			model.DB = database
			t.Cleanup(func() { model.DB = previousDB })
			previousLogConsumeEnabled := common.LogConsumeEnabled
			common.LogConsumeEnabled = false
			t.Cleanup(func() { common.LogConsumeEnabled = previousLogConsumeEnabled })

			c := taskSubmissionTestContext()
			c.Set(pluginruntime.ContextKeyPinnedRoute, pluginruntime.PinnedRoute{
				Plugin: &pluginruntime.LoadedPlugin{Meta: pluginruntime.Meta{Key: "sync-images"}},
				Route:  pluginruntime.Route{Method: http.MethodPost, Path: "/sync/images", Type: pluginruntime.RouteTypeSubmit, RetainResult: &retainFalse},
			})
			info := taskSubmissionRelayInfo(&taskSubmissionTestBilling{events: &events})
			upstream := []byte(`{"data":[{"url":"https://cdn.example/a.png"}]}`)

			outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
				return &relay.TaskSubmitResult{
					UpstreamTaskID: "task_public",
					Platform:       constant.TaskPlatform("sync-images"),
					TaskData:       upstream,
					Immediate:      tc.immediate,
				}, nil
			})
			require.Nil(t, taskErr)
			require.NotNil(t, outcome)
			assert.JSONEq(t, string(upstream), string(outcome.Task.Data), "presenter keeps the in-memory snapshot")
			assert.Equal(t, tc.wantDiscarded, outcome.Task.PrivateData.ResultDiscarded)
			assert.Equal(t, !tc.wantDiscarded, outcome.Task.ResultRetrievable())

			var stored model.Task
			require.NoError(t, database.Where("task_id = ?", "task_public").First(&stored).Error)
			assert.Equal(t, tc.wantDiscarded, stored.PrivateData.ResultDiscarded)
			var nullCount int64
			require.NoError(t, database.Model(&model.Task{}).Where("task_id = ? AND data IS NULL", "task_public").Count(&nullCount).Error)
			if tc.wantDiscarded {
				assert.Equal(t, int64(1), nullCount, "snapshot column must stay NULL")
				artifacts, err := projectTaskArtifacts(&stored)
				require.NoError(t, err)
				assert.Empty(t, artifacts)
			} else {
				assert.Equal(t, int64(0), nullCount)
				assert.JSONEq(t, string(upstream), string(stored.Data))
			}
			listed := model.TaskGetAllUserTask(1, 0, 10, model.SyncTaskQueryParams{})
			require.Len(t, listed, 1)
			assert.Empty(t, listed[0].Data, "task lists never select the snapshot column")
		})
	}
}

func TestExecuteTaskSubmissionAcceptedCancellationStillPersists(t *testing.T) {
	events := make([]string, 0, 2)
	setupTaskSubmissionDatabase(t, true, &events)
	billing := &taskSubmissionTestBilling{events: &events}
	c := taskSubmissionTestContext()
	requestContext, cancel := context.WithCancel(c.Request.Context())
	c.Request = c.Request.WithContext(requestContext)
	info := taskSubmissionRelayInfo(billing)

	outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
		cancel()
		return &relay.TaskSubmitResult{
			UpstreamTaskID: "upstream_private",
			Platform:       constant.TaskPlatform("plugin"),
		}, nil
	})

	require.NotNil(t, outcome)
	require.Nil(t, taskErr)
	assert.Equal(t, []string{"reserve", "insert", "settle"}, events)
	assert.Zero(t, billing.refunds)
	assert.False(t, c.Writer.Written())
}

func TestExecuteTaskSubmissionDisconnectBeforeUpstreamAcceptanceSkipsSubmitAndRefunds(t *testing.T) {
	events := make([]string, 0, 1)
	setupTaskSubmissionDatabase(t, true, &events)
	billing := &taskSubmissionTestBilling{events: &events}
	c := taskSubmissionTestContext()
	requestContext, cancel := context.WithCancel(c.Request.Context())
	cancel()
	c.Request = c.Request.WithContext(requestContext)
	info := taskSubmissionRelayInfo(billing)
	submitted := false

	outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
		submitted = true
		return nil, nil
	})

	assert.Nil(t, outcome)
	require.NotNil(t, taskErr)
	assert.Equal(t, "request_cancelled", taskErr.Code)
	assert.False(t, submitted)
	assert.Equal(t, []string{"refund"}, events)
	assert.Equal(t, 1, billing.refunds)
	assert.False(t, c.Writer.Written())
}

func TestExecuteTaskSubmissionCallerCancellationDuringSubmitRefundsBeforeDurableBarrier(t *testing.T) {
	events := make([]string, 0, 1)
	setupTaskSubmissionDatabase(t, true, &events)
	billing := &taskSubmissionTestBilling{events: &events}
	c := taskSubmissionTestContext()
	requestContext, cancel := context.WithCancel(c.Request.Context())
	c.Request = c.Request.WithContext(requestContext)
	info := taskSubmissionRelayInfo(billing)
	submitStarted := make(chan struct{})
	done := make(chan struct{})
	var outcome *taskSubmissionOutcome
	var taskErr *dto.TaskError

	go func() {
		defer close(done)
		outcome, taskErr = executeTaskSubmissionWith(c, info, func(c *gin.Context, _ *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
			close(submitStarted)
			<-c.Request.Context().Done()
			return nil, service.TaskErrorWrapperLocal(c.Request.Context().Err(), "do_request_failed", http.StatusInternalServerError)
		})
	}()
	select {
	case <-submitStarted:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "submission did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "submission did not stop after disconnect")
	}

	assert.Nil(t, outcome)
	require.NotNil(t, taskErr)
	assert.Equal(t, "request_cancelled", taskErr.Code)
	assert.Equal(t, []string{"refund"}, events)
	assert.Equal(t, 1, billing.refunds)
	assert.False(t, c.Writer.Written())
}

func TestExecuteTaskSubmissionDisconnectAfterDurableInsertDoesNotRefund(t *testing.T) {
	events := make([]string, 0, 3)
	database := setupTaskSubmissionDatabase(t, true, &events)
	previousLogConsumeEnabled := common.LogConsumeEnabled
	common.LogConsumeEnabled = false
	t.Cleanup(func() { common.LogConsumeEnabled = previousLogConsumeEnabled })
	c := taskSubmissionTestContext()
	requestContext, cancel := context.WithCancel(c.Request.Context())
	c.Request = c.Request.WithContext(requestContext)
	billing := &taskSubmissionTestBilling{
		events:   &events,
		onSettle: cancel,
	}
	info := taskSubmissionRelayInfo(billing)

	outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
		return &relay.TaskSubmitResult{
			UpstreamTaskID: "upstream_private",
			Platform:       constant.TaskPlatform("plugin"),
		}, nil
	})

	require.Nil(t, taskErr)
	require.NotNil(t, outcome)
	assert.Equal(t, "task_public", outcome.Task.TaskID)
	assert.Equal(t, []string{"reserve", "insert", "settle"}, events)
	assert.Zero(t, billing.refunds)
	var count int64
	require.NoError(t, database.Model(&model.Task{}).Where("task_id = ?", "task_public").Count(&count).Error)
	assert.Equal(t, int64(1), count)
	assert.False(t, c.Writer.Written())
}

// setupTaskSubmissionDatabase opens the dialect selected by
// TEST_TASK_DB_DIALECT (SQLite in memory by default) and records every task
// INSERT in events so tests can assert the reserve → insert → settle order.
// Without migrate the task table does not exist and inserts fail.
func setupTaskSubmissionDatabase(t *testing.T, migrate bool, events *[]string) *gorm.DB {
	t.Helper()
	previousDB := model.DB
	oldRedis, oldConsume := common.RedisEnabled, common.LogConsumeEnabled
	common.RedisEnabled, common.LogConsumeEnabled = false, false
	t.Cleanup(func() { common.RedisEnabled, common.LogConsumeEnabled = oldRedis, oldConsume })
	models := []any{&model.User{}, &model.Channel{}}
	if migrate {
		models = append(models, &model.Task{})
	}
	database, _ := openTaskDialectDatabase(t, models...)
	require.NoError(t, database.Callback().Create().Before("gorm:create").Register("test:task-submit-order", func(*gorm.DB) {
		*events = append(*events, "insert")
	}))
	model.DB = database
	t.Cleanup(func() { model.DB = previousDB })
	return database
}

func taskSubmissionTestContext() *gin.Context {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/plugin/submit", strings.NewReader(`{}`))
	return c
}

func taskSubmissionRelayInfo(billing relaycommon.BillingSettler) *relaycommon.RelayInfo {
	return &relaycommon.RelayInfo{
		UserId:          1,
		UsingGroup:      "default",
		OriginModelName: "plugin-model",
		Billing:         billing,
		TaskRelayInfo: &relaycommon.TaskRelayInfo{
			PublicTaskID:  "task_public",
			LockedChannel: &model.Channel{Id: 1, Type: constant.ChannelTypeTaskPlugin, Name: "plugin"},
		},
		ChannelMeta: &relaycommon.ChannelMeta{ChannelId: 1, ChannelType: constant.ChannelTypeTaskPlugin},
	}
}

// Uses the real submit adaptor, expression evaluator, BillingSession, task row
// and consume log. Set TEST_TASK_DB_DIALECT plus TEST_MYSQL_DSN or
// TEST_POSTGRES_DSN to exercise the same contract on an external test database.
// Unique table prefixes keep the fixture isolated from all existing tables.
// openTaskDialectDatabase opens the engine selected by TEST_TASK_DB_DIALECT
// (default SQLite in memory; MySQL and PostgreSQL through TEST_MYSQL_DSN and
// TEST_POSTGRES_DSN) with a unique table prefix, migrates the given models and
// drops them on cleanup. It logs the engine version so database verification
// runs leave a record.
func openTaskDialectDatabase(t *testing.T, models ...any) (*gorm.DB, common.DatabaseType) {
	t.Helper()
	dialect := common.DatabaseType(os.Getenv("TEST_TASK_DB_DIALECT"))
	var driver gorm.Dialector
	switch dialect {
	case "", common.DatabaseTypeSQLite:
		dialect = common.DatabaseTypeSQLite
		driver = sqlite.Open(":memory:")
	case common.DatabaseTypeMySQL:
		require.NotEmpty(t, os.Getenv("TEST_MYSQL_DSN"))
		driver = mysql.Open(os.Getenv("TEST_MYSQL_DSN"))
	case common.DatabaseTypePostgreSQL:
		require.NotEmpty(t, os.Getenv("TEST_POSTGRES_DSN"))
		driver = postgres.New(postgres.Config{DSN: os.Getenv("TEST_POSTGRES_DSN"), PreferSimpleProtocol: true})
	default:
		t.Fatalf("unsupported test dialect %q", dialect)
	}
	db, err := gorm.Open(driver, &gorm.Config{NamingStrategy: schema.NamingStrategy{TablePrefix: fmt.Sprintf("tsubmit_%d_", time.Now().UnixNano())}})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(models...))
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(models...)) })
	var version string
	if dialect == common.DatabaseTypeSQLite {
		require.NoError(t, db.Raw("SELECT sqlite_version()").Scan(&version).Error)
	} else {
		require.NoError(t, db.Raw("SELECT version()").Scan(&version).Error)
	}
	t.Logf("database: %s %s", dialect, version)
	return db, dialect
}

func TestImmediateTaskSettlementDatabase(t *testing.T) {
	db, dialect := openTaskDialectDatabase(t, &model.User{}, &model.Channel{}, &model.Task{}, &model.Log{}, &model.OAuthDerivedTextCharge{})
	oldDB, oldLogDB := model.DB, model.LOG_DB
	oldMain, oldLog := common.MainDatabaseType(), common.LogDatabaseType()
	oldRedis, oldMemory, oldBatch, oldConsume, oldExport := common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled, common.DataExportEnabled
	model.DB, model.LOG_DB = db, db
	common.SetDatabaseTypes(dialect, dialect)
	common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled, common.DataExportEnabled = false, false, false, true, false
	t.Cleanup(func() {
		model.DB, model.LOG_DB = oldDB, oldLogDB
		common.SetDatabaseTypes(oldMain, oldLog)
		common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled, common.DataExportEnabled = oldRedis, oldMemory, oldBatch, oldConsume, oldExport
	})

	const expression = `u("units") == 7 ? tier("missing", u("missing") * 1.0) : u("units") == 8 ? tier("invalid", -1.0) : u("units") > 3 ? tier("bulk", u("units") * 0.01) : tier("small", u("units") * 0.01)`
	withTieredBillingConfig(t, map[string]string{"document-model": "tiered_expr"}, map[string]string{"document-model": expression})
	const source = `
export const meta={apiVersion:1,key:"generic-settlement",name:"Generic settlement",version:"1.0.0",author:{name:"Test"},models:["document-model"],fetchMode:"per_task",usageSchema:{units:{type:"number",unit:"count"}}};
export function buildSubmitRequest(ctx){return {url:ctx.baseUrl+"/compile",body:ctx.requestBody};}
export function parseSubmitResponse(ctx,resp){return {taskId:"vendor-job",taskData:resp.body,immediate:{status:resp.body.status,reason:"provider rejected job"}};}
export function extractUsage(){return {units:4};}
export function extractUsageOnComplete(ctx,result,body){return body.usage;}
export function parseTaskResult(){throw new Error("completed submissions must not poll");}
export function buildQueryRequest(){throw new Error("completed submissions must not poll");}
`
	plugin, err := pluginruntime.CompilePlugin(source, pluginruntime.Options{})
	require.NoError(t, err)
	for index, tc := range []struct {
		name, status string
		actual       any
		count        float64
	}{
		{"partial", "SUCCESS", 2, 2}, {"zero", "SUCCESS", 0, 0}, {"larger", "SUCCESS", 6, 6},
		{"invalid usage", "SUCCESS", -1, 4}, {"expression failure", "SUCCESS", 7, 4}, {"negative result", "SUCCESS", 8, 4}, {"missing usage", "SUCCESS", nil, 4}, {"failed", "FAILURE", 9, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				body := map[string]any{"status": tc.status}
				if tc.actual != nil {
					body["usage"] = map[string]any{"units": tc.actual}
				}
				encoded, err := common.Marshal(body)
				if err != nil {
					panic(err)
				}
				_, _ = w.Write(encoded)
			}))
			defer server.Close()
			initial := int(20 * common.QuotaPerUnit)
			user := model.User{Username: fmt.Sprintf("task_user_%d", index), AffCode: fmt.Sprintf("task_aff_%d", index), Quota: initial}
			require.NoError(t, db.Create(&user).Error)
			ch := model.Channel{Name: "test provider", Type: constant.ChannelTypeTaskPlugin}
			require.NoError(t, db.Create(&ch).Error)
			c := taskSubmissionTestContext()
			c.Set("group", "default")
			c.Set("username", user.Username)
			c.Set("task_request", map[string]any{"model": "document-model"})
			c.Set(pluginruntime.ContextKeyPinnedPlugin, pluginruntime.PinnedPlugin{Plugin: plugin})
			common.SetContextKey(c, constant.ContextKeyOriginalModel, "document-model")
			common.SetContextKey(c, constant.ContextKeyChannelBaseUrl, server.URL)
			common.SetContextKey(c, constant.ContextKeyChannelId, ch.Id)
			common.SetContextKey(c, constant.ContextKeyChannelType, ch.Type)
			info := taskSubmissionRelayInfo(nil)
			info.UserId = user.Id
			info.OriginModelName = "document-model"
			info.UserGroup = "default"
			info.UsingGroup = "default"
			info.IsPlayground = true
			info.UserSetting.BillingPreference = "wallet_only"
			info.PublicTaskID = model.GenerateTaskID()
			info.LockedChannel = &ch
			outcome, taskErr := executeTaskSubmission(c, info)
			require.Nil(t, taskErr)
			require.NotNil(t, outcome)
			want := common.QuotaRound(tc.count * 0.01 * common.QuotaPerUnit)
			assert.Equal(t, want, outcome.Result.Quota)
			assert.Equal(t, want, info.PriceData.Quota)
			var stored model.Task
			require.NoError(t, db.Where("task_id = ?", info.PublicTaskID).First(&stored).Error)
			assert.Equal(t, want, stored.Quota)
			assert.Equal(t, model.TaskStatus(tc.status), stored.Status)
			assert.Positive(t, stored.FinishTime)
			assert.Equal(t, float64(4), info.TieredBillingSnapshot.EstimatedQuotaBeforeGroup/(0.01*common.QuotaPerUnit))
			if tc.status == "SUCCESS" {
				assert.Equal(t, tc.count, stored.PrivateData.BillingContext.TieredSnapshot.UsageFacts["units"])
			}
			var updated model.User
			require.NoError(t, db.First(&updated, user.Id).Error)
			assert.Equal(t, initial-want, updated.Quota)
			assert.Equal(t, want, updated.UsedQuota)
			var logs []model.Log
			require.NoError(t, db.Where("user_id = ?", user.Id).Find(&logs).Error)
			require.Len(t, logs, 1)
			assert.Equal(t, want, logs[0].Quota)
			var other map[string]any
			require.NoError(t, common.UnmarshalJsonStr(logs[0].Other, &other))
			if tc.status == "SUCCESS" {
				assert.Equal(t, tc.count, other["usage_facts"].(map[string]any)["units"])
			}
			assert.False(t, c.Writer.Written(), "presentation must follow persistence and settlement")
			require.NoError(t, info.Billing.Settle(want))
			info.Billing.Refund(c)
			require.NoError(t, db.First(&updated, user.Id).Error)
			assert.Equal(t, initial-want, updated.Quota, "terminal settlement is idempotent")
		})
	}
}

func TestAcceptedSubmitStreamNeverRetries(t *testing.T) {
	c := taskSubmissionTestContext()
	assert.Equal(t, service.PolicyDecision{Action: "stop", Reason: "task_accepted", Source: "system"}, decideTaskRetry(c, &dto.TaskError{StatusCode: 502, LocalError: true, NoRetry: true}, 3))
}

// Local task rejections carry a message but no cause; the response and the
// decision record must still be produced.
func TestRespondTaskSubmissionErrorWithoutCause(t *testing.T) {
	previousErrorLog := constant.ErrorLogEnabled
	constant.ErrorLogEnabled = false
	t.Cleanup(func() { constant.ErrorLogEnabled = previousErrorLog })
	c := taskSubmissionTestContext()
	taskErr := &dto.TaskError{Code: "get_channel_failed", Message: "no channel", StatusCode: http.StatusServiceUnavailable, LocalError: true}
	require.NotPanics(t, func() { respondTaskSubmissionError(c, taskErr) })
	assert.Equal(t, http.StatusServiceUnavailable, c.Writer.Status())
	events := service.RequestPolicy(c).Events()
	require.Len(t, events, 1)
	assert.Equal(t, service.PolicyDecision{Action: "stop", Reason: "request_failed", Source: "system"}, events[0].Decision)
	assert.Equal(t, http.StatusServiceUnavailable, events[0].Status)
	assert.Equal(t, service.PolicyDecision{Action: "stop", Reason: "local_rejection", Source: "system"}, decideTaskRetry(c, &dto.TaskError{StatusCode: http.StatusForbidden, LocalError: true, Message: "billing"}, 2), "local errors stop once the status rules do not force a retry")
}

// A real accepted request must survive a newly held charge, cancellation,
// and local adjustment failure. Intent insertion precedes debit and transport;
// known targets remain recoverable even when the later SQL debit fails.
func TestExecuteTaskSubmissionAcceptedSQLObligation(t *testing.T) {
	for _, scenario := range []string{"held", "cancelled", "adjustment_sql_failure", "insert_sql_failure", "unknown_send", "stage_sql_failure"} {
		t.Run(scenario, func(t *testing.T) {
			db, kind := openTaskDialectDatabase(t, &model.User{}, &model.Channel{}, &model.Task{}, &model.OAuthDerivedTextCharge{})
			oldDB := model.DB
			oldMain, oldLog := common.MainDatabaseType(), common.LogDatabaseType()
			oldRedis, oldMemory, oldBatch, oldConsume := common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled
			model.DB = db
			common.SetDatabaseTypes(kind, kind)
			common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled = false, false, false, false
			t.Cleanup(func() {
				model.DB = oldDB
				common.SetDatabaseTypes(oldMain, oldLog)
				common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled = oldRedis, oldMemory, oldBatch, oldConsume
			})
			if addr := os.Getenv("NEWAPI_TEST_REDIS_ADDR"); addr != "" {
				require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
				host, _, err := net.SplitHostPort(addr)
				require.NoError(t, err)
				require.Equal(t, "127.0.0.1", host)
				client := redis.NewClient(&redis.Options{Addr: addr})
				require.NoError(t, client.Ping(context.Background()).Err())
				old := common.RDB
				common.RDB, common.RedisEnabled = client, true
				t.Cleanup(func() {
					assert.NoError(t, client.Del(context.Background(), "user:1").Err())
					common.RDB = old
					assert.NoError(t, client.Close())
				})
			} else {
				require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"))
			}
			require.NoError(t, db.Create(&model.User{Id: 1, Username: "accepted-task", Quota: 100}).Error)
			require.NoError(t, db.Create(&model.Channel{Id: 1, Name: "fixture"}).Error)
			c := taskSubmissionTestContext()
			ctx, cancel := context.WithCancel(c.Request.Context())
			defer cancel()
			c.Request = c.Request.WithContext(ctx)
			info := taskSubmissionRelayInfo(nil)
			info.IsPlayground = true
			info.ForcePreConsume = true
			info.UserSetting.BillingPreference = "wallet_only"
			// Keep notification delivery outside this accounting fixture.
			info.UserSetting.QuotaWarningThreshold = -1000
			if scenario == "insert_sql_failure" {
				require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:accepted-insert", func(tx *gorm.DB) {
					if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "Task" {
						tx.AddError(errors.New("injected Task SQL failure"))
					}
				}))
			}
			session, billingErr := service.NewBillingSession(c, info, 80)
			if scenario == "insert_sql_failure" {
				require.NotNil(t, billingErr)
				require.Nil(t, session)
				var rows int64
				require.NoError(t, db.Model(&model.Task{}).Count(&rows).Error)
				assert.Zero(t, rows)
				var user model.User
				require.NoError(t, db.First(&user, 1).Error)
				assert.Equal(t, 100, user.Quota)
				return
			}
			require.Nil(t, billingErr)
			require.NotNil(t, session)
			info.Billing = session
			var received atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				if scenario == "unknown_send" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"task_id":"accepted-private"}`))
			}))
			defer upstream.Close()
			outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL, strings.NewReader(`{}`))
				require.NoError(t, err)
				resp, err := session.SendWalletTask(req)
				if scenario == "unknown_send" {
					require.Error(t, err)
					return nil, service.TaskErrorWrapperLocal(err, "unknown_send", 502)
				}
				require.NoError(t, err)
				_, err = io.Copy(io.Discard, resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				require.Equal(t, http.StatusAccepted, resp.StatusCode)
				require.NoError(t, db.Create(&model.OAuthDerivedTextCharge{Ref: strings.Repeat("b", 64), UserID: 1, State: "held"}).Error)
				switch scenario {
				case "cancelled":
					cancel()
				case "stage_sql_failure":
					require.NoError(t, db.Callback().Update().Before("gorm:update").Register("test:stage-failure", func(tx *gorm.DB) { tx.AddError(errors.New("injected unavailable SQL after accepted")) }))
					t.Cleanup(func() { assert.NoError(t, db.Callback().Update().Remove("test:stage-failure")) })
				case "adjustment_sql_failure":
					require.NoError(t, db.Callback().Update().Before("gorm:update").Register("test:accepted-adjustment", func(tx *gorm.DB) {
						if values, ok := tx.Statement.Dest.(map[string]any); ok && values["quota"] != nil && tx.Statement.Schema != nil && tx.Statement.Schema.Name == "User" {
							tx.AddError(errors.New("injected wallet SQL failure"))
						}
					}))
					t.Cleanup(func() { assert.NoError(t, db.Callback().Update().Remove("test:accepted-adjustment")) })
				}
				result := &relay.TaskSubmitResult{Platform: "plugin", UpstreamTaskID: "accepted-private", Quota: 140}
				if scenario == "adjustment_sql_failure" {
					result.Immediate = &relaycommon.TaskInfo{Status: model.TaskStatusSuccess, Progress: "100%"}
				}
				return result, nil
			})
			assert.EqualValues(t, 1, received.Load())
			assert.False(t, c.Writer.Written())
			assert.False(t, session.NeedsRefund(), "accepted obligations cannot be refunded by failure handlers")
			session.Refund(c)
			if taskErr != nil {
				assert.True(t, taskErr.NoRetry)
			}
			var tasks []model.Task
			require.NoError(t, db.Find(&tasks).Error)
			var user model.User
			require.NoError(t, db.First(&user, 1).Error)
			switch scenario {
			case "unknown_send", "stage_sql_failure":
				require.NotNil(t, taskErr)
				require.Len(t, tasks, 1)
				assert.Equal(t, model.TaskBillingClaimed, tasks[0].BillingState)
				assert.Equal(t, 80, tasks[0].Quota)
				assert.Equal(t, 20, user.Quota)
				if scenario == "stage_sql_failure" {
					require.NoError(t, db.Callback().Update().Remove("test:stage-failure"))
				}
				req, err := http.NewRequest(http.MethodPost, upstream.URL, strings.NewReader(`{}`))
				require.NoError(t, err)
				_, err = session.SendWalletTask(req)
				require.Error(t, err)
				assert.EqualValues(t, 1, received.Load())
			case "adjustment_sql_failure":
				require.NotNil(t, taskErr)
				assert.Equal(t, "task_billing_settlement_failed", taskErr.Code)
				assert.Nil(t, outcome)
				require.Len(t, tasks, 1)
				assert.Equal(t, 80, tasks[0].Quota)
				assert.Equal(t, 20, user.Quota)
				assert.Equal(t, model.TaskBillingPending, tasks[0].BillingState)
				assert.False(t, tasks[0].ResultRetrievable())
				var progress model.TaskBillingProgress
				require.NoError(t, common.UnmarshalJsonStr(tasks[0].BillingProgress, &progress))
				assert.Equal(t, 80, progress.Applied)
				assert.Equal(t, 140, progress.Target)
				require.NoError(t, db.Callback().Update().Remove("test:accepted-adjustment"))
				factory := service.GetTaskAdaptorFunc
				service.GetTaskAdaptorFunc = nil
				service.RunTaskPollingOnce(context.Background(), nil)
				service.GetTaskAdaptorFunc = factory
				require.NoError(t, model.ReconcileWalletTask(context.Background(), tasks[0].ID))
				require.NoError(t, db.First(&tasks[0], tasks[0].ID).Error)
				assert.Equal(t, model.TaskBillingSettled, tasks[0].BillingState)
				assert.EqualValues(t, 1, received.Load())
				require.NoError(t, db.First(&user, 1).Error)
				assert.Equal(t, -40, user.Quota)
			default:
				require.Nil(t, taskErr)
				require.NotNil(t, outcome)
				require.Len(t, tasks, 1)
				assert.Equal(t, 140, tasks[0].Quota)
				assert.Equal(t, "accepted-private", tasks[0].PrivateData.UpstreamTaskID)
				assert.Equal(t, 1, tasks[0].UserId)
				assert.Equal(t, -40, user.Quota)
				require.NoError(t, session.Settle(140))
				session.Refund(c)
				require.NoError(t, db.First(&user, 1).Error)
				assert.Equal(t, -40, user.Quota)
			}
		})
	}
}

// The fixture routes the documented public provider URL through an owned CONNECT
// proxy to a local TLS upstream. No request reaches the provider. The contract
// itself comes from provider documentation, not this fixture or plugin metadata.
func TestWalletTaskQueryWireBoundary(t *testing.T) {
	const endpoint = "https://ark.cn-beijing.volces.com/api/v3/contents/generations/tasks"
	service.InitHttpClient()
	var received, redirected atomic.Int32
	proxyURL := newWalletTaskQueryProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirected.Add(1)
		} else {
			received.Add(1)
		}
		assert.Equal(t, 1, r.ProtoMajor)
		w.Header().Set("Location", endpoint+"/redirected")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	setting := system_setting.GetFetchSetting()
	previous := *setting
	t.Cleanup(func() { *setting = previous })
	setting.AllowedPorts = []string{"443"}
	for _, scenario := range []string{"allowed_read_redirect", "unknown", "hook", "mixed_batch"} {
		t.Run(scenario, func(t *testing.T) {
			before := received.Load()
			hook := ""
			if scenario == "hook" {
				hook = `utils.fetch({url:ctx.baseUrl+"/anything",method:"GET"});`
			}
			plugin, err := pluginruntime.CompilePlugin(`
export const meta={apiVersion:1,key:"query-fixture",name:"Query fixture",version:"1.0.0",author:{name:"Fixture"},auth:"api_key",models:["fixture"],fetchMode:"batch"};
export function buildSubmitRequest(){return {}}
export function parseSubmitResponse(){return {taskId:"accepted"}}
export function buildQueryRequest(ctx){`+hook+`return {url:ctx.baseUrl+"/api/v3/contents/generations/tasks/"+ctx.taskId,method:"GET"}}
export function buildBatchQueryRequest(ctx){return {url:ctx.baseUrl+"/batch",method:"POST",body:{}}}
export function parseTaskResult(){return {status:"IN_PROGRESS"}}
export function parseBatchResult(){return []}
`, pluginruntime.Options{})
			require.NoError(t, err)
			adaptor := taskadaptor.New(plugin)
			adaptor.Init(&relaycommon.RelayInfo{ChannelMeta: &relaycommon.ChannelMeta{ChannelBaseUrl: "https://ark.cn-beijing.volces.com", ChannelSetting: kitdto.ChannelSettings{Proxy: proxyURL, TLSInsecureSkipVerify: true}}})
			ref := "fixture-ref"
			progress, err := common.Marshal(model.TaskBillingProgress{UserID: 1, Applied: 80, SubmitURL: endpoint})
			require.NoError(t, err)
			task := &model.Task{TaskID: ref, UserId: 1, Quota: 80, BillingRef: &ref, BillingProtocol: 1, BillingState: model.TaskBillingReady, BillingProgress: string(progress), PrivateData: model.TaskPrivateData{UpstreamTaskID: "accepted"}}
			if scenario == "unknown" {
				task.BillingProgress = `{"user_id":1,"applied":80}`
			}
			var resp *http.Response
			if scenario == "mixed_batch" {
				resp, err = adaptor.FetchBatchTasks("https://ark.cn-beijing.volces.com", "fixture", []*model.Task{{TaskID: "legacy"}, task}, proxyURL)
			} else {
				resp, err = adaptor.FetchTask("https://ark.cn-beijing.volces.com", "fixture", task, proxyURL)
			}
			if scenario == "allowed_read_redirect" {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
				require.NoError(t, resp.Body.Close())
				assert.Equal(t, before+1, received.Load())
			} else {
				require.Error(t, err)
				assert.Nil(t, resp)
				assert.Equal(t, before, received.Load())
			}
			assert.Zero(t, redirected.Load())
		})
	}
}

func newWalletTaskQueryProxy(t *testing.T, handler http.Handler) string {
	t.Helper()
	upstream := httptest.NewTLSServer(handler)
	t.Cleanup(upstream.Close)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "ark.cn-beijing.volces.com:443" {
			w.WriteHeader(403)
			return
		}
		dest, err := net.Dial("tcp", upstream.Listener.Addr().String())
		if err != nil {
			w.WriteHeader(502)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			dest.Close()
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done := make(chan struct{})
		go func() { _, _ = io.Copy(dest, conn); dest.Close(); close(done) }()
		_, _ = io.Copy(conn, dest)
		conn.Close()
		<-done
	}))
	t.Cleanup(proxy.Close)

	return proxy.URL
}

// A real BillingSession submit, persisted Task, formal poll dispatcher and plugin
// consumer share the same fixture. The proxy terminates only at owned loopback.
func TestWalletTaskPollerProtocol(t *testing.T) {
	oldLimit, oldTimeout := constant.TaskQueryLimit, constant.TaskTimeoutMinutes
	constant.TaskQueryLimit, constant.TaskTimeoutMinutes = 100, 10
	t.Cleanup(func() { constant.TaskQueryLimit, constant.TaskTimeoutMinutes = oldLimit, oldTimeout })
	const endpoint = "https://ark.cn-beijing.volces.com/api/v3/contents/generations/tasks"
	for _, scenario := range []string{"per_call", "mixed_batch", "timeout", "not_found", "unknown_contract", "foreign_envelope", "missing_envelope_id", "foreign_id", "missing_id", "parser_foreign_id", "parser_nil", "matched_failure", "legacy_envelope", "builtin_success", "builtin_failure", "builtin_queued", "builtin_running", "builtin_missing_id", "builtin_foreign_id", "builtin_malformed", "builtin_unknown"} {
		t.Run(scenario, func(t *testing.T) {
			db, kind := openTaskDialectDatabase(t, &model.User{}, &model.Token{}, &model.Channel{}, &model.Task{}, &model.OAuthDerivedTextCharge{}, &model.Log{})
			oldDB, oldLogDB := model.DB, model.LOG_DB
			oldMain, oldLog := common.MainDatabaseType(), common.LogDatabaseType()
			oldRDB, oldMaster := common.RDB, common.IsMasterNode
			oldRedis, oldMemory, oldConsume := common.RedisEnabled, common.MemoryCacheEnabled, common.LogConsumeEnabled
			model.DB, model.LOG_DB = db, db
			common.SetDatabaseTypes(kind, kind)
			t.Setenv("LOG_SQL_DSN", "")
			common.IsMasterNode = false
			require.NoError(t, model.InitLogDB())
			common.RedisEnabled, common.MemoryCacheEnabled, common.LogConsumeEnabled = false, false, false
			t.Cleanup(func() {
				model.DB = oldDB
				common.SetMainDatabaseType(oldMain)
				require.NoError(t, model.InitLogDB())
				model.LOG_DB, common.RDB, common.IsMasterNode = oldLogDB, oldRDB, oldMaster
				common.SetDatabaseTypes(oldMain, oldLog)
				common.RedisEnabled, common.MemoryCacheEnabled, common.LogConsumeEnabled = oldRedis, oldMemory, oldConsume
			})
			if addr := os.Getenv("NEWAPI_TEST_REDIS_ADDR"); addr != "" {
				require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
				host, _, err := net.SplitHostPort(addr)
				require.NoError(t, err)
				require.Equal(t, "127.0.0.1", host)
				client := redis.NewClient(&redis.Options{Addr: addr})
				require.NoError(t, client.Ping(context.Background()).Err())
				common.RDB, common.RedisEnabled = client, true
				t.Cleanup(func() { assert.NoError(t, client.Close()) })
			} else {
				require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"))
			}
			var submits, queries, batches, legacyQueries atomic.Int32
			proxyURL := newWalletTaskQueryProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/legacy" {
					legacyQueries.Add(1)
					assert.Equal(t, http.MethodPost, r.Method)
					_, _ = io.WriteString(w, `{"code":"success","data":{"task_id":"legacy","status":"SUCCESS","progress":"100%"}}`)
					return
				}
				if r.URL.Path == "/batch" {
					batches.Add(1)
					assert.Equal(t, http.MethodPost, r.Method)
					_, _ = io.WriteString(w, `[]`)
					return
				}
				if r.Method == http.MethodPost {
					submits.Add(1)
					_, _ = io.WriteString(w, `{"id":"accepted"}`)
					return
				}
				queries.Add(1)
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, 1, r.ProtoMajor)
				if scenario == "not_found" {
					w.WriteHeader(404)
					return
				}
				body := `{"id":"accepted","status":"succeeded"}`
				switch scenario {
				case "foreign_envelope":
					body = `{"code":"success","data":{"task_id":"foreign","status":"FAILURE","progress":"100%"}}`
				case "missing_envelope_id":
					body = `{"code":"success","data":{"status":"FAILURE","progress":"100%"}}`
				case "foreign_id", "builtin_foreign_id":
					body = `{"id":"foreign","status":"failed"}`
				case "missing_id", "builtin_missing_id":
					body = `{"status":"failed"}`
				case "parser_foreign_id":
					body = `{"id":"accepted","result_id":"foreign","status":"failed"}`
				case "parser_nil":
					body = `{"id":"accepted","result_nil":true,"status":"failed"}`
				case "matched_failure", "builtin_failure":
					body = `{"id":"accepted","status":"failed"}`
				}
				if scenario == "builtin_queued" && queries.Load() == 1 {
					body = `{"id":"accepted","status":"queued"}`
				} else if scenario == "builtin_running" && queries.Load() == 1 {
					body = `{"id":"accepted","status":"running"}`
				} else if scenario == "builtin_malformed" {
					body = `{"id":"accepted","status":`
				} else if scenario == "builtin_unknown" {
					body = `{"id":"accepted","status":"not-a-provider-status"}`
				}
				_, _ = io.WriteString(w, body)
			}))
			settings := kitdto.ChannelSettings{Proxy: proxyURL, TLSInsecureSkipVerify: true}
			encoded, err := common.Marshal(settings)
			require.NoError(t, err)
			config := string(encoded)
			base := "https://ark.cn-beijing.volces.com"
			require.NoError(t, db.Create(&model.User{Id: 1, Username: "poll-owner", Quota: 100, Status: common.UserStatusEnabled}).Error)
			require.NoError(t, db.Create(&model.Token{Id: 1, UserId: 1, Key: "synthetic-poll-token", RemainQuota: 100, Status: common.TokenStatusEnabled, ExpiredTime: -1}).Error)
			ch := model.Channel{Id: 1, Name: "owned-query-proxy", Type: constant.ChannelTypeTaskPlugin, BaseURL: &base, Setting: &config, Key: "synthetic-upstream", OtherSettings: `{"disable_task_polling_sleep":true}`}
			require.NoError(t, db.Create(&ch).Error)
			pluginSource := `
export const meta={apiVersion:1,key:"poll-fixture",name:"Poll fixture",version:"1.0.0",author:{name:"Fixture"},auth:"api_key",models:["fixture"],fetchMode:"batch"};
export function buildSubmitRequest(){return {}}
export function parseSubmitResponse(){return {taskId:"accepted"}}
export function buildQueryRequest(ctx){if(ctx.taskId==="legacy")return {url:ctx.baseUrl+"/legacy",method:"POST"};return {url:ctx.baseUrl+"/api/v3/contents/generations/tasks/"+ctx.taskId,method:"GET"}}
export function parseTaskResult(ctx,body){if(body.result_nil)return null;if(ctx.taskId==="legacy")throw Error("legacy envelope must retain host parsing");return {taskId:body.result_id||body.id,status:body.status==="succeeded"?"SUCCESS":body.status==="failed"?"FAILURE":"UNKNOWN",progress:"100%"}}
export function buildBatchQueryRequest(ctx){return {url:ctx.baseUrl+"/batch",method:"POST",body:{ids:["legacy"]}}}
export function parseBatchResult(){return [{taskId:"legacy",status:"SUCCESS",progress:"100%"}]}
`
			if scenario == "legacy_envelope" {
				pluginSource = strings.Replace(pluginSource, `fetchMode:"batch"`, `fetchMode:"per_task"`, 1)
			}
			if strings.HasPrefix(scenario, "builtin_") {
				// Compile the actual embedded source without changing its optional-ID contract.
				pluginSource, err = builtinplugins.Source("doubao")
				require.NoError(t, err)
			}
			plugin, err := pluginruntime.CompilePlugin(pluginSource, pluginruntime.Options{})
			require.NoError(t, err)
			oldFactory := service.GetTaskAdaptorFunc
			service.GetTaskAdaptorFunc = func(constant.TaskPlatform) service.TaskPollingAdaptor { return taskadaptor.New(plugin) }
			t.Cleanup(func() { service.GetTaskAdaptorFunc = oldFactory })
			fetch := system_setting.GetFetchSetting()
			oldFetch := *fetch
			fetch.AllowedPorts = []string{"443"}
			t.Cleanup(func() { *fetch = oldFetch })
			c := taskSubmissionTestContext()
			c.Set("platform", "poll-fixture")
			info := taskSubmissionRelayInfo(nil)
			info.IsPlayground = false
			info.TokenId = 1
			info.TokenKey = "synthetic-poll-token"
			info.ForcePreConsume = true
			info.UserSetting.BillingPreference = "wallet_only"
			info.UserSetting.QuotaWarningThreshold = -1000
			info.ChannelSetting = settings
			info.PriceData.UsePrice = true
			session, billingErr := service.NewBillingSession(c, info, 80)
			require.Nil(t, billingErr)
			info.Billing = session
			outcome, taskErr := executeTaskSubmissionWith(c, info, func(*gin.Context, *relaycommon.RelayInfo) (*relay.TaskSubmitResult, *dto.TaskError) {
				url := endpoint
				if scenario == "unknown_contract" {
					url = base + "/unknown-submit"
				}
				req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(`{}`))
				require.NoError(t, err)
				resp, err := session.SendWalletTask(req)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				return &relay.TaskSubmitResult{Platform: "poll-fixture", UpstreamTaskID: "accepted", Quota: 80}, nil
			})
			require.Nil(t, taskErr)
			require.NotNil(t, outcome)
			assert.EqualValues(t, 1, submits.Load())
			if scenario == "timeout" {
				require.NoError(t, db.Model(&model.Task{}).Where("id = ?", outcome.Task.ID).UpdateColumn("submit_time", int64(1)).Error)
			}
			if scenario == "mixed_batch" || scenario == "legacy_envelope" {
				legacy := &model.Task{TaskID: "legacy-public", UserId: 1, ChannelId: 1, Platform: "poll-fixture", Status: model.TaskStatusInProgress, Progress: "0%", SubmitTime: time.Now().Unix(), PrivateData: model.TaskPrivateData{UpstreamTaskID: "legacy", BillingContext: &model.TaskBillingContext{PerCallBilling: true}}}
				require.NoError(t, db.Create(legacy).Error)
			}
			var before model.Task
			require.NoError(t, db.First(&before, outcome.Task.ID).Error)
			service.RunTaskPollingOnce(context.Background(), nil)
			var stored model.Task
			require.NoError(t, db.First(&stored, outcome.Task.ID).Error)
			wantBalance, wantApplied := 20, 80
			if scenario == "matched_failure" || scenario == "builtin_failure" {
				assert.Equal(t, model.TaskBillingSettled, stored.BillingState)
				assert.EqualValues(t, model.TaskStatusFailure, stored.Status)
				assert.EqualValues(t, 1, queries.Load())
				wantBalance, wantApplied = 100, 0
			} else if scenario == "per_call" || scenario == "mixed_batch" || scenario == "legacy_envelope" || scenario == "builtin_success" {
				assert.Equal(t, model.TaskBillingSettled, stored.BillingState)
				assert.EqualValues(t, model.TaskStatusSuccess, stored.Status)
				assert.EqualValues(t, 1, queries.Load())
			} else if scenario == "builtin_queued" || scenario == "builtin_running" {
				assert.Equal(t, model.TaskBillingReady, stored.BillingState)
				wantStatus := model.TaskStatusQueued
				if scenario == "builtin_running" {
					wantStatus = model.TaskStatusInProgress
				}
				assert.EqualValues(t, wantStatus, stored.Status)
				assert.EqualValues(t, 1, queries.Load())
			} else {
				assert.Equal(t, model.TaskBillingHeld, stored.BillingState)
				assert.EqualValues(t, model.TaskStatusUnknown, stored.Status)
				if scenario != "timeout" && scenario != "unknown_contract" {
					assert.EqualValues(t, 1, queries.Load())
				} else {
					assert.Zero(t, queries.Load())
				}
			}
			if scenario == "legacy_envelope" {
				var legacy model.Task
				require.NoError(t, db.Where("task_id = ?", "legacy-public").First(&legacy).Error)
				assert.Zero(t, legacy.BillingProtocol)
				assert.EqualValues(t, model.TaskStatusSuccess, legacy.Status)
				assert.EqualValues(t, 1, legacyQueries.Load())
			} else {
				assert.Zero(t, legacyQueries.Load())
			}
			assert.Equal(t, before.BillingRef, stored.BillingRef)
			assert.Equal(t, before.UserId, stored.UserId)
			assert.Equal(t, "accepted", stored.PrivateData.UpstreamTaskID)
			var progress model.TaskBillingProgress
			require.NoError(t, common.UnmarshalJsonStr(stored.BillingProgress, &progress))
			assert.Equal(t, 1, progress.UserID)
			assert.Equal(t, 1, progress.TokenID)
			assert.Equal(t, wantApplied, progress.Applied)
			assert.Equal(t, wantApplied, progress.Target)
			assert.Equal(t, wantApplied, stored.Quota)
			if stored.BillingState == model.TaskBillingHeld {
				assert.Equal(t, before.BillingProgress, stored.BillingProgress, "unrecognized observation must not alter accounting facts")
			}
			if scenario == "mixed_batch" {
				assert.EqualValues(t, 1, batches.Load())
			} else {
				assert.Zero(t, batches.Load())
			}
			var user model.User
			require.NoError(t, db.First(&user, 1).Error)
			assert.Equal(t, wantBalance, user.Quota)
			var token model.Token
			require.NoError(t, db.First(&token, 1).Error)
			assert.Equal(t, wantBalance, token.RemainQuota)
			assert.Equal(t, wantApplied, token.UsedQuota)
			if strings.HasPrefix(scenario, "builtin_") {
				admissionErr := model.CheckUserBillingAdmission(context.Background(), 1)
				if stored.BillingState == model.TaskBillingHeld {
					require.Error(t, admissionErr)
				} else {
					require.NoError(t, admissionErr, "a valid provider observation must not hold the user")
				}
			}
			observedQueries := queries.Load()
			service.RunTaskPollingOnce(context.Background(), nil)
			session.Refund(c)
			require.NoError(t, db.First(&user, 1).Error)
			assert.Equal(t, wantBalance, user.Quota)
			require.NoError(t, db.First(&token, 1).Error)
			assert.Equal(t, wantBalance, token.RemainQuota)
			assert.Equal(t, wantApplied, token.UsedQuota)
			if scenario == "builtin_queued" || scenario == "builtin_running" {
				assert.Equal(t, observedQueries+1, queries.Load(), "ready task may query to its terminal result")
				require.NoError(t, db.First(&stored, outcome.Task.ID).Error)
				assert.Equal(t, model.TaskBillingSettled, stored.BillingState)
				assert.EqualValues(t, model.TaskStatusSuccess, stored.Status)
				require.NoError(t, model.CheckUserBillingAdmission(context.Background(), 1))
			} else {
				assert.Equal(t, observedQueries, queries.Load(), "held/terminal tasks must not query again")
			}
			assert.EqualValues(t, 1, submits.Load())
		})
	}
}

// Reuses the task dialect fixture; financial stores are explicit so missing
// tables can be tested as failures rather than being interpreted as no debt.
func newBillingAdmissionFixture(t *testing.T) (*gorm.DB, model.User, model.Token) {
	t.Helper()
	db, kind := openTaskDialectDatabase(t, &model.User{}, &model.Token{}, &model.Task{}, &model.OAuthDerivedTextCharge{}, &model.SubscriptionPlan{}, &model.UserSubscription{}, &model.SubscriptionPreConsumeRecord{})
	oldDB, oldMain, oldLog := model.DB, common.MainDatabaseType(), common.LogDatabaseType()
	oldLogDB, oldMaster := model.LOG_DB, common.IsMasterNode
	oldRedis, oldMemory, oldBatch, oldConsume, oldRDB := common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled, common.RDB
	model.DB = db
	common.SetDatabaseTypes(kind, kind)
	t.Setenv("LOG_SQL_DSN", "")
	common.IsMasterNode = false
	require.NoError(t, model.InitLogDB()) // existing dialect initializer, same pool, no migration
	common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled = false, false, false, false
	t.Cleanup(func() {
		model.DB = oldDB
		common.SetMainDatabaseType(oldMain)
		require.NoError(t, model.InitLogDB())
		model.LOG_DB, common.IsMasterNode = oldLogDB, oldMaster
		common.SetDatabaseTypes(oldMain, oldLog)
		common.RedisEnabled, common.MemoryCacheEnabled, common.BatchUpdateEnabled, common.LogConsumeEnabled, common.RDB = oldRedis, oldMemory, oldBatch, oldConsume, oldRDB
	})
	if addr := os.Getenv("NEWAPI_TEST_REDIS_ADDR"); addr != "" {
		require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
		host, _, err := net.SplitHostPort(addr)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", host)
		client := redis.NewClient(&redis.Options{Addr: addr})
		require.NoError(t, client.Ping(context.Background()).Err())
		common.RDB, common.RedisEnabled = client, true
		t.Cleanup(func() { assert.NoError(t, client.Close()) })
	} else {
		require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"))
	}
	id := 7000000 + int(responsesWSTestUserSequence.Add(1))
	user := model.User{Id: id, Username: fmt.Sprintf("admission-%d", id), AffCode: fmt.Sprint(id), Status: common.UserStatusEnabled, Quota: 100, Group: "default"}
	require.NoError(t, db.Create(&user).Error)
	token := model.Token{UserId: id, Key: fmt.Sprintf("inert-admission-fixture-%d", id), Status: common.TokenStatusEnabled, ExpiredTime: -1, RemainQuota: 100}
	require.NoError(t, db.Create(&token).Error)
	return db, user, token
}

func TestRequestBillingAdmission(t *testing.T) {
	withTieredBillingConfig(t, map[string]string{"admission-zero": "tiered_expr"}, map[string]string{"admission-zero": `tier("zero",fixed(0))`})
	prices, free := ratio_setting.ModelPrice2JSONString(), operation_setting.GetQuotaSetting().EnableFreeModelPreConsume
	require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"admission-free":0,"admission-paid":0.00002}`))
	operation_setting.GetQuotaSetting().EnableFreeModelPreConsume = false
	t.Cleanup(func() {
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(prices))
		operation_setting.GetQuotaSetting().EnableFreeModelPreConsume = free
	})
	for _, scenario := range []string{"free_clear", "free_held", "free_claimed", "zero_held", "paid_held", "trusted_held", "subscription_held", "missing_charge_store", "missing_task_store", "sql_error", "paid_clear"} {
		t.Run(scenario, func(t *testing.T) {
			db, user, token := newBillingAdmissionFixture(t)
			if strings.HasSuffix(scenario, "held") || scenario == "free_claimed" {
				task := &model.Task{UserId: user.Id, TaskID: "admission-blocker"}
				require.NoError(t, model.CreateWalletTaskObligation(context.Background(), task, token.Id, 0))
				require.NoError(t, model.ClaimWalletTaskSend(context.Background(), task.ID))
				if scenario != "free_claimed" {
					require.NoError(t, model.HoldWalletTask(context.Background(), task.ID))
				}
			}
			if scenario == "free_clear" {
				// Free service remains free even when the personal wallet is in arrears.
				user.Quota = -20
				require.NoError(t, db.Model(&user).UpdateColumn("quota", user.Quota).Error)
			}
			if scenario == "missing_charge_store" {
				require.NoError(t, db.Migrator().DropTable(&model.OAuthDerivedTextCharge{}))
			}
			if scenario == "missing_task_store" {
				require.NoError(t, db.Migrator().DropTable(&model.Task{}))
			}
			c := taskSubmissionTestContext()
			if scenario == "sql_error" {
				ctx, cancel := context.WithCancel(c.Request.Context())
				cancel()
				c.Request = c.Request.WithContext(ctx)
			}
			name := "admission-free"
			if strings.HasPrefix(scenario, "paid") || scenario == "trusted_held" {
				name = "admission-paid"
			}
			if scenario == "zero_held" {
				name = "admission-zero"
			}
			info := &relaycommon.RelayInfo{UserId: user.Id, TokenId: token.Id, TokenKey: token.Key, UserGroup: "default", UsingGroup: "default", OriginModelName: name, Request: &kitdto.GeneralOpenAIRequest{Model: name}, ForcePreConsume: scenario != "trusted_held"}
			info.UserSetting.BillingPreference = "wallet_only"
			if scenario == "subscription_held" || scenario == "free_clear" {
				info.UserSetting.BillingPreference = "subscription_only"
			}
			pref := info.UserSetting.BillingPreference
			apiErr := relay.PrepareRequestBilling(c, info)
			if scenario == "paid_clear" {
				require.Nil(t, apiErr)
				require.NotNil(t, info.Billing)
				require.NoError(t, info.Billing.Settle(10))
			} else if scenario == "free_clear" {
				require.Nil(t, apiErr)
				assert.True(t, info.PriceData.FreeModel)
				assert.Nil(t, info.Billing, "free admission must not fabricate funding ownership")
				assert.Empty(t, info.BillingSource)
			} else {
				require.NotNil(t, apiErr, "held or unreadable obligation store must reject before upstream wire")
				assert.Nil(t, info.Billing)
			}
			assert.Equal(t, pref, info.UserSetting.BillingPreference)
			var stored model.User
			require.NoError(t, db.First(&stored, user.Id).Error)
			want := user.Quota
			if scenario == "paid_clear" {
				want -= 10
			}
			assert.Equal(t, want, stored.Quota)
			require.NoError(t, db.First(&token, token.Id).Error)
			if scenario == "paid_clear" {
				assert.Equal(t, 90, token.RemainQuota)
			} else {
				assert.Equal(t, 100, token.RemainQuota)
				assert.Zero(t, token.UsedQuota)
			}
		})
	}
}

func TestSubscriptionAdmissionKeepsHistoricalSettlement(t *testing.T) {
	db, user, token := newBillingAdmissionFixture(t)
	plan := model.SubscriptionPlan{Title: "original-subscription", QuotaResetPeriod: model.SubscriptionResetNever}
	require.NoError(t, db.Create(&plan).Error)
	sub := model.UserSubscription{UserId: user.Id, PlanId: plan.Id, AmountTotal: 1000, EndTime: common.GetTimestamp() + 3600, Status: "active"}
	require.NoError(t, db.Create(&sub).Error)
	c := taskSubmissionTestContext()
	info := &relaycommon.RelayInfo{UserId: user.Id, TokenId: token.Id, TokenKey: token.Key, RequestId: "historical-subscription", ForcePreConsume: true}
	info.UserSetting.BillingPreference = "subscription_only"
	session, apiErr := service.NewBillingSession(c, info, 20)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	assert.Equal(t, service.BillingSourceSubscription, info.BillingSource)
	task := &model.Task{UserId: user.Id, TaskID: "later-held"}
	require.NoError(t, model.CreateWalletTaskObligation(context.Background(), task, token.Id, 0))
	require.NoError(t, model.ClaimWalletTaskSend(context.Background(), task.ID))
	require.NoError(t, model.HoldWalletTask(context.Background(), task.ID))
	require.Error(t, session.Reserve(20), "unchanged/zero top-up is still new admission")
	require.Error(t, session.Reserve(25))
	blocked, apiErr := service.NewBillingSession(c, info, 0)
	require.NotNil(t, apiErr)
	require.Nil(t, blocked)
	require.NoError(t, session.ReserveAcceptedTask(25), "accepted upstream obligation is historical")
	require.NoError(t, session.Settle(30))
	require.NoError(t, session.Settle(30))
	require.NoError(t, db.First(&sub, sub.Id).Error)
	assert.EqualValues(t, 30, sub.AmountUsed)
	require.NoError(t, db.First(&user, user.Id).Error)
	assert.Equal(t, 100, user.Quota)
	require.NoError(t, db.First(&token, token.Id).Error)
	assert.Equal(t, 70, token.RemainQuota)
	assert.Equal(t, 30, token.UsedQuota)
	assert.Equal(t, service.BillingSourceSubscription, info.BillingSource)
}

func TestFreeTaskAdmissionPreservesFundingPreference(t *testing.T) {
	prices, free := ratio_setting.ModelPrice2JSONString(), operation_setting.GetQuotaSetting().EnableFreeModelPreConsume
	require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"free-task":0}`))
	operation_setting.GetQuotaSetting().EnableFreeModelPreConsume = false
	t.Cleanup(func() {
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(prices))
		operation_setting.GetQuotaSetting().EnableFreeModelPreConsume = free
	})
	withTieredBillingConfig(t, map[string]string{}, map[string]string{})
	plugin, err := pluginruntime.CompilePlugin(`export const meta={apiVersion:1,key:"free-task-fixture",name:"Free",version:"1.0.0",author:{name:"Test"},models:["free-task"],fetchMode:"per_task"}; export function buildSubmitRequest(ctx){return {url:ctx.baseUrl+"/submit",body:ctx.requestBody};} export function parseSubmitResponse(ctx,resp){return {taskId:"free-job",taskData:resp.body,immediate:{status:"SUCCESS"}};} export function buildQueryRequest(){throw new Error("unexpected query");} export function parseTaskResult(){throw new Error("unexpected query");}`, pluginruntime.Options{})
	require.NoError(t, err)
	for _, held := range []bool{false, true} {
		t.Run(fmt.Sprintf("held_%t", held), func(t *testing.T) {
			db, user, token := newBillingAdmissionFixture(t)
			require.NoError(t, db.AutoMigrate(&model.Channel{}))
			t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&model.Channel{})) })
			if held {
				task := &model.Task{UserId: user.Id, TaskID: "free-held"}
				require.NoError(t, model.CreateWalletTaskObligation(context.Background(), task, token.Id, 0))
				require.NoError(t, model.ClaimWalletTaskSend(context.Background(), task.ID))
				require.NoError(t, model.HoldWalletTask(context.Background(), task.ID))
			}
			require.NoError(t, db.Model(&user).UpdateColumn("quota", -20).Error)
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"status":"SUCCESS"}`)
			}))
			t.Cleanup(upstream.Close)
			channel := model.Channel{Name: "free-local", Type: constant.ChannelTypeTaskPlugin}
			require.NoError(t, db.Create(&channel).Error)
			c := taskSubmissionTestContext()
			c.Set("group", "default")
			c.Set("task_request", map[string]any{"model": "free-task"})
			c.Set(pluginruntime.ContextKeyPinnedPlugin, pluginruntime.PinnedPlugin{Plugin: plugin})
			common.SetContextKey(c, constant.ContextKeyOriginalModel, "free-task")
			common.SetContextKey(c, constant.ContextKeyChannelBaseUrl, upstream.URL)
			common.SetContextKey(c, constant.ContextKeyChannelId, channel.Id)
			common.SetContextKey(c, constant.ContextKeyChannelType, channel.Type)
			info := taskSubmissionRelayInfo(nil)
			info.UserId = user.Id
			info.TokenId = token.Id
			info.TokenKey = token.Key
			info.OriginModelName = "free-task"
			info.UserGroup = "default"
			info.UserSetting.BillingPreference = "subscription_only"
			info.PublicTaskID = model.GenerateTaskID()
			info.LockedChannel = &channel
			outcome, taskErr := executeTaskSubmission(c, info)
			if held {
				require.NotNil(t, taskErr)
				require.Nil(t, outcome)
				assert.Zero(t, calls.Load())
			} else {
				require.Nil(t, taskErr)
				require.NotNil(t, outcome)
				assert.EqualValues(t, 1, calls.Load())
				assert.Zero(t, outcome.Task.Quota)
				assert.Zero(t, outcome.Task.BillingProtocol)
				assert.Nil(t, outcome.Task.BillingRef)
			}
			assert.Nil(t, info.Billing)
			assert.Equal(t, "subscription_only", info.UserSetting.BillingPreference)
			require.NoError(t, db.First(&user, user.Id).Error)
			assert.Equal(t, -20, user.Quota)
			require.NoError(t, db.First(&token, token.Id).Error)
			assert.Equal(t, 100, token.RemainQuota)
			assert.Zero(t, token.UsedQuota)
		})
	}
}

// Formal TokenAuth -> HTTP Relay / ResponsesWebSocket -> common admission ->
// physical local upstream. Both transports must reject before dial/write.
func TestFreeBillingHTTPAndWebSocketAdmission(t *testing.T) {
	for _, state := range []string{"clear", "held", "send_claimed"} {
		t.Run(state, func(t *testing.T) {
			var httpCalls, wsCalls atomic.Int32
			completed := `{"type":"response.completed","response":{"id":"free-response","status":"completed","model":"ws-billing","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}`
			fixture := newAdmissionResponsesFixture(t, func(ws *websocket.Conn, _ *http.Request) {
				for {
					if _, _, err := ws.ReadMessage(); err != nil {
						return
					}
					wsCalls.Add(1)
					if err := ws.WriteMessage(websocket.TextMessage, []byte(completed)); err != nil {
						return
					}
				}
			})
			require.NoError(t, model.DB.AutoMigrate(&model.Task{}, &model.OAuthDerivedTextCharge{}))
			t.Cleanup(func() { require.NoError(t, model.DB.Where("user_id = ?", fixture.user.Id).Delete(&model.Task{}).Error) })
			require.NoError(t, config.GlobalConfig.LoadFromDB(map[string]string{"billing_setting.billing_mode": `{}`, "billing_setting.billing_expr": `{}`, "perf_metrics_setting.enabled": "false"}))
			prices, free := ratio_setting.ModelPrice2JSONString(), operation_setting.GetQuotaSetting().EnableFreeModelPreConsume
			require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"ws-billing":0}`))
			operation_setting.GetQuotaSetting().EnableFreeModelPreConsume = false
			t.Cleanup(func() {
				require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(prices))
				operation_setting.GetQuotaSetting().EnableFreeModelPreConsume = free
			})
			if addr := os.Getenv("NEWAPI_TEST_REDIS_ADDR"); addr != "" {
				require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
				host, _, err := net.SplitHostPort(addr)
				require.NoError(t, err)
				require.Equal(t, "127.0.0.1", host)
				client := redis.NewClient(&redis.Options{Addr: addr})
				require.NoError(t, client.Ping(context.Background()).Err())
				oldRDB, oldEnabled := common.RDB, common.RedisEnabled
				common.RDB, common.RedisEnabled = client, true
				t.Cleanup(func() {
					common.RDB, common.RedisEnabled = oldRDB, oldEnabled
					assert.NoError(t, client.Close())
				})
			} else {
				require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"))
			}
			if state != "clear" {
				task := &model.Task{TaskID: "wire-admission-blocker", UserId: fixture.user.Id}
				require.NoError(t, model.CreateWalletTaskObligation(context.Background(), task, fixture.token.Id, 0))
				require.NoError(t, model.ClaimWalletTaskSend(context.Background(), task.ID))
				if state == "held" {
					require.NoError(t, model.HoldWalletTask(context.Background(), task.ID))
				}
			}
			fixture.httpUpstream = func(w http.ResponseWriter, r *http.Request) {
				httpCalls.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", completed)
			}
			req, err := http.NewRequest(http.MethodPost, fixture.gatewayURL+"/v1/responses", strings.NewReader(`{"model":"ws-billing","input":"free","stream":true}`))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer sk-"+fixture.token.Key)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			select {
			case <-fixture.httpDone:
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP request did not reach the formal relay handler")
			}
			if state == "clear" {
				assert.Equal(t, 200, resp.StatusCode)
				assert.Contains(t, string(body), "response.completed")
			} else {
				assert.GreaterOrEqual(t, resp.StatusCode, 400)
			}
			require.NoError(t, fixture.client.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"ws-billing","input":"free"}`)))
			require.NoError(t, fixture.client.SetReadDeadline(time.Now().Add(3*time.Second)))
			_, raw, err := fixture.client.ReadMessage()
			require.NoError(t, err)
			var event struct {
				Type string `json:"type"`
			}
			require.NoError(t, common.Unmarshal(raw, &event))
			if state == "clear" {
				assert.Equal(t, "response.completed", event.Type)
			} else {
				assert.Equal(t, "error", event.Type)
			}
			fixture.closeAndWait(t)
			want := int32(0)
			if state == "clear" {
				want = 1
			}
			assert.Equal(t, want, httpCalls.Load())
			assert.Equal(t, want, wsCalls.Load())
			assert.Equal(t, want, fixture.connections.Load())
			var user model.User
			require.NoError(t, model.DB.First(&user, fixture.user.Id).Error)
			assert.Equal(t, 100000, user.Quota)
			var token model.Token
			require.NoError(t, model.DB.First(&token, fixture.token.Id).Error)
			assert.Equal(t, 3000, token.RemainQuota)
			assert.Zero(t, token.UsedQuota)
			var rows int64
			require.NoError(t, model.DB.Model(&model.Task{}).Where("user_id = ?", user.Id).Count(&rows).Error)
			if state == "clear" {
				assert.Zero(t, rows, "free HTTP/WebSocket requests create no billing ownership")
			}
		})
	}
}

// The older Responses fixture dials before initializing S1 classification
// tables. Compose its DB/credential fixture and connection cleanup here so the
// real TokenAuth sees a controlled, explicit manual-token history fixture.
func newAdmissionResponsesFixture(t *testing.T, handle func(*websocket.Conn, *http.Request)) *responsesWSBillingTest {
	t.Helper()
	oldTimeout := constant.StreamingTimeout
	constant.StreamingTimeout = 30
	t.Cleanup(func() { constant.StreamingTimeout = oldTimeout })
	require.NoError(t, i18n.Init())
	user, token := setupResponsesWSRequestTest(t)
	require.NoError(t, model.DB.AutoMigrate(&model.Task{}, &model.OAuthDerivedTextCharge{}, &model.OAuthDerivedTokenSource{}, &model.OAuthDerivedTokenHistory{}, &model.Channel{}, &model.Ability{}, &model.Log{}))
	var birthHistory model.OAuthDerivedTokenHistory
	require.NoError(t, model.DB.First(&birthHistory).Error)
	oldCount, oldBatch, oldLogs := constant.CountToken, common.BatchUpdateEnabled, common.LogConsumeEnabled
	constant.CountToken, common.BatchUpdateEnabled, common.LogConsumeEnabled = false, false, false
	saved := map[string]string{}
	require.NoError(t, config.GlobalConfig.SaveToDB(func(k, v string) error {
		if k == "billing_setting.billing_mode" || k == "billing_setting.billing_expr" || k == "perf_metrics_setting.enabled" {
			saved[k] = v
		}
		return nil
	}))
	t.Cleanup(func() {
		constant.CountToken, common.BatchUpdateEnabled, common.LogConsumeEnabled = oldCount, oldBatch, oldLogs
		require.NoError(t, config.GlobalConfig.LoadFromDB(saved))
	})
	require.NoError(t, model.DB.Model(user).Updates(map[string]any{"quota": 100000, "setting": `{"billing_preference":"wallet_only"}`}).Error)
	require.NoError(t, model.DB.Model(token).UpdateColumn("remain_quota", 3000).Error)
	fixture := &responsesWSBillingTest{user: user, token: token, done: make(chan struct{}), upstreamDone: make(chan struct{}), httpDone: make(chan struct{}, 1)}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			fixture.httpUpstream(w, r)
			return
		}
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if !assert.NoError(t, err) {
			return
		}
		fixture.connections.Add(1)
		defer ws.Close()
		defer close(fixture.upstreamDone)
		handle(ws, r)
	}))
	t.Cleanup(upstream.Close)
	channel := &model.Channel{Name: "admission-upstream", Key: "inert-local-upstream", Status: common.ChannelStatusEnabled, Type: constant.ChannelTypeOpenAI, Group: "default", Models: "ws-billing", BaseURL: &upstream.URL}
	channel.SetSetting(kitdto.ChannelSettings{ResponsesWebSocketEnabled: true})
	require.NoError(t, model.DB.Create(channel).Error)
	fixture.channel = channel
	require.NoError(t, model.DB.Create(&model.Ability{ChannelId: channel.Id, Model: "ws-billing", Group: "default", Enabled: true}).Error)
	t.Cleanup(func() {
		require.NoError(t, model.DB.Where("channel_id = ?", channel.Id).Delete(&model.Ability{}).Error)
		require.NoError(t, model.DB.Delete(channel).Error)
	})
	engine := gin.New()
	engine.GET("/v1/responses", middleware.TokenAuth(), func(c *gin.Context) {
		defer close(fixture.done)
		c.Set(common.RequestIdKey, "admission-ws")
		ResponsesWebSocket(c)
	})
	engine.POST("/v1/responses", middleware.TokenAuth(), middleware.Distribute(), func(c *gin.Context) {
		defer func() { fixture.httpDone <- struct{}{} }()
		c.Set(common.RequestIdKey, "admission-http")
		Relay(c, relaytypes.RelayFormatOpenAIResponses)
	})
	gateway := httptest.NewServer(engine)
	fixture.gatewayURL = gateway.URL
	t.Cleanup(gateway.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(gateway.URL, "http")+"/v1/responses", http.Header{"Authorization": []string{"Bearer sk-" + token.Key}})
	require.NoError(t, err)
	fixture.client = client
	t.Cleanup(func() { fixture.closeAndWait(t) })
	return fixture
}

func (s *taskSubmissionTestBilling) ReserveBeforeSubmit(quota int) error { return s.Reserve(quota) }
