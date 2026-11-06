package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	pluginruntime "github.com/QuantumNous/new-api/pkg/jsplugin"
	"github.com/QuantumNous/new-api/relay"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type nativeRouteBilling struct {
	events      []string
	preConsumed int
	userID      int
	settled     bool
	reserveErr  error
}

// Settle charges what the reservation did not cover.
func (b *nativeRouteBilling) Settle(quota int) error {
	b.events = append(b.events, "settle")
	if quota > b.preConsumed {
		if err := model.DecreaseUserQuota(b.userID, quota-b.preConsumed, true); err != nil {
			return err
		}
	} else if quota < b.preConsumed {
		if err := model.IncreaseUserQuota(b.userID, b.preConsumed-quota, true); err != nil {
			return err
		}
	}
	b.settled = true
	return nil
}

func (b *nativeRouteBilling) Refund(*gin.Context) {
	b.events = append(b.events, "refund")
	if !b.settled && b.preConsumed > 0 {
		_ = model.IncreaseUserQuota(b.userID, b.preConsumed, true)
		b.preConsumed = 0
	}
}

func (b *nativeRouteBilling) NeedsRefund() bool {
	return !b.settled && b.preConsumed > 0
}

func (b *nativeRouteBilling) GetPreConsumedQuota() int {
	return b.preConsumed
}

func (b *nativeRouteBilling) Reserve(quota int) error {
	delta := max(0, quota-b.preConsumed)
	if delta == 0 {
		return nil
	}
	b.events = append(b.events, "reserve")
	if err := model.DecreaseUserQuota(b.userID, delta, true); err != nil {
		return err
	}
	b.preConsumed = quota
	return nil
}

// This double models legacy protocol0 billing after upstream acceptance; it
// does not create or claim a durable protocol1 wallet obligation.
func (b *nativeRouteBilling) ReserveAcceptedTask(quota int) error {
	if b.reserveErr != nil {
		b.events = append(b.events, "reserve")
		return b.reserveErr
	}
	return b.Reserve(quota)
}

func TestKlingNativeRouteSubmitPollSettleAndQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service.InitHttpClient()

	previousDB := model.DB
	previousLogDB := model.LOG_DB
	previousMemoryCache := common.MemoryCacheEnabled
	previousBatchUpdate := common.BatchUpdateEnabled
	previousLogConsume := common.LogConsumeEnabled
	previousRedisEnabled := common.RedisEnabled
	database, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, database.AutoMigrate(&model.User{}, &model.Channel{}, &model.Task{}, &model.Log{}))
	model.DB = database
	model.LOG_DB = database
	common.MemoryCacheEnabled = false
	common.BatchUpdateEnabled = false
	common.LogConsumeEnabled = false
	common.RedisEnabled = false
	previousModelRatios := ratio_setting.ModelRatio2JSONString()
	require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(`{"kling-v3":1}`))
	t.Cleanup(func() {
		model.DB = previousDB
		model.LOG_DB = previousLogDB
		common.MemoryCacheEnabled = previousMemoryCache
		common.BatchUpdateEnabled = previousBatchUpdate
		common.LogConsumeEnabled = previousLogConsume
		common.RedisEnabled = previousRedisEnabled
		require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(previousModelRatios))
	})
	require.NoError(t, database.Create(&model.User{
		Id:       7,
		Username: "native-route-user",
		Group:    "default",
		Quota:    1_000_000,
	}).Error)

	var submitCalls atomic.Int32
	var queryCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/kling/v1/videos/text2video":
			submitCalls.Add(1)
			body, readErr := io.ReadAll(r.Body)
			if !assert.NoError(t, readErr) {
				http.Error(w, "read request", http.StatusInternalServerError)
				return
			}
			assert.Contains(t, string(body), `"model_name":"kling-v3"`)
			_, _ = io.WriteString(w, `{"code":0,"message":"","data":{"task_id":"kling-private-1","task_status":"submitted"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/kling/v1/videos/text2video/kling-private-1":
			queryCalls.Add(1)
			_, _ = io.WriteString(w, `{"code":0,"message":"","data":{"task_id":"kling-private-1","task_status":"succeed","task_status_msg":"","task_result":{"videos":[{"id":"video-private","url":"https://cdn.example/video.mp4","duration":"5"}]},"final_unit_deduction":"1"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	channel := model.Channel{
		Type:    constant.ChannelTypeKling,
		Name:    "kling-native-e2e",
		Key:     "sk-test",
		BaseURL: &upstream.URL,
		Status:  common.ChannelStatusEnabled,
		Models:  "kling-v3",
		Group:   "default",
	}
	require.NoError(t, database.Create(&channel).Error)

	generation := pluginruntime.DefaultRegistry.Generation()
	require.NotNil(t, generation)
	submitBinding, found := generation.LookupDeclaredRoute(http.MethodPost, "/kling/v1/videos/text2video")
	require.True(t, found)
	require.Equal(t, "kling", submitBinding.Plugin.Meta.Key)

	submitRecorder := httptest.NewRecorder()
	submitContext, _ := gin.CreateTestContext(submitRecorder)
	submitContext.Request = httptest.NewRequest(
		http.MethodPost,
		"/kling/v1/videos/text2video",
		bytes.NewBufferString(`{"model_name":"kling-v3","prompt":"a lighthouse"}`),
	)
	submitContext.Request.Header.Set("Content-Type", "application/json")
	submitContext.Set(pluginruntime.ContextKeyPinnedRoute, pluginruntime.PinnedRoute{
		Generation: generation,
		Plugin:     submitBinding.Plugin,
		Route:      submitBinding.Route,
	})
	common.SetContextKey(submitContext, constant.ContextKeyUserId, 7)
	common.SetContextKey(submitContext, constant.ContextKeyUserGroup, "default")
	common.SetContextKey(submitContext, constant.ContextKeyUsingGroup, "default")
	common.SetContextKey(submitContext, constant.ContextKeyTokenGroup, "default")
	common.SetContextKey(submitContext, constant.ContextKeyUserQuota, 1_000_000)

	middleware.PrepareTaskPluginRoute()(submitContext)
	require.False(t, submitContext.IsAborted(), submitRecorder.Body.String())
	require.Equal(t, "kling-v3", submitContext.GetString("resolved_task_model"))
	require.Equal(t, "text_to_video", submitContext.GetString("task_action"))
	require.Nil(t, middleware.SetupContextForSelectedChannel(submitContext, &channel, "kling-v3"))

	billing := &nativeRouteBilling{userID: 7}
	relayInfo := &relaycommon.RelayInfo{
		UserId:          7,
		UserGroup:       "default",
		UsingGroup:      "default",
		UserQuota:       1_000_000,
		TokenGroup:      "default",
		OriginModelName: "kling-v3",
		Billing:         billing,
		TaskRelayInfo: &relaycommon.TaskRelayInfo{
			Action:        submitContext.GetString("task_action"),
			PublicTaskID:  "task_kling_public",
			LockedChannel: &channel,
		},
	}

	outcome, taskErr := executeTaskSubmissionWith(submitContext, relayInfo, relay.RelayTaskSubmit)
	require.Nil(t, taskErr)
	require.NotNil(t, outcome)
	require.Equal(t, []string{"reserve", "settle"}, billing.events)
	require.False(t, submitContext.Writer.Written())

	presentTaskSubmission(submitContext, outcome)
	require.Equal(t, http.StatusOK, submitRecorder.Code)
	assert.Contains(t, submitRecorder.Body.String(), `"task_id":"task_kling_public"`)
	assert.NotContains(t, submitRecorder.Body.String(), "kling-private-1")
	assert.Equal(t, int32(1), submitCalls.Load())

	var persisted model.Task
	require.NoError(t, database.Where("task_id = ?", "task_kling_public").First(&persisted).Error)
	assert.Zero(t, persisted.BillingProtocol, "legacy native adapter fixture, not protocol1 wallet coverage")
	assert.Nil(t, persisted.BillingRef)
	assert.Equal(t, constant.TaskPlatform("kling"), persisted.Platform)
	assert.Equal(t, "kling-private-1", persisted.PrivateData.UpstreamTaskID)
	assert.Equal(t, model.TaskStatus(model.TaskStatusNotStart), persisted.Status)

	previousAdaptorFactory := service.GetTaskAdaptorFunc
	service.GetTaskAdaptorFunc = func(platform constant.TaskPlatform) service.TaskPollingAdaptor {
		return relay.GetTaskAdaptor(platform)
	}
	t.Cleanup(func() { service.GetTaskAdaptorFunc = previousAdaptorFactory })
	service.DispatchPlatformUpdate(
		context.Background(),
		persisted.Platform,
		map[int][]string{channel.Id: {"kling-private-1"}},
		map[string]*model.Task{"kling-private-1": &persisted},
	)

	require.NoError(t, database.Where("task_id = ?", "task_kling_public").First(&persisted).Error)
	assert.Equal(t, model.TaskStatus(model.TaskStatusSuccess), persisted.Status)
	assert.Equal(t, "100%", persisted.Progress)
	assert.Equal(t, 1, persisted.Quota)
	assert.Equal(t, int32(1), queryCalls.Load())
	var settledUser model.User
	require.NoError(t, database.First(&settledUser, 7).Error)
	assert.Equal(t, 999_999, settledUser.Quota)

	queryBinding, found := generation.LookupDeclaredRoute(http.MethodGet, "/kling/v1/videos/text2video/:task_id")
	require.True(t, found)
	queryRecorder := httptest.NewRecorder()
	queryContext, _ := gin.CreateTestContext(queryRecorder)
	queryContext.Request = httptest.NewRequest(http.MethodGet, "/kling/v1/videos/text2video/task_kling_public", nil)
	// The inner plugin router names wildcards by position.
	queryContext.Params = gin.Params{{Key: "s4", Value: "task_kling_public"}}
	queryContext.Set(pluginruntime.ContextKeyPinnedRoute, pluginruntime.PinnedRoute{
		Generation: generation,
		Plugin:     queryBinding.Plugin,
		Route:      queryBinding.Route,
	})
	common.SetContextKey(queryContext, constant.ContextKeyUserId, 7)

	middleware.PrepareTaskPluginRoute()(queryContext)

	require.True(t, queryContext.IsAborted())
	require.Equal(t, http.StatusOK, queryRecorder.Code)
	assert.Contains(t, queryRecorder.Body.String(), `"task_id":"task_kling_public"`)
	assert.Contains(t, queryRecorder.Body.String(), `"task_status":"succeed"`)
	assert.NotContains(t, queryRecorder.Body.String(), "kling-private-1")
	assert.NotContains(t, queryRecorder.Body.String(), upstream.URL)
}

func (s *nativeRouteBilling) ReserveBeforeSubmit(quota int) error { return s.Reserve(quota) }

// Once Ark's first event has reached a native client the submission settles
// and is never refunded. A stream Ark finished bills the images it delivered;
// one that broke off, whose first event the plugin could not read, or that
// kept sending keep-alive comments until the submission deadline bills the
// reserved images. A finished stream stays billed and logged when the host
// then fails to reserve its images or to store the task.
func TestDoubaoRelayedImageStreamSettlement(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service.InitHttpClient()

	previousDB := model.DB
	previousLogDB := model.LOG_DB
	previousMemoryCache := common.MemoryCacheEnabled
	previousBatchUpdate := common.BatchUpdateEnabled
	previousLogConsume := common.LogConsumeEnabled
	previousRedisEnabled := common.RedisEnabled
	previousDeadline := constant.TaskPluginProtocolTimeoutSeconds
	database, dialect := openTaskDialectDatabase(t, &model.User{}, &model.Channel{}, &model.Task{}, &model.Log{})
	previousMainType, previousLogType := common.MainDatabaseType(), common.LogDatabaseType()
	common.SetDatabaseTypes(dialect, dialect)
	model.DB = database
	model.LOG_DB = database
	common.MemoryCacheEnabled = false
	common.BatchUpdateEnabled = false
	common.LogConsumeEnabled = true
	common.RedisEnabled = false
	constant.TaskPluginProtocolTimeoutSeconds = 1
	var failTaskInsert atomic.Bool
	require.NoError(t, database.Callback().Create().Before("gorm:create").Register("test:fail_task_insert", func(tx *gorm.DB) {
		if failTaskInsert.Load() && tx.Statement.Schema != nil && tx.Statement.Schema.Name == "Task" {
			_ = tx.AddError(errors.New("injected task insert failure"))
		}
	}))
	const seedream = "doubao-seedream-5-0-lite-260128"
	previousPrices := ratio_setting.ModelPrice2JSONString()
	// 10,000 quota per image.
	require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"`+seedream+`":0.02}`))
	t.Cleanup(func() {
		common.SetDatabaseTypes(previousMainType, previousLogType)
		model.DB = previousDB
		model.LOG_DB = previousLogDB
		common.MemoryCacheEnabled = previousMemoryCache
		common.BatchUpdateEnabled = previousBatchUpdate
		common.LogConsumeEnabled = previousLogConsume
		common.RedisEnabled = previousRedisEnabled
		constant.TaskPluginProtocolTimeoutSeconds = previousDeadline
		require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(previousPrices))
	})
	require.NoError(t, database.Create(&model.User{Id: 7, Username: "relayed-stream-user", Group: "default", Quota: 1_000_000}).Error)

	const image = `data: {"type":"image_generation.partial_succeeded","model":"` + seedream + `","created":1,"image_index":0,"url":"https://cdn.example/0.png","size":"2048x2048"}` + "\n\n"
	const completed = `data: {"type":"image_generation.completed","model":"` + seedream + `","created":1,"usage":{"generated_images":1,"output_tokens":16384,"total_tokens":16384}}` + "\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Prompt string `json:"prompt"`
		}
		_ = common.DecodeJson(r.Body, &request)
		w.Header().Set("Content-Type", "text/event-stream")
		write := func(frame string) {
			_, _ = io.WriteString(w, frame)
			w.(http.Flusher).Flush()
		}
		switch request.Prompt {
		case "finished", "insert_fails":
			write(image + completed + "data: [DONE]\n\n")
		case "reserve_fails":
			write(image + strings.Replace(image, "0.png", "1.png", 1) + strings.Replace(completed, `"generated_images":1`, `"generated_images":2`, 1) + "data: [DONE]\n\n")
		case "broken":
			write(image)
			panic(http.ErrAbortHandler)
		case "unreadable":
			write("data: {\"type\":\n\n")
			write(image)
		case "stalled":
			// Keep-alives for longer than the one-second deadline, then a
			// clean end that would bill the one image delivered.
			write(image)
			for range 50 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(100 * time.Millisecond):
					write(": keep-alive\n\n")
				}
			}
		}
	}))
	defer upstream.Close()
	channel := model.Channel{Type: constant.ChannelTypeDoubaoVideo, Name: "ark-relayed-stream", Key: "ark-key", BaseURL: &upstream.URL,
		Status: common.ChannelStatusEnabled, Models: seedream, Group: "default"}
	require.NoError(t, database.Create(&channel).Error)
	generation := pluginruntime.DefaultRegistry.Generation()
	require.NotNil(t, generation)
	binding, found := generation.LookupDeclaredRoute(http.MethodPost, "/api/v3/images/generations")
	require.True(t, found)
	require.Equal(t, "doubao", binding.Plugin.Meta.Key)

	for _, tc := range []struct {
		prompt, firstFrame string
		wantQuota          int
	}{
		{"finished", image, 10_000},
		{"broken", image, 30_000},
		{"unreadable", "data: {\"type\":\n\n", 30_000},
		{"stalled", image, 30_000},
		// Ark finished these streams, then the host could not reserve the
		// billed images or store the task.
		{"reserve_fails", image, 20_000},
		{"insert_fails", image, 10_000},
	} {
		t.Run(tc.prompt, func(t *testing.T) {
			initialQuota, maxImages := 1_000_000, "3"
			wantEvents := []string{"reserve", "settle"}
			if tc.prompt == "reserve_fails" {
				initialQuota, maxImages = 10_000, "1"
				wantEvents = []string{"reserve", "reserve", "settle"}
			}
			require.NoError(t, database.Model(&model.User{}).Where("id = ?", 7).Update("quota", initialQuota).Error)
			require.NoError(t, database.Where("type = ?", model.LogTypeConsume).Delete(&model.Log{}).Error)
			failTaskInsert.Store(tc.prompt == "insert_fails")
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/api/v3/images/generations", strings.NewReader(`{"model":"`+seedream+`","prompt":"`+tc.prompt+`","stream":true,`+
				`"sequential_image_generation":"auto","sequential_image_generation_options":{"max_images":`+maxImages+`}}`))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Set(pluginruntime.ContextKeyPinnedRoute, pluginruntime.PinnedRoute{Generation: generation, Plugin: binding.Plugin, Route: binding.Route})
			common.SetContextKey(c, constant.ContextKeyUserId, 7)
			common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
			common.SetContextKey(c, constant.ContextKeyUsingGroup, "default")
			common.SetContextKey(c, constant.ContextKeyTokenGroup, "default")
			common.SetContextKey(c, constant.ContextKeyUserQuota, 1_000_000)
			middleware.PrepareTaskPluginRoute()(c)
			require.False(t, c.IsAborted(), recorder.Body.String())
			require.Nil(t, middleware.SetupContextForSelectedChannel(c, &channel, seedream))
			billing := &nativeRouteBilling{userID: 7}
			if tc.prompt == "reserve_fails" {
				billing.reserveErr = errors.New("token quota is not enough")
			}
			relayInfo := &relaycommon.RelayInfo{UserId: 7, UserGroup: "default", UsingGroup: "default", UserQuota: 1_000_000, TokenGroup: "default",
				OriginModelName: seedream, Billing: billing,
				TaskRelayInfo: &relaycommon.TaskRelayInfo{Action: c.GetString("task_action"), PublicTaskID: "task_" + tc.prompt, LockedChannel: &channel}}

			started := time.Now()
			outcome, taskErr := executeTaskSubmissionWith(c, relayInfo, relay.RelayTaskSubmit)
			assert.Less(t, time.Since(started), 10*time.Second, "the submission deadline bounds a relayed stream")
			assert.Equal(t, wantEvents, billing.events, "a relayed stream is never refunded")
			assert.True(t, strings.HasPrefix(recorder.Body.String(), tc.firstFrame), recorder.Body.String())
			relayed := recorder.Body.String()
			if tc.prompt == "insert_fails" {
				require.NotNil(t, taskErr)
				assert.Equal(t, "task_insert_failed", taskErr.Code)
				respondTaskSubmissionError(c, taskErr)
			} else {
				require.Nil(t, taskErr)
				assert.Equal(t, tc.wantQuota, outcome.Task.Quota)
				assert.Equal(t, model.TaskStatus(model.TaskStatusSuccess), outcome.Task.Status)
				presentTaskSubmission(c, outcome)
			}
			assert.Equal(t, relayed, recorder.Body.String(), "nothing follows the relayed events")
			var user model.User
			require.NoError(t, database.First(&user, 7).Error)
			assert.Equal(t, initialQuota-tc.wantQuota, user.Quota, "the delivered images are charged")
			var consumeLogs []model.Log
			require.NoError(t, database.Where("type = ?", model.LogTypeConsume).Find(&consumeLogs).Error)
			require.Len(t, consumeLogs, 1)
			assert.Equal(t, tc.wantQuota, consumeLogs[0].Quota)
		})
	}
}

// Local httptest upstream only. It simulates a vendor SSE body; it is not a
// live provider and it does not move production money.
//
// The relayed-image test above settles through a protocol-0 double. This one
// drives the same submission barrier with a real wallet obligation:
// reserve (intent debit) → claim send → stage → reconcile. A native route
// passes vendor frames through. A direct SSE read does not. A finished stream
// settles reported usage, including explicit zero. Missing usage and a stream
// that stops early keep the reservation. A claimed send is not refunded and
// is not sent again.
const sseWalletPlugin = `
export const meta={apiVersion:1,key:"sse-wallet",name:"SSE wallet",version:"1.0.0",author:{name:"Test"},models:["sse-wallet"],fetchMode:"per_task",submitResponseTypes:["json","sse"],usageSchema:{units:{type:"number",unit:"count"}}};
export function buildSubmitRequest(ctx){return {url:ctx.baseUrl+"/compile",responseType:"sse",body:ctx.requestBody};}
export function parseSubmitEvent(ctx,event,previous){
  const chunk=JSON.parse(event.data);
  if(chunk.error) throw new Error("provider stream failure");
  const state=Object.assign({}, previous||{saw:false,omit:false,fail:false});
  if(chunk.units!==undefined) state.units=chunk.units;
  if(chunk.omit===true) state.omit=true;
  if(chunk.fail===true) state.fail=true;
  state.saw=true;
  return {state:state,done:chunk.complete===true};
}
export function parseSubmitResponse(ctx,response){
  const body=response.body||{};
  if(body.fail===true) return {taskId:"vendor-sse",immediate:{status:"FAILURE",reason:"vendor failed"}};
  return {taskId:"vendor-sse",taskData:body,immediate:{status:"SUCCESS"}};
}
export function extractUsage(){return {units:4};}
export function extractUsageOnComplete(ctx,result,body){
  if(!body||body.omit===true) return null;
  if(body.units===undefined) return {};
  return {units:body.units};
}
export function parseTaskResult(){throw new Error("completed submissions must not poll");}
export function buildQueryRequest(){throw new Error("completed submissions must not poll");}
`

func TestNativeAndDirectSSEWalletObligation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service.InitHttpClient()

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
	previousGroups := ratio_setting.GroupRatio2JSONString()
	require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(`{"default":1}`))
	t.Cleanup(func() { require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(previousGroups)) })
	withTieredBillingConfig(t, map[string]string{"sse-wallet": "tiered_expr"}, map[string]string{"sse-wallet": `tier("meter", u("units") * 0.01)`})

	plugin, err := pluginruntime.CompilePlugin(sseWalletPlugin, pluginruntime.Options{})
	require.NoError(t, err)
	const initial = 100_000
	reserved := common.QuotaRound(4 * 0.01 * common.QuotaPerUnit)
	actual := common.QuotaRound(2 * 0.01 * common.QuotaPerUnit)
	require.Positive(t, reserved)
	require.Less(t, actual, reserved)

	var calls atomic.Int32
	var lastBody atomic.Value
	lastBody.Store("")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		lastBody.Store(string(body))
		var request struct {
			Scenario string `json:"scenario"`
		}
		_ = common.Unmarshal(body, &request)
		w.Header().Set("Content-Type", "text/event-stream")
		frame := map[string]string{
			"done":   "data: {\"units\":2,\"complete\":true}\n\n",
			"break":  "data: {\"units\":1}\n\n",
			"omit":   "data: {\"omit\":true,\"complete\":true}\n\n",
			"absent": "data: {\"complete\":true}\n\n",
			"zero":   "data: {\"units\":0,\"complete\":true}\n\n",
			"fail":   "data: {\"fail\":true,\"complete\":true}\n\n",
			"hook":   "data: {\"error\":true}\n\n",
		}[request.Scenario]
		if frame == "" {
			http.Error(w, "unknown scenario", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, frame)
		w.(http.Flusher).Flush()
		if request.Scenario == "break" {
			panic(http.ErrAbortHandler)
		}
	}))
	t.Cleanup(upstream.Close)
	channel := model.Channel{Name: "sse-wallet-local", Type: constant.ChannelTypeTaskPlugin, Key: "local-fixture-key", BaseURL: &upstream.URL, Status: common.ChannelStatusEnabled, Models: "sse-wallet", Group: "default"}
	require.NoError(t, db.Create(&channel).Error)

	cases := []struct {
		name    string
		native  bool
		want    int
		status  model.TaskStatus
		failed  bool
		frame   string
		replay  bool
		retries int
	}{
		{name: "done", native: true, want: actual, status: model.TaskStatusSuccess, frame: "data: {\"units\":2,\"complete\":true}\n\n", replay: true},
		{name: "break", native: true, want: reserved, status: model.TaskStatusSuccess, frame: "data: {\"units\":1}\n\n"},
		{name: "omit", native: true, want: reserved, status: model.TaskStatusSuccess, frame: "data: {\"omit\":true,\"complete\":true}\n\n"},
		{name: "absent", native: true, want: reserved, status: model.TaskStatusSuccess, frame: "data: {\"complete\":true}\n\n"},
		{name: "zero", native: true, want: 0, status: model.TaskStatusSuccess, frame: "data: {\"units\":0,\"complete\":true}\n\n"},
		{name: "fail", native: true, want: 0, status: model.TaskStatusFailure, frame: "data: {\"fail\":true,\"complete\":true}\n\n"},
		{name: "done", native: false, want: actual, status: model.TaskStatusSuccess},
		{name: "break", native: false, failed: true},
		{name: "hook", native: false, failed: true, replay: true, retries: 2},
	}
	for index, tc := range cases {
		label := "direct/" + tc.name
		if tc.native {
			label = "native/" + tc.name
		}
		t.Run(label, func(t *testing.T) {
			calls.Store(0)
			if tc.retries > 0 {
				previous := common.RetryTimes
				common.RetryTimes = tc.retries
				t.Cleanup(func() { common.RetryTimes = previous })
			}
			user := model.User{Username: fmt.Sprintf("sse%02d", index), AffCode: "sse-" + label, Quota: initial, Status: common.UserStatusEnabled, Group: "default"}
			require.NoError(t, db.Create(&user).Error)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/compile", strings.NewReader(`{}`))
			c.Set("group", "default")
			c.Set("username", user.Username)
			c.Set("task_request", map[string]any{"scenario": tc.name})
			c.Set(pluginruntime.ContextKeyPinnedPlugin, pluginruntime.PinnedPlugin{Plugin: plugin})
			if tc.native {
				c.Set(pluginruntime.ContextKeyPinnedRoute, pluginruntime.PinnedRoute{
					Plugin: plugin,
					Route:  pluginruntime.Route{Method: http.MethodPost, Path: "/compile", Type: pluginruntime.RouteTypeSubmit},
				})
			}
			common.SetContextKey(c, constant.ContextKeyOriginalModel, "sse-wallet")
			common.SetContextKey(c, constant.ContextKeyChannelBaseUrl, upstream.URL)
			common.SetContextKey(c, constant.ContextKeyChannelId, channel.Id)
			common.SetContextKey(c, constant.ContextKeyChannelType, channel.Type)
			info := &relaycommon.RelayInfo{
				UserId: user.Id, UserGroup: "default", UsingGroup: "default", OriginModelName: "sse-wallet", IsPlayground: true,
				TaskRelayInfo: &relaycommon.TaskRelayInfo{PublicTaskID: "task_" + strings.ReplaceAll(label, "/", "_"), LockedChannel: &channel},
			}
			info.UserSetting.BillingPreference = "wallet_only"
			info.UserSetting.QuotaWarningThreshold = -1000
			outcome, taskErr := executeTaskSubmission(c, info)
			assert.Equal(t, int32(1), calls.Load(), "upstream body %s", lastBody.Load())
			require.NotNil(t, info.Billing)
			assert.False(t, info.Billing.NeedsRefund())

			var stored model.Task
			require.NoError(t, db.Where("user_id = ?", user.Id).First(&stored).Error)
			var rows int64
			require.NoError(t, db.Model(&model.Task{}).Where("user_id = ?", user.Id).Count(&rows).Error)
			assert.Equal(t, int64(1), rows)
			assert.Equal(t, 1, stored.BillingProtocol)
			require.NotNil(t, stored.BillingRef)
			assert.Equal(t, info.PublicTaskID, *stored.BillingRef)

			relayed := recorder.Body.String()
			if tc.failed {
				require.NotNil(t, taskErr, "upstream body %s", lastBody.Load())
				assert.True(t, taskErr.NoRetry)
				assert.Empty(t, relayed)
				assert.Equal(t, model.TaskBillingClaimed, stored.BillingState)
				assert.Equal(t, reserved, stored.Quota)
				respondTaskSubmissionError(c, taskErr)
			} else {
				require.Nil(t, taskErr, "task error %#v upstream %s", taskErr, lastBody.Load())
				require.NotNil(t, outcome)
				assert.Equal(t, tc.want, outcome.Task.Quota)
				assert.Equal(t, tc.status, outcome.Task.Status)
				assert.Equal(t, model.TaskBillingSettled, outcome.Task.BillingState)
				assert.Equal(t, tc.want, stored.Quota)
				if tc.native {
					assert.Equal(t, "text/event-stream", recorder.Header().Get("Content-Type"))
					assert.Equal(t, tc.frame, relayed)
					presentTaskSubmission(c, outcome)
					assert.Equal(t, relayed, recorder.Body.String())
				} else {
					assert.Empty(t, relayed)
					assert.False(t, c.Writer.Written())
					presentTaskSubmission(c, outcome)
					assert.NotContains(t, recorder.Body.String(), "data:")
					assert.Contains(t, recorder.Body.String(), info.PublicTaskID)
				}
			}

			var updated model.User
			require.NoError(t, db.First(&updated, user.Id).Error)
			if tc.failed {
				assert.Equal(t, initial-reserved, updated.Quota)
				assert.Zero(t, updated.UsedQuota)
				assert.Zero(t, updated.RequestCount)
			} else {
				assert.Equal(t, initial-tc.want, updated.Quota)
				assert.Equal(t, tc.want, updated.UsedQuota)
				assert.Equal(t, 1, updated.RequestCount)
			}
			var logs []model.Log
			require.NoError(t, db.Where("user_id = ? AND type = ?", user.Id, model.LogTypeConsume).Find(&logs).Error)
			if tc.failed {
				assert.Empty(t, logs)
			} else {
				require.Len(t, logs, 1)
				assert.Equal(t, tc.want, logs[0].Quota)
			}

			if tc.replay {
				require.NotNil(t, info.Billing)
				if !tc.failed {
					require.NoError(t, info.Billing.Settle(tc.want))
				}
				info.Billing.Refund(c)
				session, ok := info.Billing.(*service.BillingSession)
				require.True(t, ok)
				again, reqErr := http.NewRequest(http.MethodPost, upstream.URL+"/compile", strings.NewReader(`{}`))
				require.NoError(t, reqErr)
				_, sendErr := session.SendWalletTask(again)
				require.Error(t, sendErr)
				assert.Equal(t, int32(1), calls.Load())
				require.NoError(t, db.First(&updated, user.Id).Error)
				if tc.failed {
					assert.Equal(t, initial-reserved, updated.Quota)
				} else {
					assert.Equal(t, initial-tc.want, updated.Quota)
				}
				require.NoError(t, db.Where("user_id = ? AND type = ?", user.Id, model.LogTypeConsume).Find(&logs).Error)
				if tc.failed {
					assert.Empty(t, logs)
				} else {
					require.Len(t, logs, 1)
				}
			}
		})
	}
}
