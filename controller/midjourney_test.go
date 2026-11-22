package controller

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMidjourneyHistoryPreservesLegacyImageLinks(t *testing.T) {
	database, _ := openTaskDialectDatabase(t, &model.Midjourney{})
	oldDB, oldForward, oldAddress := model.DB, setting.MjForwardUrlEnabled, system_setting.ServerAddress
	model.DB = database
	system_setting.ServerAddress = "https://gateway.example/tenant"
	t.Cleanup(func() {
		model.DB = oldDB
		setting.MjForwardUrlEnabled = oldForward
		system_setting.ServerAddress = oldAddress
	})

	const ownerID = 42
	const upstream = "https://images.example/history.png"
	require.NoError(t, database.Create(&model.Midjourney{
		UserId: ownerID, MjId: "migration-fixture", ImageUrl: upstream, Status: "SUCCESS",
	}).Error)
	for _, history := range []struct {
		name    string
		path    string
		handler gin.HandlerFunc
	}{
		{"personal", "/api/mj/self", GetUserMidjourney},
		{"admin", "/api/mj/", GetAllMidjourney},
	} {
		t.Run(history.name, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				forward bool
				want    string
			}{
				{"gateway link", true, "https://gateway.example/tenant/mj/image/migration-fixture"},
				{"upstream link", false, upstream},
			} {
				t.Run(tc.name, func(t *testing.T) {
					setting.MjForwardUrlEnabled = tc.forward
					response := httptest.NewRecorder()
					c, _ := gin.CreateTestContext(response)
					c.Set("id", ownerID)
					c.Request = httptest.NewRequest(http.MethodGet, history.path, nil)
					history.handler(c)

					require.Equal(t, http.StatusOK, response.Code)
					var result struct {
						Success bool `json:"success"`
						Data    struct {
							Items []model.Midjourney `json:"items"`
						} `json:"data"`
					}
					require.NoError(t, common.DecodeJson(response.Body, &result))
					require.True(t, result.Success)
					require.Len(t, result.Data.Items, 1)
					assert.Equal(t, tc.want, result.Data.Items[0].ImageUrl)
				})
			}
		})
	}
}

func TestMidjourneyPollKeepsProviderDataOutOfLogs(t *testing.T) {
	database, _ := openTaskDialectDatabase(t, &model.Channel{}, &model.Midjourney{})
	oldDB, oldCache := model.DB, common.MemoryCacheEnabled
	model.DB, common.MemoryCacheEnabled = database, false
	t.Cleanup(func() { model.DB, common.MemoryCacheEnabled = oldDB, oldCache })
	service.InitHttpClient()

	var logs bytes.Buffer
	common.LogWriterMu.Lock()
	oldWriter, oldErrorWriter := gin.DefaultWriter, gin.DefaultErrorWriter
	gin.DefaultWriter, gin.DefaultErrorWriter = &logs, &logs
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter, gin.DefaultErrorWriter = oldWriter, oldErrorWriter
		common.LogWriterMu.Unlock()
	})

	const taskID = "fixture-private-poll-id-%2B"
	const unknownID = "fixture-private-unmatched-id"
	const failReason = "fixture-private-provider-reason"
	const prompt = "fixture-private-prompt"
	const channelKey = "fixture-channel-marker"
	malformedBody := `{"message":"fixture-private-malformed-body"`
	for _, tc := range []struct {
		name, wantLog, body string
		status              int
		update              bool
	}{
		{
			name: "malformed JSON", status: http.StatusOK, body: malformedBody,
			wantLog: "poll response decode failed",
		},
		{
			name: "upstream error", status: http.StatusBadGateway, body: `{"message":"fixture-private-http-error"}`,
			wantLog: "poll upstream rejected request",
		},
		{
			name: "valid result and unmatched item", status: http.StatusOK, update: true,
			wantLog: "poll ignored unknown task",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UnixMilli()
			body := tc.body
			if tc.update {
				body = fmt.Sprintf(`[{"id":%q,"status":"FAILURE","progress":"65%%","failReason":%q,"promptEn":%q,"submitTime":%d},{"id":%q}]`,
					taskID, failReason, prompt, now, unknownID)
			}
			type pollRequest struct {
				ids    []string
				method string
				path   string
				key    string
				err    error
			}
			requests := make(chan pollRequest, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				var input struct {
					IDs []string `json:"ids"`
				}
				err := common.DecodeJson(request.Body, &input)
				requests <- pollRequest{input.IDs, request.Method, request.URL.Path, request.Header.Get("mj-api-secret"), err}
				writer.WriteHeader(tc.status)
				_, _ = io.WriteString(writer, body)
			}))
			t.Cleanup(upstream.Close)

			url := upstream.URL
			channel := model.Channel{Type: constant.ChannelTypeMidjourney, BaseURL: &url, Key: channelKey}
			require.NoError(t, database.Create(&channel).Error)
			task := model.Midjourney{Code: 1, MjId: taskID, ChannelId: channel.Id, Status: "IN_PROGRESS", Progress: "25%", SubmitTime: now}
			require.NoError(t, database.Create(&task).Error)
			t.Cleanup(func() { require.NoError(t, database.Delete(&task).Error) })

			logs.Reset()
			summary := runMidjourneyTaskUpdateOnce(t.Context(), nil)
			assert.Equal(t, midjourneyPollSummary{UnfinishedTasks: 1, ChannelsScanned: 1}, summary)
			require.Len(t, requests, 1)
			request := <-requests
			require.NoError(t, request.err)
			assert.Equal(t, []string{taskID}, request.ids)
			assert.Equal(t, http.MethodPost, request.method)
			assert.Equal(t, "/mj/task/list-by-condition", request.path)
			assert.Equal(t, channelKey, request.key)

			var stored model.Midjourney
			require.NoError(t, database.First(&stored, task.Id).Error)
			assert.Contains(t, logs.String(), tc.wantLog)
			if tc.update {
				assert.Equal(t, "FAILURE", stored.Status)
				assert.Equal(t, "100%", stored.Progress)
				assert.Equal(t, failReason, stored.FailReason)
				assert.Equal(t, prompt, stored.PromptEn)
				assert.Contains(t, logs.String(), fmt.Sprintf("task_row_id=%d", task.Id))
			} else {
				assert.Equal(t, task.Status, stored.Status)
				assert.Equal(t, task.Progress, stored.Progress)
				assert.Empty(t, stored.FailReason)
			}
			for _, value := range []string{taskID, unknownID, failReason, prompt, channelKey, "fixture-private-malformed-body", "fixture-private-http-error"} {
				assert.NotContains(t, logs.String(), value)
			}
		})
	}
}
