package coze

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCozeStreamErrorLogsCodeAndContinues(t *testing.T) {
	var logs bytes.Buffer
	common.LogWriterMu.Lock()
	writer := gin.DefaultWriter
	gin.DefaultWriter = &logs
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		defer common.LogWriterMu.Unlock()
		gin.DefaultWriter = writer
	})

	const detail = "sample Coze diagnostic"
	body := "event: error\ndata: {\"code\":7,\"message\":\"" + detail + "\"}\n\n" +
		"event: conversation.message.delta\ndata: {\"content\":\"sample output\"}\n\n" +
		"event: conversation.chat.completed\ndata: {\"usage\":{\"input_count\":2,\"output_count\":1,\"token_count\":3}}\n\n"
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	info := &relaycommon.RelayInfo{ChannelMeta: &relaycommon.ChannelMeta{UpstreamModelName: "coze-fixture"}}
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(body))}

	usage, apiErr := cozeChatStreamHandler(c, info, resp)
	require.Nil(t, apiErr)
	require.NotNil(t, usage)
	assert.Equal(t, 3, usage.TotalTokens)
	assert.Contains(t, recorder.Body.String(), "sample output")
	assert.Contains(t, recorder.Body.String(), "data: [DONE]")
	assert.Contains(t, logs.String(), "code=7")
	assert.NotContains(t, logs.String(), detail)
}
