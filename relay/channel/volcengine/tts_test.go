package volcengine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVolcengineTTSKeepsProviderErrorOutOfDiagnostics(t *testing.T) {
	const detail = "sample speech service error"
	reply, err := NewMessage(MsgTypeError, MsgTypeFlagNoSeq)
	require.NoError(t, err)
	reply.ErrorCode = 7
	reply.Payload = []byte(detail)
	frame, err := reply.Marshal()
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if !assert.NoError(t, err) {
			return
		}
		defer conn.Close()
		if !assert.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second))) {
			return
		}
		if _, err = ReceiveMessage(conn); !assert.NoError(t, err) {
			return
		}
		if !assert.NoError(t, conn.SetWriteDeadline(time.Now().Add(3*time.Second))) {
			return
		}
		assert.NoError(t, conn.WriteMessage(websocket.BinaryMessage, frame))
	}))
	defer server.Close()

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/audio/speech", nil)
	info := &relaycommon.RelayInfo{ChannelMeta: &relaycommon.ChannelMeta{ApiKey: "fixture-app|fixture-token"}}
	usage, apiErr := handleTTSWebSocketResponse(c, "ws"+strings.TrimPrefix(server.URL, "http"), VolcengineTTSRequest{}, info, "mp3")
	require.Nil(t, usage)
	require.NotNil(t, apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
	assert.Equal(t, types.ErrorCodeBadResponse, apiErr.GetErrorCode())
	assert.Contains(t, apiErr.Error(), detail)
	assert.Equal(t, "status_code=400, upstream returned an error", service.RelayErrorLogMessage(apiErr))
}
