package openai

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRealtimeTestConnection(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	peer := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if assert.NoError(t, err) {
			peer <- conn
		}
	}))
	t.Cleanup(server.Close)
	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	relay, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = relay.Close() })
	select {
	case remote := <-peer:
		t.Cleanup(func() { _ = remote.Close() })
		require.NoError(t, remote.SetReadDeadline(time.Now().Add(3*time.Second)))
		return relay, remote
	case <-time.After(3 * time.Second):
		t.Fatal("test WebSocket was not accepted")
		return nil, nil
	}
}

func TestRealtimeLogsMetadataAndForwardsOriginalFrames(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/realtime", nil)
	client, clientPeer := newRealtimeTestConnection(t)
	upstream, upstreamPeer := newRealtimeTestConnection(t)
	logs := captureProviderStreamLogs(t)
	info := &relaycommon.RelayInfo{ClientWs: client, TargetWs: upstream,
		ChannelMeta: &relaycommon.ChannelMeta{UpstreamModelName: "realtime-fixture"}}
	result := make(chan struct {
		err   *types.NewAPIError
		usage *dto.RealtimeUsage
	}, 1)
	go func() {
		err, usage := OpenaiRealtimeHandler(c, info)
		result <- struct {
			err   *types.NewAPIError
			usage *dto.RealtimeUsage
		}{err, usage}
	}()

	clientFrame := []byte("{\"type\":\"test.client.event\"}")
	require.NoError(t, clientPeer.WriteMessage(websocket.TextMessage, clientFrame))
	_, received, err := upstreamPeer.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, clientFrame, received)

	upstreamFrame := []byte("{\"type\":\"test.upstream.event\"}")
	require.NoError(t, upstreamPeer.WriteMessage(websocket.TextMessage, upstreamFrame))
	_, received, err = clientPeer.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, upstreamFrame, received)

	const closeDetail = "sample upstream close explanation"
	require.NoError(t, upstreamPeer.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseInternalServerErr, closeDetail), time.Now().Add(time.Second)))
	select {
	case output := <-result:
		require.Nil(t, output.err)
		require.NotNil(t, output.usage)
		assert.Zero(t, output.usage.TotalTokens)
	case <-time.After(3 * time.Second):
		t.Fatal("realtime handler did not finish on upstream close")
	}

	assert.Contains(t, logs.String(), "realtime client event tokens")
	assert.Contains(t, logs.String(), "realtime upstream event tokens")
	assert.NotContains(t, logs.String(), "test.client.event")
	assert.NotContains(t, logs.String(), "test.upstream.event")
	assert.NotContains(t, logs.String(), closeDetail)
}
