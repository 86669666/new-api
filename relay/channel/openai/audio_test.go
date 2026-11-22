package openai

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertAudioRequestKeepsMultipartContentOutOfDebugLog(t *testing.T) {
	var payload, output bytes.Buffer
	input := multipart.NewWriter(&payload)
	const first = "fixture-private-audio-prompt"
	const second = "fixture-encoded-prompt-%2B"
	const filename = "fixture-private-filename.wav"
	require.NoError(t, input.WriteField("prompt", first))
	require.NoError(t, input.WriteField("prompt", second))
	part, err := input.CreateFormFile("file", filename)
	require.NoError(t, err)
	_, err = io.WriteString(part, "fixture audio")
	require.NoError(t, err)
	require.NoError(t, input.Close())

	oldDebug := common.DebugEnabled
	common.DebugEnabled = true
	common.LogWriterMu.Lock()
	oldWriter := gin.DefaultErrorWriter
	gin.DefaultErrorWriter = &output
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.DebugEnabled = oldDebug
		common.LogWriterMu.Lock()
		gin.DefaultErrorWriter = oldWriter
		common.LogWriterMu.Unlock()
	})

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", &payload)
	c.Request.Header.Set("Content-Type", input.FormDataContentType())
	info := &relaycommon.RelayInfo{RelayMode: relayconstant.RelayModeAudioTranscription}
	converted, err := (&Adaptor{}).ConvertAudioRequest(c, info, dto.AudioRequest{Model: "whisper-1"})
	require.NoError(t, err)

	upstream := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", converted)
	upstream.Header.Set("Content-Type", c.Request.Header.Get("Content-Type"))
	require.NoError(t, upstream.ParseMultipartForm(1<<20))
	t.Cleanup(func() { require.NoError(t, upstream.MultipartForm.RemoveAll()) })
	assert.Equal(t, []string{first, second}, upstream.PostForm["prompt"])
	assert.Equal(t, "whisper-1", upstream.PostForm.Get("model"))
	file, header, err := upstream.FormFile("file")
	require.NoError(t, err)
	defer file.Close()
	content, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.Equal(t, filename, header.Filename)
	assert.Equal(t, "fixture audio", string(content))
	assert.Contains(t, output.String(), "audio multipart request body bytes:")
	for _, value := range []string{first, second, filename, "fixture audio"} {
		assert.NotContains(t, output.String(), value)
	}
}
