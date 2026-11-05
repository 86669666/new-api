package common

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/QuantumNous/new-api/constant"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultipartRequestAllowancePreservesDefaultsReplayAndCleanup(t *testing.T) {
	previousFileLimit, previousRequestLimit := constant.MaxFileDownloadMB, constant.MaxRequestBodyMB
	constant.MaxFileDownloadMB, constant.MaxRequestBodyMB = 1, 4
	t.Cleanup(func() {
		constant.MaxFileDownloadMB, constant.MaxRequestBodyMB = previousFileLimit, previousRequestLimit
	})
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	require.NoError(t, writer.WriteField("caption", "hello"))
	part, err := writer.CreateFormFile("media", "clip.bin")
	require.NoError(t, err)
	payload := bytes.Repeat([]byte{'x'}, (1<<20)+1)
	_, err = part.Write(payload)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	// Running the default again after opt-in also checks request isolation.
	for _, name := range []string{"default", "request allowance", "next request default"} {
		t.Run(name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body.Bytes()))
			c.Request.Header.Set("Content-Type", writer.FormDataContentType())
			defer CleanupBodyStorage(c)
			allow := name == "request allowance"
			if allow {
				AllowRequestSizedMultipartText(c)
			}
			for range 2 {
				form, err := ParseMultipartFormReusable(c)
				require.NoError(t, err)
				defer form.RemoveAll()
				assert.Equal(t, []string{"hello"}, form.Value["caption"])
				require.Len(t, form.File["media"], 1)
				file, err := form.File["media"][0].Open()
				require.NoError(t, err)
				_, onDisk := file.(*os.File)
				assert.Equal(t, !allow, onDisk, "unrelated requests keep the 1 MiB spill threshold")
				actual, err := io.ReadAll(file)
				require.NoError(t, err)
				assert.True(t, bytes.Equal(payload, actual))
				require.NoError(t, file.Close())
				require.NoError(t, form.RemoveAll())
				entries, err := os.ReadDir(tempDir)
				require.NoError(t, err)
				assert.Empty(t, entries, "parsed multipart temporary files must be removed")
				replayed, err := io.ReadAll(c.Request.Body)
				require.NoError(t, err)
				assert.True(t, bytes.Equal(body.Bytes(), replayed))
				// Rebuilt upstream headers must not change the saved inbound boundary.
				c.Request.Header.Set("Content-Type", "multipart/form-data; boundary=rebuilt")
			}
			var fields map[string]any
			require.NoError(t, UnmarshalBodyReusable(c, &fields))
			assert.Equal(t, map[string]any{"caption": "hello"}, fields)
			entries, err := os.ReadDir(tempDir)
			require.NoError(t, err)
			assert.Empty(t, entries, "unmarshalling must also remove multipart temporary files")
		})
	}
}
