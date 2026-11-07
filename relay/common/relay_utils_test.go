package common

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/constant"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeURLForLogMasksSensitiveQueryValues(t *testing.T) {
	rawURL := "https://example.test/v1beta/models/gemini:streamGenerateContent?alt=sse&key=sk-secret&access_token=ya29-secret&api-version=2024-02-01"

	got := SanitizeURLForLog(rawURL)

	assert.NotContains(t, got, "sk-secret")
	assert.NotContains(t, got, "ya29-secret")
	parsedURL, err := url.Parse(got)
	require.NoError(t, err)
	query := parsedURL.Query()
	assert.Equal(t, "***masked***", query.Get("key"))
	assert.Equal(t, "***masked***", query.Get("access_token"))
	assert.Equal(t, "sse", query.Get("alt"))
	assert.Equal(t, "2024-02-01", query.Get("api-version"))
}

func TestSanitizeURLForLogMasksAWSAndSecretLikeQueryKeys(t *testing.T) {
	rawURL := "https://example.test/path?X-Amz-Credential=credential&X-Amz-Signature=signature&session_token=session&client_secret=secret&model=gpt-test"

	got := SanitizeURLForLog(rawURL)

	assert.NotContains(t, got, "X-Amz-Credential=credential")
	assert.NotContains(t, got, "X-Amz-Signature=signature")
	assert.NotContains(t, got, "session_token=session")
	assert.NotContains(t, got, "client_secret=secret")
	parsedURL, err := url.Parse(got)
	require.NoError(t, err)
	query := parsedURL.Query()
	assert.Equal(t, "***masked***", query.Get("X-Amz-Credential"))
	assert.Equal(t, "***masked***", query.Get("X-Amz-Signature"))
	assert.Equal(t, "***masked***", query.Get("session_token"))
	assert.Equal(t, "***masked***", query.Get("client_secret"))
	assert.Equal(t, "gpt-test", query.Get("model"))
}

func TestSanitizeURLForLogKeepsURLWithoutSensitiveQuery(t *testing.T) {
	for _, rawURL := range []string{
		"",
		"https://example.test/v1/chat/completions",
		"https://example.test/v1/chat/completions?",
		"https://example.test/v1/chat/completions?api-version=2024-02-01&alt=sse",
		"https://example.test/path?model=a%20b&model=c#section",
	} {
		assert.Equal(t, rawURL, SanitizeURLForLog(rawURL))
	}
}

func TestSanitizeURLForLogRejectsMalformedURL(t *testing.T) {
	const syntheticCredential = "synthetic-log-test-credential"
	tests := []struct {
		name   string
		rawURL string
	}{
		{"invalid path escape", "https://example.test/%zz?key=" + syntheticCredential},
		{"invalid authority", "https://[example.test/path?token=" + syntheticCredential},
		{"invalid query value escape", "https://example.test/path?key=" + syntheticCredential + "%zz"},
		{"invalid query key escape", "https://example.test/path?to%zzken=" + syntheticCredential},
		{"partial query parse", "https://example.test/path?model=test&token=" + syntheticCredential + "%zz"},
		{"invalid query separator", "https://example.test/path?token=" + syntheticCredential + ";model=test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeURLForLog(tt.rawURL)
			// Boolean assertions keep even synthetic credentials out of failure logs.
			assert.False(t, strings.Contains(got, syntheticCredential), "credential survives log projection")
			assert.True(t, got == "[invalid URL]", "malformed input must use a fixed log placeholder")
		})
	}
}

func TestSanitizeURLForLogRemovesUserinfo(t *testing.T) {
	const syntheticCredential = "synthetic-log-test-credential"
	tests := []struct {
		name  string
		user  string
		query string
		want  string
	}{
		{"username credential", syntheticCredential, "", "https://example.test/path"},
		{"password credential", "user:" + syntheticCredential, "?model=a%20b", "https://example.test/path?model=a%20b"},
		{"userinfo and query credential", "user:" + syntheticCredential, "?token=" + syntheticCredential, "https://example.test/path?token=%2A%2A%2Amasked%2A%2A%2A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawURL := "https://" + tt.user + "@example.test/path" + tt.query
			got := SanitizeURLForLog(rawURL)
			assert.False(t, strings.Contains(got, syntheticCredential), "credential survives log projection")
			assert.True(t, got == tt.want, "log projection must remove userinfo and preserve harmless URL parts")
		})
	}
}

func TestValidateMultipartDirectNormalizesImageField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	body := strings.NewReader(`{"model":"wan2.7-i2v","prompt":"animate","image":" https://example.com/first.png "}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/video/generations", body)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = request
	info := &RelayInfo{
		TaskRelayInfo: &TaskRelayInfo{},
	}

	taskErr := ValidateMultipartDirect(context, info)

	require.Nil(t, taskErr)
	storedReq, err := GetTaskRequest(context)
	require.NoError(t, err)
	require.Equal(t, []string{"https://example.com/first.png"}, storedReq.Images)
	require.Equal(t, constant.TaskActionImageToVideo, info.Action)
}

// TestTaskDurationBounds guards the billing invariant that user-supplied
// video duration (a quota multiplier via OtherRatio "seconds") is bounded, so
// it can never overflow quota calculation into a negative charge.
func TestTaskDurationBounds(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newContext := func(t *testing.T, body string) (*gin.Context, *RelayInfo) {
		request := httptest.NewRequest(http.MethodPost, "/v1/video/generations", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		context, _ := gin.CreateTestContext(httptest.NewRecorder())
		context.Request = request
		return context, &RelayInfo{TaskRelayInfo: &TaskRelayInfo{}}
	}

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "huge duration is rejected",
			body:    `{"model":"sora-2","prompt":"a cat","duration":9999999999}`,
			wantErr: true,
		},
		{
			name:    "huge seconds string is rejected",
			body:    `{"model":"sora-2","prompt":"a cat","seconds":"9999999999"}`,
			wantErr: true,
		},
		{
			name:    "negative duration is rejected",
			body:    `{"model":"sora-2","prompt":"a cat","duration":-8}`,
			wantErr: true,
		},
		{
			name: "normal duration is accepted",
			body: `{"model":"sora-2","prompt":"a cat","seconds":"8"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" (multipart direct)", func(t *testing.T) {
			context, info := newContext(t, tt.body)
			taskErr := ValidateMultipartDirect(context, info)
			if tt.wantErr {
				require.NotNil(t, taskErr)
				require.Equal(t, "invalid_seconds", taskErr.Code)
			} else {
				require.Nil(t, taskErr)
			}
		})
		t.Run(tt.name+" (basic task request)", func(t *testing.T) {
			context, info := newContext(t, tt.body)
			taskErr := ValidateBasicTaskRequest(context, info, constant.TaskActionImageToVideo)
			if tt.wantErr {
				require.NotNil(t, taskErr)
				require.Equal(t, "invalid_seconds", taskErr.Code)
			} else {
				require.Nil(t, taskErr)
			}
		})
	}
}
