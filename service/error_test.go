package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResetStatusCode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		statusCode       int
		statusCodeConfig string
		expectedCode     int
	}{
		{
			name:             "map string value",
			statusCode:       429,
			statusCodeConfig: `{"429":"503"}`,
			expectedCode:     503,
		},
		{
			name:             "map int value",
			statusCode:       429,
			statusCodeConfig: `{"429":503}`,
			expectedCode:     503,
		},
		{
			name:             "skip invalid string value",
			statusCode:       429,
			statusCodeConfig: `{"429":"bad-code"}`,
			expectedCode:     429,
		},
		{
			name:             "skip status code 200",
			statusCode:       200,
			statusCodeConfig: `{"200":503}`,
			expectedCode:     200,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			newAPIError := &types.NewAPIError{
				StatusCode: tc.statusCode,
			}
			ResetStatusCode(newAPIError, tc.statusCodeConfig)
			require.Equal(t, tc.expectedCode, newAPIError.StatusCode)
		})
	}
}

func TestRelayErrorHandlerOmitsProviderBodiesFromLogs(t *testing.T) {
	const diagnostic = "fixture-provider-detail"
	for _, tc := range []struct {
		name           string
		body           string
		debug          bool
		showDiagnostic bool
	}{
		{name: "invalid JSON", body: diagnostic},
		{name: "empty error message in debug mode", body: `{"diagnostic":"` + diagnostic + `"}`, debug: true},
		{name: "channel test returns diagnostics", body: diagnostic, debug: true, showDiagnostic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withDebugEnabled(t, tc.debug)
			var logBuffer bytes.Buffer
			common.LogWriterMu.Lock()
			oldWriter := gin.DefaultErrorWriter
			gin.DefaultErrorWriter = &logBuffer
			common.LogWriterMu.Unlock()
			t.Cleanup(func() {
				common.LogWriterMu.Lock()
				gin.DefaultErrorWriter = oldWriter
				common.LogWriterMu.Unlock()
			})

			resp := &http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}
			err := RelayErrorHandler(context.Background(), resp, tc.showDiagnostic)

			require.NotNil(t, err)
			assert.Equal(t, http.StatusBadGateway, err.StatusCode)
			assert.Equal(t, types.ErrorCodeBadResponseStatusCode, err.GetErrorCode())
			assert.NotContains(t, logBuffer.String(), diagnostic)
			if tc.showDiagnostic {
				assert.Contains(t, err.Error(), diagnostic)
				assert.Equal(t, "status_code=502, upstream returned an error", RelayErrorLogMessage(err))
			} else {
				assert.Contains(t, logBuffer.String(), fmt.Sprintf("[omitted, %d bytes]", len(tc.body)))
				assert.NotContains(t, err.Error(), diagnostic)
			}
		})
	}
}

func TestProviderErrorDiagnosticsAreSafeInChannelAndPolicyLogs(t *testing.T) {
	const detail = "fixture-private-provider-detail"
	const code = "fixture-private-provider-code"
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	var logs bytes.Buffer
	common.LogWriterMu.Lock()
	oldWriter := gin.DefaultErrorWriter
	gin.DefaultErrorWriter = &logs
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultErrorWriter = oldWriter
		common.LogWriterMu.Unlock()
	})

	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"` + detail + `","code":"` + code + `"}}`)),
	}
	err := RelayErrorHandler(c, resp, false)
	require.NotNil(t, err)
	types.ErrOptionWithNoRecordErrorLog()(err)
	ProcessChannelError(c, types.ChannelError{}, err, nil)
	RecordPolicyFailure(c, 1, err, PolicyDecision{Action: "retry"})
	RecordRequestPolicyTermination(c, err)
	assert.Contains(t, logs.String(), "status_code=502, upstream returned an error")
	assert.NotContains(t, logs.String(), detail)
	assert.NotContains(t, logs.String(), code)
	for _, event := range RequestPolicy(c).Events() {
		assert.Equal(t, string(types.ErrorCodeBadResponseStatusCode), event.ErrorCode)
	}
	assert.Equal(t, detail, err.ToOpenAIError().Message)
	assert.Equal(t, types.ErrorCode(code), err.GetErrorCode())

	// Rewrapping a provider error for violation handling preserves its log policy.
	const providerType = "fixture-private-provider-type"
	resp.Body = io.NopCloser(strings.NewReader(fmt.Sprintf(
		`{"error":{"message":%q,"type":%q,"code":%q}}`, detail, providerType, types.ErrorCodeViolationFeeGrokCSAM)))
	normalized := NormalizeViolationFeeError(RelayErrorHandler(c, resp, false))
	assert.Equal(t, "status_code=502, upstream returned an error", RelayErrorLogMessage(normalized))
	assert.Equal(t, types.ErrorCodeViolationFeeGrokCSAM, relayErrorLogCode(normalized))
	logType, logCode := violationFeeLogClassification(normalized)
	assert.Equal(t, "upstream_error", logType)
	assert.Equal(t, string(types.ErrorCodeViolationFeeGrokCSAM), logCode)
	clientError := normalized.ToOpenAIError()
	assert.Equal(t, detail, clientError.Message)
	assert.Equal(t, providerType, clientError.Type)
	assert.True(t, types.IsSkipRetryError(normalized))
}

func TestRelayErrorHandlerKeepsStructuredErrorMessage(t *testing.T) {
	message := strings.Repeat("c", common.LocalLogContentLimit+256)
	body := `{"message":"` + message + `"}`
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	newAPIError := RelayErrorHandler(context.Background(), resp, false)

	require.NotNil(t, newAPIError)
	require.Equal(t, message, newAPIError.Error())
}

func TestRelayErrorHandlerKeepsOpenAIErrorMessage(t *testing.T) {
	message := strings.Repeat("d", common.LocalLogContentLimit+256)
	body := `{"error":{"message":"` + message + `","type":"server_error","code":"server_error"}}`
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	newAPIError := RelayErrorHandler(context.Background(), resp, false)

	require.NotNil(t, newAPIError)
	require.Equal(t, message, newAPIError.Error())
}

func withDebugEnabled(t *testing.T, enabled bool) {
	t.Helper()

	oldDebug := common.DebugEnabled
	common.DebugEnabled = enabled
	t.Cleanup(func() {
		common.DebugEnabled = oldDebug
	})
}
