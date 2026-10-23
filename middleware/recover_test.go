package middleware

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recoveryLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *recoveryLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *recoveryLogBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestHTTPPanicRecoverTerminalAbort(t *testing.T) {
	previousMode := gin.Mode()
	gin.SetMode(gin.DebugMode) // Gin's old recovery dumps request headers in this mode.
	t.Cleanup(func() { gin.SetMode(previousMode) })
	for _, protocol := range []string{"http1", "http2"} {
		for _, layer := range []string{"global", "nested_relay"} {
			for _, scenario := range []string{"abort_empty", "abort_partial", "ordinary_panic", "abort_message_only", "wrapped_abort", "success"} {
				t.Run(protocol+"/"+layer+"/"+scenario, func(t *testing.T) {
					var logs recoveryLogBuffer
					common.LogWriterMu.Lock()
					previousOut, previousErr := gin.DefaultWriter, gin.DefaultErrorWriter
					gin.DefaultWriter, gin.DefaultErrorWriter = &logs, &logs
					common.LogWriterMu.Unlock()
					t.Cleanup(func() {
						common.LogWriterMu.Lock()
						gin.DefaultWriter, gin.DefaultErrorWriter = previousOut, previousErr
						common.LogWriterMu.Unlock()
					})

					var calls, cleanup, continued, observedProtocol atomic.Int32
					done := make(chan struct{})
					releaseAbort := make(chan struct{})
					var releaseOnce sync.Once
					release := func() { releaseOnce.Do(func() { close(releaseAbort) }) }
					engine := gin.New()
					engine.Use(HTTPPanicRecover()) // The constructor installed by main.
					engine.Use(func(c *gin.Context) {
						defer close(done)
						defer cleanup.Add(1)
						c.Next()
					})
					if layer == "nested_relay" {
						engine.Use(RelayPanicRecover())
					}
					engine.POST("/terminal", func(c *gin.Context) {
						calls.Add(1)
						observedProtocol.Store(int32(c.Request.ProtoMajor))
						defer cleanup.Add(1)
						switch scenario {
						case "abort_empty":
							panic(http.ErrAbortHandler)
						case "abort_partial":
							c.Header("Content-Length", "64")
							c.Header("Content-Type", "text/plain")
							_, _ = c.Writer.WriteString("partial")
							c.Writer.Flush()
							<-releaseAbort // Ensure the client has observed the partial body.
							panic(http.ErrAbortHandler)
						case "ordinary_panic":
							panic("ordinary test panic")
						case "abort_message_only":
							panic(http.ErrAbortHandler.Error())
						case "wrapped_abort":
							panic(fmt.Errorf("wrapped: %w", http.ErrAbortHandler))
						default:
							c.Header("X-Recovery-Test", "preserved")
							c.String(http.StatusCreated, "original success")
						}
					}, func(c *gin.Context) { continued.Add(1) })
					server := httptest.NewUnstartedServer(engine)
					server.Config.ErrorLog = log.New(&logs, "", 0)
					if protocol == "http2" {
						server.EnableHTTP2 = true
						server.StartTLS()
					} else {
						server.Start()
					}
					client := server.Client()
					client.Timeout = 5 * time.Second
					defer func() {
						release()
						client.CloseIdleConnections()
						server.Close()
					}()
					req, err := http.NewRequest(http.MethodPost, server.URL+"/terminal", strings.NewReader("test body"))
					require.NoError(t, err)
					sentinels := map[string]string{
						"Authorization": "Bearer terminal-auth-sentinel",
						"Cookie":        "session=terminal-cookie-sentinel",
						"Api-Key":       "terminal-api-key-sentinel",
						"X-Api-Key":     "terminal-x-api-key-sentinel",
					}
					for header, value := range sentinels {
						req.Header.Set(header, value)
					}
					resp, requestErr := client.Do(req)
					if scenario == "abort_empty" {
						require.Error(t, requestErr)
						assert.Nil(t, resp, "terminal abort must not manufacture HTTP status or JSON")
					} else {
						require.NoError(t, requestErr)
						defer resp.Body.Close()
						if scenario == "abort_partial" {
							prefix := make([]byte, len("partial"))
							_, err = io.ReadFull(resp.Body, prefix)
							require.NoError(t, err)
							assert.Equal(t, "partial", string(prefix))
							release()
							rest, readErr := io.ReadAll(resp.Body)
							require.Error(t, readErr, "client must observe truncation or stream reset")
							assert.Empty(t, rest, "no second error body may be appended")
							assert.Equal(t, http.StatusOK, resp.StatusCode, "only the already flushed status is visible")
							if protocol == "http1" {
								assert.ErrorIs(t, readErr, io.ErrUnexpectedEOF)
							} else {
								assert.Contains(t, readErr.Error(), "INTERNAL_ERROR")
							}
						} else {
							body, err := io.ReadAll(resp.Body)
							require.NoError(t, err)
							if scenario == "success" {
								assert.Equal(t, http.StatusCreated, resp.StatusCode)
								assert.Equal(t, "original success", string(body))
								assert.Equal(t, "preserved", resp.Header.Get("X-Recovery-Test"))
							} else {
								assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
								var payload struct {
									Error struct{ Message, Type string } `json:"error"`
								}
								require.NoError(t, common.Unmarshal(body, &payload))
								assert.Equal(t, "new_api_panic", payload.Error.Type)
								assert.Contains(t, payload.Error.Message, "Panic detected, error:")
							}
						}
						assert.Equal(t, int(observedProtocol.Load()), resp.ProtoMajor)
					}
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("handler cleanup did not finish")
					}
					client.CloseIdleConnections()
					server.Close() // Wait for net/http recovery before inspecting all logs.
					assert.EqualValues(t, 1, calls.Load(), "no server retry")
					assert.EqualValues(t, 2, cleanup.Load(), "handler and middleware cleanup must run")
					if protocol == "http2" {
						assert.EqualValues(t, 2, observedProtocol.Load(), "TLS must actually negotiate HTTP/2")
					} else {
						assert.EqualValues(t, 1, observedProtocol.Load())
					}
					if scenario == "success" {
						assert.EqualValues(t, 1, continued.Load())
					} else {
						assert.Zero(t, continued.Load(), "panic must not continue the route")
					}
					logged := logs.text()
					for _, sentinel := range sentinels {
						assert.NotContains(t, logged, sentinel)
					}
					if strings.HasPrefix(scenario, "abort_") && scenario != "abort_message_only" {
						assert.NotContains(t, logged, http.ErrAbortHandler.Error())
						assert.NotContains(t, logged, "[SYS]")
						assert.NotContains(t, logged, "panic recovered")
					} else if scenario != "success" {
						assert.Contains(t, logged, "writePanicResponse", "ordinary panic retains a diagnostic stack")
					}
				})
			}
		}
	}
}
