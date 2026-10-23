package middleware

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
)

// HTTPPanicRecover is the server recovery boundary. ErrAbortHandler must reach
// net/http unchanged, before any logging or response write. Gin's recovery
// callback is too late: its request dump happens before invoking the callback.
func HTTPPanicRecover() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				if err == http.ErrAbortHandler {
					panic(err)
				}
				// Preserve Gin's handling of a connection that cannot be written to,
				// without dumping request headers (which may contain credentials).
				if ne, ok := err.(*net.OpError); ok {
					var se *os.SyscallError
					if errors.As(ne, &se) {
						message := strings.ToLower(se.Error())
						if strings.Contains(message, "broken pipe") || strings.Contains(message, "connection reset by peer") {
							common.SysLog(common.LogText("panic detected: %v", err))
							_ = c.Error(ne)
							c.Abort()
							return
						}
					}
				}
				writePanicResponse(c, err)
			}
		}()
		c.Next()
	}
}

func RelayPanicRecover() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				if err == http.ErrAbortHandler {
					panic(err)
				}
				writePanicResponse(c, err)
			}
		}()
		c.Next()
	}
}

func writePanicResponse(c *gin.Context, err any) {
	common.SysLog(common.LogText("panic detected: %v", err))
	common.SysLog(common.LogText("stacktrace from panic: %s", string(debug.Stack())))
	c.JSON(http.StatusInternalServerError, gin.H{
		"error": gin.H{
			"message": fmt.Sprintf("Panic detected, error: %v. Please submit a issue here: https://github.com/Calcium-Ion/new-api", err),
			"type":    "new_api_panic",
		},
	})
	c.Abort()
}
