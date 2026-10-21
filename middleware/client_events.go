package middleware

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

const clientEventCredentialKey = "client_event_credential"

func WriteClientEventError(c *gin.Context, status int) {
	code, message := "CLIENT_EVENTS_INVALID", "Invalid request"
	switch status {
	case 401:
		code, message = "CLIENT_EVENTS_UNAUTHORIZED", "Unauthorized"
	case 403:
		code, message = "CLIENT_EVENTS_FORBIDDEN", "Unauthorized Access"
	case 404:
		code = "CLIENT_EVENTS_DISABLED"
	case 413:
		code = "CLIENT_EVENTS_TOO_LARGE"
	case 429:
		code, message = "CLIENT_EVENTS_RATE_LIMIT", "Too many requests"
	case 503:
		code, message = "CLIENT_EVENTS_UNAVAILABLE", "Internal Server Error!"
	}
	c.Header("Cache-Control", "private, no-store")
	common.ApiErrorStatus(c, status, common.NewMessage(message), gin.H{"code": code})
	c.Abort()
}

func ClientEventErrorStatus(err error) int {
	if errors.Is(err, model.ErrClientEventUnauthorized) {
		return 401
	}
	if errors.Is(err, model.ErrClientEventForbidden) {
		return 403
	}
	return 503
}

func GetClientEventCredential(c *gin.Context) (model.ClientEventCredential, bool) {
	value, ok := c.Get(clientEventCredentialKey)
	credential, valid := value.(model.ClientEventCredential)
	return credential, ok && valid && credential.TokenID() > 0
}

// This exact endpoint has its own gate before its single global limiter. The
// ordinary /api group cannot supply that ordering or JSON limiter failures.
func ClientEventsBoundary() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		config := service.CurrentClientEventsConfig()
		if !config.Enabled {
			WriteClientEventError(c, 404)
			return
		}
		if common.GlobalApiRateLimitEnable {
			// Enabled GlobalAPIRateLimit contains no c.Next. Calling defNext when
			// disabled would run downstream handlers before this boundary finishes.
			GlobalAPIRateLimit()(c)
			if c.IsAborted() {
				if c.Writer.Status() == 429 {
					if retry, err := strconv.Atoi(c.Writer.Header().Get("Retry-After")); err != nil || retry <= 0 {
						c.Header("Retry-After", "1")
					}
					WriteClientEventError(c, 429)
				} else {
					WriteClientEventError(c, 503)
				}
				return
			}
		}
		if c.Request.URL.RawQuery != "" || strings.HasSuffix(c.Request.URL.Path, "/") {
			WriteClientEventError(c, 400)
			return
		}
		for _, name := range []string{"Authorization", "Content-Type", "X-Client-Id"} {
			count := 0
			for key, values := range c.Request.Header {
				if strings.EqualFold(key, name) {
					count += len(values)
				}
			}
			if count > 1 {
				WriteClientEventError(c, 400)
				return
			}
		}
		media, params, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
		if err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") || c.GetHeader("Content-Encoding") != "" {
			WriteClientEventError(c, 400)
			return
		}
		scheme, bearer, found := strings.Cut(c.GetHeader("Authorization"), " ")
		if !found || (scheme != "Bearer" && scheme != "bearer") || !strings.HasPrefix(bearer, "sk-") || len(bearer) <= 3 || len(bearer) > 131 {
			WriteClientEventError(c, 401)
			return
		}
		for _, ch := range bearer {
			if ch < 0x21 || ch > 0x7e || ch == ',' {
				WriteClientEventError(c, 401)
				return
			}
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		credential, err := model.AuthenticateClientEvent(ctx, bearer[3:], c.ClientIP())
		if err != nil {
			WriteClientEventError(c, ClientEventErrorStatus(err))
			return
		}
		key := fmt.Sprintf("%s:client-events:token:%d", redisRateLimitNamespace, credential.TokenID())
		allowed, retry := true, int64(60)
		if common.RedisEnabled {
			allowed, _, retry, err = redisFixedWindowTake(ctx, key, config.RateLimit, 60)
			if err != nil {
				WriteClientEventError(c, 503)
				return
			}
		} else {
			inMemoryRateLimiter.Init(common.RateLimitKeyExpirationDuration)
			allowed = inMemoryRateLimiter.Request(key, config.RateLimit, 60)
		}
		if !allowed {
			c.Header("Retry-After", strconv.FormatInt(max(retry, 1), 10))
			WriteClientEventError(c, 429)
			return
		}
		c.Set(clientEventCredentialKey, credential)
		c.Next()
	}
}
