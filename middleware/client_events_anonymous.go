package middleware

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
)

const anonymousClientEventIPKey = "anonymous_client_event_peer"

var anonymousClientEventSlots = make(chan struct{}, 8)

func IsAnonymousClientEvent(c *gin.Context) bool {
	_, ok := c.Get(anonymousClientEventIPKey)
	return ok
}

// Only the explicit no-proxy mode is supported here. Read the transport peer,
// never forwarding headers. Operational Redis keys are short lived, not an
// anonymity guarantee; no peer/header/body is persisted with an event.
func anonymousClientEventsBoundary(c *gin.Context, rate int) {
	if os.Getenv("TRUSTED_PROXIES") != "none" || !common.RedisEnabled || common.RDB == nil {
		WriteClientEventError(c, 503)
		return
	}
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || ip.Zone() != "" {
		WriteClientEventError(c, 503)
		return
	}
	ip = ip.Unmap()
	bits := 64
	if ip.Is4() {
		bits = 32
	}
	network := netip.PrefixFrom(ip, bits).Masked().String()
	select {
	case anonymousClientEventSlots <- struct{}{}:
		defer func() { <-anonymousClientEventSlots }()
	default:
		c.Header("Retry-After", "1")
		WriteClientEventError(c, 503)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)
	// The fixed site gate precedes every variable key, bounding key cardinality.
	for _, budget := range []struct {
		key   string
		limit int
	}{
		{redisRateLimitNamespace + ":client-events:anonymous:site", 600},
		{redisRateLimitNamespace + ":client-events:anonymous:network:" + network, min(rate, 60)},
	} {
		allowed, _, retry, err := redisFixedWindowTake(ctx, budget.key, budget.limit, 60)
		if err != nil {
			WriteClientEventError(c, 503)
			return
		}
		if !allowed {
			c.Header("Retry-After", strconv.FormatInt(max(retry, 1), 10))
			WriteClientEventError(c, 429)
			return
		}
	}
	c.Set(anonymousClientEventIPKey, ip.String())
	c.Next()
}

// Called only after the existing bounded UUID parser, before any SQL write.
func TakeAnonymousClientEventPair(c *gin.Context, clientID string) bool {
	ip, ok := c.Get(anonymousClientEventIPKey)
	if !ok {
		WriteClientEventError(c, 503)
		return false
	}
	allowed, _, retry, err := redisFixedWindowTake(c.Request.Context(),
		redisRateLimitNamespace+":client-events:anonymous:pair:"+ip.(string)+":"+clientID,
		operation_setting.CurrentClientEventsSnapshot().RateLimit, 60)
	if err != nil {
		WriteClientEventError(c, 503)
		return false
	}
	if !allowed {
		c.Header("Retry-After", strconv.FormatInt(max(retry, 1), 10))
		WriteClientEventError(c, 429)
		return false
	}
	return true
}
