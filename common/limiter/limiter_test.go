package limiter

import (
	"context"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A socket selects a dedicated disposable Redis instance: these tests flush its script cache.
func newTestRedisLimiter(t *testing.T) (*RedisLimiter, *redis.Client) {
	t.Helper()
	options := &redis.Options{}
	if socket := os.Getenv("NEW_API_LIMITER_TEST_REDIS_SOCKET"); socket != "" {
		options.Network = "unix"
		options.Addr = socket
	} else {
		options.Addr = miniredis.RunT(t).Addr()
	}
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	require.NoError(t, client.Ping(ctx).Err())
	sha, err := client.ScriptLoad(ctx, rateLimitScript).Result()
	require.NoError(t, err)
	return &RedisLimiter{client: client, limitScriptSHA: sha}, client
}

func TestAllowAfterScriptFlush(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested int64
		allowed   bool
		tokens    string
	}{
		{name: "allowed", requested: 3, allowed: true, tokens: "1"},
		{name: "denied", requested: 4, allowed: false, tokens: "3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			limiter, client := newTestRedisLimiter(t)
			key := "limiter-test:" + t.Name()
			require.NoError(t, client.Del(ctx, key).Err())
			t.Cleanup(func() { _ = client.Del(ctx, key).Err() })
			opts := []Option{WithCapacity(7), WithRate(0), WithRequested(tc.requested)}
			allowed, err := limiter.Allow(ctx, key, opts...)
			require.NoError(t, err)
			require.True(t, allowed)
			require.NoError(t, client.ScriptFlush(ctx).Err())
			exists, err := client.ScriptExists(ctx, limiter.limitScriptSHA).Result()
			require.NoError(t, err)
			require.Equal(t, []bool{false}, exists)

			allowed, err = limiter.Allow(ctx, key, opts...)
			require.NoError(t, err)
			assert.Equal(t, tc.allowed, allowed)
			tokens, err := client.HGet(ctx, key, "tokens").Result()
			require.NoError(t, err)
			assert.Equal(t, tc.tokens, tokens)
			exists, err = client.ScriptExists(ctx, limiter.limitScriptSHA).Result()
			require.NoError(t, err)
			assert.Equal(t, []bool{true}, exists)

			allowed, err = limiter.Allow(ctx, key, opts...)
			require.NoError(t, err)
			assert.False(t, allowed)
		})
	}
}

func TestAllowPropagatesRedisErrors(t *testing.T) {
	for _, flush := range []bool{false, true} {
		name := "cached-script"
		if flush {
			name = "flushed-script"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			limiter, client := newTestRedisLimiter(t)
			key := "limiter-test:" + t.Name()
			require.NoError(t, client.Set(ctx, key, "wrong-type", 0).Err())
			t.Cleanup(func() { _ = client.Del(ctx, key).Err() })
			if flush {
				require.NoError(t, client.ScriptFlush(ctx).Err())
			}
			allowed, err := limiter.Allow(ctx, key)
			require.ErrorContains(t, err, "rate limit failed:")
			assert.ErrorContains(t, err, "WRONGTYPE")
			assert.False(t, allowed)
		})
	}
}
