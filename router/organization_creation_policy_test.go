package router

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercise the production SetRouter chain, with independent persisted sessions
// and real databases. The optional Redis endpoint must be explicitly supplied.
func TestOrganizationCreationRatePolicy(t *testing.T) {
	for _, backend := range []string{"memory", "redis"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "redis" && os.Getenv("NEWAPI_CREATION_REDIS_ADDR") == "" {
				t.Skip("explicit owned Redis endpoint required")
			}
			for _, scenario := range []string{"sessions_and_users", "credential_boundary", "scope_isolation", "duplicate", "disabled", "redis_failure"} {
				if scenario == "redis_failure" && backend != "redis" {
					continue
				}
				t.Run(scenario, func(t *testing.T) {
					oldEnabled, oldNum, oldDuration := common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.CriticalRateLimitDuration
					t.Cleanup(func() {
						common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.CriticalRateLimitDuration = oldEnabled, oldNum, oldDuration
					})
					common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.CriticalRateLimitDuration = scenario != "disabled", 2, 1200
					f := newOrganizationHTTPFixture(t)
					// Random positive IDs prevent process-global memory buckets or shared Redis
					// caches from colliding with fixtures in other independently running suites.
					keys := []string{}
					for _, actor := range []string{"creator", "other"} {
						n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
						require.NoError(t, err)
						id := 1_000_000_000 + int(n.Int64())
						u := &model.User{Id: id, Username: "creation-" + common.NewRequestId(), Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: strconv.Itoa(id)}
						require.NoError(t, f.db.Create(u).Error)
						f.users[actor] = u
						keys = append(keys, fmt.Sprintf("user:%d", id), fmt.Sprintf("auth:user:fence:%d", id), fmt.Sprintf("auth:user:version:%d", id), fmt.Sprintf("rateLimit:v2:user:UC:organization-create:%d", id), fmt.Sprintf("rateLimit:v2:user:UC:security-verification:%d", id))
						for _, suffix := range []string{"", "-second"} {
							sid := "creation-" + common.NewRequestId()
							require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("a", 64), LoginMethod: "password", ExpiresAt: time.Now().Unix() + 3600}))
							token, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
							require.NoError(t, err)
							f.bearer[actor+suffix] = token
							keys = append(keys, "auth:session:"+common.GenerateHMACWithKey([]byte("user-session-cache-v1:"+common.SessionSecret), sid))
						}
					}
					patSuffix, err := common.GenerateRandomCharsKey(43)
					require.NoError(t, err)
					pat := model.AccessTokenPrefix + patSuffix
					row := &model.UserAccessToken{Name: "creation boundary", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
					require.NoError(t, row.SetScopes([]string{"*"}))
					require.NoError(t, model.CreateUserAccessToken(f.users["creator"].Id, row, service.AccessTokenMaxPerUser))
					var client *redis.Client
					if backend == "redis" {
						client = redis.NewClient(&redis.Options{Addr: os.Getenv("NEWAPI_CREATION_REDIS_ADDR"), DB: 15, MaxRetries: -1})
						require.NoError(t, client.Ping(t.Context()).Err())
						existing, err := client.Exists(t.Context(), keys...).Result()
						require.NoError(t, err)
						require.Zero(t, existing, "refuse foreign Redis keys")
						t.Cleanup(func() {
							require.NoError(t, client.Del(context.Background(), keys...).Err())
							n, err := client.Exists(context.Background(), keys...).Result()
							require.NoError(t, err)
							assert.Zero(t, n)
							require.NoError(t, client.Close())
						})
						info, err := client.Info(t.Context(), "server").Result()
						require.NoError(t, err)
						for line := range strings.SplitSeq(info, "\n") {
							if strings.HasPrefix(line, "redis_version:") {
								t.Log(strings.TrimSpace(line))
							}
						}
						common.RDB, common.RedisEnabled = client, true
					}
					// Limiter backend is chosen at route registration, so rebuild the complete
					// production router after selecting Redis. No replacement handlers are used.
					engine := gin.New()
					SetRouter(engine, WebAssets{IndexPage: []byte("creation-fixture")})
					// Model a trusted local reverse proxy so changing X-Forwarded-For
					// really changes ClientIP, while the user bucket remains shared.
					require.NoError(t, engine.SetTrustedProxies([]string{"127.0.0.1"}))
					server := httptest.NewServer(engine)
					t.Cleanup(server.Close)
					f.server, f.client = server, server.Client()
					f.client.Timeout = 10 * time.Second
					request := func(actor, path, name string, extra http.Header) (int, http.Header, string) {
						body, err := common.Marshal(map[string]string{"name": name})
						require.NoError(t, err)
						req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(string(body)))
						require.NoError(t, err)
						req.Header.Set("Content-Type", "application/json")
						if actor != "" {
							token := f.bearer[actor]
							if token == "" {
								token = actor
							}
							req.Header.Set("Authorization", "Bearer "+token)
						}
						for k, v := range extra {
							req.Header[k] = v
						}
						resp, err := f.client.Do(req)
						require.NoError(t, err)
						defer resp.Body.Close()
						raw, err := io.ReadAll(resp.Body)
						require.NoError(t, err)
						return resp.StatusCode, resp.Header, string(raw)
					}
					counts := func() [3]int64 {
						var result [3]int64
						for i, table := range []any{&model.Organization{}, &model.OrganizationMember{}, &model.OrganizationEvent{}} {
							require.NoError(t, f.db.Model(table).Count(&result[i]).Error)
						}
						return result
					}
					create := func(actor, name string) {
						before := counts()
						status, h, body := request(actor, "/api/organizations", name, nil)
						require.Equal(t, 201, status, body)
						assert.True(t, organizationPrivateNoStore(h.Values("Cache-Control")))
						var response map[string]any
						require.NoError(t, common.UnmarshalJsonStr(body, &response))
						assert.Equal(t, true, response["success"])
						assert.Equal(t, [3]int64{before[0] + 1, before[1] + 1, before[2] + 1}, counts())
					}
					blocked := func(actor string) {
						before := counts()
						status, h, body := request(actor, "/api/organizations", "blocked", http.Header{"X-Forwarded-For": {"198.51.100.8"}})
						require.Equal(t, 429, status, body)
						assert.Empty(t, body)
						retry, err := strconv.Atoi(h.Get("Retry-After"))
						require.NoError(t, err)
						assert.Positive(t, retry)
						assert.LessOrEqual(t, retry, 1200)
						assert.True(t, organizationPrivateNoStore(h.Values("Cache-Control")))
						assert.Equal(t, before, counts())
					}
					switch scenario {
					case "sessions_and_users":
						create("creator", "one")
						create("creator-second", "two")
						blocked("creator")
						blocked("creator-second")
						create("other", "one")
					case "credential_boundary":
						before := counts()
						for _, tc := range []struct {
							actor, path string
							want        int
						}{{"", "/api/organizations", 401}, {pat, "/api/organizations", 403}, {"creator", "/api/organizations?org_id=bad", 400}} {
							status, _, body := request(tc.actor, tc.path, "unauthorized", nil)
							require.Equal(t, tc.want, status, body)
						}
						assert.Equal(t, before, counts())
						create("creator", "one")
						create("creator", "two")
						blocked("creator")
					case "scope_isolation":
						for range 2 {
							status, _, _ := request("creator", "/api/user/passkey/verify/begin", "", nil)
							require.NotEqual(t, 429, status)
							require.NotEqual(t, 404, status)
						}
						status, _, body := request("creator", "/api/user/passkey/verify/begin", "", nil)
						require.Equal(t, 429, status, body)
						create("creator", "one")
						create("creator", "two")
						blocked("creator")
					case "duplicate":
						create("creator", "same")
						before := counts()
						status, _, body := request("creator", "/api/organizations", "same", nil)
						require.Equal(t, 409, status, body)
						assert.Contains(t, body, "ORG_NAME_TAKEN")
						assert.Equal(t, before, counts())
						blocked("creator")
					case "disabled":
						for _, name := range []string{"one", "two", "three"} {
							create("creator", name)
						}
					case "redis_failure":
						// Close only a test-owned client, keeping the shared server and cleanup
						// connection live. Authentication may fall back to SQL; rate limiting must not.
						failed := redis.NewClient(&redis.Options{Addr: os.Getenv("NEWAPI_CREATION_REDIS_ADDR"), DB: 15, MaxRetries: -1})
						require.NoError(t, failed.Close())
						common.RDB = failed
						before := counts()
						status, h, body := request("creator", "/api/organizations", "no fallback", nil)
						require.Equal(t, 500, status, body)
						assert.Empty(t, body)
						assert.True(t, organizationPrivateNoStore(h.Values("Cache-Control")))
						assert.Equal(t, before, counts())
						common.RDB = client
						create("creator", "recovered")
					}
				})
			}
		})
	}
}
