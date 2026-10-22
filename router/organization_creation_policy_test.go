package router

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/config"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

// Set persisted policy directly so the admission tests cannot accidentally rely
// on a process-local configuration cache.
func organizationCountPolicy(t *testing.T, c *organizationLifecycleClient, owned, joined string) {
	t.Helper()
	for key, value := range map[string]string{operation_setting.OrganizationCreatedLimitOptionKey: owned, operation_setting.OrganizationJoinedLimitOptionKey: joined} {
		require.NoError(t, c.db.Save(&model.Option{Key: key, Value: value}).Error)
	}
}

func organizationCountDenied(t *testing.T, c *organizationLifecycleClient, request organizationNameWrite, code string) {
	t.Helper()
	before := organizationNamesSnapshot(t, c)
	status, h, b := c.json(t, request.method, request.path, request.actor, request.body, request.proof)
	organizationError(t, status, h, b, 409, code)
	assert.Equal(t, before, organizationNamesSnapshot(t, c))
}

func TestOrganizationCountPolicy(t *testing.T) {
	create := func(actor, name string) organizationNameWrite {
		return organizationNameWrite{method: "POST", path: "/api/organizations", actor: actor, body: map[string]any{"name": name}}
	}
	t.Run("owned_boundary", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		organizationCountPolicy(t, c, "1", "0")
		organizationCountDenied(t, c, create("owner", "over capacity"), "ORG_CREATED_LIMIT_REACHED")
		organizationNamedClient(t, c, "empty", "first owned")
		organizationCountDenied(t, c, create("empty", "second owned"), "ORG_CREATED_LIMIT_REACHED")
	})
	t.Run("unlimited_and_joined_includes_owned", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		organizationNamedClient(t, c, "owner", "missing policy unlimited")
		organizationCountPolicy(t, c, "0", "0")
		organizationNamedClient(t, c, "owner", "explicit unlimited")
		organizationCountPolicy(t, c, "0", "1")
		organizationCountDenied(t, c, create("foreign", "owned occupies membership"), "ORG_JOINED_LIMIT_REACHED")
		organizationNamedClient(t, c, "empty", "independent membership")
		organizationCountDenied(t, c, create("empty", "owned also joined"), "ORG_JOINED_LIMIT_REACHED")
		status, _, b := c.json(t, "GET", c.path(), "owner", nil, "")
		require.Equal(t, 200, status, b)
	})
	t.Run("disabled_occupies_dissolve_and_leave_release", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		organizationCountPolicy(t, c, "1", "0")
		for _, field := range []string{"self_disabled_at", "platform_disabled_at"} {
			require.NoError(t, c.db.Model(&model.Organization{}).Where("id = ?", c.orgA).Update(field, time.Now().Unix()).Error)
			organizationCountDenied(t, c, create("owner", field), "ORG_CREATED_LIMIT_REACHED")
			require.NoError(t, c.db.Model(&model.Organization{}).Where("id = ?", c.orgA).Update(field, 0).Error)
		}
		c.mutate(t, "owner", "POST", c.path()+"/dissolve", "dissolve", map[string]any{"revision": c.revision(t)}, nil, true)
		organizationNamedClient(t, c, "owner", "released by dissolve")
		// Member initially belonged to both fixture organizations. Dissolution freed
		// one slot; leaving the surviving organization frees the remaining one.
		fixture := *c.organizationHTTPFixture
		fixture.orgA = c.orgB
		other := &organizationLifecycleClient{organizationHTTPFixture: &fixture, passwords: c.passwords, refresh: c.refresh}
		organizationCountPolicy(t, c, "0", "1")
		organizationCountDenied(t, c, create("member", "still joined"), "ORG_JOINED_LIMIT_REACHED")
		other.mutate(t, "member", "POST", other.path()+"/leave", "leave", map[string]any{"revision": other.revision(t)}, nil, false)
		organizationNamedClient(t, c, "member", "released by leave")
	})
	t.Run("invitation_pending_reactivation_and_duplicate", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		invitation := c.mutate(t, "owner", "POST", c.path()+"/invitations", "invite", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["empty"].Id), "role": "member"}, nil, false)
		organizationCountPolicy(t, c, "0", "1")
		owned := organizationNamedClient(t, c, "empty", "pending did not reserve")
		request := organizationNameWrite{method: "POST", path: c.path() + "/invitations/" + invitation["object_id"].(string) + "/accept", actor: "empty", body: map[string]any{"revision": c.revision(t), "generation": invitation["generation"]}}
		organizationCountDenied(t, c, request, "ORG_JOINED_LIMIT_REACHED")
		owned.mutate(t, "empty", "POST", owned.path()+"/dissolve", "dissolve", map[string]any{"revision": owned.revision(t)}, nil, true)
		c.mutate(t, "empty", request.method, request.path, "invitation_accept", request.body, nil, false)
		status, _, b := c.json(t, request.method, request.path, request.actor, request.body, "")
		require.Equal(t, 409, status, b)
		assert.NotEqual(t, "ORG_JOINED_LIMIT_REACHED", b["code"])
		c.mutate(t, "empty", "POST", c.path()+"/leave", "leave", map[string]any{"revision": c.revision(t)}, nil, false)
		invitation = c.mutate(t, "owner", "POST", c.path()+"/invitations/"+invitation["object_id"].(string)+"/reissue", "reissue", map[string]any{"revision": c.revision(t), "generation": invitation["generation"], "target_user_id": strconv.Itoa(c.users["empty"].Id), "role": "member"}, nil, false)
		c.mutate(t, "empty", "POST", c.path()+"/invitations/"+invitation["object_id"].(string)+"/accept", "invitation_accept", map[string]any{"revision": c.revision(t), "generation": invitation["generation"]}, nil, false)
		var count int64
		require.NoError(t, c.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", c.orgA, c.users["empty"].Id).Count(&count).Error)
		assert.EqualValues(t, 1, count)
	})
	t.Run("over_limit_release_and_transfer_keeps_membership", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		extra := organizationNamedClient(t, c, "owner", "second historical organization")
		organizationCountPolicy(t, c, "1", "1")
		organizationCountDenied(t, c, create("owner", "over historical owned"), "ORG_CREATED_LIMIT_REACHED")
		organizationCountDenied(t, c, create("member", "over historical joined"), "ORG_JOINED_LIMIT_REACHED")
		status, _, b := c.json(t, "GET", c.path(), "member", nil, "")
		require.Equal(t, 200, status, b)
		c.mutate(t, "member", "POST", c.path()+"/leave", "leave", map[string]any{"revision": c.revision(t)}, nil, false)
		// Admin already belongs to this organization. Ownership transfer is not
		// a joined-count increase, even at the membership limit.
		request := organizationNameTransfer(t, c, "owner", "admin", true)
		status, _, b = c.json(t, request.method, request.path, request.actor, request.body, request.proof)
		require.Equal(t, 200, status, b)
		var former model.OrganizationMember
		require.NoError(t, c.db.Where("organization_id = ? AND user_id = ?", c.orgA, c.users["owner"].Id).First(&former).Error)
		assert.Zero(t, former.RemovedAt)
		assert.Equal(t, model.OrganizationRoleAdmin, former.Role)
		// The original creator no longer owns the transferred organization.
		extra.mutate(t, "owner", "POST", extra.path()+"/dissolve", "dissolve", map[string]any{"revision": extra.revision(t)}, nil, true)
		organizationCountPolicy(t, c, "1", "0")
		organizationNamedClient(t, c, "owner", "current owner count released")
	})
	t.Run("configuration_validation", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		previousConfig := config.GlobalConfig.ExportAllConfigs()
		common.OptionMapRWMutex.Lock()
		previous := common.OptionMap
		common.OptionMap = map[string]string{}
		common.OptionMapRWMutex.Unlock()
		t.Cleanup(func() {
			common.OptionMapRWMutex.Lock()
			common.OptionMap = previous
			common.OptionMapRWMutex.Unlock()
			require.NoError(t, config.GlobalConfig.LoadFromDB(map[string]string{operation_setting.OrganizationCreatedLimitOptionKey: previousConfig[operation_setting.OrganizationCreatedLimitOptionKey], operation_setting.OrganizationJoinedLimitOptionKey: previousConfig[operation_setting.OrganizationJoinedLimitOptionKey]}))
		})
		for _, key := range []string{operation_setting.OrganizationCreatedLimitOptionKey, operation_setting.OrganizationJoinedLimitOptionKey} {
			for _, valid := range []string{"0", "1", "9007199254740991"} {
				require.NoError(t, model.UpdateOption(key, valid))
			}
			require.NoError(t, model.UpdateOption(key, "1"))
			for _, invalid := range []string{"", "-1", "1.5", "NaN", "Inf", "9007199254740992", "9223372036854775808", "01", "+1", " 1", "1 ", "1e0"} {
				require.Error(t, model.UpdateOption(key, invalid), invalid)
				require.Error(t, model.UpdateOptionsBulk(map[string]string{key: invalid, "OrganizationCountSentinel": "changed"}), invalid)
				var stored model.Option
				require.NoError(t, c.db.Where(&model.Option{Key: key}).First(&stored).Error)
				assert.Equal(t, "1", stored.Value)
				var n int64
				require.NoError(t, c.db.Model(&model.Option{}).Where(&model.Option{Key: "OrganizationCountSentinel"}).Count(&n).Error)
				assert.Zero(t, n)
			}
		}
		require.NoError(t, model.UpdateOptionsBulk(map[string]string{operation_setting.OrganizationCreatedLimitOptionKey: "2", operation_setting.OrganizationJoinedLimitOptionKey: "3"}))
		if c.mainKind == "mysql" {
			equivalent := 0
			for _, alias := range []string{strings.ToUpper(operation_setting.OrganizationCreatedLimitOptionKey), operation_setting.OrganizationCreatedLimitOptionKey + " "} {
				var stored model.Option
				err := c.db.Where(&model.Option{Key: alias}).First(&stored).Error
				if errors.Is(err, gorm.ErrRecordNotFound) {
					continue
				}
				require.NoError(t, err)
				require.Equal(t, operation_setting.OrganizationCreatedLimitOptionKey, stored.Key)
				equivalent++
				require.Error(t, model.UpdateOption(alias, "0"))
				require.Error(t, model.UpdateOptionsBulk(map[string]string{alias: "0"}))
				var unchanged model.Option
				require.NoError(t, c.db.Where(&model.Option{Key: stored.Key}).First(&unchanged).Error)
				assert.Equal(t, stored, unchanged)
			}
			require.Positive(t, equivalent, "exercise a real collation-equivalent key")
		}
		// A corrupt authoritative row must not turn into an unlimited policy, even
		// if the cached setting was previously valid.
		organizationCountPolicy(t, c, "garbage", "0")
		before := organizationNamesSnapshot(t, c)
		status, _, b := c.json(t, "POST", "/api/organizations", "empty", map[string]any{"name": "corrupt policy"}, "")
		require.Equal(t, 500, status, b)
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
		organizationCountPolicy(t, c, "0", "broken")
		status, _, b = c.json(t, "POST", "/api/organizations", "empty", map[string]any{"name": "corrupt joined"}, "")
		require.Equal(t, 500, status, b)
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
	})
	t.Run("policy_read_failure", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		before := organizationNamesSnapshot(t, c)
		// A real SQL failure, not a mocked policy read.
		require.NoError(t, c.db.Migrator().DropTable(&model.Option{}))
		status, _, b := c.json(t, "POST", "/api/organizations", "empty", map[string]any{"name": "unreadable policy"}, "")
		require.Equal(t, 500, status, b)
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
	})
	for _, scenario := range []string{"owned", "joined", "independent", "invitations", "transfer"} {
		t.Run("race_"+scenario, func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			first, second := create("empty", "slot one"), create("empty-second", "slot two")
			code := "ORG_CREATED_LIMIT_REACHED"
			if scenario == "invitations" {
				requests := []organizationNameWrite{}
				for _, owner := range []string{"owner", "foreign"} {
					source := organizationNamedClient(t, c, owner, "invite source")
					invitation := source.mutate(t, owner, "POST", source.path()+"/invitations", "invite", map[string]any{"revision": source.revision(t), "target_user_id": strconv.Itoa(c.users["empty"].Id), "role": "member"}, nil, false)
					requests = append(requests, organizationNameWrite{method: "POST", path: source.path() + "/invitations/" + invitation["object_id"].(string) + "/accept", actor: "empty", body: map[string]any{"revision": source.revision(t), "generation": invitation["generation"]}})
				}
				first, second = requests[0], requests[1]
			}
			if scenario == "transfer" {
				first = organizationNameTransfer(t, c, "owner", "empty", true)
				second = create("empty", "competing owned")
			}
			if scenario == "owned" || scenario == "joined" {
				sid := "count-" + common.NewRequestId()
				require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: c.users["empty"].Id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("b", 64), LoginMethod: "password", ExpiresAt: time.Now().Unix() + 3600}))
				token, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: c.users["empty"].Id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
				require.NoError(t, err)
				c.bearer["empty-second"] = token
			}
			if scenario == "joined" || scenario == "invitations" {
				organizationCountPolicy(t, c, "0", "1")
				code = "ORG_JOINED_LIMIT_REACHED"
			} else {
				organizationCountPolicy(t, c, "1", "0")
			}
			if scenario == "independent" {
				second = create("admin", "different user")
			}
			organizationCountRace(t, c, first, second, code, scenario == "independent")
		})
	}
	t.Run("transfer_final_recheck_and_consumed_proof", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		request := organizationNameTransfer(t, c, "owner", "empty", true)
		organizationCountPolicy(t, c, "1", "0")
		original, statement := c.db.ConnPool, c.db.Statement.ConnPool
		pool := &organizationSelectorPool{ConnPool: original, afterRollback: func() error {
			status, _, b := c.json(t, "POST", "/api/organizations", "empty", map[string]any{"name": "intervening final slot"}, "")
			if status != 201 || b["success"] != true {
				return errors.New("intervening creation failed")
			}
			return nil
		}}
		c.db.ConnPool, c.db.Statement.ConnPool = pool, pool
		defer func() { c.db.ConnPool, c.db.Statement.ConnPool = original, statement }()
		status, h, b := c.json(t, request.method, request.path, request.actor, request.body, request.proof)
		organizationError(t, status, h, b, 409, "ORG_CREATED_LIMIT_REACHED")
		require.True(t, pool.fired.Load())
		var org model.Organization
		require.NoError(t, c.db.First(&org, c.orgA).Error)
		assert.Equal(t, c.users["owner"].Id, org.OwnerUserID)
		// Remove capacity pressure so the retry reaches proof validation.
		organizationCountPolicy(t, c, "0", "0")
		status, h, b = c.json(t, request.method, request.path, request.actor, request.body, request.proof)
		organizationError(t, status, h, b, 403, "SECURITY_PROOF_CONSUMED")
	})
}

// Hold the winner before its event commits and observe the competing user
// lock attempt. Both requests must have entered transactions before release.
func organizationCountRace(t *testing.T, c *organizationLifecycleClient, first, second organizationNameWrite, code string, independent bool) {
	t.Helper()
	before := organizationNamesSnapshot(t, c)
	if c.mainKind == "mysql" {
		var local, global string
		err := c.db.Raw("SELECT @@transaction_isolation, @@global.transaction_isolation").Row().Scan(&local, &global)
		if err != nil {
			err = c.db.Raw("SELECT @@tx_isolation, @@global.tx_isolation").Row().Scan(&local, &global)
		}
		require.NoError(t, err)
		require.Equal(t, "REPEATABLE-READ", local)
		require.Equal(t, "REPEATABLE-READ", global)
		t.Log("count-race transaction isolation: REPEATABLE-READ")
	}
	held, attempted, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var winner atomic.Bool
	var releaseOnce, attemptOnce sync.Once
	var wg sync.WaitGroup
	callback := "organization_count_race"
	require.NoError(t, c.db.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table != "organization_events" || !winner.CompareAndSwap(false, true) {
			return
		}
		close(held)
		select {
		case <-release:
		case <-tx.Statement.Context.Done():
			tx.AddError(tx.Statement.Context.Err())
		}
	}))
	observe := func(tx *gorm.DB) {
		if !winner.Load() || tx.Statement.Table != "users" {
			return
		}
		if _, ok := tx.Statement.ConnPool.(gorm.TxCommitter); !ok {
			return
		}
		_, lockingRead := tx.Statement.Clauses["FOR"]
		values, _ := tx.Statement.Dest.(map[string]any)
		reservation, _ := values["auth_version"].(clause.Expr)
		if lockingRead || reservation.SQL == "auth_version" {
			attemptOnce.Do(func() { close(attempted) })
		}
	}
	require.NoError(t, c.db.Callback().Query().Before("gorm:query").Register(callback, observe))
	require.NoError(t, c.db.Callback().Update().Before("gorm:update").Register(callback, observe))
	defer func() {
		releaseOnce.Do(func() { close(release) })
		wg.Wait()
		_ = c.db.Callback().Create().Remove(callback)
		_ = c.db.Callback().Query().Remove(callback)
		_ = c.db.Callback().Update().Remove(callback)
	}()
	type response struct {
		status int
		h      http.Header
		body   map[string]any
	}
	firstDone, secondDone := make(chan response, 1), make(chan response, 1)
	wg.Go(func() {
		status, h, body := c.json(t, first.method, first.path, first.actor, first.body, first.proof)
		firstDone <- response{status, h, body}
	})
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("first name writer did not reach its uncommitted event")
	}
	wg.Go(func() {
		status, h, body := c.json(t, second.method, second.path, second.actor, second.body, second.proof)
		secondDone <- response{status, h, body}
	})
	select {
	case <-attempted:
	case <-time.After(5 * time.Second):
		t.Fatal("second transaction did not attempt its namespace lock before first commit")
	}
	var other response
	if independent && c.mainKind != "sqlite" {
		select {
		case other = <-secondDone:
		case <-time.After(5 * time.Second):
			t.Fatal("a different owner was blocked by the first namespace")
		}
	}
	releaseOnce.Do(func() { close(release) })
	var initial response
	select {
	case initial = <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("first writer did not finish")
	}
	want := 200
	if first.path == "/api/organizations" {
		want = 201
	}
	require.Equal(t, want, initial.status)
	assert.Equal(t, true, initial.body["success"])
	if !independent || c.mainKind == "sqlite" {
		select {
		case other = <-secondDone:
		case <-time.After(5 * time.Second):
			t.Fatal("second writer did not finish")
		}
	}
	after := organizationNamesSnapshot(t, c)
	creates, events := 0, 1
	if first.path == "/api/organizations" {
		creates++
	}
	if independent {
		creates++
		events++
	}
	assert.Len(t, after.Organizations, len(before.Organizations)+creates)
	assert.Len(t, after.Events, len(before.Events)+events)
	memberAdds := creates
	if strings.Contains(first.path, "/invitations/") {
		memberAdds++
	}
	assert.Len(t, after.Members, len(before.Members)+memberAdds)
	if strings.Contains(first.path, "/invitations/") {
		pending := 0
		for _, invitation := range after.Invitations {
			if invitation.Status == model.OrganizationPending {
				pending++
			}
		}
		assert.Equal(t, 1, pending)
	}
	if independent {
		require.Equal(t, 201, other.status)
		assert.Equal(t, true, other.body["success"])
	} else {
		organizationError(t, other.status, other.h, other.body, 409, code)
	}
}
