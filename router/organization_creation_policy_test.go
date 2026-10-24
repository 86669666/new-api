package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/QuantumNous/new-api/setting/config"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	gormlogger "gorm.io/gorm/logger"
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

func organizationKeyRequest(t *testing.T, c *organizationLifecycleClient, actor, name, key string) (int, http.Header, map[string]any) {
	t.Helper()
	raw, err := common.Marshal(map[string]string{"name": name})
	require.NoError(t, err)
	return c.request(t, "POST", "/api/organizations", actor, string(raw), http.Header{"Content-Type": {"application/json"}, "Idempotency-Key": {key}})
}

func TestOrganizationCreationIdempotency(t *testing.T) {
	if mode := os.Getenv("NEWAPI_ORGANIZATION_CREATE_CHILD"); mode != "" {
		organizationCreationProcess(t, mode)
		return
	}
	t.Run("receipt_scope_and_capacity", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		organizationCountPolicy(t, c, "1", "1")
		status, _, body := organizationKeyRequest(t, c, "empty", "durable create", "create-one")
		require.Equal(t, 201, status, body)
		before := organizationNamesSnapshot(t, c)
		var auditsBefore int64
		require.NoError(t, model.LOG_DB.Model(&model.AuditLog{}).Where("user_id = ? AND action = ?", c.users["empty"].Id, "organization.create").Count(&auditsBefore).Error)
		status, _, replay := organizationKeyRequest(t, c, "empty", "  durable create  ", "create-one")
		require.Equal(t, 200, status, replay)
		assert.Equal(t, body, replay)
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
		var auditsAfter int64
		require.NoError(t, model.LOG_DB.Model(&model.AuditLog{}).Where("user_id = ? AND action = ?", c.users["empty"].Id, "organization.create").Count(&auditsAfter).Error)
		assert.EqualValues(t, 1, auditsBefore)
		assert.Equal(t, auditsBefore, auditsAfter)
		status, h, b := organizationKeyRequest(t, c, "empty", "DURABLE CREATE", "create-one")
		organizationError(t, status, h, b, 409, "ORG_IDEMPOTENCY_CONFLICT")
		status, h, b = organizationKeyRequest(t, c, "empty", "different name", "create-two")
		organizationError(t, status, h, b, 409, "ORG_CREATED_LIMIT_REACHED")
		organizationCountPolicy(t, c, "0", "0")
		status, h, b = organizationKeyRequest(t, c, "empty", "durable create", "different-key")
		organizationError(t, status, h, b, 409, "ORG_NAME_TAKEN")
		status, _, b = organizationKeyRequest(t, c, "admin", "durable create", "create-one")
		require.Equal(t, 201, status, b)
		assert.NotEqual(t, body["data"], b["data"])
		var rows []model.OrganizationCreationRequest
		require.NoError(t, c.db.Order("id").Find(&rows).Error)
		require.Len(t, rows, 2)
		digest := sha256.Sum256([]byte("create-one"))
		assert.Equal(t, hex.EncodeToString(digest[:]), rows[0].KeyHash)
		require.True(t, c.db.Migrator().HasIndex(&model.OrganizationCreationRequest{}, "uq_org_creation_user_key"))
		duplicate := rows[0]
		duplicate.ID = 0
		require.Error(t, c.db.Create(&duplicate).Error)
		var count int64
		require.NoError(t, c.db.Model(&model.OrganizationCreationRequest{}).Count(&count).Error)
		assert.EqualValues(t, 2, count)
	})
	t.Run("strict_header_and_route_boundary", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		before := organizationNamesSnapshot(t, c)
		for _, key := range []string{"", "-prefix", "a,b", "with space", "é", strings.Repeat("a", 129)} {
			status, h, b := organizationKeyRequest(t, c, "empty", "invalid", key)
			organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
		}
		for _, headers := range []http.Header{{"Idempotency-Key": {"one", "two"}}, {"Idempotency-Key": {"one"}, "idempotency-key": {"two"}}} {
			headers.Set("Content-Type", "application/json")
			status, h, b := c.request(t, "POST", "/api/organizations", "empty", `{"name":"duplicate headers"}`, headers)
			organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
		}
		for _, route := range []struct{ method, path, body string }{{"GET", "/api/organizations", ""}, {"PATCH", c.path() + "/name", `{"revision":"1","name":"rename"}`}, {"POST", c.path() + "/authorization-context", `{}`}, {"POST", "/api/verify", `{}`}} {
			status, h, b := c.request(t, route.method, route.path, "owner", route.body, http.Header{"Content-Type": {"application/json"}, "Idempotency-Key": {"key"}})
			organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
		}
		status, h, b := c.request(t, "POST", "/api/organizations", "empty", `{"name":"x","name":"y"}`, http.Header{"Content-Type": {"application/json"}, "Idempotency-Key": {"key"}})
		organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
		for i, key := range []string{"A", strings.Repeat("z", 128), "a._:-9", "a"} {
			status, _, b := organizationKeyRequest(t, c, "empty", fmt.Sprint("valid", i), key)
			require.Equal(t, 201, status, b)
		}
	})
	t.Run("current_access_and_historical_receipt", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		status, _, first := organizationKeyRequest(t, c, "empty", "original display", "history")
		require.Equal(t, 201, status, first)
		id, err := strconv.ParseInt(first["data"].(map[string]any)["organization_id"].(string), 10, 64)
		require.NoError(t, err)
		fixture := *c.organizationHTTPFixture
		fixture.orgA = id
		created := &organizationLifecycleClient{organizationHTTPFixture: &fixture, passwords: c.passwords, refresh: c.refresh}
		created.mutate(t, "empty", "PATCH", created.path()+"/name", "rename", map[string]any{"revision": created.revision(t), "name": "renamed display"}, nil, false)
		request := organizationNameTransfer(t, created, "empty", "admin", true)
		status, _, b := created.json(t, request.method, request.path, request.actor, request.body, request.proof)
		require.Equal(t, 200, status, b)
		status, _, b = organizationKeyRequest(t, c, "empty", "original display", "history")
		require.Equal(t, 200, status, b)
		assert.Equal(t, first, b)
		before := organizationNamesSnapshot(t, c)
		for _, field := range []string{"self_disabled_at", "platform_disabled_at"} {
			require.NoError(t, c.db.Model(&model.Organization{}).Where("id = ?", id).Update(field, time.Now().Unix()).Error)
			status, h, b := organizationKeyRequest(t, c, "empty", "original display", "history")
			organizationError(t, status, h, b, 409, "ORG_DISABLED")
			require.NoError(t, c.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", id, c.users["empty"].Id).Update("removed_at", time.Now().Unix()).Error)
			status, h, b = organizationKeyRequest(t, c, "empty", "original display", "history")
			organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
			require.NoError(t, c.db.Model(&model.OrganizationMember{}).Where("organization_id = ? AND user_id = ?", id, c.users["empty"].Id).Update("removed_at", 0).Error)
			require.NoError(t, c.db.Model(&model.Organization{}).Where("id = ?", id).Update(field, 0).Error)
		}
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
		created.mutate(t, "admin", "POST", created.path()+"/dissolve", "dissolve", map[string]any{"revision": created.revision(t)}, nil, true)
		before = organizationNamesSnapshot(t, c)
		status, h, b := organizationKeyRequest(t, c, "empty", "original display", "history")
		organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
		var count int64
		require.NoError(t, c.db.Model(&model.OrganizationCreationRequest{}).Count(&count).Error)
		assert.EqualValues(t, 1, count)
	})
	t.Run("fresh_identity", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		status, _, first := organizationKeyRequest(t, c, "empty", "authenticated", "auth")
		require.Equal(t, 201, status, first)
		before := organizationNamesSnapshot(t, c)
		var session model.UserSession
		require.NoError(t, c.db.Where("sid = ?", c.sids["empty"]).First(&session).Error)
		for _, change := range []map[string]any{{"expires_at": time.Now().Unix() - 1}, {"revoked_at": time.Now().Unix()}, {"version": session.Version + 1}} {
			require.NoError(t, c.db.Model(&session).Updates(change).Error)
			status, _, b := organizationKeyRequest(t, c, "empty", "authenticated", "auth")
			require.Equal(t, 401, status, b)
			require.NoError(t, c.db.Model(&session).Updates(map[string]any{"expires_at": time.Now().Unix() + 3600, "revoked_at": 0, "version": session.Version}).Error)
		}
		require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", c.users["empty"].Id).Update("status", common.UserStatusDisabled).Error)
		status, _, b := organizationKeyRequest(t, c, "empty", "authenticated", "auth")
		require.Contains(t, []int{401, 403}, status, b)
		require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", c.users["empty"].Id).Update("status", common.UserStatusEnabled).Error)
		require.NoError(t, c.db.Where("id = ?", c.users["empty"].Id).Delete(&model.User{}).Error)
		status, _, b = organizationKeyRequest(t, c, "empty", "authenticated", "auth")
		require.Contains(t, []int{401, 403}, status, b)
		require.NoError(t, c.db.Unscoped().Model(&model.User{}).Where("id = ?", c.users["empty"].Id).Update("deleted_at", nil).Error)
		c.login(t, "empty")
		status, _, b = organizationKeyRequest(t, c, "empty", "authenticated", "auth")
		require.Equal(t, 200, status, b)
		assert.Equal(t, first, b)
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
	})
	t.Run("atomic_insert_failure", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		before := organizationNamesSnapshot(t, c)
		require.NoError(t, c.db.Callback().Create().Before("gorm:create").Register("create_receipt_fault", func(tx *gorm.DB) {
			if tx.Statement.Table == "organization_creation_requests" {
				tx.AddError(errors.New("owned receipt insertion fault"))
			}
		}))
		status, _, b := organizationKeyRequest(t, c, "empty", "rollback", "fault")
		require.Equal(t, 500, status, b)
		require.NoError(t, c.db.Callback().Create().Remove("create_receipt_fault"))
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
		var count int64
		require.NoError(t, c.db.Model(&model.OrganizationCreationRequest{}).Count(&count).Error)
		assert.Zero(t, count)
		status, _, b = organizationKeyRequest(t, c, "empty", "rollback", "fault")
		require.Equal(t, 201, status, b)
	})
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprintf("concurrent_sessions_conflict_%t", conflict), func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			sid := "idem-" + common.NewRequestId()
			user := c.users["empty"]
			require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: user.Id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("d", 64), LoginMethod: "password", ExpiresAt: time.Now().Unix() + 3600}))
			token, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: user.Id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
			require.NoError(t, err)
			c.bearer["second"] = token
			before := organizationNamesSnapshot(t, c)
			held, attempted, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var winner atomic.Bool
			var once, attemptOnce sync.Once
			var wg sync.WaitGroup
			require.NoError(t, c.db.Callback().Create().Before("gorm:create").Register("idem_race", func(tx *gorm.DB) {
				if tx.Statement.Table == "organization_creation_requests" && winner.CompareAndSwap(false, true) {
					close(held)
					select {
					case <-release:
					case <-tx.Statement.Context.Done():
						tx.AddError(tx.Statement.Context.Err())
					}
				}
			}))
			require.NoError(t, c.db.Callback().Update().Before("gorm:update").Register("idem_race", func(tx *gorm.DB) {
				if winner.Load() && tx.Statement.Table == "users" {
					attemptOnce.Do(func() { close(attempted) })
				}
			}))
			defer func() {
				once.Do(func() { close(release) })
				wg.Wait()
				_ = c.db.Callback().Create().Remove("idem_race")
				_ = c.db.Callback().Update().Remove("idem_race")
			}()
			type response struct {
				status int
				body   map[string]any
			}
			done := make(chan response, 2)
			wg.Go(func() {
				status, _, b := organizationKeyRequest(t, c, "empty", "one concurrent organization", "concurrent")
				done <- response{status, b}
			})
			select {
			case <-held:
			case <-time.After(5 * time.Second):
				t.Fatal("winner did not hold receipt transaction")
			}
			wg.Go(func() {
				name := "one concurrent organization"
				if conflict {
					name = "different concurrent organization"
				}
				status, _, b := organizationKeyRequest(t, c, "second", name, "concurrent")
				done <- response{status, b}
			})
			select {
			case <-attempted:
			case <-time.After(5 * time.Second):
				t.Fatal("second session did not enter user-lock transaction")
			}
			once.Do(func() { close(release) })
			wg.Wait()
			a, b := <-done, <-done
			if conflict {
				assert.ElementsMatch(t, []int{201, 409}, []int{a.status, b.status})
				if a.status == 409 {
					assert.Equal(t, "ORG_IDEMPOTENCY_CONFLICT", a.body["code"])
				} else {
					assert.Equal(t, "ORG_IDEMPOTENCY_CONFLICT", b.body["code"])
				}
			} else {
				assert.ElementsMatch(t, []int{201, 200}, []int{a.status, b.status})
				assert.Equal(t, a.body, b.body)
			}
			after := organizationNamesSnapshot(t, c)
			assert.Len(t, after.Organizations, len(before.Organizations)+1)
			assert.Len(t, after.Members, len(before.Members)+1)
			assert.Len(t, after.Events, len(before.Events)+1)
			var count int64
			require.NoError(t, c.db.Model(&model.OrganizationCreationRequest{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})
	}
	t.Run("expiry_after_replay_locks", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		status, _, b := organizationKeyRequest(t, c, "empty", "expiry", "expires")
		require.Equal(t, 201, status, b)
		before := organizationNamesSnapshot(t, c)
		deadline := time.Now().Add(3 * time.Second).Truncate(time.Second)
		require.NoError(t, c.db.Model(&model.UserSession{}).Where("sid = ?", c.sids["empty"]).Update("expires_at", deadline.Unix()).Error)
		reached, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		var blocked atomic.Bool
		// Hold after the real member locking read, before final identity validation.
		// This deterministic lock barrier models a wait extending past the deadline.
		require.NoError(t, c.db.Callback().Query().After("gorm:query").Register("idem_expiry", func(tx *gorm.DB) {
			if _, ok := tx.Statement.Dest.(*model.OrganizationMember); ok && blocked.CompareAndSwap(false, true) {
				close(reached)
				select {
				case <-release:
				case <-tx.Statement.Context.Done():
					tx.AddError(tx.Statement.Context.Err())
				}
			}
		}))
		defer func() { once.Do(func() { close(release) }); _ = c.db.Callback().Query().Remove("idem_expiry") }()
		done := make(chan int, 1)
		go func() { status, _, _ := organizationKeyRequest(t, c, "empty", "expiry", "expires"); done <- status }()
		select {
		case <-reached:
		case <-time.After(5 * time.Second):
			t.Fatal("replay member lock barrier not reached")
		}
		timer := time.NewTimer(time.Until(deadline) + 10*time.Millisecond)
		defer timer.Stop()
		<-timer.C
		once.Do(func() { close(release) })
		select {
		case status := <-done:
			require.Equal(t, 401, status)
		case <-time.After(5 * time.Second):
			t.Fatal("bounded replay did not complete")
		}
		assert.Equal(t, before, organizationNamesSnapshot(t, c))
		var count int64
		require.NoError(t, c.db.Model(&model.OrganizationCreationRequest{}).Count(&count).Error)
		assert.EqualValues(t, 1, count)
	})
	if kind := os.Getenv("NEWAPI_S2_MAIN"); kind == "mysql" || kind == "postgres" {
		t.Run("real_organization_lock_crosses_expiry", func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			status, _, b := organizationKeyRequest(t, c, "empty", "locked expiry", "lock-expiry")
			require.Equal(t, 201, status, b)
			id, err := strconv.ParseInt(b["data"].(map[string]any)["organization_id"].(string), 10, 64)
			require.NoError(t, err)
			before := organizationNamesSnapshot(t, c)
			deadline := time.Now().Add(3 * time.Second).Truncate(time.Second)
			require.NoError(t, c.db.Model(&model.UserSession{}).Where("sid = ?", c.sids["empty"]).Update("expires_at", deadline.Unix()).Error)
			holder := c.db.WithContext(t.Context()).Begin()
			require.NoError(t, holder.Error)
			defer holder.Rollback()
			var org model.Organization
			require.NoError(t, holder.Clauses(clause.Locking{Strength: "UPDATE"}).First(&org, id).Error)
			attempted := make(chan struct{})
			var once sync.Once
			require.NoError(t, c.db.Callback().Query().Before("gorm:query").Register("idem_real_lock", func(tx *gorm.DB) {
				if _, ok := tx.Statement.Dest.(*model.Organization); ok {
					once.Do(func() { close(attempted) })
				}
			}))
			defer c.db.Callback().Query().Remove("idem_real_lock")
			done := make(chan int, 1)
			go func() {
				status, _, _ := organizationKeyRequest(t, c, "empty", "locked expiry", "lock-expiry")
				done <- status
			}()
			select {
			case <-attempted:
			case <-time.After(5 * time.Second):
				t.Fatal("organization locking read not attempted")
			}
			timer := time.NewTimer(time.Until(deadline) + 10*time.Millisecond)
			defer timer.Stop()
			<-timer.C
			require.NoError(t, holder.Commit().Error)
			select {
			case status := <-done:
				require.Equal(t, 401, status)
			case <-time.After(5 * time.Second):
				t.Fatal("locked replay did not finish")
			}
			assert.Equal(t, before, organizationNamesSnapshot(t, c))
			var count int64
			require.NoError(t, c.db.Model(&model.OrganizationCreationRequest{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})
	}
	for _, backend := range []string{"memory", "redis"} {
		t.Run("replay_rate_"+backend, func(t *testing.T) {
			if backend == "redis" && os.Getenv("NEWAPI_CREATION_REDIS_ADDR") == "" {
				t.Skip("explicit owned Redis endpoint required")
			}
			c := newOrganizationLifecycleClient(t)
			n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
			require.NoError(t, err)
			id := 1_000_000_000 + int(n.Int64())
			sid := "idem-rate-" + common.NewRequestId()
			user := &model.User{Id: id, Username: "idem-" + common.NewRequestId(), Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: strconv.Itoa(id)}
			require.NoError(t, c.db.Create(user).Error)
			require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: strings.Repeat("e", 64), LoginMethod: "password", ExpiresAt: time.Now().Unix() + 3600}))
			token, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
			require.NoError(t, err)
			c.bearer["rate"] = token
			oldEnabled, oldNum, oldDuration := common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.CriticalRateLimitDuration
			t.Cleanup(func() {
				common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.CriticalRateLimitDuration = oldEnabled, oldNum, oldDuration
			})
			common.CriticalRateLimitEnable, common.CriticalRateLimitNum, common.CriticalRateLimitDuration = true, 2, 1200
			if backend == "redis" {
				client := redis.NewClient(&redis.Options{Addr: os.Getenv("NEWAPI_CREATION_REDIS_ADDR"), DB: 15, MaxRetries: -1})
				require.NoError(t, client.Ping(t.Context()).Err())
				keys := []string{fmt.Sprintf("user:%d", id), fmt.Sprintf("auth:user:fence:%d", id), fmt.Sprintf("auth:user:version:%d", id), fmt.Sprintf("rateLimit:v2:user:UC:organization-create:%d", id), "auth:session:" + common.GenerateHMACWithKey([]byte("user-session-cache-v1:"+common.SessionSecret), sid)}
				count, err := client.Exists(t.Context(), keys...).Result()
				require.NoError(t, err)
				require.Zero(t, count)
				t.Cleanup(func() {
					require.NoError(t, client.Del(context.Background(), keys...).Err())
					require.NoError(t, client.Close())
				})
				common.RDB, common.RedisEnabled = client, true
			}
			engine := gin.New()
			SetRouter(engine, WebAssets{IndexPage: []byte("idem-rate")})
			server := httptest.NewServer(engine)
			t.Cleanup(server.Close)
			c.server, c.client = server, server.Client()
			status, _, first := organizationKeyRequest(t, c, "rate", "rate replay", "rate-key")
			require.Equal(t, 201, status, first)
			status, _, second := organizationKeyRequest(t, c, "rate", "rate replay", "rate-key")
			require.Equal(t, 200, status, second)
			assert.Equal(t, first, second)
			req, err := http.NewRequest("POST", server.URL+"/api/organizations", strings.NewReader(`{"name":"rate replay"}`))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "rate-key")
			response, err := c.client.Do(req)
			require.NoError(t, err)
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assert.Equal(t, 429, response.StatusCode)
			assert.Empty(t, raw)
			assert.NotEmpty(t, response.Header.Get("Retry-After"))
			assert.True(t, organizationPrivateNoStore(response.Header.Values("Cache-Control")))
			var count int64
			require.NoError(t, c.db.Model(&model.OrganizationCreationRequest{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})
	}
	t.Run("new_process_replays_discarded_response", func(t *testing.T) {
		c := newOrganizationLifecycleClient(t)
		before := organizationNamesSnapshot(t, c)
		input := organizationBudgetProcessInput{Kind: c.mainKind, DSN: c.mainDSN, Port: os.Getenv("NEWAPI_S2_" + strings.ToUpper(c.mainKind) + "_PORT"), SQLiteRoot: filepath.Dir(c.mainDSN), SessionSecret: common.SessionSecret, Bearer: c.bearer["empty"]}
		raw, err := common.Marshal(input)
		require.NoError(t, err)
		for _, mode := range []string{"commit", "replay"} {
			inR, inW, err := os.Pipe()
			require.NoError(t, err)
			outR, outW, err := os.Pipe()
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOrganizationCreationIdempotency$", "-test.count=1")
			cmd.Env = append(os.Environ(), "NEWAPI_ORGANIZATION_CREATE_CHILD="+mode, "NEWAPI_ORGANIZATION_CHILD_SQLITE_DSN="+c.mainDSN)
			cmd.ExtraFiles = []*os.File{inR, outW}
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			wait := organizationChildWait(t, cmd, cancel, inR, inW, outR, outW)
			require.NoError(t, cmd.Start())
			inR.Close()
			outW.Close()
			_, err = inW.Write(raw)
			require.NoError(t, err)
			inW.Close()
			var result struct {
				Status int
				Body   map[string]any
			}
			organizationChildDecode(t, outR, &result, cancel, wait, &output, input)
			outR.Close()
			err = wait()
			cancel()
			require.NoError(t, err, organizationChildDiagnostic(output.String(), input))
			if mode == "commit" {
				require.Equal(t, 201, result.Status)
				require.Nil(t, result.Body)
			} else {
				require.Equal(t, 200, result.Status, result.Body)
				var row model.OrganizationCreationRequest
				require.NoError(t, c.db.First(&row).Error)
				assert.Equal(t, strconv.FormatInt(row.OrganizationID, 10), result.Body["data"].(map[string]any)["organization_id"])
				assert.Equal(t, strconv.FormatInt(row.EventID, 10), result.Body["data"].(map[string]any)["event_id"])
			}
		}
		after := organizationNamesSnapshot(t, c)
		assert.Len(t, after.Organizations, len(before.Organizations)+1)
		assert.Len(t, after.Events, len(before.Events)+1)
	})
}

func organizationCreationProcess(t *testing.T, mode string) {
	require.Contains(t, []string{"commit", "replay", "limits"}, mode)
	input, output := os.NewFile(3, "owned-input"), os.NewFile(4, "owned-output")
	defer input.Close()
	defer output.Close()
	var config organizationBudgetProcessInput
	require.NoError(t, common.DecodeJson(io.LimitReader(input, 65536), &config))
	var dialector gorm.Dialector
	switch config.Kind {
	case "sqlite":
		root, err := filepath.EvalSymlinks(config.SQLiteRoot)
		require.NoError(t, err)
		path, err := filepath.EvalSymlinks(config.DSN)
		require.NoError(t, err)
		require.Equal(t, root, filepath.Dir(path))
		if os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") != "" {
			// Bind to the exact birth returned to the parent, not any new.db.
			require.NotEmpty(t, os.Getenv("OAUTH_BOOTSTRAP_JOURNAL"))
			require.NotEmpty(t, os.Getenv("NEWAPI_ORGANIZATION_CHILD_SQLITE_DSN"))
			born, err := filepath.EvalSymlinks(os.Getenv("NEWAPI_ORGANIZATION_CHILD_SQLITE_DSN"))
			require.NoError(t, err)
			require.Equal(t, born, path)
			require.Equal(t, "new.db", filepath.Base(path))
		} else {
			require.Equal(t, "organization.db", filepath.Base(path))
		}
		dialector = sqlite.Open(path + "?_pragma=busy_timeout(10000)&_txlock=immediate")
	case "mysql", "postgres":
		require.NoError(t, organizationFixtureDSN(config.Kind, config.DSN, config.Port))
		require.Contains(t, config.DSN, "/newapi_s2_")
		if config.Kind == "mysql" {
			dialector = mysql.Open(config.DSN)
		} else {
			dialector = postgres.Open(config.DSN)
		}
	default:
		t.Fatal("unsupported owned database")
	}
	db, err := gorm.Open(dialector, &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	conn, err := db.DB()
	require.NoError(t, err)
	defer conn.Close()
	model.DB, model.LOG_DB = db, db
	common.SetDatabaseTypes(common.DatabaseType(config.Kind), common.DatabaseType(config.Kind))
	common.RedisEnabled, common.MemoryCacheEnabled, common.IsMasterNode, common.GlobalApiRateLimitEnable, common.CriticalRateLimitEnable = false, false, false, false, false
	common.SessionSecret = config.SessionSecret
	require.NoError(t, i18n.Init())
	require.NoError(t, authz.Init(db))
	gin.DefaultWriter, gin.DefaultErrorWriter = io.Discard, io.Discard
	engine := gin.New()
	SetRouter(engine, WebAssets{IndexPage: []byte("idempotency-child")})
	server := httptest.NewServer(engine)
	defer server.Close()
	if mode == "limits" {
		for i := range 2 {
			if i > 0 {
				signal := make([]byte, 1)
				_, err := io.ReadFull(input, signal)
				require.NoError(t, err)
			}
			req, err := http.NewRequest("GET", server.URL+"/api/organizations/limits", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+config.Bearer)
			response, err := server.Client().Do(req)
			require.NoError(t, err)
			var body map[string]any
			require.NoError(t, common.DecodeJson(response.Body, &body))
			response.Body.Close()
			require.Equal(t, 200, response.StatusCode)
			raw, err := common.Marshal(body)
			require.NoError(t, err)
			_, err = output.Write(append(raw, '\n'))
			require.NoError(t, err)
		}
		return
	}
	req, err := http.NewRequest("POST", server.URL+"/api/organizations", strings.NewReader(`{"name":"survives restart"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+config.Bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "process-restart")
	response, err := server.Client().Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	var body map[string]any
	if mode == "replay" {
		require.NoError(t, common.DecodeJson(response.Body, &body))
	} else {
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
	}
	raw, err := common.Marshal(struct {
		Status int
		Body   map[string]any
	}{response.StatusCode, body})
	require.NoError(t, err)
	_, err = output.Write(raw)
	require.NoError(t, err)
}

// Limits use the formal router (including session-only policy and early cache
// headers), real SQL, and the same fixture as admission/idempotency regressions.
func TestOrganizationLimitsPublication(t *testing.T) {
	if os.Getenv("NEWAPI_ORGANIZATION_LIMITS_CHILD") == "read" {
		organizationCreationProcess(t, "limits")
		return
	}
	previousConfig := config.GlobalConfig.ExportAllConfigs()
	common.OptionMapRWMutex.Lock()
	previousOptions := common.OptionMap
	common.OptionMap = map[string]string{}
	common.OptionMapRWMutex.Unlock()
	t.Cleanup(func() {
		common.OptionMapRWMutex.Lock()
		common.OptionMap = previousOptions
		common.OptionMapRWMutex.Unlock()
		require.NoError(t, config.GlobalConfig.LoadFromDB(map[string]string{operation_setting.OrganizationCreatedLimitOptionKey: previousConfig[operation_setting.OrganizationCreatedLimitOptionKey], operation_setting.OrganizationJoinedLimitOptionKey: previousConfig[operation_setting.OrganizationJoinedLimitOptionKey]}))
	})
	const read = "/api/organizations/limits"
	const write = "/api/option/organization_limits"
	const pair = `{"max_organizations_created":"2","max_organizations_joined":"3"}`
	headers := http.Header{"Content-Type": {"application/json"}}
	t.Run("complete_snapshot_and_legacy_single_key", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		status, h, body := f.request(t, "GET", read, "empty", "", nil)
		require.Equal(t, 200, status, body)
		assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
		assert.Equal(t, map[string]any{"max_organizations_created": float64(0), "max_organizations_joined": float64(0)}, body["data"])
		// A single absent row defaults to zero; cached values are not authoritative.
		require.NoError(t, f.db.Create(&model.Option{Key: operation_setting.OrganizationCreatedLimitOptionKey, Value: "7"}).Error)
		status, _, body = f.request(t, "GET", read, "empty", "", nil)
		require.Equal(t, 200, status, body)
		assert.Equal(t, map[string]any{"max_organizations_created": float64(7), "max_organizations_joined": float64(0)}, body["data"])
		status, h, body = f.request(t, "PUT", write, "root", pair, headers)
		require.Equal(t, 200, status, body)
		assert.Equal(t, true, body["success"])
		assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
		status, _, body = f.request(t, "GET", read, "empty", "", nil)
		require.Equal(t, 200, status, body)
		assert.Equal(t, map[string]any{"max_organizations_created": float64(2), "max_organizations_joined": float64(3)}, body["data"])
		raw, err := common.Marshal(map[string]string{"key": operation_setting.OrganizationCreatedLimitOptionKey, "value": "9007199254740991"})
		require.NoError(t, err)
		status, _, body = f.request(t, "PUT", "/api/option/", "root", string(raw), headers)
		require.Equal(t, 200, status, body)
		require.Equal(t, true, body["success"])
		status, _, body = f.request(t, "GET", read, "root", "", nil)
		require.Equal(t, 200, status, body)
		assert.Equal(t, map[string]any{"max_organizations_created": float64(9007199254740991), "max_organizations_joined": float64(3)}, body["data"])
		status, _, body = f.request(t, "PUT", write, "root", `{"max_organizations_created":"0","max_organizations_joined":"9007199254740991"}`, headers)
		require.Equal(t, 200, status, body)
		status, _, body = f.request(t, "GET", read, "empty", "", nil)
		require.Equal(t, 200, status, body)
		assert.Equal(t, map[string]any{"max_organizations_created": float64(0), "max_organizations_joined": float64(9007199254740991)}, body["data"])

	})
	t.Run("strict_pair_and_transport", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		for _, raw := range []string{`{}`, `null`, `[]`, pair + `{}`, `{"max_organizations_created":"0"}`, `{"max_organizations_created":null,"max_organizations_joined":"0"}`, `{"max_organizations_created":0,"max_organizations_joined":"0"}`, `{"max_organizations_created":"0","max_organizations_joined":"0","x":"1"}`, `{"max_organizations_created":"1","max_organizations_created":"2","max_organizations_joined":"0"}`} {
			status, h, b := f.request(t, "PUT", write, "root", raw, headers)
			organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
		}
		for _, value := range []string{"", "-1", "+1", "01", "1.0", "1e0", " 1", "1 ", "9007199254740992"} {
			raw, err := common.Marshal(map[string]string{"max_organizations_created": value, "max_organizations_joined": "0"})
			require.NoError(t, err)
			status, h, b := f.request(t, "PUT", write, "root", string(raw), headers)
			organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
		}
		for _, method := range []string{"GET", "PUT"} {
			path, raw := read, ""
			if method == "PUT" {
				path, raw = write, pair
			}
			for _, suffix := range []string{"?x=1", "?org_id=0", "?org_id=2", "?org_id=bad", "?org_id=1&org_id=2"} {
				status, h, b := f.request(t, method, path+suffix, "root", raw, headers)
				assert.Equal(t, 400, status, b)
				assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
			}
			for _, key := range []string{"X-Organization-Id", "X-Security-Proof", "Idempotency-Key", "X-HTTP-Method-Override"} {
				extra := headers.Clone()
				extra.Set(key, "0")
				status, h, b := f.request(t, method, path, "root", raw, extra)
				assert.Equal(t, 400, status, b)
				assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
			}
			extra := headers.Clone()
			extra.Set("Origin", "https://untrusted.invalid")
			status, h, b := f.request(t, method, path, "root", raw, extra)
			organizationError(t, status, h, b, 403, "AUTH_ORIGIN_FORBIDDEN")
			extra = headers.Clone()
			extra.Set("Sec-Fetch-Site", "cross-site")
			status, h, b = f.request(t, method, path, "root", raw, extra)
			organizationError(t, status, h, b, 403, "AUTH_ORIGIN_FORBIDDEN")
		}
		status, h, b := f.request(t, "GET", read, "root", "{}", nil)
		organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
		status, h, b = f.request(t, "PUT", write, "root", pair, http.Header{"Content-Type": {"text/plain"}})
		organizationError(t, status, h, b, 415, "UNSUPPORTED_MEDIA_TYPE")
		status, h, b = f.request(t, "PUT", write, "root", strings.Repeat(" ", 1025), headers)
		organizationError(t, status, h, b, 413, "REQUEST_TOO_LARGE")
		status, _, b = f.request(t, "GET", fmt.Sprintf("/api/organizations/%d", f.orgA), "owner", "", nil)
		require.Equal(t, 200, status, b)
		status, _, b = f.request(t, "GET", "/api/organizations/not-a-number", "owner", "", nil)
		require.Equal(t, 400, status, b)
		var n int64
		require.NoError(t, f.db.Model(&model.Option{}).Where(map[string]any{"key": []string{operation_setting.OrganizationCreatedLimitOptionKey, operation_setting.OrganizationJoinedLimitOptionKey}}).Count(&n).Error)
		assert.Zero(t, n)
	})
	t.Run("session_only_root_and_revocation", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		suffix, err := common.GenerateRandomCharsKey(43)
		require.NoError(t, err)
		pat := model.AccessTokenPrefix + suffix
		row := &model.UserAccessToken{Name: "limits boundary", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
		require.NoError(t, row.SetScopes([]string{"option:write"}))
		require.NoError(t, model.CreateUserAccessToken(f.users["root"].Id, row, service.AccessTokenMaxPerUser))
		legacy, err := common.GenerateRandomCharsKey(32)
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["root"].Id).Update("access_token", legacy).Error)
		for _, method := range []string{"GET", "PUT"} {
			path, raw := read, ""
			if method == "PUT" {
				path, raw = write, pair
			}
			for _, actor := range []string{"", pat, legacy, "relay"} {
				status, h, b := f.request(t, method, path, actor, raw, headers)
				assert.Contains(t, []int{401, 403}, status, b)
				assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
				assert.NotEqual(t, true, b["success"])
				if actor == pat || actor == legacy {
					assert.Equal(t, 403, status)
					assert.Equal(t, "AUTH_SESSION_REQUIRED", b["code"])
				}
			}
			cookie := headers.Clone()
			cookie.Set("Cookie", "session="+f.bearer["root"])
			cookie.Set("Origin", "https://untrusted.invalid")
			status, h, b := f.request(t, method, path, "", raw, cookie)
			assert.Contains(t, []int{401, 403}, status, b)
			assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
		}
		status, h, b := f.request(t, "PUT", write, "owner", pair, headers)
		assert.Equal(t, 403, status, b)
		assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
		for _, state := range []string{"expired", "revoked", "disabled", "demoted"} {
			t.Run(state, func(t *testing.T) {
				f := newOrganizationHTTPFixture(t)
				switch state {
				case "expired":
					require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["root"]).Update("expires_at", time.Now().Unix()-1).Error)
				case "revoked":
					require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["root"]).Update("revoked_at", time.Now().Unix()).Error)
				case "disabled":
					require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["root"].Id).Update("status", common.UserStatusDisabled).Error)
				case "demoted":
					require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["root"].Id).Update("role", common.RoleCommonUser).Error)
				}
				for _, method := range []string{"GET", "PUT"} {
					if state == "demoted" && method == "GET" {
						continue
					}
					path, raw := read, ""
					if method == "PUT" {
						path, raw = write, pair
					}
					status, h, b := f.request(t, method, path, "root", raw, headers)
					assert.Contains(t, []int{401, 403}, status, b)
					assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
				}
			})
		}
	})
	t.Run("corrupt_policy_and_sql_failure", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		for _, bad := range []string{"", "01", "bad", "9007199254740992"} {
			require.NoError(t, f.db.Save(&model.Option{Key: operation_setting.OrganizationCreatedLimitOptionKey, Value: bad}).Error)
			status, h, b := f.request(t, "GET", read, "empty", "", nil)
			organizationError(t, status, h, b, 503, "ORG_LIMITS_UNAVAILABLE")
			assert.NotContains(t, b, "data")
		}
		if f.mainKind == "mysql" {
			require.NoError(t, f.db.Where(&model.Option{Key: operation_setting.OrganizationCreatedLimitOptionKey}).Delete(&model.Option{}).Error)
			require.NoError(t, f.db.Create(&model.Option{Key: strings.ToUpper(operation_setting.OrganizationCreatedLimitOptionKey), Value: "1"}).Error)
			status, h, b := f.request(t, "GET", read, "empty", "", nil)
			organizationError(t, status, h, b, 503, "ORG_LIMITS_UNAVAILABLE")
			status, h, b = f.request(t, "PUT", write, "root", pair, headers)
			organizationError(t, status, h, b, 503, "ORG_LIMITS_UPDATE_FAILED")
		}
		require.NoError(t, f.db.Migrator().DropTable(&model.Option{}))
		status, h, b := f.request(t, "GET", read, "empty", "", nil)
		organizationError(t, status, h, b, 503, "ORG_LIMITS_UNAVAILABLE")
		status, h, b = f.request(t, "PUT", write, "root", pair, headers)
		organizationError(t, status, h, b, 503, "ORG_LIMITS_UPDATE_FAILED")
	})
	t.Run("unavailable_database_fails_closed", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		conn, err := f.db.DB()
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		for _, method := range []string{"GET", "PUT"} {
			path, raw := read, ""
			if method == "PUT" {
				path, raw = write, pair
			}
			status, h, b := f.request(t, method, path, "root", raw, headers)
			assert.Contains(t, []int{401, 500, 503}, status, b)
			assert.NotEqual(t, true, b["success"])
			assert.Equal(t, "private, no-store", h.Get("Cache-Control"))
			assert.NotContains(t, b, "data")
		}
	})
	t.Run("second_sql_write_rolls_back_pair", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		status, _, b := f.request(t, "PUT", write, "root", pair, headers)
		require.Equal(t, 200, status, b)
		writes := 0
		require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register("limits-second-write-fault", func(tx *gorm.DB) {
			if tx.Statement.Table == "options" {
				writes++
				if writes == 2 {
					tx.Statement.Table = "missing_limits_table"
				}
			}
		}))
		t.Cleanup(func() { require.NoError(t, f.db.Callback().Update().Remove("limits-second-write-fault")) })
		status, h, b := f.request(t, "PUT", write, "root", `{"max_organizations_created":"8","max_organizations_joined":"9"}`, headers)
		organizationError(t, status, h, b, 503, "ORG_LIMITS_UPDATE_FAILED")
		require.Equal(t, 2, writes)
		status, _, b = f.request(t, "GET", read, "empty", "", nil)
		require.Equal(t, 200, status, b)
		assert.Equal(t, map[string]any{"max_organizations_created": float64(2), "max_organizations_joined": float64(3)}, b["data"])
	})
	t.Run("concurrent_complete_snapshots", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		status, _, b := f.request(t, "PUT", write, "root", pair, headers)
		require.Equal(t, 200, status, b)
		start := make(chan struct{})
		results := make(chan int, 2)
		var wg sync.WaitGroup
		for _, raw := range []string{`{"max_organizations_created":"10","max_organizations_joined":"11"}`, `{"max_organizations_created":"20","max_organizations_joined":"21"}`} {
			wg.Go(func() {
				<-start
				req, err := http.NewRequest("PUT", f.server.URL+write, strings.NewReader(raw))
				if err != nil {
					results <- 0
					return
				}
				req.Header = headers.Clone()
				req.Header.Set("Authorization", "Bearer "+f.bearer["root"])
				resp, err := f.client.Do(req)
				if err != nil {
					results <- 0
					return
				}
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)
				results <- resp.StatusCode
			})
		}
		close(start)
		wg.Wait()
		close(results)
		successes := 0
		for status := range results {
			assert.Contains(t, []int{200, 503}, status)
			if status == 200 {
				successes++
			}
		}
		require.Positive(t, successes)
		status, _, b = f.request(t, "GET", read, "empty", "", nil)
		require.Equal(t, 200, status, b)
		assert.Contains(t, []any{map[string]any{"max_organizations_created": float64(10), "max_organizations_joined": float64(11)}, map[string]any{"max_organizations_created": float64(20), "max_organizations_joined": float64(21)}}, b["data"])
	})
	t.Run("no_store_before_global_rate_rejection", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		enabled, num, duration := common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration
		t.Cleanup(func() {
			common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = enabled, num, duration
		})
		common.GlobalApiRateLimitEnable, common.GlobalApiRateLimitNum, common.GlobalApiRateLimitDuration = true, 1, 1200
		engine := gin.New()
		SetRouter(engine, WebAssets{IndexPage: []byte("limits-rate")})
		require.NoError(t, engine.SetTrustedProxies(nil))
		for i, method := range []string{"GET", "PUT"} {
			path, raw := read, ""
			if method == "PUT" {
				path, raw = write, pair
			}
			for attempt := range 2 {
				req := httptest.NewRequest(method, path, strings.NewReader(raw))
				req.RemoteAddr = fmt.Sprintf("198.18.%d.%d:1234", f.users["root"].Id%250, i+1)
				req.Header = headers.Clone()
				req.Header.Set("Authorization", "Bearer "+f.bearer["root"])
				response := httptest.NewRecorder()
				engine.ServeHTTP(response, req)
				assert.Equal(t, "private, no-store", response.Header().Get("Cache-Control"))
				if attempt == 0 {
					require.Equal(t, 200, response.Code, response.Body.String())
				} else {
					assert.Equal(t, 429, response.Code)
				}
			}
		}
	})
	t.Run("lost_put_response_requires_read_not_replay", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		committed := make(chan struct{})
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, err := http.NewRequest("PUT", f.server.URL+write, r.Body)
			if err != nil {
				w.WriteHeader(502)
				return
			}
			req.Header = r.Header.Clone()
			resp, err := f.client.Do(req)
			if err != nil {
				w.WriteHeader(502)
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != 200 {
				w.WriteHeader(resp.StatusCode)
				return
			}
			close(committed)
			<-r.Context().Done()
		}))
		defer proxy.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "PUT", proxy.URL+write, strings.NewReader(pair))
		require.NoError(t, err)
		req.Header = headers.Clone()
		req.Header.Set("Authorization", "Bearer "+f.bearer["root"])
		result := make(chan error, 1)
		go func() {
			resp, err := proxy.Client().Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			result <- err
		}()
		select {
		case <-committed:
		case <-time.After(10 * time.Second):
			t.Fatal("PUT did not commit")
		}
		cancel()
		require.Error(t, <-result)
		// No automatic PUT retry: an explicit read resolves the unknown outcome.
		status, _, b := f.request(t, "GET", read, "root", "", nil)
		require.Equal(t, 200, status, b)
		assert.Equal(t, map[string]any{"max_organizations_created": float64(2), "max_organizations_joined": float64(3)}, b["data"])
	})
	t.Run("running_second_process_observes_commit", func(t *testing.T) {
		f := newOrganizationHTTPFixture(t)
		inR, inW, err := os.Pipe()
		require.NoError(t, err)
		defer inW.Close()
		outR, outW, err := os.Pipe()
		require.NoError(t, err)
		defer outR.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOrganizationLimitsPublication$", "-test.count=1")
		cmd.Env = append(os.Environ(), "NEWAPI_ORGANIZATION_LIMITS_CHILD=read", "NEWAPI_ORGANIZATION_CHILD_SQLITE_DSN="+f.mainDSN)
		cmd.ExtraFiles = []*os.File{inR, outW}
		var logs bytes.Buffer
		cmd.Stdout = &logs
		cmd.Stderr = &logs
		wait := organizationChildWait(t, cmd, cancel, inR, inW, outR, outW)
		require.NoError(t, cmd.Start())
		inR.Close()
		outW.Close()
		input := organizationBudgetProcessInput{Kind: f.mainKind, DSN: f.mainDSN, Port: os.Getenv("NEWAPI_S2_" + strings.ToUpper(f.mainKind) + "_PORT"), SQLiteRoot: filepath.Dir(f.mainDSN), SessionSecret: common.SessionSecret, Bearer: f.bearer["root"]}
		raw, err := common.Marshal(input)
		require.NoError(t, err)
		_, err = inW.Write(append(raw, '\n'))
		require.NoError(t, err)
		var first map[string]any
		organizationChildDecode(t, outR, &first, cancel, wait, &logs, input)
		assert.Equal(t, map[string]any{"max_organizations_created": float64(0), "max_organizations_joined": float64(0)}, first["data"])
		status, _, b := f.request(t, "PUT", write, "root", pair, headers)
		require.Equal(t, 200, status, b)
		_, err = inW.Write([]byte{1})
		require.NoError(t, err)
		var second map[string]any
		organizationChildDecode(t, outR, &second, cancel, wait, &logs, input)
		assert.Equal(t, map[string]any{"max_organizations_created": float64(2), "max_organizations_joined": float64(3)}, second["data"])
		require.NoError(t, wait(), organizationChildDiagnostic(logs.String(), input))
	})
}

// Reap only this fixture's child even when a pipe/assertion fails before Wait.
func organizationChildWait(t *testing.T, cmd *exec.Cmd, cancel context.CancelFunc, pipes ...*os.File) func() error {
	t.Helper()
	var once sync.Once
	var err error
	wait := func() error {
		once.Do(func() {
			if cmd.Process != nil {
				err = cmd.Wait()
			}
		})
		return err
	}
	t.Cleanup(func() {
		cancel()
		for _, pipe := range pipes {
			_ = pipe.Close()
		}
		_ = wait()
	})
	return wait
}

func organizationChildDiagnostic(output string, input organizationBudgetProcessInput) string {
	for _, secret := range []string{input.Bearer, input.SessionSecret, input.DSN} {
		if secret != "" {
			output = strings.ReplaceAll(output, secret, "[redacted]")
		}
	}
	return output
}

func organizationChildDecode(t *testing.T, reader io.Reader, result any, cancel context.CancelFunc, wait func() error, output *bytes.Buffer, input organizationBudgetProcessInput) {
	t.Helper()
	if err := common.DecodeJson(reader, result); err != nil {
		cancel()
		exit := wait() // Wait also joins stdout/stderr copies before reading the buffer.
		t.Fatalf("organization child pipe failed: %v; exit: %v; diagnostic: %s", err, exit, organizationChildDiagnostic(output.String(), input))
	}
}
