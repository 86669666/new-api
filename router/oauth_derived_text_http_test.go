package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestOAuthDerivedTextHTTPSettlement(t *testing.T) {
	dsn, adminDSN := os.Getenv("NEWAPI_H29_PAID_SERVICE"), os.Getenv("NEWAPI_H29_PAID_ADMIN")
	if dsn == "" || adminDSN == "" {
		t.Skip("requires a fresh isolated PostgreSQL database seeded by the real first-key issuer")
	}
	open := func(dsn string) *gorm.DB {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		require.NoError(t, err)
		pool, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, pool.Close()) })
		var name string
		require.NoError(t, db.Raw("SELECT current_database()").Row().Scan(&name))
		require.Equal(t, "h29_key_http_final", name)
		return db
	}
	admin, db := open(adminDSN), open(dsn)
	t.Setenv("SQL_DSN", dsn)
	t.Setenv("OAUTH_PROTECTED_SOURCE_OPS", "true")
	oldDB, oldLog, oldType, oldLogType := model.DB, model.LOG_DB, common.MainDatabaseType(), common.LogDatabaseType()
	oldMaster, oldRedis := common.IsMasterNode, common.RedisEnabled
	t.Cleanup(func() {
		model.DB, model.LOG_DB, common.IsMasterNode, common.RedisEnabled = oldDB, oldLog, oldMaster, oldRedis
		common.SetDatabaseTypes(oldType, oldLogType)
	})
	common.SetMainDatabaseType(common.DatabaseTypePostgreSQL)
	model.DB, common.IsMasterNode, common.RedisEnabled = db, false, false
	require.NoError(t, model.InitLogDB())
	require.NoError(t, i18n.Init())
	require.NoError(t, model.InitOAuthGrantStore(true))

	var source model.OAuthDerivedTokenSource
	require.NoError(t, admin.Where("user_id = ? AND token_id IS NOT NULL AND terminal_at IS NULL", 1).Order("token_id").First(&source).Error)
	var token model.Token
	require.NoError(t, admin.First(&token, *source.TokenID).Error)
	const selectedModel = "gpt-4o-mini"
	const goodBody = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}],"max_tokens":16}`
	const goodResponse = `{"id":"fixture","object":"chat.completion","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"isolated result"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`
	type wireRequest struct {
		body string
		err  error
	}
	wire := make(chan wireRequest, 4)
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		raw, err := io.ReadAll(req.Body)
		wire <- wireRequest{string(raw), err}
		assert.Equal(t, "/v1/chat/completions", req.URL.Path)
		assert.Equal(t, "Bearer fixture-channel-key", req.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(raw), "over completion cap") {
			_, _ = io.WriteString(w, strings.Replace(goodResponse, `"completion_tokens":2,"total_tokens":12`, `"completion_tokens":17,"total_tokens":27`, 1))
			return
		}
		_, _ = io.WriteString(w, goodResponse)
	}))
	t.Cleanup(upstream.Close)
	ca := filepath.Join(t.TempDir(), "upstream.pem")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600))
	t.Setenv("SSL_CERT_FILE", ca)
	channel := model.Channel{Type: constant.ChannelTypeOpenAI, Key: "fixture-channel-key", Name: "paid-http", Status: common.ChannelStatusEnabled, Group: "default", Models: selectedModel, BaseURL: &upstream.URL}
	require.NoError(t, admin.Create(&channel).Error)
	require.NoError(t, admin.Create(&model.Ability{Group: "default", Model: selectedModel, ChannelId: channel.Id, Enabled: true, Priority: common.GetPointer(int64(0))}).Error)
	policy := relay.OAuthDerivedTextPolicy{
		SourcePolicyHash: source.PolicyHash, Model: selectedModel, Group: "default",
		ChannelID: channel.Id, Endpoint: upstream.URL + "/v1/chat/completions", MaxCompletion: 16,
		ModelRatio: 1, CompletionRatio: 1, GroupRatio: 1, CacheRatio: 1,
	}
	start := func(policy *relay.OAuthDerivedTextPolicy) *httptest.Server {
		engine := gin.New()
		engine.Use(middleware.RequestId())
		setRelayRouter(engine, policy)
		server := httptest.NewServer(engine)
		t.Cleanup(server.Close)
		return server
	}
	call := func(server *httptest.Server, body string) (int, string, string) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer sk-"+token.Key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(common.RequestIdKey, "client-provided-ref")
		res, err := server.Client().Do(req)
		require.NoError(t, err)
		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		return res.StatusCode, res.Header.Get(common.RequestIdKey), string(raw)
	}
	balances := func(wallet, remain, used int) {
		t.Helper()
		var user model.User
		var row model.Token
		require.NoError(t, admin.First(&user, token.UserId).Error)
		require.NoError(t, admin.First(&row, token.Id).Error)
		assert.Equal(t, wallet, user.Quota)
		assert.Equal(t, remain, row.RemainQuota)
		assert.Equal(t, used, row.UsedQuota)
	}
	receipt := func(id string) model.OAuthDerivedTextCharge {
		t.Helper()
		require.NotEmpty(t, id)
		require.NotEqual(t, "client-provided-ref", id)
		hash := sha256.Sum256([]byte("newapi.oauth.text.receipt.v1\x00" + id))
		row, err := model.ReadOAuthDerivedTextCharge(context.Background(), hex.EncodeToString(hash[:]))
		require.NoError(t, err)
		var committed model.OAuthDerivedTextCharge
		require.NoError(t, admin.First(&committed, "ref = ?", row.Ref).Error)
		require.Equal(t, *row, committed)
		return committed
	}
	wrong := policy
	wrong.SourcePolicyHash = strings.Repeat("f", 64)
	server := start(&policy)
	policy.Model, policy.ModelRatio = "changed-after-router-start", 99
	for _, denied := range []*httptest.Server{start(nil), start(&wrong)} {
		status, _, _ := call(denied, goodBody)
		require.Equal(t, http.StatusServiceUnavailable, status)
	}
	status, _, _ := call(server, strings.Replace(goodBody, `"max_tokens":16`, `"max_tokens":17`, 1))
	require.Equal(t, http.StatusServiceUnavailable, status)
	for _, unsupported := range []string{`{"system_prompt":"configured override"}`, `{"proxy":"http://127.0.0.1:1"}`} {
		require.NoError(t, admin.Model(&channel).UpdateColumn("setting", unsupported).Error)
		status, _, _ := call(server, goodBody)
		require.Equal(t, http.StatusServiceUnavailable, status)
	}
	require.NoError(t, admin.Model(&channel).UpdateColumn("setting", nil).Error)
	require.Zero(t, calls.Load())
	var count int64
	require.NoError(t, admin.Model(&model.OAuthDerivedTextCharge{}).Count(&count).Error)
	require.Zero(t, count)
	balances(100, 105, 0)

	status, requestID, raw := call(server, goodBody)
	require.Equal(t, http.StatusOK, status)
	require.JSONEq(t, goodResponse, raw)
	received := <-wire
	require.NoError(t, received.err)
	require.Equal(t, goodBody, received.body)
	paid := receipt(requestID)
	require.Equal(t, "settled", paid.State)
	require.NotNil(t, paid.Actual)
	require.Equal(t, 12, *paid.Actual)
	var facts model.OAuthTextFacts
	require.NoError(t, common.UnmarshalJsonStr(paid.Facts, &facts))
	h := sha256.Sum256([]byte(received.body))
	require.Equal(t, hex.EncodeToString(h[:]), facts.BodyHash)
	require.Equal(t, selectedModel, facts.Model)
	require.Equal(t, float64(1), facts.ModelRatio)
	require.Equal(t, facts.PromptEstimate+16, paid.Reserve)
	balances(88, 93, 12)

	status, requestID, raw = call(server, strings.Replace(goodBody, "hello", "over completion cap", 1))
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.NotContains(t, raw, "isolated result")
	unresolved := receipt(requestID)
	require.Equal(t, "send_claimed", unresolved.State)
	require.Nil(t, unresolved.Actual)
	balances(88-unresolved.Reserve, 93-unresolved.Reserve, 12+unresolved.Reserve)
	require.EqualValues(t, 2, calls.Load())
	t.Logf("closed/invalid=503 with 0 sends; valid=200 after 1 send reserve=%d net=12; excess completion=503 after 1 send held=%d", paid.Reserve, unresolved.Reserve)
}
