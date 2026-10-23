package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	mysqlconfig "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const oauthConsumerRawUsage = `{ "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12, "prompt_tokens_details": { "cached_tokens": 4 } }`
const oauthConsumerResponse = `{"id":"chatcmpl-consumer","object":"chat.completion","created":1,"model":"observed-model","choices":[{"index":0,"message":{"role":"assistant","content":"private-body-canary"},"finish_reason":"stop"}],"usage":` + oauthConsumerRawUsage + `}`

type oauthConsumerBody struct {
	io.Reader
	closes   int
	closeErr error
}

func (b *oauthConsumerBody) Close() error {
	b.closes++
	return b.closeErr
}

type oauthConsumerWriter struct {
	recorder *httptest.ResponseRecorder
	events   []string
	writeErr error
	short    bool
}

func (w *oauthConsumerWriter) Header() http.Header {
	w.events = append(w.events, "headers")
	return w.recorder.Header()
}

func (w *oauthConsumerWriter) WriteHeader(status int) {
	w.events = append(w.events, "status")
	w.recorder.WriteHeader(status)
}

func (w *oauthConsumerWriter) Write(body []byte) (int, error) {
	w.events = append(w.events, "body")
	if w.writeErr != nil || w.short {
		n, _ := w.recorder.Write(body[:1])
		return n, w.writeErr
	}
	return w.recorder.Write(body)
}

func TestConsumeOAuthDerivedTextResponse(t *testing.T) {
	const ref = "server-receipt-ref"
	const failure = "OAuth derived text response could not be completed"
	privateErr := errors.New("private-finalizer-writer-canary")
	positive, zero, negative := 13, 0, -1
	settled := &model.OAuthDerivedTextCharge{Ref: ref, State: "settled", Actual: &positive}
	for _, tc := range []struct {
		name          string
		receipt       *model.OAuthDerivedTextCharge
		finalizeErr   error
		response      string
		closeErr      error
		cancelled     bool
		writeErr      error
		shortWrite    bool
		readerRejects bool
		publishes     bool
	}{
		{name: "settled_before_exact_output", receipt: settled, publishes: true},
		{name: "nil_receipt"},
		{name: "wrong_ref", receipt: &model.OAuthDerivedTextCharge{Ref: "other-ref", State: "settled", Actual: &positive}},
		{name: "held", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "held", Actual: &positive}},
		{name: "send_claimed", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "send_claimed", Actual: &positive}},
		{name: "unknown", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "unknown", Actual: &positive}},
		{name: "refunded_zero", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "refunded", Actual: &zero}},
		{name: "refunded_positive", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "refunded", Actual: &positive}},
		{name: "actual_missing", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "settled"}},
		{name: "actual_zero", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "settled", Actual: &zero}},
		{name: "actual_negative", receipt: &model.OAuthDerivedTextCharge{Ref: ref, State: "settled", Actual: &negative}},
		{name: "commit_error_despite_receipt", receipt: settled, finalizeErr: privateErr},
		{name: "cancelled_client_finalize_error", cancelled: true, finalizeErr: privateErr},
		{name: "cancelled_client_still_settles_without_output", cancelled: true, receipt: settled},
		{name: "partial_write_error_terminal", receipt: settled, publishes: true, writeErr: privateErr},
		{name: "short_write_terminal", receipt: settled, publishes: true, shortWrite: true},
		{name: "truncated_body", response: oauthConsumerResponse[:len(oauthConsumerResponse)-1], readerRejects: true},
		{name: "unsupported_shape", response: strings.Replace(oauthConsumerResponse, `"chat.completion"`, `"chat.completion.chunk"`, 1), readerRejects: true},
		{name: "missing_usage", response: strings.Replace(oauthConsumerResponse, `,"usage":`+oauthConsumerRawUsage, "", 1), readerRejects: true},
		{name: "body_close_error", closeErr: privateErr, readerRejects: true},
		{name: "raw_usage_rejected_by_finalizer", response: strings.Replace(oauthConsumerResponse, oauthConsumerRawUsage, `{}`, 1), finalizeErr: model.ErrOAuthTextCharge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.response
			if original == "" {
				original = oauthConsumerResponse
			}
			body := &oauthConsumerBody{Reader: strings.NewReader(original), closeErr: tc.closeErr}
			resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, ContentLength: -1}
			writer := &oauthConsumerWriter{recorder: httptest.NewRecorder(), writeErr: tc.writeErr, short: tc.shortWrite}
			type contextKey struct{}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "request-context-value"))
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			calls := 0
			var finalizedContext context.Context
			err := consumeOAuthDerivedTextResponseWithFinalizer(ctx, ref, resp, writer, func(settleCtx context.Context, gotRef string, rawUsage []byte) (*model.OAuthDerivedTextCharge, error) {
				calls++
				finalizedContext = settleCtx
				require.Empty(t, writer.events, "no success headers/status/body before finalization returns")
				assert.Empty(t, writer.recorder.Header())
				assert.Empty(t, writer.recorder.Body.String())
				assert.Equal(t, 1, body.closes)
				assert.Equal(t, ref, gotRef)
				wantUsage := oauthConsumerRawUsage
				if tc.name == "raw_usage_rejected_by_finalizer" {
					wantUsage = `{}`
				}
				assert.Equal(t, wantUsage, string(rawUsage))
				assert.NoError(t, settleCtx.Err(), "client cancellation must not cancel settlement")
				assert.Equal(t, "request-context-value", settleCtx.Value(contextKey{}))
				_, bounded := settleCtx.Deadline()
				assert.True(t, bounded)
				writer.events = append(writer.events, "finalize")
				return tc.receipt, tc.finalizeErr
			})
			assert.Equal(t, 1, body.closes)
			if tc.readerRejects {
				assert.Zero(t, calls)
				assert.Empty(t, writer.events)
			} else {
				assert.Equal(t, 1, calls)
				require.NotNil(t, finalizedContext)
				assert.ErrorIs(t, finalizedContext.Err(), context.Canceled, "settlement timer must be released on return")
			}
			if tc.publishes {
				assert.Equal(t, []string{"finalize", "headers", "status", "body"}, writer.events)
				assert.Equal(t, http.StatusOK, writer.recorder.Code)
				assert.Equal(t, "application/json", writer.recorder.Header().Get("Content-Type"))
				assert.Equal(t, strconv.Itoa(len(original)), writer.recorder.Header().Get("Content-Length"))
				if tc.writeErr == nil && !tc.shortWrite {
					require.NoError(t, err)
					assert.Equal(t, original, writer.recorder.Body.String())
					return
				}
				assert.Equal(t, original[:1], writer.recorder.Body.String())
			} else {
				assert.Empty(t, writer.recorder.Header())
				assert.Empty(t, writer.recorder.Body.String())
				if !tc.readerRejects {
					assert.Equal(t, []string{"finalize"}, writer.events)
				}
			}
			require.EqualError(t, err, failure)
			assert.NotContains(t, err.Error(), ref)
			assert.NotContains(t, err.Error(), original)
			assert.NotContains(t, err.Error(), privateErr.Error())
			assert.NotContains(t, err.Error(), "private-body-canary")
		})
	}
}

func TestConsumeOAuthDerivedTextResponseFinalizerDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		body := &oauthConsumerBody{Reader: strings.NewReader(oauthConsumerResponse)}
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, ContentLength: -1}
		writer := &oauthConsumerWriter{recorder: httptest.NewRecorder()}
		calls := 0
		err := consumeOAuthDerivedTextResponseWithFinalizer(context.Background(), "receipt", resp, writer, func(ctx context.Context, ref string, _ []byte) (*model.OAuthDerivedTextCharge, error) {
			calls++
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			assert.Equal(t, 5*time.Second, deadline.Sub(time.Now()))
			<-ctx.Done() // Virtual time: no wall-clock wait or real database.
			require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
			actual := 13
			return &model.OAuthDerivedTextCharge{Ref: ref, State: "settled", Actual: &actual}, nil
		})
		require.EqualError(t, err, "OAuth derived text response could not be completed")
		assert.Equal(t, 1, calls)
		assert.Equal(t, 1, body.closes)
		assert.Empty(t, writer.events, "late success cannot publish after the settlement deadline")
	})
}

// This opt-in fixture represents historical, already-sent debt. It deliberately
// creates no grant/session/source or admission path and never calls Reserve/Claim.
func newOAuthConsumerHistoryStore(t *testing.T, kind common.DatabaseType) (*gorm.DB, *gorm.DB) {
	t.Helper()
	var lease struct {
		RunID        string
		Database     string
		MySQLPort    int
		PostgresPort int
	}
	raw, err := os.ReadFile(os.Getenv("NEWAPI_W03_CONSUMER_LEASE"))
	require.NoError(t, err)
	require.NoError(t, common.Unmarshal(raw, &lease))
	runBytes, err := hex.DecodeString(lease.RunID)
	require.NoError(t, err)
	require.Len(t, runBytes, 12)
	require.Equal(t, os.Getenv("NEWAPI_W03_CONSUMER_RUN"), lease.RunID)
	require.Equal(t, "newapi_ci_w03_"+lease.RunID, lease.Database)
	password := os.Getenv("NEWAPI_W03_CONSUMER_PASSWORD")
	require.True(t, len(password) >= 32, "private database credential required")
	sqlitePath := filepath.Join(t.TempDir(), "history.sqlite")
	var pools []*gorm.DB
	for range 2 {
		var dialect gorm.Dialector
		switch kind {
		case common.DatabaseTypeSQLite:
			dialect = sqlite.Open(sqlitePath)
		case common.DatabaseTypeMySQL:
			require.Greater(t, lease.MySQLPort, 0)
			require.LessOrEqual(t, lease.MySQLPort, 65535)
			cfg := mysqlconfig.NewConfig()
			cfg.Net, cfg.Addr = "tcp", "127.0.0.1:"+strconv.Itoa(lease.MySQLPort)
			cfg.User, cfg.Passwd, cfg.DBName = "w03", password, lease.Database
			cfg.ParseTime = true
			cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 5*time.Second, 5*time.Second
			dialect = mysql.Open(cfg.FormatDSN())
		case common.DatabaseTypePostgreSQL:
			// No ambient PG service/host/database defaults, query overrides or fallback
			// hosts may redirect this fixture. The runner verifies the port's lease.
			for _, entry := range os.Environ() {
				key, value, _ := strings.Cut(entry, "=")
				require.False(t, strings.HasPrefix(key, "PG") && value != "", "PG environment overrides forbidden")
			}
			require.Greater(t, lease.PostgresPort, 0)
			require.LessOrEqual(t, lease.PostgresPort, 65535)
			cfg, parseErr := pgx.ParseConfig("postgres://w03@127.0.0.1:" + strconv.Itoa(lease.PostgresPort) + "/" + lease.Database + "?sslmode=disable")
			require.True(t, parseErr == nil, "fixed private PostgreSQL configuration must parse")
			require.Equal(t, "127.0.0.1", cfg.Host)
			require.Equal(t, lease.Database, cfg.Database)
			require.Equal(t, "w03", cfg.User)
			require.Equal(t, lease.PostgresPort, int(cfg.Port))
			require.Empty(t, cfg.Fallbacks)
			cfg.Password, cfg.ConnectTimeout = password, 5*time.Second
			sqlDB := stdlib.OpenDB(*cfg)
			t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
			dialect = postgres.New(postgres.Config{Conn: sqlDB})
		default:
			t.Fatal("unsupported history database")
		}
		db, openErr := gorm.Open(dialect, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		require.True(t, openErr == nil, "private history database connection failed")
		sqlDB, sqlErr := db.DB()
		require.NoError(t, sqlErr)
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
		pools = append(pools, db)
	}
	db, observer := pools[0], pools[1]
	primarySQL, err := db.DB()
	require.NoError(t, err)
	observerSQL, err := observer.DB()
	require.NoError(t, err)
	require.NotSame(t, primarySQL, observerSQL)
	tables, err := db.Migrator().GetTables()
	require.NoError(t, err)
	require.Empty(t, tables, "lease must target a fresh empty database")
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}, &model.OAuthDerivedTextCharge{}))
	var version string
	versionQuery := "SELECT version()"
	if kind == common.DatabaseTypeSQLite {
		versionQuery = "SELECT sqlite_version()"
	}
	require.NoError(t, db.Raw(versionQuery).Scan(&version).Error)
	t.Logf("history database=%s version=%s", kind, version)
	if kind != common.DatabaseTypeSQLite {
		query := "SELECT CONNECTION_ID()"
		if kind == common.DatabaseTypePostgreSQL {
			query = "SELECT pg_backend_pid()"
		}
		var primaryID, observerID int64
		require.NoError(t, db.Raw(query).Scan(&primaryID).Error)
		require.NoError(t, observer.Raw(query).Scan(&observerID).Error)
		require.NotEqual(t, primaryID, observerID, "observer must use a distinct server connection")
	}
	oldDB, oldKind, oldRedis := model.DB, common.MainDatabaseType(), common.RedisEnabled
	oldReady := model.OAuthCleanupReady()
	model.DB = db
	common.SetMainDatabaseType(kind)
	common.RedisEnabled = false
	t.Cleanup(func() {
		model.DB = oldDB
		common.SetMainDatabaseType(oldKind)
		common.RedisEnabled = oldRedis
		assert.Equal(t, oldReady, model.OAuthCleanupReady(), "history settlement must not mutate readiness")
	})
	return db, observer
}

type oauthConsumerCommittedWriter struct {
	*oauthConsumerWriter
	observeCommit func()
}

func (w *oauthConsumerCommittedWriter) Header() http.Header {
	w.observeCommit()
	return w.oauthConsumerWriter.Header()
}

func (w *oauthConsumerCommittedWriter) Write(body []byte) (int, error) {
	w.observeCommit()
	return w.oauthConsumerWriter.Write(body)
}

func TestConsumeOAuthDerivedTextResponsePersistentSettlement(t *testing.T) {
	if os.Getenv("NEWAPI_W03_CONSUMER_LEASE") == "" {
		t.Skip("requires an explicitly leased private three-database runtime")
	}
	for _, kind := range []common.DatabaseType{common.DatabaseTypeSQLite, common.DatabaseTypeMySQL, common.DatabaseTypePostgreSQL} {
		t.Run(string(kind), func(t *testing.T) {
			db, observer := newOAuthConsumerHistoryStore(t, kind)
			for i, name := range []string{"settled_before_output", "invalid_usage", "insufficient_delta_held", "missing_ref", "cancelled_client", "write_failure"} {
				t.Run(name, func(t *testing.T) {
					// Balances already include a historical reservation of 10. Neither this
					// fixture nor consumption calls an admission or pre-consumption API.
					userQuota := 90
					if name == "insufficient_delta_held" {
						userQuota = 1
					}
					user := model.User{Username: "history" + strconv.Itoa(i), AffCode: "history" + strconv.Itoa(i), Quota: userQuota}
					require.NoError(t, db.Create(&user).Error)
					token := model.Token{UserId: user.Id, Key: "synthetic-history-only-" + strconv.Itoa(i), RemainQuota: 90, UsedQuota: 10}
					require.NoError(t, db.Create(&token).Error)
					h := strings.Repeat("a", 64)
					facts := model.OAuthTextFacts{GrantRef: h, UserID: user.Id, TokenID: token.Id, Model: "historical-selected-text", ChannelID: 1, RouteHash: h, BodyHash: h, PolicyHash: h, ModelRatio: 2, CompletionRatio: 3, GroupRatio: .5, CacheRatio: .25, PromptEstimate: 10, MaxCompletion: 10}
					factsJSON, err := common.Marshal(facts)
					require.NoError(t, err)
					// Encode the persisted fixture's existing integrity contract, not a quota
					// formula. ReadOAuthDerivedTextCharge verifies it through production code.
					fingerprintJSON, err := common.Marshal(struct {
						Facts   model.OAuthTextFacts
						Reserve int
					}{facts, 10})
					require.NoError(t, err)
					fingerprint := sha256.Sum256(fingerprintJSON)
					refHash := sha256.Sum256([]byte(name))
					charge := model.OAuthDerivedTextCharge{Ref: hex.EncodeToString(refHash[:]), Fingerprint: hex.EncodeToString(fingerprint[:]), GrantRef: h, UserID: user.Id, PayerID: user.Id, TokenID: token.Id, TokenKeyRef: model.OAuthDerivedTokenKeyRef(token.Key), QuotaLimit: 100, Facts: string(factsJSON), Reserve: 10, State: "send_claimed", Version: 1, Attempt: 1}
					require.NoError(t, db.Create(&charge).Error)
					_, err = model.ReadOAuthDerivedTextCharge(context.Background(), charge.Ref)
					require.NoError(t, err, "fixture must satisfy the real persisted fact integrity check")
					var countBefore int64
					require.NoError(t, observer.Model(&model.OAuthDerivedTextCharge{}).Count(&countBefore).Error)
					original, callRef := oauthConsumerResponse, charge.Ref
					if name == "invalid_usage" {
						original = strings.Replace(original, oauthConsumerRawUsage, `{"prompt_tokens":10,"completion_tokens":2}`, 1)
					}
					if name == "missing_ref" {
						callRef = strings.Repeat("f", 64)
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if name == "cancelled_client" {
						cancel()
					}
					body := &oauthConsumerBody{Reader: strings.NewReader(original)}
					resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, ContentLength: -1}
					baseWriter := &oauthConsumerWriter{recorder: httptest.NewRecorder()}
					if name == "write_failure" {
						baseWriter.writeErr = errors.New("private-write-canary")
					}
					observations := 0
					writer := &oauthConsumerCommittedWriter{oauthConsumerWriter: baseWriter, observeCommit: func() {
						observations++
						readCtx, readCancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer readCancel()
						var committed model.OAuthDerivedTextCharge
						var committedUser model.User
						var committedToken model.Token
						require.NoError(t, observer.WithContext(readCtx).Where("ref = ?", charge.Ref).First(&committed).Error)
						require.NoError(t, observer.WithContext(readCtx).First(&committedUser, user.Id).Error)
						require.NoError(t, observer.WithContext(readCtx).First(&committedToken, token.Id).Error)
						require.Equal(t, "settled", committed.State, "independent connection must see committed settlement before any output")
						require.NotNil(t, committed.Actual)
						assert.Equal(t, 13, *committed.Actual)
						assert.Equal(t, charge.Ref, committed.Ref)
						assert.Equal(t, user.Id, committed.PayerID)
						assert.Equal(t, 87, committedUser.Quota)
						assert.Equal(t, 87, committedToken.RemainQuota)
						assert.Equal(t, 13, committedToken.UsedQuota)
					}}
					// Actual default entry: real reader -> real service Finalize -> SQL commit.
					err = consumeOAuthDerivedTextResponse(ctx, callRef, resp, writer)
					assert.Equal(t, 1, body.closes)
					if name == "settled_before_output" {
						require.NoError(t, err)
						assert.Equal(t, original, baseWriter.recorder.Body.String())
					} else {
						require.EqualError(t, err, "OAuth derived text response could not be completed")
						assert.NotContains(t, err.Error(), "private-")
					}
					publishes := name == "settled_before_output" || name == "write_failure"
					if publishes {
						assert.Equal(t, 2, observations)
						assert.Equal(t, []string{"headers", "status", "body"}, baseWriter.events)
						assert.Equal(t, http.StatusOK, baseWriter.recorder.Code)
						assert.Equal(t, "application/json", baseWriter.recorder.Header().Get("Content-Type"))
						assert.Equal(t, strconv.Itoa(len(original)), baseWriter.recorder.Header().Get("Content-Length"))
						if name == "write_failure" {
							assert.Equal(t, original[:1], baseWriter.recorder.Body.String())
						}
					} else {
						assert.Zero(t, observations)
						assert.Empty(t, baseWriter.events)
						assert.Empty(t, baseWriter.recorder.Header())
						assert.Empty(t, baseWriter.recorder.Body.String())
					}
					var stored model.OAuthDerivedTextCharge
					var afterUser model.User
					var afterToken model.Token
					require.NoError(t, observer.Where("ref = ?", charge.Ref).First(&stored).Error)
					require.NoError(t, observer.First(&afterUser, user.Id).Error)
					require.NoError(t, observer.First(&afterToken, token.Id).Error)
					assert.Equal(t, charge.Ref, stored.Ref)
					assert.Equal(t, user.Id, stored.UserID)
					assert.Equal(t, user.Id, stored.PayerID)
					assert.Equal(t, token.Id, stored.TokenID)
					assert.Equal(t, charge.Facts, stored.Facts)
					assert.Equal(t, charge.Fingerprint, stored.Fingerprint)
					assert.Equal(t, 10, stored.Reserve)
					assert.Equal(t, 1, stored.Attempt)
					switch name {
					case "invalid_usage", "missing_ref":
						assert.Equal(t, "send_claimed", stored.State)
						assert.Nil(t, stored.Actual)
						assert.Empty(t, stored.Usage)
						assert.Equal(t, int64(1), stored.Version)
						assert.Equal(t, userQuota, afterUser.Quota)
						assert.Equal(t, 90, afterToken.RemainQuota)
						assert.Equal(t, 10, afterToken.UsedQuota)
					default:
						require.NotNil(t, stored.Actual)
						assert.Equal(t, 13, *stored.Actual)
						assert.Equal(t, int64(2), stored.Version, "exactly one settlement mutation")
						var usage model.OAuthTextUsage
						require.NoError(t, common.UnmarshalJsonStr(stored.Usage, &usage))
						assert.Equal(t, model.OAuthTextUsage{Prompt: 10, Completion: 2, Total: 12, Cached: 4}, usage)
						if name == "insufficient_delta_held" {
							assert.Equal(t, "held", stored.State)
							assert.Equal(t, "insufficient_delta", stored.HeldReason)
							assert.Equal(t, 1, afterUser.Quota)
							assert.Equal(t, 90, afterToken.RemainQuota)
							assert.Equal(t, 10, afterToken.UsedQuota)
						} else {
							assert.Equal(t, "settled", stored.State)
							assert.Empty(t, stored.HeldReason)
							assert.Equal(t, 87, afterUser.Quota)
							assert.Equal(t, 87, afterToken.RemainQuota)
							assert.Equal(t, 13, afterToken.UsedQuota)
						}
					}
					var countAfter int64
					require.NoError(t, observer.Model(&model.OAuthDerivedTextCharge{}).Count(&countAfter).Error)
					assert.Equal(t, countBefore, countAfter, "consumer must not create replacement receipts")
					if name == "missing_ref" {
						var missing model.OAuthDerivedTextCharge
						assert.ErrorIs(t, observer.Where("ref = ?", callRef).First(&missing).Error, gorm.ErrRecordNotFound)
					}
					if name == "write_failure" {
						// Re-read without another consumer invocation: output failure must not
						// schedule a second settlement, refund or send.
						var again model.OAuthDerivedTextCharge
						var againUser model.User
						var againToken model.Token
						require.NoError(t, observer.Where("ref = ?", charge.Ref).First(&again).Error)
						require.NoError(t, observer.First(&againUser, user.Id).Error)
						require.NoError(t, observer.First(&againToken, token.Id).Error)
						assert.Equal(t, stored, again)
						assert.Equal(t, afterUser.Quota, againUser.Quota)
						assert.Equal(t, afterToken.RemainQuota, againToken.RemainQuota)
						assert.Equal(t, afterToken.UsedQuota, againToken.UsedQuota)
					}
				})
			}
		})
	}
}
