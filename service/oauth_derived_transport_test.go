package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	mysqlconfig "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type oauthTextWireFixture struct {
	server   *httptest.Server
	requests atomic.Int32
	connects atomic.Int32
}

func newOAuthTextWireFixture(t *testing.T, handler http.HandlerFunc) *oauthTextWireFixture {
	t.Helper()
	f := &oauthTextWireFixture{}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		handler(w, r)
	}))
	f.server.EnableHTTP2 = true
	f.server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			f.connects.Add(1)
		}
	}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}

func oauthTextWireInput(t *testing.T, endpoint string) (string, model.OAuthTextFacts, OAuthDerivedTextSelectedRequest) {
	t.Helper()
	selected := OAuthDerivedTextSelectedRequest{URL: endpoint + "/v1/chat/completions", Body: []byte(`{"model":"unit-text","messages":[{"role":"user","content":"hello"}],"max_tokens":10}`), APIKey: "synthetic-fixture-key"}
	facts := model.OAuthTextFacts{ChannelID: 1, Model: "unit-text", PolicyHash: strings.Repeat("a", 64)}
	route, err := common.Marshal([]any{"POST", selected.URL, facts.ChannelID, facts.Model})
	require.NoError(t, err)
	rh, bh := sha256.Sum256(route), sha256.Sum256(selected.Body)
	facts.RouteHash, facts.BodyHash = hex.EncodeToString(rh[:]), hex.EncodeToString(bh[:])
	return strings.Repeat("b", 64), facts, selected
}

func newOAuthTextWireOperation(t *testing.T, f *oauthTextWireFixture) *oauthTextSendOperation {
	t.Helper()
	ref, facts, selected := oauthTextWireInput(t, f.server.URL)
	op, err := newOAuthTextSendOperation(ref, facts, 10, selected)
	require.NoError(t, err)
	op.roots = x509.NewCertPool()
	op.roots.AddCert(f.server.Certificate())
	op.claim = func(context.Context, string, model.OAuthTextFacts, int) (*model.OAuthTextSendPermit, error) {
		return &model.OAuthTextSendPermit{Ref: ref, Deadline: time.Now().Unix() + 60}, nil
	}
	return op
}

func TestOAuthDerivedTransportSuccessAndOneUse(t *testing.T) {
	type observed struct {
		method, path, body, auth, contentType, accept, proto, alpn string
		close                                                      bool
	}
	wire := make(chan observed, 1)
	f := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wire <- observed{r.Method, r.URL.RequestURI(), string(b), r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("Accept"), r.Proto, r.TLS.NegotiatedProtocol, r.Close}
		_, _ = io.WriteString(w, `{"usage":{}}`)
	})
	op := newOAuthTextWireOperation(t, f)
	var claims atomic.Int32
	claim := op.claim
	op.claim = func(ctx context.Context, ref string, facts model.OAuthTextFacts, reserve int) (*model.OAuthTextSendPermit, error) {
		claims.Add(1)
		return claim(ctx, ref, facts, reserve)
	}
	type result struct {
		resp *http.Response
		err  error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { <-start; resp, err := op.do(context.Background()); results <- result{resp, err} })
	}
	close(start)
	wg.Wait()
	close(results)
	var success, rejected int
	for result := range results {
		if result.err != nil {
			assert.ErrorIs(t, result.err, errOAuthTextTransport)
			rejected++
			continue
		}
		success++
		require.NotNil(t, result.resp)
		assert.Nil(t, result.resp.Request.GetBody, "request must not be replayable")
		body, err := io.ReadAll(result.resp.Body)
		require.NoError(t, err)
		assert.Equal(t, `{"usage":{}}`, string(body))
		require.NoError(t, result.resp.Body.Close())
	}
	assert.Equal(t, 1, success)
	assert.Equal(t, 1, rejected)
	resp, err := op.do(context.Background())
	assert.ErrorIs(t, err, errOAuthTextTransport)
	assert.Nil(t, resp)
	assert.EqualValues(t, 1, claims.Load())
	assert.EqualValues(t, 1, f.requests.Load())
	assert.EqualValues(t, 1, f.connects.Load())
	got := <-wire
	assert.Equal(t, "POST", got.method)
	assert.Equal(t, "/v1/chat/completions", got.path)
	assert.Equal(t, string(op.body), got.body)
	assert.Equal(t, "Bearer synthetic-fixture-key", got.auth)
	assert.Equal(t, "application/json", got.contentType)
	assert.Equal(t, "application/json", got.accept)
	assert.Equal(t, "HTTP/1.1", got.proto)
	assert.Equal(t, "http/1.1", got.alpn)
	assert.True(t, got.close)
}

func TestOAuthDerivedTransportFreezeAndProxy(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyRequests.Add(1); w.WriteHeader(502) }))
	defer proxy.Close()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	bodies := make(chan string, 2)
	f := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		assert.Equal(t, "Bearer synthetic-fixture-key", r.Header.Get("Authorization"))
		bodies <- string(b)
		w.WriteHeader(200)
	})
	_, port, err := net.SplitHostPort(f.server.Listener.Addr().String())
	require.NoError(t, err)
	ref, facts, selected := oauthTextWireInput(t, "https://example.com:"+port)
	original := string(selected.Body)
	op, err := newOAuthTextSendOperation(ref, facts, 10, selected)
	require.NoError(t, err)
	op.roots = x509.NewCertPool()
	op.roots.AddCert(f.server.Certificate())
	op.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		assert.Equal(t, "example.com:"+port, addr)
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}
	op.claim = func(_ context.Context, gotRef string, gotFacts model.OAuthTextFacts, reserve int) (*model.OAuthTextSendPermit, error) {
		// Mutation occurs after construction, before the wire send.
		copy(selected.Body, strings.Repeat("x", len(selected.Body)))
		selected.URL, selected.APIKey, facts.Model = "https://invalid.invalid/", "changed", "changed"
		assert.Equal(t, "unit-text", gotFacts.Model)
		assert.Equal(t, 10, reserve)
		return &model.OAuthTextSendPermit{Ref: gotRef, Deadline: time.Now().Unix() + 60}, nil
	}
	resp, err := op.do(context.Background())
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, original, <-bodies)
	// Another operation has a new transport and connection, not a shared pool.
	second := newOAuthTextWireOperation(t, f)
	resp, err = second.do(context.Background())
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, original, <-bodies)
	assert.Zero(t, proxyRequests.Load())
	assert.EqualValues(t, 2, f.connects.Load())
	assert.EqualValues(t, 2, f.requests.Load())
}

func TestOAuthDerivedTransportClosedAndInvalid(t *testing.T) {
	f := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	ref, facts, selected := oauthTextWireInput(t, f.server.URL)
	resp, err := DoOAuthDerivedTextOnce(context.Background(), ref, facts, 10, selected)
	assert.ErrorIs(t, err, ErrOAuthDerivedTextClosed)
	assert.Nil(t, resp)
	for _, suffix := range []string{"?", "?x=1", "#", "#fragment", "/", "%2f", "/../chat/completions"} {
		t.Run(suffix, func(t *testing.T) {
			bad := selected
			bad.URL += suffix
			_, err := newOAuthTextSendOperation(ref, facts, 10, bad)
			assert.ErrorIs(t, err, errOAuthTextTransport)
		})
	}
	for _, endpoint := range []string{"http://127.0.0.1/v1/chat/completions", "https://user@localhost/v1/chat/completions", "https://LOCALHOST/v1/chat/completions", "https://localhost:443/v1/chat/completions", "https://localhost:/v1/chat/completions", "https://localhost/v1/%63hat/completions"} {
		bad := selected
		bad.URL = endpoint
		_, err := newOAuthTextSendOperation(ref, facts, 10, bad)
		assert.ErrorIs(t, err, errOAuthTextTransport)
	}
	for _, change := range []func(*model.OAuthTextFacts, *OAuthDerivedTextSelectedRequest){
		func(f *model.OAuthTextFacts, _ *OAuthDerivedTextSelectedRequest) {
			f.BodyHash = strings.Repeat("0", 64)
		},
		func(f *model.OAuthTextFacts, _ *OAuthDerivedTextSelectedRequest) {
			f.RouteHash = strings.Repeat("0", 64)
		},
		func(_ *model.OAuthTextFacts, s *OAuthDerivedTextSelectedRequest) { s.APIKey = "bad\r\nheader" },
	} {
		f, s := facts, selected
		change(&f, &s)
		_, err := newOAuthTextSendOperation(ref, f, 10, s)
		assert.ErrorIs(t, err, errOAuthTextTransport)
	}
	for _, tc := range []struct {
		name   string
		permit *model.OAuthTextSendPermit
		err    error
	}{
		{"nil", nil, nil}, {"claim_error", nil, ErrOAuthDerivedTextClosed},
		{"wrong_ref", &model.OAuthTextSendPermit{Ref: "other", Deadline: time.Now().Unix() + 60}, nil},
		{"expired", &model.OAuthTextSendPermit{Ref: ref, Deadline: time.Now().Unix() - 1}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := newOAuthTextWireOperation(t, f)
			op.claim = func(context.Context, string, model.OAuthTextFacts, int) (*model.OAuthTextSendPermit, error) {
				return tc.permit, tc.err
			}
			resp, err := op.do(context.Background())
			require.Error(t, err)
			assert.Nil(t, resp)
		})
	}
	assert.Zero(t, f.requests.Load())
	assert.Zero(t, f.connects.Load())
}

func TestOAuthDerivedTransportRedirectAndDisconnect(t *testing.T) {
	target := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	for _, status := range []int{301, 302, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.server.URL+"/v1/chat/completions")
				w.WriteHeader(status)
			})
			op := newOAuthTextWireOperation(t, f)
			resp, err := op.do(context.Background())
			require.NoError(t, err)
			assert.Equal(t, status, resp.StatusCode)
			require.NoError(t, resp.Body.Close())
			assert.EqualValues(t, 1, f.requests.Load())
			assert.EqualValues(t, 1, f.connects.Load())
		})
	}
	assert.Zero(t, target.requests.Load())
	assert.Zero(t, target.connects.Load())
	f := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})
	op := newOAuthTextWireOperation(t, f)
	resp, err := op.do(context.Background())
	require.Error(t, err)
	assert.Nil(t, resp)
	resp, err = op.do(context.Background())
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.EqualValues(t, 1, f.requests.Load())
	assert.EqualValues(t, 1, f.connects.Load())
}

func TestOAuthDerivedTransportTLSAndDeadlines(t *testing.T) {
	t.Run("untrusted_certificate", func(t *testing.T) {
		f := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
		op := newOAuthTextWireOperation(t, f)
		op.roots = nil
		resp, err := op.do(context.Background())
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Zero(t, f.requests.Load())
	})
	t.Run("deadline_after_handshake_before_first_byte", func(t *testing.T) {
		// Raw TLS observer proves a completed handshake but zero application bytes.
		certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		certServer.Close()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()
		var clock atomic.Int64
		clock.Store(100)
		type observation struct {
			handshake error
			n         int
			readErr   error
		}
		observed := make(chan observation, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				observed <- observation{handshake: err}
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			cfg := certServer.TLS.Clone()
			cfg.NextProtos = []string{"http/1.1"}
			cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { clock.Store(200); return nil, nil }
			secure := tls.Server(conn, cfg)
			err = secure.Handshake()
			if err != nil {
				observed <- observation{handshake: err}
				return
			}
			buf := make([]byte, 1)
			n, readErr := secure.Read(buf)
			observed <- observation{n: n, readErr: readErr}
		}()
		ref, facts, selected := oauthTextWireInput(t, "https://"+ln.Addr().String())
		op, err := newOAuthTextSendOperation(ref, facts, 10, selected)
		require.NoError(t, err)
		op.roots = x509.NewCertPool()
		op.roots.AddCert(certServer.Certificate())
		op.now = func() time.Time { return time.Unix(clock.Load(), 0) }
		op.claim = func(context.Context, string, model.OAuthTextFacts, int) (*model.OAuthTextSendPermit, error) {
			return &model.OAuthTextSendPermit{Ref: ref, Deadline: 150}, nil
		}
		resp, err := op.do(context.Background())
		require.Error(t, err)
		assert.Nil(t, resp)
		got := <-observed
		require.NoError(t, got.handshake)
		assert.Zero(t, got.n)
		require.Error(t, got.readErr)
	})
	t.Run("blocked_handshake_timeout", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()
		accepted := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			close(accepted)
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.Copy(io.Discard, conn)
		}()
		ref, facts, selected := oauthTextWireInput(t, "https://"+ln.Addr().String())
		op, err := newOAuthTextSendOperation(ref, facts, 10, selected)
		require.NoError(t, err)
		op.timeout = 100 * time.Millisecond
		op.claim = func(context.Context, string, model.OAuthTextFacts, int) (*model.OAuthTextSendPermit, error) {
			return &model.OAuthTextSendPermit{Ref: ref, Deadline: time.Now().Unix() + 60}, nil
		}
		resp, err := op.do(context.Background())
		require.Error(t, err)
		assert.Nil(t, resp)
		<-accepted
		<-done
	})
	t.Run("response_read_timeout", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		f := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-release
		})
		op := newOAuthTextWireOperation(t, f)
		op.timeout = 200 * time.Millisecond
		resp, err := op.do(context.Background())
		require.NoError(t, err)
		_, err = io.ReadAll(resp.Body)
		require.Error(t, err)
		_ = resp.Body.Close()
		assert.EqualValues(t, 1, f.requests.Load())
		assert.EqualValues(t, 1, f.connects.Load())
	})
}

// These tests cross the real SQL Claim CAS and local TLS wire boundary. Only
// the private operation receives model.Claim; public service admission stays closed.
func TestOAuthDerivedTransportDatabaseCASWire(t *testing.T) {
	for _, kind := range []common.DatabaseType{common.DatabaseTypeSQLite, common.DatabaseTypeMySQL, common.DatabaseTypePostgreSQL} {
		t.Run(string(kind), func(t *testing.T) {
			for _, scenario := range []string{"competing_claims_settle", "revoked_before_claim", "expired_before_claim", "disconnect_retains_reserve", "revoked_after_send_settle", "revoked_after_send_debt"} {
				t.Run(scenario, func(t *testing.T) {
					db, facts := newOAuthDerivedTextBillingFixture(t, kind, oauthTextCASWireDialect(t, kind))
					sqlDB, err := db.DB()
					require.NoError(t, err)
					// Separate operations may enter SQL concurrently, not just queue
					// behind the fixture's original one-connection pool.
					sqlDB.SetMaxOpenConns(2)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					raw := `{"prompt_tokens":20,"completion_tokens":40,"total_tokens":60}`
					if scenario == "revoked_after_send_debt" {
						raw = `{"prompt_tokens":20,"completion_tokens":100,"total_tokens":120}`
					}
					type received struct {
						body  string
						err   error
						proto string
					}
					wire := make(chan received, 1)
					server := newOAuthTextWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
						body, err := io.ReadAll(r.Body)
						wire <- received{string(body), err, r.Proto}
						if scenario == "disconnect_retains_reserve" {
							conn, _, err := w.(http.Hijacker).Hijack()
							if assert.NoError(t, err) {
								assert.NoError(t, conn.Close())
							}
							return
						}
						_, _ = io.WriteString(w, `{"usage":`+raw+`}`)
					})
					ref, route, selected := oauthTextWireInput(t, server.server.URL)
					selected.Body = []byte(strings.Replace(string(selected.Body), `"max_tokens":10`, `"max_tokens":60`, 1))
					bodyHash := sha256.Sum256(selected.Body)
					facts.RouteHash, facts.BodyHash = route.RouteHash, hex.EncodeToString(bodyHash[:])
					reserved, err := model.ReserveOAuthDerivedText(ctx, ref, facts, 80)
					require.NoError(t, err)
					require.Equal(t, "reserved", reserved.State)
					require.Nil(t, reserved.Actual)
					assertOAuthTextCASBalances(t, db, facts, 20, 20, 80)
					// Even a real reserved receipt never opens the public API.
					resp, err := DoOAuthDerivedTextOnce(ctx, ref, facts, 80, selected)
					require.ErrorIs(t, err, ErrOAuthDerivedTextClosed)
					require.Nil(t, resp)
					assert.Zero(t, server.requests.Load())
					assert.Zero(t, server.connects.Load())
					stored, err := model.ReadOAuthDerivedTextCharge(ctx, ref)
					require.NoError(t, err)
					assert.Equal(t, reserved, stored)

					var winners atomic.Int32
					newOperation := func() *oauthTextSendOperation {
						op, err := newOAuthTextSendOperation(ref, facts, 80, selected)
						require.NoError(t, err)
						op.roots = x509.NewCertPool()
						op.roots.AddCert(server.server.Certificate())
						op.claim = func(ctx context.Context, ref string, f model.OAuthTextFacts, reserve int) (*model.OAuthTextSendPermit, error) {
							permit, err := model.ClaimOAuthDerivedText(ctx, ref, f, reserve)
							if permit != nil {
								winners.Add(1)
							}
							return permit, err
						}
						return op
					}
					op := newOperation()
					if scenario == "revoked_before_claim" || scenario == "expired_before_claim" {
						var source model.OAuthDerivedTokenSource
						require.NoError(t, db.Where("grant_ref = ?", facts.GrantRef).First(&source).Error)
						if scenario == "revoked_before_claim" {
							now, reason := time.Now().Unix(), "revoked"
							source.TerminalAt, source.TerminalReason = &now, &reason
						} else {
							source.ExpiresAt = time.Now().Unix() - 1
						}
						require.NoError(t, db.Save(&source).Error)
						permit, err := model.ClaimOAuthDerivedText(ctx, ref, facts, 80)
						require.Error(t, err)
						require.Nil(t, permit)
						resp, err = op.do(ctx)
						require.Error(t, err)
						assert.Nil(t, resp)
						assert.Zero(t, winners.Load())
						assert.Zero(t, server.requests.Load())
						assert.Zero(t, server.connects.Load())
						stored, err = model.ReadOAuthDerivedTextCharge(ctx, ref)
						require.NoError(t, err)
						assert.Equal(t, reserved, stored)
						assertOAuthTextCASBalances(t, db, facts, 20, 20, 80)
						return
					}
					if scenario == "competing_claims_settle" {
						type result struct {
							response *http.Response
							err      error
						}
						results := make(chan result, 2)
						ready, start := make(chan struct{}, 2), make(chan struct{})
						var wg sync.WaitGroup
						for _, contender := range []*oauthTextSendOperation{op, newOperation()} {
							claim := contender.claim
							contender.claim = func(ctx context.Context, ref string, f model.OAuthTextFacts, reserve int) (*model.OAuthTextSendPermit, error) {
								ready <- struct{}{}
								<-start
								return claim(ctx, ref, f, reserve)
							}
							wg.Go(func() { r, e := contender.do(ctx); results <- result{r, e} })
						}
						<-ready
						<-ready
						close(start)
						wg.Wait()
						close(results)
						var succeeded, denied int
						for result := range results {
							if result.err != nil {
								assert.ErrorIs(t, result.err, errOAuthTextTransport)
								assert.Nil(t, result.response)
								denied++
							} else {
								succeeded++
								resp = result.response
							}
						}
						require.Equal(t, 1, succeeded)
						require.Equal(t, 1, denied)
					} else {
						resp, err = op.do(ctx)
						if scenario == "disconnect_retains_reserve" {
							require.Error(t, err)
							require.Nil(t, resp)
						} else {
							require.NoError(t, err)
						}
					}
					var responseUsage []byte
					if resp != nil {
						require.Equal(t, http.StatusOK, resp.StatusCode)
						body, err := io.ReadAll(resp.Body)
						require.NoError(t, err)
						require.NoError(t, resp.Body.Close())
						fields, err := common.DecodeRawJSONObject(body)
						require.NoError(t, err)
						responseUsage = fields["usage"]
						require.JSONEq(t, raw, string(responseUsage))
					}
					got := <-wire
					require.NoError(t, got.err)
					assert.Equal(t, string(selected.Body), got.body)
					assert.Equal(t, "HTTP/1.1", got.proto)
					assert.EqualValues(t, 1, winners.Load())
					assert.EqualValues(t, 1, server.requests.Load())
					claimed, err := model.ReadOAuthDerivedTextCharge(ctx, ref)
					require.NoError(t, err)
					assert.Equal(t, "send_claimed", claimed.State)
					assert.EqualValues(t, 2, claimed.Version)
					assert.Nil(t, claimed.Actual)
					assert.Equal(t, reserved.Facts, claimed.Facts)
					assert.Equal(t, reserved.Fingerprint, claimed.Fingerprint)
					assertOAuthTextCASBalances(t, db, facts, 20, 20, 80)
					for _, repeat := range []*oauthTextSendOperation{op, newOperation()} {
						r, err := repeat.do(ctx)
						require.ErrorIs(t, err, errOAuthTextTransport)
						assert.Nil(t, r)
					}
					assert.EqualValues(t, 1, winners.Load())
					assert.EqualValues(t, 1, server.requests.Load())
					assert.EqualValues(t, 1, server.connects.Load())
					stored, err = model.ReadOAuthDerivedTextCharge(ctx, ref)
					require.NoError(t, err)
					assert.Equal(t, claimed, stored, "lost response/replay never retries or refunds")
					assertOAuthTextCASBalances(t, db, facts, 20, 20, 80)
					if scenario == "disconnect_retains_reserve" {
						return
					}

					if strings.HasPrefix(scenario, "revoked_after_send") {
						now := time.Now().Unix()
						var source model.OAuthDerivedTokenSource
						require.NoError(t, db.Where("grant_ref = ?", facts.GrantRef).First(&source).Error)
						reason := "revoked"
						source.TerminalAt, source.TerminalReason = &now, &reason
						require.NoError(t, db.Save(&source).Error)
						require.NoError(t, db.Model(&model.OAuthGrant{}).Where("grant_ref = ?", facts.GrantRef).Updates(map[string]any{"state": "revoked", "revoked_at": now}).Error)
						permit, err := model.ClaimOAuthDerivedText(ctx, ref, facts, 80)
						require.Error(t, err)
						require.Nil(t, permit)
					}
					settled, err := FinalizeOAuthDerivedText(ctx, ref, responseUsage)
					require.NoError(t, err)
					assert.Equal(t, reserved.PayerID, settled.PayerID)
					assert.Equal(t, facts.UserID, settled.PayerID)
					assert.Equal(t, reserved.Facts, settled.Facts)
					assert.Equal(t, reserved.Fingerprint, settled.Fingerprint)
					assert.Equal(t, reserved.SourceSnapshotHash, settled.SourceSnapshotHash)
					assert.EqualValues(t, 3, settled.Version)
					require.NotNil(t, settled.Actual)
					if scenario == "revoked_after_send_debt" {
						assert.Equal(t, "held", settled.State)
						assert.Equal(t, "insufficient_delta", settled.HeldReason)
						assert.Equal(t, 120, *settled.Actual)
						assertOAuthTextCASBalances(t, db, facts, 20, 20, 80)
					} else {
						assert.Equal(t, "settled", settled.State)
						assert.Equal(t, 60, *settled.Actual)
						assertOAuthTextCASBalances(t, db, facts, 40, 40, 60)
					}
					actual, usage, err := CalculateOAuthDerivedTextQuota(facts, responseUsage)
					require.NoError(t, err)
					replay, err := model.FinalizeOAuthDerivedTextSnapshot(ctx, ref, actual, usage, reserved.Fingerprint)
					require.NoError(t, err)
					assert.Equal(t, settled, replay)
					replay, err = FinalizeOAuthDerivedText(ctx, ref, responseUsage)
					require.NoError(t, err)
					assert.Equal(t, settled, replay)
					stored, err = model.ReadOAuthDerivedTextCharge(ctx, ref)
					require.NoError(t, err)
					assert.Equal(t, settled, stored)
					if scenario == "revoked_after_send_debt" {
						assertOAuthTextCASBalances(t, db, facts, 20, 20, 80)
					} else {
						assertOAuthTextCASBalances(t, db, facts, 40, 40, 60)
					}
					assert.EqualValues(t, 1, server.requests.Load())
				})
			}
		})
	}
}

func assertOAuthTextCASBalances(t *testing.T, db *gorm.DB, facts model.OAuthTextFacts, wallet, remaining, used int) {
	t.Helper()
	var user model.User
	var token model.Token
	require.NoError(t, db.First(&user, facts.UserID).Error)
	require.NoError(t, db.First(&token, facts.TokenID).Error)
	assert.Equal(t, wallet, user.Quota)
	assert.Equal(t, remaining, token.RemainQuota)
	assert.Equal(t, used, token.UsedQuota)
}

func oauthTextCASWireDialect(t *testing.T, kind common.DatabaseType) gorm.Dialector {
	t.Helper()
	if os.Getenv("NEWAPI_BOOTSTRAP_CLIENT") != "" {
		require.Equal(t, string(kind), os.Getenv("NEWAPI_BOOTSTRAP_ENGINE"))
		return nil // The billing fixture asks the trusted installer for this namespace.
	}
	switch kind {
	case common.DatabaseTypeSQLite:
		return sqlite.Open(filepath.Join(t.TempDir(), "cas-wire.sqlite") + "?_pragma=busy_timeout(5000)")
	case common.DatabaseTypeMySQL:
		dsn := os.Getenv("TEST_MYSQL_DSN")
		if dsn == "" {
			require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"), "TEST_MYSQL_DSN is required")
			t.Skip("TEST_MYSQL_DSN is not configured")
		}
		require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
		cfg, err := mysqlconfig.ParseDSN(dsn)
		require.NoError(t, err)
		host, _, err := net.SplitHostPort(cfg.Addr)
		require.NoError(t, err)
		require.Equal(t, "tcp", cfg.Net)
		require.Equal(t, "127.0.0.1", host)
		require.True(t, strings.HasPrefix(cfg.DBName, "newapi_ci_"))
		return mysql.Open(dsn)
	case common.DatabaseTypePostgreSQL:
		dsn := os.Getenv("TEST_POSTGRES_DSN")
		if dsn == "" {
			require.NotEqual(t, "1", os.Getenv("NEWAPI_REQUIRE_DATABASES"), "TEST_POSTGRES_DSN is required")
			t.Skip("TEST_POSTGRES_DSN is not configured")
		}
		require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
		cfg, err := isolatedOAuthTextPostgresConfig(dsn)
		require.NoError(t, err)
		sqlDB := stdlib.OpenDB(*cfg)
		t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
		return postgres.New(postgres.Config{Conn: sqlDB})
	default:
		t.Fatalf("unsupported test database: %s", kind)
		return nil
	}
}
