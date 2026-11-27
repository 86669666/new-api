package service

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthProviderRedirectFragments(t *testing.T) {
	for _, tc := range []struct {
		name, requested, registered string
		allowed                     bool
	}{
		{"loopback different port", "http://127.0.0.1:39874/oauth/callback", "http://127.0.0.1:29873/oauth/callback", true},
		{"loopback template any port", "http://127.0.0.1:39874/oauth/callback", "http://127.0.0.1/oauth/callback", true},
		{"loopback template ipv6", "http://[::1]:9/oauth/callback", "http://[::1]/oauth/callback", true},
		{"loopback template self", "http://127.0.0.1/oauth/callback", "http://127.0.0.1/oauth/callback", true},
		{"loopback different path", "http://127.0.0.1:39874/oauth/other", "http://127.0.0.1/oauth/callback", false},
		{"loopback root path", "http://127.0.0.1:39874/", "http://127.0.0.1:39874/", false},
		{"loopback missing request port", "http://127.0.0.1/oauth/callback", "http://127.0.0.1:29873/oauth/callback", false},
		{"non-loopback http", "http://192.0.2.1:39874/oauth/callback", "http://192.0.2.1:39874/oauth/callback", false},
		{"non-loopback against template", "http://10.0.0.1:9/oauth/callback", "http://127.0.0.1/oauth/callback", false},
		{"loopback empty fragment", "http://127.0.0.1:39874/oauth/callback#", "http://127.0.0.1:29873/oauth/callback", false},
		{"loopback nonempty fragment", "http://127.0.0.1:39874/oauth/callback#fragment", "http://127.0.0.1:29873/oauth/callback", false},
		{"registered loopback fragment", "http://127.0.0.1:39874/oauth/callback", "http://127.0.0.1:29873/oauth/callback#", false},
		{"https exact match", "https://client.example/callback", "https://client.example/callback", true},
		{"https empty fragment", "https://client.example/callback#", "https://client.example/callback#", false},
		{"https nonempty fragment", "https://client.example/callback#fragment", "https://client.example/callback#fragment", false},
		{"boxnai exact match", "boxnai://oauth/callback", "boxnai://oauth/callback", true},
		{"boxnai unregistered", "boxnai://oauth/callback", "cherrystudio://oauth/callback", false},
		{"boxnai path", "boxnai://oauth/other", "boxnai://oauth/other", false},
		{"boxnai host", "boxnai://other/callback", "boxnai://other/callback", false},
		{"boxnai query", "boxnai://oauth/callback?x=1", "boxnai://oauth/callback?x=1", false},
		{"boxnai empty query", "boxnai://oauth/callback?", "boxnai://oauth/callback?", false},
		{"boxnai port", "boxnai://oauth:123/callback", "boxnai://oauth:123/callback", false},
		{"boxnai fragment", "boxnai://oauth/callback#", "boxnai://oauth/callback#", false},
		{"boxnai credentials", "boxnai://user@oauth/callback", "boxnai://user@oauth/callback", false},
		{"boxnai encoded path", "boxnai://oauth/%63allback", "boxnai://oauth/%63allback", false},
		{"boxnai opaque", "boxnai:oauth/callback", "boxnai:oauth/callback", false},
		{"unknown custom scheme", "other://oauth/callback", "other://oauth/callback", false},
		{"legacy scheme exact match", "cherrystudio://oauth/callback", "cherrystudio://oauth/callback", true},
		{"legacy scheme empty fragment", "cherrystudio://oauth/callback#", "cherrystudio://oauth/callback#", false},
		{"encoded hash in path", "http://127.0.0.1:39874/oauth/callback%23", "http://127.0.0.1:29873/oauth/callback%23", true},
		{"encoded hash in query", "http://127.0.0.1:39874/oauth/callback?context=%23", "http://127.0.0.1:29873/oauth/callback?context=%23", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.allowed, validOAuthProviderRedirect(tc.requested, tc.registered))
		})
	}
}

func TestOAuthDerivedConsentDecideProtectedReservation(t *testing.T) {
	adminDSN := os.Getenv("NEWAPI_ISSUE_DECIDE_TEST_ADMIN")
	if adminDSN == "" {
		t.Skip("requires a disposable PostgreSQL target with the protected attestor installed")
	}
	gatewayDSN, writerDSN := os.Getenv("NEWAPI_ISSUE_DECIDE_TEST_GATEWAY"), os.Getenv("NEWAPI_ISSUE_DECIDE_TEST_ATTESTOR")
	open := func(dsn string) *gorm.DB {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		require.NoError(t, err)
		pool, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, pool.Close()) })
		return db
	}
	admin := open(adminDSN)
	var target string
	require.NoError(t, admin.Raw("SELECT current_database()").Row().Scan(&target))
	require.Regexp(t, "^h29_(issue|key)_[a-z0-9_]+$", target)
	issuerDSN := os.Getenv("NEWAPI_ISSUE_DECIDE_TEST_ISSUER")
	gatewayRole, writerRole := "source_ops_service", "source_ops_attestor"
	if issuerDSN != "" {
		gatewayRole, writerRole = "source_key_service", "source_key_attestor"
		t.Setenv("SQL_DSN", gatewayDSN)
	}
	oldDB, oldMaster := model.DB, common.IsMasterNode
	oldKind, oldRedis := common.MainDatabaseType(), common.RedisEnabled
	oldPassword, oldEncrypted := common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled
	t.Cleanup(func() {
		model.DB, common.IsMasterNode = oldDB, oldMaster
		common.SetMainDatabaseType(oldKind)
		common.RedisEnabled = oldRedis
		common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled = oldPassword, oldEncrypted
	})
	model.DB, common.IsMasterNode, common.RedisEnabled = admin, true, false
	common.SetMainDatabaseType(common.DatabaseTypePostgreSQL)
	common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled = true, false
	t.Setenv("OAUTH_PROTECTED_SOURCE_OPS", "true")
	t.Setenv("OAUTH_DERIVED_ATTESTOR_DSN", writerDSN)
	useTestSessionSecret(t)
	require.NoError(t, model.InitOAuthGrantStore(true))
	require.NoError(t, admin.AutoMigrate(&model.SessionRevocationEvent{}, &model.TwoFA{}, &model.PasskeyCredential{}))
	for _, value := range []any{&model.User{}, &model.UserSession{}, &model.AuthFlow{},
		&model.OAuthGrant{}, &model.OAuthOperation{}, &model.OAuthArtifact{}, &model.OAuthCleanupJob{},
		&model.SessionRevocationEvent{}, &model.TwoFA{}, &model.PasskeyCredential{}, &model.Token{}} {
		statement := &gorm.Statement{DB: admin}
		require.NoError(t, statement.Parse(value))
		require.NoError(t, admin.Exec("GRANT SELECT, INSERT, UPDATE, DELETE ON public."+statement.Table+" TO "+gatewayRole).Error)
	}
	require.NoError(t, admin.Exec("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "+gatewayRole).Error)
	model.DB, common.IsMasterNode = open(gatewayDSN), false
	require.NoError(t, model.InitOAuthGrantStore(true))
	attestor, err := model.OpenOAuthIssueAttestationWriter(t.Context(), gatewayDSN, writerDSN)
	require.NoError(t, err)
	var keyIssuer *model.OAuthFirstKeyIssuer
	if issuerDSN != "" {
		keyIssuer, err = model.OpenOAuthFirstKeyIssuer(t.Context(), gatewayDSN, issuerDSN)
		require.NoError(t, err)
	}
	password := "isolated-consent-fixture-password"
	hash, err := common.Password2Hash(password)
	require.NoError(t, err)
	const issuer, client, audience = "https://issuer.invalid/", "fixture-client", "fixture-audience"
	for index, scenario := range []string{"success", "provider-unavailable", "attestor-unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			owner := model.User{Id: 10_000 + index, Username: scenario, Password: hash, Role: common.RoleCommonUser,
				Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: scenario}
			require.NoError(t, admin.Create(&owner).Error)
			session := model.UserSession{SID: "consent-" + scenario, UserID: owner.Id, Status: model.UserSessionStatusActive,
				UserAuthVersion: 1, Version: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}
			require.NoError(t, admin.Create(&session).Error)
			actor := AuthIdentity{UserID: owner.Id, SessionID: session.SID, UserAuthVersion: 1, SessionVersion: 1}
			challenge := "test-challenge-" + scenario
			redirect := "http://127.0.0.1:23456/oauth/callback"
			query := url.Values{"client_id": {client}, "response_type": {"code"}, "redirect_uri": {redirect},
				"scope": {"profile tokens:write"}, "state": {"fixture-state"}, "code_challenge_method": {"S256"},
				"code_challenge": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}
			authorize := issuer + "oauth2/auth"
			var writes atomic.Int32
			var bearerGrant atomic.Pointer[model.OAuthGrant]
			var bearerRejected atomic.Bool
			const bearer = "local-fixture-access-token"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var response any
				if r.Method == http.MethodGet {
					response = map[string]any{"challenge": challenge, "subject": strconv.Itoa(owner.Id),
						"consent_request_id": scenario, "login_session_id": "session-" + scenario, "skip": false,
						"request_url": authorize + "?" + query.Encode(), "requested_scope": []string{"profile", "tokens:write"},
						"requested_access_token_audience": []string{audience}, "client": map[string]any{
							"client_id": client, "token_endpoint_auth_method": "none", "scope": "profile tokens:write",
							"audience": []string{audience}, "redirect_uris": []string{redirect},
							"grant_types": []string{"authorization_code"}, "response_types": []string{"code"},
						}}
				} else if r.Method == http.MethodPost && r.URL.Path == "/admin/oauth2/introspect" {
					grant := bearerGrant.Load()
					if r.ParseForm() != nil || r.PostForm.Get("token") != bearer || grant == nil || bearerRejected.Load() {
						response = map[string]bool{"active": false}
					} else {
						response = map[string]any{"active": true, "token_use": "access_token", "token_type": "Bearer",
							"iss": issuer, "aud": []string{audience}, "client_id": client, "sub": strconv.Itoa(owner.Id),
							"exp": grant.ExpiresAt - 60, "scope": "profile tokens:write", "ext": map[string]string{
								"newapi_auth_version": "1", "newapi_grant_id": grant.GrantID,
								"newapi_grant_expires_at": strconv.FormatInt(grant.ExpiresAt, 10),
							}}
					}
				} else if r.Method == http.MethodPut && r.URL.Path == "/admin/oauth2/auth/requests/consent/accept" {
					writes.Add(1)
					if scenario == "provider-unavailable" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					resume, err := url.ParseQuery(query.Encode())
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					resume.Set("consent_verifier", "fixture-verifier-"+scenario)
					response = OAuthProviderRedirect{RedirectTo: authorize + "?" + resume.Encode()}
				} else {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				data, err := common.Marshal(response)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				_, _ = w.Write(data)
			}))
			t.Cleanup(server.Close)
			res := &OAuthUserInfoResource{issuer: issuer, audience: audience, clients: []string{client}, client: server.Client()}
			bridge := &OAuthProviderBridge{resource: res, admin: server.URL, authorize: authorize,
				policy: "fixture", public: &OAuthPublic{}, attestor: attestor}
			ctx := t.Context()
			preview, err := bridge.Preview(ctx, actor, "consent", challenge)
			require.NoError(t, err)
			require.NotEmpty(t, preview.DerivedConsentRef)
			consent := OAuthDerivedConsentContext{Issuer: preview.DerivedIssuer, ConsentRef: preview.DerivedConsentRef,
				ClientID: client, Scopes: []string{"profile", "tokens:write"}, PolicyHash: preview.DerivedPolicyHash,
				QuotaLimit: 600, ExpiresAt: time.Now().Add(20 * time.Minute).Unix()}
			contextJSON, err := common.Marshal(consent)
			require.NoError(t, err)
			proof, err := VerifySecurityInput(actor, VerificationInput{Scope: VerificationScopeOAuthDerivedIssue,
				Method: VerificationMethodPassword, Password: password, Context: contextJSON})
			require.NoError(t, err)
			if scenario == "attestor-unavailable" {
				require.NoError(t, admin.Exec("REVOKE INSERT ON public.oauth_derived_issue_attestations FROM "+writerRole).Error)
				t.Cleanup(func() {
					require.NoError(t, admin.Exec("GRANT INSERT ON public.oauth_derived_issue_attestations TO "+writerRole).Error)
				})
			}
			result, err := bridge.Decide(ctx, actor, "consent", OAuthProviderDecision{
				Challenge: challenge, PreviewToken: preview.PreviewToken, Decision: "approve", SelectedScopes: consent.Scopes,
				Derived: &OAuthDerivedConsentInput{ProofToken: proof.ProofToken, QuotaLimit: consent.QuotaLimit, ExpiresAt: consent.ExpiresAt}})
			require.Equal(t, int32(1), writes.Load())
			var grant model.OAuthGrant
			require.NoError(t, admin.Where("consent_ref = ?", consent.ConsentRef).First(&grant).Error)
			var proofs, sources int64
			require.NoError(t, admin.Model(&model.OAuthIssueAttestation{}).Where("grant_ref = ?", grant.GrantRef).Count(&proofs).Error)
			require.NoError(t, admin.Model(&model.OAuthDerivedTokenSource{}).Where("grant_ref = ?", grant.GrantRef).Count(&sources).Error)
			if scenario == "success" {
				require.NoError(t, err)
				require.NotEmpty(t, result.RedirectTo)
				require.Equal(t, "approved", grant.State)
				require.Equal(t, int64(1), proofs)
				require.Equal(t, int64(1), sources)
				if keyIssuer != nil {
					res.endpoint, res.grantsRequired = server.URL+"/admin/oauth2/introspect", true
					res.firstKeyIssuer = keyIssuer
					_, err := model.AuthorizeOAuthGrant(ctx, model.OAuthGrantAuthorization{Issuer: grant.Issuer, GrantID: grant.GrantID, ClientID: grant.ClientID,
						Subject: grant.Subject, UserID: owner.Id, AuthVersion: 1, GrantExpiresAt: grant.ExpiresAt, TokenExpiresAt: grant.ExpiresAt - 60,
						Scopes: consent.Scopes, Activate: true})
					require.NoError(t, err)
					bearerGrant.Store(&grant)
					access, err := res.Authorize(ctx, bearer)
					require.NoError(t, err)
					bearerRejected.Store(true)
					_, err = access.CreateAPIToken(ctx, "fixture-key", []string{"key-attempt"})
					require.ErrorIs(t, err, ErrOAuthInvalidToken)
					bearerRejected.Store(false)
					_, err = access.CreateAPIToken(ctx, "fixture-key", nil)
					require.ErrorIs(t, err, ErrOAuthIssueIdempotency)
					issued, err := access.CreateAPIToken(ctx, "fixture-key", []string{"key-attempt"})
					require.NoError(t, err)
					require.True(t, issued.Derived)
					require.NotEmpty(t, issued.Key)
					require.EqualValues(t, consent.QuotaLimit, issued.QuotaLimit)
					receipt, err := access.CreateAPIToken(ctx, "fixture-key", []string{"key-attempt"})
					require.NoError(t, err)
					require.Equal(t, issued.ID, receipt.ID)
					require.Empty(t, receipt.Key)
					kind, err := model.ClassifyOAuthDerivedToken(ctx, issued.ID)
					require.NoError(t, err)
					require.Equal(t, model.OAuthDerivedTokenBound, kind)
					require.NoError(t, model.RevokeOAuth(ctx, owner.Id, "grant", grant.GrantRef))
					var disabled model.Token
					require.NoError(t, model.DB.Select("id", "status").First(&disabled, issued.ID).Error)
					require.Equal(t, common.TokenStatusDisabled, disabled.Status)
					_, err = access.CreateAPIToken(ctx, "fixture-key", []string{"key-attempt"})
					require.ErrorIs(t, err, ErrOAuthInvalidToken)
				}
			} else {
				require.Error(t, err)
				require.Nil(t, result)
				if keyIssuer != nil {
					require.Equal(t, "revoked", grant.State)
				} else {
					require.Equal(t, "prepared", grant.State)
				}
				require.Zero(t, proofs)
				require.Zero(t, sources)
			}
		})
	}
}
