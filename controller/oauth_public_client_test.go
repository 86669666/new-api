/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
package controller

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthPublicClientManagementAndAuthorizedApps(t *testing.T) {
	user, identity := setupSecurityEnrollmentTest(t)
	require.NoError(t, model.DB.AutoMigrate(&model.OAuthPublicClient{}, &model.OAuthGrant{}, &model.CustomOAuthProvider{}))
	require.NoError(t, model.DB.AutoMigrate(&model.OAuthPublicClient{}))
	require.NoError(t, model.DB.Model(user).Update("role", common.RoleRootUser).Error)
	user.Role = common.RoleRootUser
	previousPassword := common.PasswordLoginEnabled
	common.PasswordLoginEnabled = true
	t.Cleanup(func() { common.PasswordLoginEnabled = previousPassword })

	t.Run("presets document loopback clients without choosing a client id", func(t *testing.T) {
		response := oauthPublicClientRequest(t, http.MethodGet, "/api/oauth/public-clients/presets", "", "", identity, common.RoleRootUser, nil, GetOAuthPublicClientPresets)
		assert.Equal(t, http.StatusOK, response.Code)
		assert.Contains(t, response.Body.String(), "http://127.0.0.1/oauth/callback")
		assert.Contains(t, response.Body.String(), "http://127.0.0.1:29873/oauth/callback")
		assert.Contains(t, response.Body.String(), "boxnai://oauth/callback")
		assert.Contains(t, response.Body.String(), "tokens:write")
		assert.Contains(t, response.Body.String(), "openid")
		assert.Contains(t, response.Body.String(), "offline_access")
		assert.NotContains(t, response.Body.String(), "balance:read")
		assert.NotContains(t, response.Body.String(), "usage:read")
		assert.NotContains(t, response.Body.String(), "tokens:read")
		assert.NotContains(t, response.Body.String(), "client_secret")
		assert.NotContains(t, response.Body.String(), "boxnai-desktop-20261026")
	})

	t.Run("rejects a non-root manager before consuming a proof", func(t *testing.T) {
		body := publicClientBody("boxnai-desktop-test", "http://127.0.0.1/oauth/callback")
		proof := publicClientProof(t, identity, "create", "boxnai-desktop-test")
		response := oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleCommonUser, nil, CreateOAuthPublicClient)
		assert.Contains(t, response.Body.String(), "No permission to perform this action")
		assert.Equal(t, int64(0), countPublicClients(t))
		_, err := service.ConsumeOperationProof(proof, identity, publicClientOperation("create", "boxnai-desktop-test"))
		assert.NoError(t, err)
	})

	var createdID int
	t.Run("create requires a single-use proof bound to the client and writes an audit", func(t *testing.T) {
		body := publicClientBody("boxnai-desktop-test", "http://127.0.0.1/oauth/callback")
		response := oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, "", identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
		assert.Equal(t, int64(0), countPublicClients(t))

		wrong := publicClientProof(t, identity, "create", "other-client-id")
		response = oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, wrong, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
		assert.Equal(t, int64(0), countPublicClients(t))

		proof := publicClientProof(t, identity, "create", "boxnai-desktop-test")
		response = oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"success":true`)
		assert.Contains(t, response.Body.String(), `"token_endpoint_auth_method":"none"`)
		assert.NotContains(t, response.Body.String(), "client_secret")
		assert.NotContains(t, response.Body.String(), proof)
		var payload struct {
			Data struct {
				ID int `json:"id"`
			} `json:"data"`
		}
		require.NoError(t, common.Unmarshal(response.Body.Bytes(), &payload))
		createdID = payload.Data.ID
		require.NotZero(t, createdID)

		response = oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
		assert.Equal(t, int64(1), countPublicClients(t))

		var audit model.AuditLog
		require.NoError(t, model.LOG_DB.Where("action = ?", "oauth.public_client.create").First(&audit).Error)
		assert.True(t, audit.Success)
		encoded, err := common.Marshal(audit)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), proof)
		assert.Contains(t, string(encoded), "boxnai-desktop-test")
	})

	t.Run("rejects a non-loopback redirect and a client secret", func(t *testing.T) {
		body := publicClientBody("rejected-client", "http://192.0.2.10/oauth/callback")
		response := oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, "", identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Contains(t, response.Body.String(), "Invalid OAuth redirect URI")
		secret := strings.Replace(publicClientBody("rejected-client", "https://client.example/callback"), "}", `,"client_secret":"super-secret"}`, 1)
		response = oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", secret, "", identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Contains(t, response.Body.String(), "Invalid parameters")
		assert.NotContains(t, response.Body.String(), "super-secret")
	})

	t.Run("update and delete keep the client id and require their own proofs", func(t *testing.T) {
		body := `{"name":"Boxnai Desktop","redirect_uris":["http://127.0.0.1/oauth/callback","boxnai://oauth/callback"],"scopes":["profile","offline_access"],"enabled":false}`
		proof := publicClientProof(t, identity, "update", "boxnai-desktop-test")
		id := strconv.Itoa(createdID)
		response := oauthPublicClientRequest(t, http.MethodPut, "/api/oauth/public-clients/"+id, body, proof, identity, common.RoleRootUser, gin.Params{{Key: "id", Value: id}}, UpdateOAuthPublicClient)
		assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"enabled":false`)
		assert.Contains(t, response.Body.String(), "boxnai://oauth/callback")

		deleteProof := publicClientProof(t, identity, "delete", "boxnai-desktop-test")
		response = oauthPublicClientRequest(t, http.MethodDelete, "/api/oauth/public-clients/"+id, "", deleteProof, identity, common.RoleRootUser, gin.Params{{Key: "id", Value: id}}, DeleteOAuthPublicClient)
		assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Equal(t, int64(0), countPublicClients(t))
		var audit model.AuditLog
		require.NoError(t, model.LOG_DB.Where("action = ?", "oauth.public_client.delete").First(&audit).Error)
		assert.True(t, audit.Success)
	})

	t.Run("reserved provider slugs cannot shadow the authorization routes", func(t *testing.T) {
		for _, slug := range []string{"login", "consent", "logout", "admin", "provider", "telegram"} {
			err := model.CreateCustomOAuthProvider(&model.CustomOAuthProvider{
				Name: slug, Slug: slug, ClientId: "client", AuthorizationEndpoint: "https://issuer.example/auth",
				TokenEndpoint: "https://issuer.example/token", UserInfoEndpoint: "https://issuer.example/userinfo",
			})
			assert.ErrorContains(t, err, "This slug is reserved")
		}
	})

	t.Run("a user lists and revokes only their own authorized app", func(t *testing.T) {
		now := time.Now().Unix()
		require.NoError(t, model.DB.Create(&model.OAuthGrant{
			GrantRef: strings.Repeat("a", 64), ConsentRef: strings.Repeat("b", 64), GrantID: "grant-own",
			Issuer: "https://issuer.example/", ClientID: "boxnai-desktop-test", Subject: "1", UserID: user.Id,
			ConsentRequestID: "consent-own", HydraLoginSessionID: "login-own", OriginSID: identity.SessionID,
			SessionVersion: identity.SessionVersion, UserAuthVersion: identity.UserAuthVersion, Scopes: `["openid","profile"]`,
			PolicyHash: strings.Repeat("c", 64), Revision: 2, State: "active", CreatedAt: now, ApprovedAt: now, ExpiresAt: now + 3600,
		}).Error)
		other := &model.User{Username: "other-oauth-user", Password: user.Password, Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AffCode: "other-oauth", AuthVersion: 1}
		require.NoError(t, model.DB.Create(other).Error)
		require.NoError(t, model.DB.Create(&model.OAuthGrant{
			GrantRef: strings.Repeat("d", 64), ConsentRef: strings.Repeat("e", 64), GrantID: "grant-other",
			Issuer: "https://issuer.example/", ClientID: "boxnai-desktop-test", Subject: "2", UserID: other.Id,
			ConsentRequestID: "consent-other", HydraLoginSessionID: "login-other", OriginSID: "other-session",
			SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("f", 64),
			Revision: 2, State: "active", CreatedAt: now, ApprovedAt: now, ExpiresAt: now + 3600,
		}).Error)
		require.NoError(t, model.DB.Create(&model.OAuthGrant{
			GrantRef: strings.Repeat("1", 64), ConsentRef: strings.Repeat("2", 64), GrantID: "grant-expired",
			Issuer: "https://issuer.example/", ClientID: "expired-client-id", Subject: "1", UserID: user.Id,
			ConsentRequestID: "consent-expired", HydraLoginSessionID: "login-expired", OriginSID: identity.SessionID,
			SessionVersion: 1, UserAuthVersion: 1, Scopes: `["profile"]`, PolicyHash: strings.Repeat("3", 64),
			Revision: 2, State: "active", CreatedAt: now - 10, ApprovedAt: now - 10, ExpiresAt: now - 1,
		}).Error)

		response := oauthPublicClientRequest(t, http.MethodGet, "/api/user/oauth/apps", "", "", identity, common.RoleCommonUser, nil, ListAuthorizedOAuthApps)
		assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), "boxnai-desktop-test")
		assert.NotContains(t, response.Body.String(), "expired-client-id")
		assert.NotContains(t, response.Body.String(), "grant-other")
		assert.NotContains(t, response.Body.String(), "login-own")

		missing := oauthPublicClientRequest(t, http.MethodDelete, "/api/user/oauth/apps/missing-client", "", "", identity, common.RoleCommonUser, gin.Params{{Key: "client_id", Value: "missing-client"}}, RevokeAuthorizedOAuthApp)
		assert.Contains(t, missing.Body.String(), "Authorized application not found")

		proof := issueSecurityEnrollmentProof(t, identity, service.VerificationOperation{
			Scope: service.VerificationScopeOAuthAppRevoke, Context: mustMarshal(t, service.OAuthAppRevokeContext{ClientID: "boxnai-desktop-test"}),
		}, service.VerificationMethodPassword)
		response = oauthPublicClientRequest(t, http.MethodDelete, "/api/user/oauth/apps/boxnai-desktop-test", "", proof, identity, common.RoleCommonUser, gin.Params{{Key: "client_id", Value: "boxnai-desktop-test"}}, RevokeAuthorizedOAuthApp)
		assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), "Authorized application revoked")

		response = oauthPublicClientRequest(t, http.MethodGet, "/api/user/oauth/apps", "", "", identity, common.RoleCommonUser, nil, ListAuthorizedOAuthApps)
		assert.NotContains(t, response.Body.String(), "boxnai-desktop-test")
		var otherGrant model.OAuthGrant
		require.NoError(t, model.DB.Where("grant_ref = ?", strings.Repeat("d", 64)).First(&otherGrant).Error)
		assert.Equal(t, "active", otherGrant.State)
		assert.Zero(t, otherGrant.RevokedAt)
		var audit model.AuditLog
		require.NoError(t, model.LOG_DB.Where("action = ?", "oauth.app.revoke").First(&audit).Error)
		encoded, err := common.Marshal(audit)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), proof)
	})
}

func oauthPublicClientRequest(t *testing.T, method, path, body, proof string, identity service.AuthIdentity, role int, params gin.Params, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return oauthPublicClientRequestContext(t, context.Background(), method, path, body, proof, identity, role, params, handler)
}

func oauthPublicClientRequestContext(t *testing.T, ctx context.Context, method, path, body, proof string, identity service.AuthIdentity, role int, params gin.Params, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
	c.Request.Header.Set("Content-Type", "application/json")
	if proof != "" {
		c.Request.Header.Set("X-Security-Proof", proof)
	}
	c.Params = params
	c.Set("id", identity.UserID)
	c.Set("username", "enrollment-user")
	c.Set("role", role)
	c.Set("session_id", identity.SessionID)
	c.Set("auth_version", identity.UserAuthVersion)
	c.Set("session_version", identity.SessionVersion)
	handler(c)
	return response
}

func publicClientBody(clientID, redirect string) string {
	return `{"client_id":"` + clientID + `","name":"Boxnai Desktop","redirect_uris":["` + redirect + `"],"scopes":["openid","profile","offline_access"],"enabled":true}`
}

func publicClientOperation(action, clientID string) service.VerificationOperation {
	payload, err := common.Marshal(service.OAuthPublicClientManageContext{Action: action, ClientID: clientID})
	if err != nil {
		panic(err)
	}
	return service.VerificationOperation{Scope: service.VerificationScopeOAuthPublicClientManage, Context: payload}
}

func publicClientProof(t *testing.T, identity service.AuthIdentity, action, clientID string) string {
	t.Helper()
	return issueSecurityEnrollmentProof(t, identity, publicClientOperation(action, clientID), service.VerificationMethodPassword)
}

func countPublicClients(t *testing.T) int64 {
	t.Helper()
	var count int64
	require.NoError(t, model.DB.Model(&model.OAuthPublicClient{}).Count(&count).Error)
	return count
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := common.Marshal(value)
	require.NoError(t, err)
	return payload
}

type hydraAdminStub struct {
	mu   sync.Mutex
	docs map[string][]byte
	hits atomic.Int32
	mode atomic.Value
	srv  *httptest.Server
}

func newHydraAdminStub() *hydraAdminStub {
	stub := &hydraAdminStub{docs: map[string][]byte{}}
	stub.mode.Store("ok")
	return stub
}

func (s *hydraAdminStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	mode, _ := s.mode.Load().(string)
	if mode == "timeout" {
		_, _ = io.Copy(io.Discard, r.Body)
		// The client aborts on its own deadline. Cap the handler so server
		// shutdown is not left waiting on a context that never cancels.
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-r.Context().Done():
		case <-timer.C:
		}
		timer.Stop()
		return
	}
	if mode == "reject" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_client","client_secret":"rejected-secret"}`)
		return
	}
	if r.URL.Path == "/admin/clients" && r.Method == http.MethodPost {
		s.store(w, r, "", http.StatusCreated)
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, "/admin/clients/")
	if !ok || id == "" || strings.Contains(id, "/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		raw, found := s.docs[id]
		s.mu.Unlock()
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	case http.MethodPut:
		s.mu.Lock()
		_, found := s.docs[id]
		s.mu.Unlock()
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.store(w, r, id, http.StatusOK)
	case http.MethodDelete:
		s.mu.Lock()
		_, found := s.docs[id]
		delete(s.docs, id)
		s.mu.Unlock()
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *hydraAdminStub) store(w http.ResponseWriter, r *http.Request, id string, status int) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var doc map[string]any
	if common.Unmarshal(body, &doc) != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if id == "" {
		rawID, _ := doc["client_id"].(string)
		id = rawID
	}
	s.mu.Lock()
	s.docs[id] = append([]byte(nil), body...)
	s.mu.Unlock()
	if mode, _ := s.mode.Load().(string); mode == "scope-mismatch" {
		doc["scope"] = "openid profile offline_access"
	}
	doc["client_secret"] = "echo-secret-value"
	encoded, err := common.Marshal(doc)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func (s *hydraAdminStub) document(t *testing.T, id string) (int, string) {
	t.Helper()
	response, err := s.srv.Client().Get(s.srv.URL + "/admin/clients/" + url.PathEscape(id))
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, string(body)
}

func installPublicClientHydra(t *testing.T, stub *hydraAdminStub, withPublic bool) {
	t.Helper()
	stub.srv = httptest.NewTLSServer(stub)
	t.Cleanup(stub.srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(stub.srv.Certificate())
	resource, err := service.NewOAuthUserInfoResource(service.OAuthUserInfoConfig{
		Enabled: true, IntrospectionURL: stub.srv.URL + "/admin/oauth2/introspect",
		Issuer: "https://gateway.example/", Audience: "newapi-userinfo", ClientIDs: []string{"configured-client"},
	}, roots)
	require.NoError(t, err)
	t.Cleanup(resource.CloseIdleConnections)
	bridge, err := service.NewOAuthProviderBridge(service.OAuthProviderConfig{
		Enabled: true, RevocationEnabled: true, AdminBaseURL: stub.srv.URL,
		AuthorizationURL: "https://gateway.example/oauth2/auth",
	}, resource)
	require.NoError(t, err)
	if withPublic {
		_, err = service.NewOAuthPublic(service.OAuthPublicConfig{Enabled: true, BaseURL: "https://hydra-public.example/"}, bridge)
		require.NoError(t, err)
	}
	previous := service.SetCurrentOAuthProviderBridge(bridge)
	t.Cleanup(func() { service.SetCurrentOAuthProviderBridge(previous) })
}

func TestOAuthPublicClientHydraSync(t *testing.T) {
	user, identity := setupSecurityEnrollmentTest(t)
	require.NoError(t, model.DB.AutoMigrate(&model.OAuthPublicClient{}))
	require.NoError(t, model.DB.Model(user).Update("role", common.RoleRootUser).Error)
	previousPassword := common.PasswordLoginEnabled
	common.PasswordLoginEnabled = true
	t.Cleanup(func() { common.PasswordLoginEnabled = previousPassword })

	t.Run("switch off does not call hydra", func(t *testing.T) {
		stub := newHydraAdminStub()
		installPublicClientHydra(t, stub, false)
		body := publicClientSyncBody("switch-off-client", true)
		proof := publicClientProof(t, identity, "create", "switch-off-client")
		response := oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"hydra_synced":false`)
		assert.NotContains(t, response.Body.String(), `"hydra_synced":true`)
		assert.NotContains(t, response.Body.String(), "OAUTH_PUBLIC_CLIENT_SYNC_")
		assert.Zero(t, stub.hits.Load())
		assert.Equal(t, int64(1), countPublicClients(t))
	})

	t.Run("admin accepts the same redirect and scope", func(t *testing.T) {
		stub := newHydraAdminStub()
		installPublicClientHydra(t, stub, true)
		body := publicClientSyncBody("hydra-sync-client", true)
		proof := publicClientProof(t, identity, "create", "hydra-sync-client")
		response := oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"hydra_synced":true`)
		assert.NotContains(t, response.Body.String(), "echo-secret-value")
		assert.NotContains(t, response.Body.String(), "client_secret")
		status, document := stub.document(t, "hydra-sync-client")
		require.Equal(t, http.StatusOK, status, document)
		assert.Contains(t, document, "http://127.0.0.1/oauth/callback")
		assert.Contains(t, document, "boxnai://oauth/callback")
		assert.Contains(t, document, "tokens:write")
		assert.Contains(t, document, "offline_access")
		assert.Contains(t, document, `"token_endpoint_auth_method":"none"`)
		assert.NotContains(t, document, "client_secret")
		assert.NotContains(t, document, "echo-secret-value")

		var created struct {
			Data struct {
				ID int `json:"id"`
			} `json:"data"`
		}
		require.NoError(t, common.Unmarshal(response.Body.Bytes(), &created))
		id := strconv.Itoa(created.Data.ID)
		update := `{"name":"Boxnai Updated","redirect_uris":["http://127.0.0.1/oauth/callback"],"scopes":["profile","tokens:write"],"enabled":true}`
		proof = publicClientProof(t, identity, "update", "hydra-sync-client")
		response = oauthPublicClientRequest(t, http.MethodPut, "/api/oauth/public-clients/"+id, update, proof, identity, common.RoleRootUser, gin.Params{{Key: "id", Value: id}}, UpdateOAuthPublicClient)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"hydra_synced":true`)
		_, document = stub.document(t, "hydra-sync-client")
		assert.Contains(t, document, "Boxnai Updated")
		assert.Contains(t, document, "tokens:write")
		assert.NotContains(t, document, "boxnai://oauth/callback")
		assert.NotContains(t, document, "offline_access")

		proof = publicClientProof(t, identity, "delete", "hydra-sync-client")
		response = oauthPublicClientRequest(t, http.MethodDelete, "/api/oauth/public-clients/"+id, "", proof, identity, common.RoleRootUser, gin.Params{{Key: "id", Value: id}}, DeleteOAuthPublicClient)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"hydra_synced":true`)
		status, _ = stub.document(t, "hydra-sync-client")
		assert.Equal(t, http.StatusNotFound, status)
		var remaining model.OAuthPublicClient
		err := model.DB.Where("client_id = ?", "hydra-sync-client").First(&remaining).Error
		assert.Error(t, err)
	})

	t.Run("disabled client is removed from hydra and kept locally", func(t *testing.T) {
		stub := newHydraAdminStub()
		installPublicClientHydra(t, stub, true)
		body := publicClientSyncBody("hydra-disabled-client", false)
		proof := publicClientProof(t, identity, "create", "hydra-disabled-client")
		response := oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"hydra_synced":true`)
		assert.Contains(t, response.Body.String(), `"enabled":false`)
		status, _ := stub.document(t, "hydra-disabled-client")
		assert.Equal(t, http.StatusNotFound, status)
		var stored model.OAuthPublicClient
		require.NoError(t, model.DB.Where("client_id = ?", "hydra-disabled-client").First(&stored).Error)
		assert.False(t, stored.Enabled)
	})

	t.Run("admin 400 rolls the local row back", func(t *testing.T) {
		stub := newHydraAdminStub()
		installPublicClientHydra(t, stub, true)
		before := countPublicClients(t)
		stub.mode.Store("reject")
		body := publicClientSyncBody("hydra-reject-client", true)
		proof := publicClientProof(t, identity, "create", "hydra-reject-client")
		response := oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Equal(t, http.StatusConflict, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"code":"OAUTH_PUBLIC_CLIENT_SYNC_REJECTED"`)
		assert.Contains(t, response.Body.String(), `"success":false`)
		assert.NotContains(t, response.Body.String(), `"hydra_synced":true`)
		assert.NotContains(t, response.Body.String(), "rejected-secret")
		assert.NotContains(t, response.Body.String(), "echo-secret-value")
		assert.Equal(t, before, countPublicClients(t))
		assert.Positive(t, stub.hits.Load())
		var audit int64
		require.NoError(t, model.LOG_DB.Model(&model.AuditLog{}).Where("action = ? AND content LIKE ?", "oauth.public_client.create", "%hydra-reject-client%").Count(&audit).Error)
		assert.Zero(t, audit)

		stub.mode.Store("ok")
		keep := publicClientSyncBody("hydra-keep-client", true)
		proof = publicClientProof(t, identity, "create", "hydra-keep-client")
		response = oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", keep, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var created struct {
			Data struct {
				ID int `json:"id"`
			} `json:"data"`
		}
		require.NoError(t, common.Unmarshal(response.Body.Bytes(), &created))
		stub.mode.Store("reject")
		id := strconv.Itoa(created.Data.ID)
		update := `{"name":"Should Not Stick","redirect_uris":["https://client.example/callback"],"scopes":["profile"],"enabled":true}`
		proof = publicClientProof(t, identity, "update", "hydra-keep-client")
		response = oauthPublicClientRequest(t, http.MethodPut, "/api/oauth/public-clients/"+id, update, proof, identity, common.RoleRootUser, gin.Params{{Key: "id", Value: id}}, UpdateOAuthPublicClient)
		assert.Equal(t, http.StatusConflict, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), "OAUTH_PUBLIC_CLIENT_SYNC_REJECTED")
		var stored model.OAuthPublicClient
		require.NoError(t, model.DB.Where("client_id = ?", "hydra-keep-client").First(&stored).Error)
		assert.Equal(t, "Boxnai Desktop", stored.Name)
		assert.NotContains(t, stored.RedirectURIs, "client.example")
		stub.mode.Store("ok")
		_, document := stub.document(t, "hydra-keep-client")
		assert.Contains(t, document, "boxnai://oauth/callback")
		assert.NotContains(t, document, "client.example")
	})

	t.Run("admin success with mismatched scope rolls the local row back", func(t *testing.T) {
		stub := newHydraAdminStub()
		installPublicClientHydra(t, stub, true)
		stub.mode.Store("scope-mismatch")
		before := countPublicClients(t)
		body := publicClientSyncBody("hydra-mismatch-client", true)
		proof := publicClientProof(t, identity, "create", "hydra-mismatch-client")
		response := oauthPublicClientRequest(t, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Equal(t, http.StatusConflict, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"code":"OAUTH_PUBLIC_CLIENT_SYNC_REJECTED"`)
		assert.Contains(t, response.Body.String(), `"success":false`)
		assert.NotContains(t, response.Body.String(), `"hydra_synced":true`)
		assert.NotContains(t, response.Body.String(), "echo-secret-value")
		assert.NotContains(t, response.Body.String(), "client_secret")
		assert.Equal(t, before, countPublicClients(t))
		var audit int64
		require.NoError(t, model.LOG_DB.Model(&model.AuditLog{}).Where("action = ? AND content LIKE ?", "oauth.public_client.create", "%hydra-mismatch-client%").Count(&audit).Error)
		assert.Zero(t, audit)
	})

	t.Run("admin timeout rolls the local row back", func(t *testing.T) {
		stub := newHydraAdminStub()
		installPublicClientHydra(t, stub, true)
		stub.mode.Store("timeout")
		before := countPublicClients(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		body := publicClientSyncBody("hydra-timeout-client", true)
		proof := publicClientProof(t, identity, "create", "hydra-timeout-client")
		response := oauthPublicClientRequestContext(t, ctx, http.MethodPost, "/api/oauth/public-clients/", body, proof, identity, common.RoleRootUser, nil, CreateOAuthPublicClient)
		assert.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
		assert.Contains(t, response.Body.String(), `"code":"OAUTH_PUBLIC_CLIENT_SYNC_UNAVAILABLE"`)
		assert.Contains(t, response.Body.String(), `"success":false`)
		assert.NotContains(t, response.Body.String(), `"hydra_synced":true`)
		assert.Equal(t, before, countPublicClients(t))
		assert.Positive(t, stub.hits.Load())
	})
}

func publicClientSyncBody(clientID string, enabled bool) string {
	flag := "false"
	if enabled {
		flag = "true"
	}
	return `{"client_id":"` + clientID + `","name":"Boxnai Desktop","redirect_uris":["http://127.0.0.1/oauth/callback","boxnai://oauth/callback"],"scopes":["openid","profile","offline_access","tokens:write"],"enabled":` + flag + `}`
}
