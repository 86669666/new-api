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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
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
