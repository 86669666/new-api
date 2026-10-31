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
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type oauthPublicClientBody struct {
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Enabled      bool     `json:"enabled"`
}

type oauthPublicClientView struct {
	ID                      int       `json:"id"`
	ClientID                string    `json:"client_id"`
	Name                    string    `json:"name"`
	RedirectURIs            []string  `json:"redirect_uris"`
	Scopes                  []string  `json:"scopes"`
	GrantTypes              []string  `json:"grant_types"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	Enabled                 bool      `json:"enabled"`
	HydraSynced             *bool     `json:"hydra_synced,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

type authorizedOAuthAppView struct {
	ClientID   string   `json:"client_id"`
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes"`
	GrantCount int      `json:"grant_count"`
	ApprovedAt int64    `json:"approved_at"`
	ExpiresAt  int64    `json:"expires_at"`
}

func GetOAuthPublicClientPresets(c *gin.Context) {
	if !publicOAuthClientManager(c) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "", "data": service.PublicOAuthClientPresets()})
}

func ListOAuthPublicClients(c *gin.Context) {
	if !publicOAuthClientManager(c) {
		return
	}
	clients, err := model.ListOAuthPublicClients()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	views := make([]oauthPublicClientView, 0, len(clients))
	for _, client := range clients {
		view, err := presentOAuthPublicClient(&client)
		if err != nil {
			common.ApiError(c, err)
			return
		}
		views = append(views, view)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "", "data": views})
}

func CreateOAuthPublicClient(c *gin.Context) {
	if !publicOAuthClientManager(c) {
		return
	}
	body, ok := readOAuthPublicClientBody(c, false)
	if !ok {
		return
	}
	client, ok := normalizedOAuthPublicClient(c, body)
	if !ok {
		return
	}
	// Consume the bound proof before the uniqueness check so a replay cannot
	// skip step-up by colliding with the client that the first use created.
	if requireAdminUserProof(c, service.VerificationScopeOAuthPublicClientManage, service.OAuthPublicClientManageContext{Action: "create", ClientID: client.ClientID}) == nil {
		return
	}
	if _, err := model.GetOAuthPublicClientByClientID(client.ClientID); err == nil {
		common.ApiErrorT(c, "This client ID is already in use")
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		common.ApiError(c, err)
		return
	}
	synced, err := service.CommitOAuthPublicClient(c.Request.Context(), client, "create")
	if err != nil {
		writeOAuthPublicClientFailure(c, err)
		return
	}
	recordManageAudit(c, "oauth.public_client.create", map[string]any{"client_id": client.ClientID, "name": client.Name, "enabled": client.Enabled, "hydra_synced": synced})
	view, err := presentOAuthPublicClient(client)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	view.HydraSynced = &synced
	common.ApiSuccessT(c, "Public OAuth client created", view)
}

func UpdateOAuthPublicClient(c *gin.Context) {
	if !publicOAuthClientManager(c) {
		return
	}
	client, ok := loadOAuthPublicClient(c)
	if !ok {
		return
	}
	body, ok := readOAuthPublicClientBody(c, true)
	if !ok {
		return
	}
	body.ClientID = client.ClientID
	normalized, ok := normalizedOAuthPublicClient(c, body)
	if !ok {
		return
	}
	if requireAdminUserProof(c, service.VerificationScopeOAuthPublicClientManage, service.OAuthPublicClientManageContext{Action: "update", ClientID: client.ClientID}) == nil {
		return
	}
	client.Name = normalized.Name
	client.RedirectURIs = normalized.RedirectURIs
	client.Scopes = normalized.Scopes
	client.Enabled = normalized.Enabled
	synced, err := service.CommitOAuthPublicClient(c.Request.Context(), client, "update")
	if err != nil {
		writeOAuthPublicClientFailure(c, err)
		return
	}
	recordManageAudit(c, "oauth.public_client.update", map[string]any{"client_id": client.ClientID, "name": client.Name, "enabled": client.Enabled, "hydra_synced": synced})
	view, err := presentOAuthPublicClient(client)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	view.HydraSynced = &synced
	common.ApiSuccessT(c, "Public OAuth client updated", view)
}

func DeleteOAuthPublicClient(c *gin.Context) {
	if !publicOAuthClientManager(c) {
		return
	}
	client, ok := loadOAuthPublicClient(c)
	if !ok {
		return
	}
	if requireAdminUserProof(c, service.VerificationScopeOAuthPublicClientManage, service.OAuthPublicClientManageContext{Action: "delete", ClientID: client.ClientID}) == nil {
		return
	}
	synced, err := service.CommitOAuthPublicClient(c.Request.Context(), client, "delete")
	if err != nil {
		writeOAuthPublicClientFailure(c, err)
		return
	}
	recordManageAudit(c, "oauth.public_client.delete", map[string]any{"client_id": client.ClientID, "name": client.Name, "enabled": client.Enabled, "hydra_synced": synced})
	common.ApiSuccessT(c, "Public OAuth client deleted", gin.H{"hydra_synced": synced})
}

func ListAuthorizedOAuthApps(c *gin.Context) {
	userID := c.GetInt("id")
	if userID <= 0 {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	apps, err := model.ListAuthorizedOAuthApps(userID, time.Now().Unix())
	if err != nil {
		common.ApiErrorT(c, "OAuth revocation is unavailable")
		return
	}
	views := make([]authorizedOAuthAppView, 0, len(apps))
	for _, app := range apps {
		name := app.ClientID
		if registered, err := model.GetOAuthPublicClientByClientID(app.ClientID); err == nil && registered.Name != "" {
			name = registered.Name
		}
		views = append(views, authorizedOAuthAppView{
			ClientID: app.ClientID, Name: name, Scopes: app.Scopes, GrantCount: app.GrantCount,
			ApprovedAt: app.ApprovedAt, ExpiresAt: app.ExpiresAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "", "data": views})
}

func RevokeAuthorizedOAuthApp(c *gin.Context) {
	userID := c.GetInt("id")
	clientID := c.Param("client_id")
	if userID <= 0 {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	apps, err := model.ListAuthorizedOAuthApps(userID, time.Now().Unix())
	if err != nil {
		common.ApiErrorT(c, "OAuth revocation is unavailable")
		return
	}
	found := false
	for _, app := range apps {
		if app.ClientID == clientID {
			found = true
			break
		}
	}
	if !found {
		common.ApiErrorT(c, "Authorized application not found")
		return
	}
	if requireAdminUserProof(c, service.VerificationScopeOAuthAppRevoke, service.OAuthAppRevokeContext{ClientID: clientID}) == nil {
		return
	}
	if err := model.RevokeAuthorizedOAuthApp(c.Request.Context(), userID, clientID); err != nil {
		if errors.Is(err, model.ErrOAuthGrantInvalid) {
			common.ApiErrorT(c, "Authorized application not found")
			return
		}
		common.ApiErrorT(c, "OAuth revocation is unavailable")
		return
	}
	recordUserSecurityAudit(c, userID, "oauth.app.revoke", map[string]any{"client_id": clientID, "success": true})
	markAuditLogged(c)
	common.ApiSuccessT(c, "Authorized application revoked", nil)
}

func writeOAuthPublicClientFailure(c *gin.Context, err error) {
	var syncErr *service.OAuthPublicClientSyncError
	if errors.As(err, &syncErr) {
		common.ApiErrorStatus(c, syncErr.HTTPStatus, common.NewMessage(syncErr.Error()), gin.H{"code": syncErr.Code})
		return
	}
	common.ApiError(c, err)
}

func publicOAuthClientManager(c *gin.Context) bool {
	if c.GetInt("role") != common.RoleRootUser {
		common.ApiErrorT(c, "No permission to perform this action")
		return false
	}
	return true
}

func loadOAuthPublicClient(c *gin.Context) (*model.OAuthPublicClient, bool) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		common.ApiErrorT(c, "Invalid ID")
		return nil, false
	}
	client, err := model.GetOAuthPublicClientByID(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		common.ApiErrorT(c, "OAuth client not found")
		return nil, false
	}
	if err != nil {
		common.ApiError(c, err)
		return nil, false
	}
	return client, true
}

func readOAuthPublicClientBody(c *gin.Context, update bool) (oauthPublicClientBody, bool) {
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, 65537))
	var body oauthPublicClientBody
	if err != nil || len(data) > 65536 {
		common.ApiErrorT(c, "Invalid parameters")
		return body, false
	}
	required := []string{"name", "redirect_uris", "scopes", "enabled"}
	if !update {
		required = []string{"client_id", "name", "redirect_uris", "scopes", "enabled"}
	}
	if common.ValidateJSONObjectFields(data, required, nil) != nil || common.UnmarshalStrictObject(data, &body) != nil {
		common.ApiErrorT(c, "Invalid parameters")
		return body, false
	}
	return body, true
}

func normalizedOAuthPublicClient(c *gin.Context, body oauthPublicClientBody) (*model.OAuthPublicClient, bool) {
	clientID, name, redirects, scopes, err := service.NormalizePublicOAuthClient(body.ClientID, body.Name, body.RedirectURIs, body.Scopes)
	if err != nil {
		common.ApiErrorT(c, err.Error())
		return nil, false
	}
	return &model.OAuthPublicClient{ClientID: clientID, Name: name, RedirectURIs: redirects, Scopes: scopes, Enabled: body.Enabled}, true
}

func presentOAuthPublicClient(client *model.OAuthPublicClient) (oauthPublicClientView, error) {
	redirects, err := model.DecodeOAuthPublicClientList(client.RedirectURIs)
	if err != nil {
		return oauthPublicClientView{}, err
	}
	scopes, err := model.DecodeOAuthPublicClientList(client.Scopes)
	if err != nil {
		return oauthPublicClientView{}, err
	}
	return oauthPublicClientView{
		ID: client.ID, ClientID: client.ClientID, Name: client.Name, RedirectURIs: redirects, Scopes: scopes,
		GrantTypes: []string{"authorization_code", "refresh_token"}, TokenEndpointAuthMethod: "none",
		Enabled: client.Enabled, CreatedAt: client.CreatedAt, UpdatedAt: client.UpdatedAt,
	}, nil
}
