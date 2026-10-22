package controller

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// OAuthClientGate hides the client registry until the userinfo resource is on.
// The routes stay registered so access-token rules can name them. A disabled
// deployment answers 404 before authentication.
func OAuthClientGate(c *gin.Context) {
	if service.CurrentOAuthUserInfoResource() == nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	c.Next()
}

type oauthClientView struct {
	ID        int      `json:"id"`
	ClientID  string   `json:"client_id"`
	Name      string   `json:"name"`
	Redirects []string `json:"redirects"`
	Scopes    []string `json:"scopes"`
	Enabled   bool     `json:"enabled"`
}

type oauthAuthorizationView struct {
	ClientID string   `json:"client_id"`
	Name     string   `json:"name"`
	Scopes   []string `json:"scopes"`
}

type oauthClientWrite struct {
	Name      string
	Preset    string
	Redirects []string
	Scopes    []string
	Enabled   *bool
}

func ListOAuthClients(c *gin.Context) {
	rows, err := model.ListOAuthClients()
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	views := make([]oauthClientView, 0, len(rows))
	for _, row := range rows {
		view, viewErr := newOAuthClientView(row)
		if viewErr != nil {
			common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
			return
		}
		views = append(views, view)
	}
	common.ApiSuccess(c, views)
}

func CreateOAuthClient(c *gin.Context) {
	body, err := readOAuthClientWrite(c)
	if err != nil {
		common.ApiError(c, common.NewMessage("Invalid parameters"))
		return
	}
	name, redirects, scopes, err := service.NormalizeOAuthClientRegistration(body.Name, body.Preset, body.Redirects, body.Scopes)
	if err != nil {
		common.ApiError(c, common.NewMessage("Invalid parameters"))
		return
	}
	if !oauthClientProof(c, service.OAuthClientManageContext{Action: "create", Name: name, Redirects: redirects, Scopes: scopes}) {
		return
	}
	clientID, err := service.NewOAuthClientID()
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	encoded, err := common.Marshal(redirects)
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	now := common.GetTimestamp()
	row := &model.OAuthClient{
		ClientID: clientID, Name: name, RedirectURIs: string(encoded), Scopes: strings.Join(scopes, " "),
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err = model.CreateOAuthClient(row); err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	if err = service.CurrentOAuthProviderBridge().SyncPublicClient(c.Request.Context(), clientID, name, strings.Join(scopes, " "), redirects, true); err != nil {
		if delErr := model.DeleteOAuthClient(row.ID); delErr != nil {
			common.SysLog("oauth public client rollback failed")
		}
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	recordManageAudit(c, "oauth.client.create", map[string]any{
		"client_id": clientID, "name": name, "redirects": redirects, "scopes": scopes,
	})
	view, err := newOAuthClientView(*row)
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	common.ApiSuccess(c, view)
}

func UpdateOAuthClient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		common.ApiError(c, common.NewMessage("Invalid parameters"))
		return
	}
	row, err := model.GetOAuthClientByID(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		common.ApiError(c, common.NewMessage("OAuth client not found"))
		return
	}
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	body, err := readOAuthClientWrite(c)
	if err != nil {
		common.ApiError(c, common.NewMessage("Invalid parameters"))
		return
	}
	name, redirects, scopes, err := service.NormalizeOAuthClientRegistration(body.Name, body.Preset, body.Redirects, body.Scopes)
	if err != nil {
		common.ApiError(c, common.NewMessage("Invalid parameters"))
		return
	}
	if !oauthClientProof(c, service.OAuthClientManageContext{Action: "update", ClientRowID: id, Name: name, Redirects: redirects, Scopes: scopes}) {
		return
	}
	previous := row
	encoded, err := common.Marshal(redirects)
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	row.Name = name
	row.RedirectURIs = string(encoded)
	row.Scopes = strings.Join(scopes, " ")
	if body.Enabled != nil {
		row.Enabled = *body.Enabled
	}
	row.UpdatedAt = common.GetTimestamp()
	if err = model.UpdateOAuthClient(&row); err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	if err = service.CurrentOAuthProviderBridge().SyncPublicClient(c.Request.Context(), row.ClientID, name, row.Scopes, redirects, false); err != nil {
		previous.UpdatedAt = common.GetTimestamp()
		if restoreErr := model.UpdateOAuthClient(&previous); restoreErr != nil {
			common.SysLog("oauth public client restore failed")
		}
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	recordManageAudit(c, "oauth.client.update", map[string]any{
		"client_id": row.ClientID, "name": name, "redirects": redirects, "scopes": scopes, "enabled": row.Enabled,
	})
	view, err := newOAuthClientView(row)
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	common.ApiSuccess(c, view)
}

func DeleteOAuthClient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		common.ApiError(c, common.NewMessage("Invalid parameters"))
		return
	}
	row, err := model.GetOAuthClientByID(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		common.ApiError(c, common.NewMessage("OAuth client not found"))
		return
	}
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	if !oauthClientProof(c, service.OAuthClientManageContext{Action: "delete", ClientRowID: id}) {
		return
	}
	if err = service.CurrentOAuthProviderBridge().DeletePublicClient(c.Request.Context(), row.ClientID); err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	if err = model.DisableOAuthIssuedTokensByClient(row.ClientID); err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	if err = model.RevokeOAuthAuthorizationsForClient(row.ClientID); err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	if err = model.DeleteOAuthClient(row.ID); err != nil {
		common.ApiError(c, common.NewMessage("OAuth client could not be registered"))
		return
	}
	recordManageAudit(c, "oauth.client.delete", map[string]any{"client_id": row.ClientID, "name": row.Name})
	common.ApiSuccess(c, gin.H{"client_id": row.ClientID})
}

func ListOAuthAuthorizations(c *gin.Context) {
	rows, err := model.ListOAuthAuthorizations(c.GetInt("id"))
	if err != nil {
		common.ApiError(c, common.NewMessage("OAuth authorization not found"))
		return
	}
	views := make([]oauthAuthorizationView, 0, len(rows))
	for _, row := range rows {
		scopes := []string{}
		if row.Scopes != "" {
			scopes = strings.Fields(row.Scopes)
		}
		views = append(views, oauthAuthorizationView{ClientID: row.ClientID, Name: row.Name, Scopes: scopes})
	}
	common.ApiSuccess(c, views)
}

func DeleteOAuthAuthorization(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" || len(clientID) > 255 || strings.ContainsAny(clientID, "\r\n") {
		common.ApiError(c, common.NewMessage("Invalid parameters"))
		return
	}
	userID := c.GetInt("id")
	if err := model.RevokeOAuthAuthorization(userID, clientID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			common.ApiError(c, common.NewMessage("OAuth authorization not found"))
			return
		}
		common.ApiError(c, common.NewMessage("OAuth authorization not found"))
		return
	}
	recordUserSecurityAudit(c, userID, "oauth.authorization.revoke", map[string]any{"client_id": clientID, "success": true})
	common.ApiSuccess(c, gin.H{"client_id": clientID})
}

func oauthClientProof(c *gin.Context, operation service.OAuthClientManageContext) bool {
	encoded, err := common.Marshal(operation)
	if err != nil {
		common.ApiError(c, common.NewMessage("Invalid parameters"))
		return false
	}
	return middleware.RequireSecurityProof(c, service.VerificationOperation{
		Scope: service.VerificationScopeOAuthClientManage, Context: encoded,
	}) != nil
}

func newOAuthClientView(row model.OAuthClient) (oauthClientView, error) {
	redirects, err := row.RedirectList()
	if err != nil {
		return oauthClientView{}, err
	}
	scopes := []string{}
	if row.Scopes != "" {
		scopes = strings.Fields(row.Scopes)
	}
	return oauthClientView{
		ID: row.ID, ClientID: row.ClientID, Name: row.Name, Redirects: redirects, Scopes: scopes, Enabled: row.Enabled,
	}, nil
}

func readOAuthClientWrite(c *gin.Context) (oauthClientWrite, error) {
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20+1))
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return oauthClientWrite{}, errors.New("invalid oauth client body")
	}
	fields, err := common.DecodeRawJSONObject(data)
	if err != nil {
		return oauthClientWrite{}, err
	}
	if _, ok := fields["client_secret"]; ok {
		return oauthClientWrite{}, errors.New("oauth client secret is not accepted")
	}
	if raw, ok := fields["token_endpoint_auth_method"]; ok {
		var method string
		if common.Unmarshal(raw, &method) != nil || method != "none" {
			return oauthClientWrite{}, errors.New("oauth client must be public")
		}
	}
	var body oauthClientWrite
	if raw, ok := fields["name"]; ok && common.Unmarshal(raw, &body.Name) != nil {
		return oauthClientWrite{}, errors.New("invalid oauth client name")
	}
	if raw, ok := fields["preset"]; ok && common.Unmarshal(raw, &body.Preset) != nil {
		return oauthClientWrite{}, errors.New("invalid oauth client preset")
	}
	if raw, ok := fields["redirects"]; ok && common.Unmarshal(raw, &body.Redirects) != nil {
		return oauthClientWrite{}, errors.New("invalid oauth client redirects")
	}
	if raw, ok := fields["scopes"]; ok && common.Unmarshal(raw, &body.Scopes) != nil {
		return oauthClientWrite{}, errors.New("invalid oauth client scopes")
	}
	if raw, ok := fields["enabled"]; ok {
		var enabled bool
		if common.Unmarshal(raw, &enabled) != nil {
			return oauthClientWrite{}, errors.New("invalid oauth client enabled")
		}
		body.Enabled = &enabled
	}
	return body, nil
}
