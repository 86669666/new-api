package controller

import (
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func RevokeOAuthToken(bridge *service.OAuthProviderBridge) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, 8193))
		if err != nil || len(data) > 8192 {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		form, err := url.ParseQuery(string(data))
		if err != nil {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		for key, values := range form {
			if !slices.Contains([]string{"token", "client_id", "token_type_hint"}, key) || len(values) != 1 {
				middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
				return
			}
			limit := 256
			if key == "token" {
				limit = 4096
			}
			if len(values[0]) > limit || key != "token_type_hint" && values[0] == "" {
				middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
				return
			}
			for _, ch := range values[0] {
				if ch < 0x21 || ch > 0x7e {
					middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
					return
				}
			}
		}
		if form.Get("token") == "" || form.Get("client_id") == "" {
			middleware.WriteOAuthRevocationError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		// Unknown/empty hints are ignored; only the issuer determines token kind.
		if err := bridge.RevokeToken(c.Request.Context(), form.Get("token"), form.Get("client_id")); err != nil {
			middleware.WriteOAuthRevocationFailure(c, err)
			return
		}
		c.Status(http.StatusOK)
	}
}

func OAuthProviderHandler(bridge *service.OAuthProviderBridge, phase string, preview bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, ok := middleware.GetAuthIdentity(c)
		if !ok {
			middleware.WriteOAuthProviderError(c, service.ErrOAuthInvalidToken)
			return
		}
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, 16385))
		required := []string{"challenge"}
		if !preview {
			required = append(required, "preview_token", "decision")
			if phase == "consent" {
				required = append(required, "selected_scopes")
			}
		}
		if err != nil || len(data) > 16384 || common.ValidateJSONObjectFields(data, required, nil) != nil {
			middleware.WriteOAuthProviderError(c, service.ErrOAuthProviderRequest)
			return
		}
		var input service.OAuthProviderDecision
		if common.UnmarshalStrictObject(data, &input) != nil {
			middleware.WriteOAuthProviderError(c, service.ErrOAuthProviderRequest)
			return
		}
		var result any
		if preview {
			result, err = bridge.Preview(c.Request.Context(), identity, phase, input.Challenge)
		} else {
			result, err = bridge.Decide(c.Request.Context(), identity, phase, input)
		}
		if err != nil {
			middleware.WriteOAuthProviderError(c, err)
			return
		}
		encoded, err := common.Marshal(result)
		if err != nil {
			middleware.WriteOAuthProviderError(c, service.ErrOAuthResourceUnavailable)
			return
		}
		c.Data(http.StatusOK, "application/json", encoded)
	}
}
