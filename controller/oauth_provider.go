package controller

import (
	"io"
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

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
