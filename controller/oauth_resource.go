package controller

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func GetOAuthUserInfo(c *gin.Context) {
	access, ok := middleware.GetOAuthUserInfoAccess(c)
	if !ok {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
		return
	}
	profile, err := access.Read(c.Request.Context())
	if err != nil {
		middleware.WriteOAuthResourceError(c, err)
		return
	}
	data, err := common.Marshal(profile)
	if err != nil {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthResourceUnavailable)
		return
	}
	c.Data(http.StatusOK, "application/json", data)
}
