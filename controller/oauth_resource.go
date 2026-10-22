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

func GetOAuthBalance(c *gin.Context) {
	access, ok := middleware.GetOAuthUserInfoAccess(c)
	if !ok {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken, "balance:read")
		return
	}
	balance, err := access.ReadBalance(c.Request.Context())
	if err != nil {
		middleware.WriteOAuthResourceError(c, err, "balance:read")
		return
	}
	data, err := common.Marshal(gin.H{"success": true, "message": "", "data": balance})
	if err != nil {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthResourceUnavailable, "balance:read")
		return
	}
	c.Data(http.StatusOK, "application/json", data)
}
