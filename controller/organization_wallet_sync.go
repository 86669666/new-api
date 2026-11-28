package controller

import (
	"errors"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// OrganizationWalletSyncHandler is the isolated synchronous adapter. The
// production router does not register it until a spending policy is approved.
func OrganizationWalletSyncHandler(policy service.OrganizationWalletSyncPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, data, _, err := organizationRequest(c, false, false, 8*1024, false)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		if c.Request.URL.RawQuery != "" {
			writeOrganizationLifecycleError(c, model.ErrOrganizationInvalidInput)
			return
		}
		for key := range c.Request.Header {
			if strings.EqualFold(key, "X-Organization-Id") {
				writeOrganizationLifecycleError(c, model.ErrOrganizationInvalidInput)
				return
			}
		}
		orgID, err := service.OrganizationDecimal(c.Param("org_id"), false)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		var input map[string]string
		if err := common.Unmarshal(data, &input); err != nil || len(input) != 2 {
			writeOrganizationLifecycleError(c, model.ErrOrganizationInvalidInput)
			return
		}
		receipt, err := service.RunOrganizationWalletSync(c.Request.Context(), identity, orgID, input["request_id"], input["text"], policy)
		switch {
		case errors.Is(err, model.ErrOrganizationChargeFunds):
			writeOrganizationLifecycleError(c, &organizationHTTPError{http.StatusPaymentRequired, "ORG_WALLET_INSUFFICIENT", "Insufficient available organization wallet balance."})
		case errors.Is(err, service.ErrOrganizationChargeUnconfirmed):
			writeOrganizationLifecycleError(c, &organizationHTTPError{http.StatusBadGateway, "ORG_WALLET_OUTCOME_UNCONFIRMED", "The organization charge outcome is unconfirmed."})
		case err != nil:
			writeOrganizationLifecycleError(c, err)
		case receipt.State == model.OrganizationChargeDispatched:
			c.JSON(http.StatusAccepted, gin.H{"success": true, "data": receipt})
		default:
			common.ApiSuccess(c, receipt)
		}
	}
}
