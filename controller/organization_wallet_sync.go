package controller

import (
	"errors"
	"net/http"
	"strconv"
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
		identity, orgID, input, err := organizationWalletConsumptionRequest(c)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
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

// OrganizationWalletTaskHandler is mounted only by an isolated application
// with a fixed organization execution policy.
func OrganizationWalletTaskHandler(policy service.OrganizationTaskPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, orgID, input, err := organizationWalletConsumptionRequest(c)
		if err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		task, err := service.SubmitOrganizationWalletTask(c.Request.Context(), identity, orgID, input["request_id"], input["text"], policy)
		switch {
		case errors.Is(err, model.ErrOrganizationChargeFunds):
			writeOrganizationLifecycleError(c, &organizationHTTPError{http.StatusPaymentRequired, "ORG_WALLET_INSUFFICIENT", "Insufficient available organization wallet balance."})
		case errors.Is(err, service.ErrOrganizationChargeUnconfirmed):
			writeOrganizationLifecycleError(c, &organizationHTTPError{http.StatusBadGateway, "ORG_WALLET_OUTCOME_UNCONFIRMED", "The organization charge outcome is unconfirmed."})
		case err != nil:
			writeOrganizationLifecycleError(c, err)
		default:
			c.JSON(http.StatusAccepted, gin.H{"success": true, "data": gin.H{
				"task_row_id": strconv.FormatInt(task.TaskRowID, 10), "task_id": task.PublicID, "status": task.Status,
			}})
		}
	}
}

func organizationWalletConsumptionRequest(c *gin.Context) (service.AuthIdentity, int64, map[string]string, error) {
	identity, data, _, err := organizationRequest(c, false, false, 8*1024, false)
	if err != nil {
		return identity, 0, nil, err
	}
	if c.Request.URL.RawQuery != "" {
		return identity, 0, nil, model.ErrOrganizationInvalidInput
	}
	for key := range c.Request.Header {
		if strings.EqualFold(key, "X-Organization-Id") {
			return identity, 0, nil, model.ErrOrganizationInvalidInput
		}
	}
	orgID, err := service.OrganizationDecimal(c.Param("org_id"), false)
	if err != nil {
		return identity, 0, nil, err
	}
	var input map[string]string
	if err := common.Unmarshal(data, &input); err != nil || len(input) != 2 {
		return identity, 0, nil, model.ErrOrganizationInvalidInput
	}
	return identity, orgID, input, nil
}
