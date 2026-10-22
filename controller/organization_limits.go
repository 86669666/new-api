package controller

import (
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
)

// OrganizationLimitsHandler publishes global policy or replaces its full pair.
// The registered routes additionally require session-only UserAuth/RootAuth,
// and the global boundary sets no-store before any early rejection.
func OrganizationLimitsHandler(update bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, data, _, err := organizationRequest(c, false, false, 1024, false)
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
		if err := model.ValidateOrganizationLimitsIdentity(c.Request.Context(), identity, update); err != nil {
			writeOrganizationLifecycleError(c, err)
			return
		}
		if !update {
			limits, err := model.ReadOrganizationLimits(model.DB.WithContext(c.Request.Context()))
			if err != nil {
				writeOrganizationLifecycleError(c, &organizationHTTPError{http.StatusServiceUnavailable, "ORG_LIMITS_UNAVAILABLE", "Organization limits are temporarily unavailable."})
				return
			}
			common.ApiSuccess(c, limits)
			return
		}
		// organizationRequest already rejects duplicates and non-object JSON. Pointers
		// distinguish null/absent from a canonical string, including explicit "0".
		var values map[string]*string
		if common.Unmarshal(data, &values) != nil || len(values) != 2 || values["max_organizations_created"] == nil || values["max_organizations_joined"] == nil {
			writeOrganizationLifecycleError(c, model.ErrOrganizationInvalidInput)
			return
		}
		created, joined := *values["max_organizations_created"], *values["max_organizations_joined"]
		for _, value := range []string{created, joined} {
			if _, err := operation_setting.ParseOrganizationLimit(value); err != nil {
				writeOrganizationLifecycleError(c, model.ErrOrganizationInvalidInput)
				return
			}
		}
		// Persist both in the existing bulk transaction; never retry an uncertain
		// outcome. Cache publication follows commit and is not a rollback guarantee.
		if err := model.UpdateOptionsBulk(map[string]string{
			operation_setting.OrganizationCreatedLimitOptionKey: created,
			operation_setting.OrganizationJoinedLimitOptionKey:  joined,
		}); err != nil {
			writeOrganizationLifecycleError(c, &organizationHTTPError{http.StatusServiceUnavailable, "ORG_LIMITS_UPDATE_FAILED", "Unable to update organization limits."})
			return
		}
		recordManageAudit(c, "option.update", map[string]any{"keys": []string{operation_setting.OrganizationCreatedLimitOptionKey, operation_setting.OrganizationJoinedLimitOptionKey}})
		c.JSON(http.StatusOK, gin.H{"success": true, "message": ""})
	}
}
