package controller

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func ListAccessibleOrganizations(c *gin.Context) {
	serveOrganizationAccess(c, model.OrganizationAccessDiscovery)
}
func GetOrganizationRequestContext(c *gin.Context) {
	serveOrganizationAccess(c, model.OrganizationAccessContext)
}
func GetOrganizationAccess(c *gin.Context) {
	serveOrganizationAccess(c, model.OrganizationAccessDetail)
}
func ListOrganizationMembers(c *gin.Context) {
	serveOrganizationAccess(c, model.OrganizationAccessMembers)
}
func ListOrganizationEvents(c *gin.Context) {
	serveOrganizationAccess(c, model.OrganizationAccessEvents)
}

// organizationAccessPage validates only these GET endpoints. Existing provider
// bodies and unrelated legacy query parameters never pass through this parser.
func organizationAccessPage(c *gin.Context, kind model.OrganizationAccessKind) (model.OrganizationPage, error) {
	page := model.OrganizationPage{Limit: 20}
	paged := kind == model.OrganizationAccessDiscovery || kind == model.OrganizationAccessMembers || kind == model.OrganizationAccessEvents
	query, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil {
		return page, model.ErrOrganizationInvalidInput
	}
	for key, values := range query {
		if len(values) != 1 {
			return page, model.ErrOrganizationInvalidInput
		}
		switch key {
		case "org_id": // The global boundary already validated selection/conflicts.
		case "after_id", "limit":
			if !paged {
				return page, model.ErrOrganizationInvalidInput
			}
			n, valid := middleware.ParseOrganizationDecimal(values[0])
			if !valid {
				return page, model.ErrOrganizationInvalidInput
			}
			if key == "after_id" {
				page.AfterID = n
			} else {
				if n < 1 || n > 100 {
					return page, model.ErrOrganizationInvalidInput
				}
				page.Limit = int(n)
			}
		default:
			return page, model.ErrOrganizationInvalidInput
		}
	}
	return page, rejectOrganizationReadWriteInputs(c)
}

// rejectOrganizationReadWriteInputs refuses inputs that only state-changing
// organization requests carry: a security proof, an idempotency key or a body.
func rejectOrganizationReadWriteInputs(c *gin.Context) error {
	for key := range c.Request.Header {
		if strings.EqualFold(key, "X-Security-Proof") || strings.EqualFold(key, "Idempotency-Key") {
			return model.ErrOrganizationInvalidInput
		}
	}
	if c.Request.Body != nil {
		// One byte is sufficient, including for chunked/unknown-length bodies.
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1))
		if err != nil || len(body) > 0 {
			return model.ErrOrganizationInvalidInput
		}
	}
	return nil
}

func serveOrganizationAccess(c *gin.Context, kind model.OrganizationAccessKind) {
	identity, ok := middleware.GetAuthIdentity(c)
	if !ok || identity.SessionID == "" {
		writeOrganizationAccessError(c, model.ErrOrganizationUnauthenticated)
		return
	}
	orgID, selectorError := middleware.OrganizationSelection(c)
	if selectorError != "" {
		writeOrganizationAccessError(c, model.ErrOrganizationInvalidInput)
		return
	}
	page, err := organizationAccessPage(c, kind)
	if err != nil {
		// The middleware identity may be cached; do not invent an authoritative
		// audit actor for validation failures before the domain recheck.
		logger.LogWarn(c.Request.Context(), common.LogText("organization.access_denied actor=unverified decision=ORG_REQUEST_INVALID"))
		writeOrganizationAccessError(c, err)
		return
	}
	data, actorRole, err := service.OrganizationAccessResponse(identity, kind, orgID, page)
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	common.ApiSuccess(c, data)
	if kind == model.OrganizationAccessEvents {
		recordOrganizationAccessAudit(c, identity.UserID, actorRole, orgID, "organization.events_read", "allowed", true)
	}
}

// writeOrganizationAccessDenial audits domain denials only for an actor whose
// role was read in the authorization transaction.
func writeOrganizationAccessDenial(c *gin.Context, userID, actorRole int, orgID int64, err error) {
	code := writeOrganizationAccessError(c, err)
	if actorRole > 0 && (code == "ORG_NOT_FOUND" || code == "ORG_FORBIDDEN" || code == "ORG_STATE_CHANGED") {
		recordOrganizationAccessAudit(c, userID, actorRole, orgID, "organization.access_denied", code, false)
		return
	}
	logger.LogWarn(c.Request.Context(), common.LogText("organization.access_denied actor=unverified decision=%s", code))
}

// organizationTaskListQuery parses the organization branch of GET
// /api/task/self. It is strictly bounded because the read runs while
// membership rows are locked.
func organizationTaskListQuery(c *gin.Context) (params model.SyncTaskQueryParams, page, pageSize int64, err error) {
	page, pageSize = 1, int64(common.ItemsPerPage)
	query, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil {
		return params, page, pageSize, model.ErrOrganizationInvalidInput
	}
	for key, values := range query {
		if len(values) != 1 {
			return params, page, pageSize, model.ErrOrganizationInvalidInput
		}
		value := values[0]
		switch key {
		case "org_id": // The global boundary already validated selection/conflicts.
		case "p", "page_size":
			n, valid := middleware.ParseOrganizationDecimal(value)
			if !valid || n < 1 || n > 100 {
				return params, page, pageSize, model.ErrOrganizationInvalidInput
			}
			if key == "p" {
				page = n
			} else {
				pageSize = n
			}
		case "start_timestamp", "end_timestamp":
			if value == "" {
				continue
			}
			n, valid := middleware.ParseOrganizationDecimal(value)
			if !valid {
				return params, page, pageSize, model.ErrOrganizationInvalidInput
			}
			if key == "start_timestamp" {
				params.StartTimestamp = n
			} else {
				params.EndTimestamp = n
			}
		case "task_id":
			params.TaskID = value
		case "action":
			params.Action = value
		case "status":
			params.Status = value
		case "platform":
			params.Platform = constant.TaskPlatform(value)
		default:
			return params, page, pageSize, model.ErrOrganizationInvalidInput
		}
	}
	return params, page, pageSize, rejectOrganizationReadWriteInputs(c)
}

// serveOrganizationTasks is the organization branch of GET /api/task/self.
// Only a dashboard session may read it.
func serveOrganizationTasks(c *gin.Context, orgID int64) {
	identity, ok := middleware.RequireOrganizationScopeSession(c)
	if !ok {
		return
	}
	params, page, pageSize, err := organizationTaskListQuery(c)
	if err != nil {
		// The middleware identity may be cached; validation failures carry no
		// authoritative audit actor.
		writeOrganizationAccessDenial(c, identity.UserID, 0, orgID, err)
		return
	}
	items, total, actorRole, err := model.ReadOrganizationTasks(identity, orgID, params, int((page-1)*pageSize), int(pageSize))
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	pageInfo := &common.PageInfo{Page: int(page), PageSize: int(pageSize)}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(tasksToDto(items, false, common.RoleCommonUser))
	common.ApiSuccess(c, pageInfo)
}

func writeOrganizationAccessError(c *gin.Context, err error) string {
	status, code, message := http.StatusInternalServerError, "ORG_INTERNAL_ERROR", "Unable to load organization access."
	switch {
	case errors.Is(err, model.ErrOrganizationUnauthenticated), errors.Is(err, model.ErrUserSessionInactive):
		status, code, message = http.StatusUnauthorized, "AUTH_SESSION_REVOKED", "Unauthorized, not logged in and no access token provided"
	case errors.Is(err, model.ErrOrganizationInvalidInput):
		status, code, message = http.StatusBadRequest, "ORG_REQUEST_INVALID", "Invalid organization request."
	case errors.Is(err, model.ErrOrganizationNotFound), errors.Is(err, model.ErrOrganizationDisabled), errors.Is(err, model.ErrOrganizationTerminal):
		status, code, message = http.StatusNotFound, "ORG_NOT_FOUND", "Organization is unavailable."
	case errors.Is(err, model.ErrOrganizationForbidden):
		status, code, message = http.StatusForbidden, "ORG_FORBIDDEN", "Organization operation is forbidden."
	case errors.Is(err, model.ErrOrganizationConflict):
		status, code, message = http.StatusConflict, "ORG_STATE_CHANGED", "Organization state changed. Retry the request."
	}
	common.ApiErrorStatus(c, status, common.NewMessage(message), gin.H{"code": code})
	c.Abort()
	return code
}

func recordOrganizationAccessAudit(c *gin.Context, userID, actorRole int, orgID int64, action, decision string, success bool) {
	// nil context deliberately prevents the shared sink from copying raw User-
	// Agent/IP. Route is the registered template; parameters are fixed/decimal.
	model.RecordAuditLog(nil, model.AuditLog{
		UserId: userID, ActorRole: actorRole, Category: model.AuditCategorySecurity,
		Action: action, AuthMethod: "session", Method: http.MethodGet, Route: c.FullPath(),
		Status: c.Writer.Status(), Success: success, RequestId: c.GetString(common.RequestIdKey),
		Other: model.AuditOther{Op: &model.AuditOperation{Action: action, Params: model.AuditFields{"org_id": strconv.FormatInt(orgID, 10), "decision": decision}}},
	})
}
