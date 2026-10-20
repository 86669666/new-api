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
	items, total, actorRole, organizationWide, err := model.ReadOrganizationTasks(identity, orgID, params, int((page-1)*pageSize), int(pageSize))
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	pageInfo := &common.PageInfo{Page: int(page), PageSize: int(pageSize)}
	pageInfo.SetTotal(int(total))
	projected := tasksToDto(items, false, common.RoleCommonUser)
	for index, item := range projected {
		item.TaskRowID = strconv.FormatInt(items[index].ID, 10)
		// Provider error text is not an organization artifact delivery channel.
		item.FailReason = ""
		item.ResultURL = ""
	}
	pageInfo.SetItems(projected)
	actorRole, err = model.RecheckOrganizationTaskListAccessWithContext(c.Request.Context(), identity, orgID, organizationWide)
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	common.ApiSuccess(c, pageInfo)
}

// OrganizationTaskReadHandler serves only the current session's bounded
// organization task view. All potentially blocking artifact work finishes
// before the final authoritative check that precedes first response publication.
func organizationTaskDetail(task *model.Task) gin.H {
	created := task.CreatedAt
	if created == 0 {
		created = task.SubmitTime
	}
	return gin.H{
		"task_row_id": strconv.FormatInt(task.ID, 10), "task_id": task.TaskID,
		"platform": task.Platform, "action": task.Action, "status": task.Status,
		"progress": task.Progress, "created_at": created, "submit_time": task.SubmitTime,
		"start_time": task.StartTime, "finished_at": task.FinishTime,
	}
}

func organizationTaskBatchQuery(c *gin.Context) (int64, []int64, error) {
	orgID, selectionError := middleware.OrganizationSelection(c)
	query, queryError := url.ParseQuery(c.Request.URL.RawQuery)
	invalid := selectionError != "" || orgID <= 0 || queryError != nil
	for name, values := range query {
		if name != "task_row_ids" && name != "org_id" || len(values) != 1 {
			invalid = true
		}
	}
	value := query.Get("task_row_ids")
	if invalid || len(value) < 1 || len(value) > 399 || rejectOrganizationReadWriteInputs(c) != nil {
		return orgID, nil, model.ErrOrganizationInvalidInput
	}
	rowIDs := make([]int64, 0, 20)
	seen := make(map[int64]bool, 20)
	for part := range strings.SplitSeq(value, ",") {
		id, valid := middleware.ParseOrganizationDecimal(part)
		if !valid || id <= 0 || seen[id] || len(rowIDs) == 20 {
			return orgID, nil, model.ErrOrganizationInvalidInput
		}
		seen[id] = true
		rowIDs = append(rowIDs, id)
	}
	return orgID, rowIDs, nil
}

func GetOrganizationTaskBatch(c *gin.Context) {
	identity, ok := middleware.RequireOrganizationScopeSession(c)
	if !ok {
		return
	}
	orgID, rowIDs, err := organizationTaskBatchQuery(c)
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, 0, orgID, err)
		return
	}
	tasks, actorRole, err := model.ReadOrganizationTaskBatchWithContext(c.Request.Context(), identity, orgID, rowIDs)
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	items := make([]gin.H, 0, len(tasks))
	for _, task := range tasks {
		items = append(items, organizationTaskDetail(task))
	}
	if _, actorRole, err = model.ReadOrganizationTaskBatchWithContext(c.Request.Context(), identity, orgID, rowIDs); err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	common.ApiSuccess(c, gin.H{"items": items})
}

func ExportOrganizationTaskBatch(c *gin.Context) {
	identity, ok := middleware.RequireOrganizationScopeSession(c)
	if !ok {
		return
	}
	orgID, rowIDs, err := organizationTaskBatchQuery(c)
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, 0, orgID, err)
		return
	}
	tasks, actorRole, err := model.ReadOrganizationTaskBatchWithContext(c.Request.Context(), identity, orgID, rowIDs)
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	items := make([]gin.H, 0, len(tasks))
	for _, task := range tasks {
		items = append(items, organizationTaskDetail(task))
	}
	encoded, err := common.Marshal(gin.H{"success": true, "message": "", "data": gin.H{"items": items}})
	if err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	if _, actorRole, err = model.ReadOrganizationTaskBatchWithContext(c.Request.Context(), identity, orgID, rowIDs); err != nil {
		writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
		return
	}
	c.Header("Content-Disposition", `attachment; filename="organization-task-states.json"`)
	c.Data(http.StatusOK, "application/json; charset=utf-8", encoded)
}

func OrganizationTaskReadHandler(kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, ok := middleware.RequireOrganizationScopeSession(c)
		if !ok {
			return
		}
		orgID, selectionError := middleware.OrganizationSelection(c)
		rowID, valid := middleware.ParseOrganizationDecimal(c.Param("task_row_id"))
		query, queryError := url.ParseQuery(c.Request.URL.RawQuery)
		invalid := selectionError != "" || orgID <= 0 || !valid || rowID <= 0 || queryError != nil
		for name, values := range query {
			if name != "org_id" || len(values) != 1 {
				invalid = true
			}
		}
		if invalid || rejectOrganizationReadWriteInputs(c) != nil {
			writeOrganizationAccessDenial(c, identity.UserID, 0, orgID, model.ErrOrganizationInvalidInput)
			return
		}
		task, actorRole, err := model.ReadOrganizationTaskWithContext(c.Request.Context(), identity, orgID, rowID)
		if err != nil {
			writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
			return
		}
		beforePublish := func() error {
			_, role, err := model.ReadOrganizationTaskWithContext(c.Request.Context(), identity, orgID, rowID)
			actorRole = role
			return err
		}
		switch kind {
		case "detail":
			if err := beforePublish(); err != nil {
				writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
				return
			}
			common.ApiSuccess(c, organizationTaskDetail(task))
		case "artifacts":
			artifacts, projectionError := projectTaskArtifacts(task)
			if err := beforePublish(); err != nil {
				writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
				return
			}
			if projectionError != nil {
				writeTaskArtifactProjectionError(c, projectionError)
				return
			}
			items := make([]taskArtifactResponse, 0, len(artifacts)+1)
			base := "/api/organizations/" + strconv.FormatInt(orgID, 10) + "/tasks/" + strconv.FormatInt(rowID, 10) + "/artifacts/"
			for _, artifact := range artifacts {
				items = append(items, taskArtifactResponse{Key: artifact.Key, Type: artifact.Type, MimeType: artifact.MimeType, ContentURL: base + url.PathEscape(artifact.Key) + "/content"})
			}
			if legacyVideoAvailable(task) {
				items = append(items, taskArtifactResponse{Key: "video", Type: "video", ContentURL: base + "video/content"})
			}
			// Legacy audio snapshots contain provider URLs and are not projected.
			common.ApiSuccess(c, gin.H{"task_row_id": strconv.FormatInt(rowID, 10), "task_id": task.TaskID, "artifacts": items})
		case "content":
			if err := writeTaskArtifactContent(c, task, beforePublish); err != nil {
				writeOrganizationAccessDenial(c, identity.UserID, actorRole, orgID, err)
			}
		default:
			writeOrganizationAccessError(c, model.ErrOrganizationInvalidInput)
		}
	}
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
