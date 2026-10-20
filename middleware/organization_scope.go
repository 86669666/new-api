package middleware

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/logger"
	"github.com/gin-gonic/gin"
)

const organizationSelectionKey = "organization_selection"
const organizationSafeLogKey = "organization_safe_log_route"

// Only canonical scope and a fixed error code survive parsing. Never retain raw
// queries, selector strings or credentials in this context value.
type organizationSelection struct {
	id      int64
	present bool
	code    string
}

// ParseOrganizationDecimal accepts the canonical int64 wire representation.
// It is also used for the new endpoints' bounded cursor and limit parameters.
func ParseOrganizationDecimal(value string) (int64, bool) {
	if value == "" || len(value) > 19 || len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	for _, b := range value {
		if b < '0' || b > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil
}

func parseOrganizationSelection(c *gin.Context) organizationSelection {
	var selection organizationSelection
	headerCount, queryCount := 0, 0
	for key, values := range c.Request.Header {
		if !strings.EqualFold(key, "X-Organization-Id") {
			continue
		}
		selection.present = true
		if len(values) == 0 {
			selection.code = "ORG_SELECTOR_INVALID"
		}
		for _, value := range values {
			headerCount++
			id, valid := ParseOrganizationDecimal(value)
			if !valid {
				selection.code = "ORG_SELECTOR_INVALID"
			}
			selection.id = id
		}
	}
	for segment := range strings.SplitSeq(c.Request.URL.RawQuery, "&") {
		// Raw semicolon separators can be swallowed by a later URL parser or
		// capability redactor. Reject reserved fragments before either runs.
		if strings.Contains(segment, ";") {
			for fragment := range strings.SplitSeq(segment, ";") {
				key, _, _ := strings.Cut(fragment, "=")
				decoded, err := url.QueryUnescape(key)
				if err == nil && (strings.EqualFold(decoded, "org_id") || strings.EqualFold(decoded, "organization_id")) {
					selection.code = "ORG_SELECTOR_INVALID"
				}
			}
		}
		key, value, _ := strings.Cut(segment, "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil || !strings.EqualFold(decoded, "org_id") && !strings.EqualFold(decoded, "organization_id") {
			continue
		}
		selection.present = true
		queryCount++
		if decoded != "org_id" {
			selection.code = "ORG_SELECTOR_INVALID"
		}
		value, err = url.QueryUnescape(value)
		id, valid := ParseOrganizationDecimal(value)
		if err != nil || !valid {
			selection.code = "ORG_SELECTOR_INVALID"
		}
		selection.id = id
	}
	if headerCount > 1 || queryCount > 1 {
		selection.code = "ORG_SELECTOR_INVALID"
	}
	if selection.code == "" && headerCount == 1 && queryCount == 1 {
		selection.code = "ORG_SELECTOR_CONFLICT"
	}
	if selection.code != "" {
		selection.id = 0
	}
	return selection
}

// organizationRequestSelection is shared by early artifact redaction, the global
// boundary and the defensive personal-owner guard. It never interprets bodies.
func organizationRequestSelection(c *gin.Context) organizationSelection {
	if value, ok := c.Get(organizationSelectionKey); ok {
		if selection, ok := value.(organizationSelection); ok {
			return selection
		}
	}
	selection := parseOrganizationSelection(c)
	c.Set(organizationSelectionKey, selection)
	return selection
}

// OrganizationSelection returns only the normalized request scope, not a grant.
func OrganizationSelection(c *gin.Context) (int64, string) {
	selection := organizationRequestSelection(c)
	return selection.id, selection.code
}

func markOrganizationSafeLog(c *gin.Context) {
	route := c.FullPath()
	if route == "" {
		route = "unmatched"
	}
	c.Set(organizationSafeLogKey, route)
}

func rejectOrganizationSelection(c *gin.Context, code string) {
	markOrganizationSafeLog(c)
	c.Header("Cache-Control", "private, no-store")
	status, message, key, relayCode := http.StatusBadRequest, "Invalid organization selector.", i18n.MsgOrganizationSelectorInvalid, "organization_selector_invalid"
	switch code {
	case "ORG_SELECTOR_CONFLICT":
		message, key, relayCode = "Organization selectors conflict.", i18n.MsgOrganizationSelectorConflict, "organization_selector_conflict"
	case "ORG_SELECTOR_NOT_ALLOWED":
		message = "Organization selection is not allowed on this endpoint."
	case "ORG_RESOURCE_UNSUPPORTED":
		status, message, key, relayCode = http.StatusForbidden, "Organization resources are not supported on this endpoint.", i18n.MsgOrganizationScopeUnsupported, "organization_scope_unsupported"
	}
	// No authenticated principal has been established here. A fixed server
	// event is appropriate; no invented actor is written to the audit DB.
	logger.LogWarn(c.Request.Context(), common.LogText("organization.access_denied actor=unauthenticated decision=%s", code))
	if c.Request.URL.Path == "/api" || strings.HasPrefix(c.Request.URL.Path, "/api/") {
		common.ApiErrorStatus(c, status, common.NewMessage(message), gin.H{"code": code})
	} else {
		c.JSON(status, gin.H{"error": gin.H{"message": i18n.T(c, key), "type": "invalid_request_error", "param": "org_id", "code": relayCode}})
	}
	c.Abort()
}

// Exact lifecycle routes and whether their selector is bound to an org path.
var organizationLifecycleRoutes = map[string]bool{
	"GET /api/organizations/:org_id/wallet":                                                   true,
	"GET /api/platform/organizations/:org_id/wallet":                                          true,
	"POST /api/platform/organizations/:org_id/wallet/credits":                                 true,
	"POST /api/platform/organizations/:org_id/wallet/credits/:credit_id/reverse":              true,
	"POST /api/organizations":                                                                 false,
	"PATCH /api/organizations/:org_id/name":                                                   true,
	"POST /api/organizations/:org_id/self-state":                                              true,
	"POST /api/platform/organizations/:org_id/state":                                          true,
	"POST /api/organizations/:org_id/dissolve":                                                true,
	"PATCH /api/organizations/:org_id/members/:user_id/role":                                  true,
	"DELETE /api/organizations/:org_id/members/:user_id":                                      true,
	"POST /api/organizations/:org_id/leave":                                                   true,
	"POST /api/organizations/:org_id/invitations":                                             true,
	"POST /api/organizations/:org_id/invitations/:invitation_id/reissue":                      true,
	"POST /api/organizations/:org_id/invitations/:invitation_id/accept":                       true,
	"POST /api/organizations/:org_id/invitations/:invitation_id/decline":                      true,
	"POST /api/organizations/:org_id/invitations/:invitation_id/revoke":                       true,
	"POST /api/organizations/:org_id/ownership-transfers":                                     true,
	"POST /api/organizations/:org_id/ownership-transfers/:transfer_id/accept":                 true,
	"POST /api/organizations/:org_id/ownership-transfers/:transfer_id/decline":                true,
	"POST /api/organizations/:org_id/ownership-transfers/:transfer_id/cancel":                 true,
	"GET /api/organization-invitations":                                                       false,
	"GET /api/organization-ownership-transfers":                                               false,
	"GET /api/organizations/:org_id/invitations":                                              true,
	"GET /api/organizations/:org_id/ownership-transfer":                                       true,
	"GET /api/organizations/:org_id/invitations/:invitation_id/generations/:generation":       true,
	"GET /api/organizations/:org_id/ownership-transfers/:transfer_id/generations/:generation": true,
	"GET /api/organizations/:org_id/self-state":                                               true,
	"GET /api/platform/organizations/:org_id/state":                                           true,
	"POST /api/organizations/:org_id/authorization-context":                                   true,
	"POST /api/platform/organizations/:org_id/authorization-context":                          true,
}

// Existing personal resource routes that also serve an organization-owned view.
// Organization hardening applies only when a positive selector is present, so
// unselected and explicit-zero requests keep their legacy behavior.
var organizationResourceRoutes = map[string]bool{
	"GET /api/task/self": true,
}

// OrganizationSelectionBoundary must be registered before every application
// route and NoRoute dispatcher. Only an exact method/template pair is eligible.
func OrganizationSelectionBoundary() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAccess, pathSelection, discovery := false, false, false
		if selection := organizationRequestSelection(c); selection.code == "" && selection.id > 0 && organizationResourceRoutes[c.Request.Method+" "+c.FullPath()] {
			isAccess = true
		}
		if c.Request.Method == http.MethodGet {
			switch c.FullPath() {
			case "/api/organizations":
				isAccess, discovery = true, true
			case "/api/organization-context":
				isAccess = true
			case "/api/organizations/:org_id", "/api/organizations/:org_id/members", "/api/organizations/:org_id/events", "/api/organizations/:org_id/tasks/batch", "/api/organizations/:org_id/tasks/export":
				isAccess, pathSelection = true, true
			}
		}
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
			switch c.FullPath() {
			case "/api/organizations/:org_id/tasks/:task_row_id", "/api/organizations/:org_id/tasks/:task_row_id/artifacts", "/api/organizations/:org_id/tasks/:task_row_id/artifacts/:artifact_key/content":
				isAccess, pathSelection = true, true
			}
		}
		if pathBound, exists := organizationLifecycleRoutes[c.Request.Method+" "+c.FullPath()]; exists {
			isAccess, pathSelection, discovery = true, pathBound, !pathBound
		}
		switch c.Request.Method + " " + c.FullPath() {
		case "GET /api/verify/methods", "POST /api/verify", "POST /api/user/passkey/verify/begin", "POST /api/user/passkey/verify/finish":
			isAccess, discovery = true, true
			markOrganizationSafeLog(c)
			c.Header("Cache-Control", "private, no-store")
		}
		if isAccess {
			contentRead := (c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead) &&
				c.FullPath() == "/api/organizations/:org_id/tasks/:task_row_id/artifacts/:artifact_key/content"
			if !contentRead {
				ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
				defer cancel()
				c.Request = c.Request.WithContext(ctx)
			}
			markOrganizationSafeLog(c)
			c.Header("Cache-Control", "private, no-store")
		}
		if isAccess {
			invalid := false
			for _, name := range []string{"Authorization", "X-Security-Proof", "Origin", "Referer", "Content-Type", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
				count := 0
				for key, values := range c.Request.Header {
					if strings.EqualFold(key, name) {
						count += len(values)
					}
				}
				if count > 1 {
					invalid = true
				}
			}
			for key := range c.Request.Header {
				if strings.EqualFold(key, "Idempotency-Key") || strings.EqualFold(key, "X-HTTP-Method-Override") || strings.EqualFold(key, "X-Method-Override") || strings.EqualFold(key, "X-HTTP-Method") {
					invalid = true
				}
			}
			if invalid {
				common.ApiErrorStatus(c, http.StatusBadRequest, common.NewMessage("Invalid organization request."), gin.H{"code": "ORG_REQUEST_INVALID"})
				c.Abort()
				return
			}
		}
		selection := organizationRequestSelection(c)
		if selection.code != "" {
			rejectOrganizationSelection(c, selection.code)
			return
		}
		if pathSelection {
			id, valid := ParseOrganizationDecimal(c.Param("org_id"))
			if !valid || id == 0 {
				rejectOrganizationSelection(c, "ORG_SELECTOR_INVALID")
				return
			}
			if selection.present && selection.id != id {
				rejectOrganizationSelection(c, "ORG_SELECTOR_CONFLICT")
				return
			}
			selection.id, selection.present = id, true
			c.Set(organizationSelectionKey, selection)
		}
		if discovery && selection.id > 0 {
			rejectOrganizationSelection(c, "ORG_SELECTOR_NOT_ALLOWED")
			return
		}
		if !isAccess && selection.id > 0 {
			rejectOrganizationSelection(c, "ORG_RESOURCE_UNSUPPORTED")
			return
		}
		c.Next()
	}
}
