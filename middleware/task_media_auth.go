package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

const taskMediaTicketContextKey = "task_media_ticket"

// PersonalTaskMediaAuth keeps the existing dashboard Bearer path intact while
// allowing a native video element to present only its short-lived media cookie.
func PersonalTaskMediaAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.TrimSpace(c.GetHeader("Authorization")) != "" {
			UserAuth()(c)
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			abortTaskMediaCookie(c)
			return
		}
		cookie, err := c.Request.Cookie(service.TaskMediaCookieName)
		if err != nil {
			UserAuth()(c)
			return
		}
		if !sameOriginVideoRequest(c) {
			abortTaskMediaCookie(c)
			return
		}
		rowID, rowErr := strconv.ParseInt(c.Param("row_id"), 10, 64)
		ticket, err := service.ParseTaskMediaTicket(cookie.Value)
		if rowErr != nil || err != nil || ticket.RowID != rowID || ticket.ArtifactKey != c.Param("artifact_key") {
			abortTaskMediaCookie(c)
			return
		}
		c.Set(authIdentityContextKey, service.AuthIdentity{
			UserID: ticket.UserID, SessionID: ticket.SessionID,
			UserAuthVersion: ticket.UserAuthVersion, SessionVersion: ticket.SessionVersion,
		})
		c.Set(taskMediaTicketContextKey, ticket)
		c.Next()
	}
}

func sameOriginVideoRequest(c *gin.Context) bool {
	return oneHeaderValue(c, "Sec-Fetch-Site") == "same-origin" && oneHeaderValue(c, "Sec-Fetch-Dest") == "video"
}

func oneHeaderValue(c *gin.Context, name string) string {
	values := c.Request.Header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func abortTaskMediaCookie(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"success": false, "code": "artifact_not_found", "message": "Task or artifact not found"})
}

func GetTaskMediaTicket(c *gin.Context) (service.TaskMediaTicket, bool) {
	value, ok := c.Get(taskMediaTicketContextKey)
	if !ok {
		return service.TaskMediaTicket{}, false
	}
	ticket, ok := value.(service.TaskMediaTicket)
	return ticket, ok
}
