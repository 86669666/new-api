package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	relaychannel "github.com/QuantumNous/new-api/relay/channel"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func personalMediaRequest(c *gin.Context) (model.AuthSessionIdentity, int64, bool) {
	setTaskMediaResponseSecurityHeaders(c.Writer.Header())
	identity, ok := middleware.GetSessionAuthIdentity(c)
	if !ok {
		writeTaskArtifactError(c, http.StatusUnauthorized, "artifact_session_required", "A dashboard login session is required")
		return model.AuthSessionIdentity{}, 0, false
	}
	if _, ok := middleware.RequirePersonalResourceOwner(c); !ok {
		return model.AuthSessionIdentity{}, 0, false
	}
	rawID := c.Param("row_id")
	rowID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || rowID <= 0 || strconv.FormatInt(rowID, 10) != rawID {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return model.AuthSessionIdentity{}, 0, false
	}
	return identity, rowID, true
}

func writePersonalMediaError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound), errors.Is(err, model.ErrUserSessionInactive):
		writeTaskArtifactError(c, http.StatusNotFound, "artifact_not_found", "Task or artifact not found")
	case errors.Is(err, model.ErrMidjourneyImageNotReady):
		writeTaskArtifactError(c, http.StatusConflict, "artifact_not_ready", "Midjourney image is not complete")
	case errors.Is(err, model.ErrMidjourneyImageChanged):
		writeTaskArtifactError(c, http.StatusConflict, "artifact_changed", "Midjourney image changed while it was being pinned")
	default:
		writeTaskArtifactError(c, http.StatusInternalServerError, "artifact_internal_error", "Failed to query task")
	}
}

func PersonalTaskArtifactContent(c *gin.Context) {
	identity, rowID, ok := personalMediaRequest(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	task, err := model.ReadPersonalTaskArtifact(ctx, identity, rowID)
	if err != nil {
		writePersonalMediaError(c, err)
		return
	}
	ticket, hasTicket := middleware.GetTaskMediaTicket(c)
	if hasTicket && (!personalNativeVideoAvailable(c, task) ||
		!ticket.Matches(identity, rowID, c.Param("artifact_key"), model.TaskMediaResultFingerprint(task))) {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	if hasTicket {
		c.Set("require_video_media", true)
		c.Header("Cross-Origin-Resource-Policy", "same-origin")
	}
	beforePublish := func() error {
		current, err := model.ReadPersonalTaskArtifact(ctx, identity, rowID)
		if err != nil {
			return err
		}
		if !current.ResultRetrievable() || current.TaskID != task.TaskID ||
			current.Status != task.Status || current.Platform != task.Platform ||
			current.ChannelId != task.ChannelId || current.Action != task.Action ||
			current.CreatedAt != task.CreatedAt || current.UpdatedAt != task.UpdatedAt ||
			current.GetResultURL() != task.GetResultURL() || current.Properties != task.Properties ||
			!bytes.Equal(current.Data, task.Data) || !reflect.DeepEqual(current.PrivateData, task.PrivateData) {
			return gorm.ErrRecordNotFound
		}
		if hasTicket && !ticket.Matches(identity, rowID, c.Param("artifact_key"), model.TaskMediaResultFingerprint(current)) {
			return gorm.ErrRecordNotFound
		}
		return nil
	}
	if err := writeTaskArtifactContent(c, task, beforePublish); err != nil {
		writePersonalMediaError(c, err)
	}
}

// PersonalTaskArtifactContext mints the cookie used by a native personal
// legacy-video element. The cookie deliberately omits Path: the browser's
// default-path rule scopes it to the /content path, including the deployment
// prefix. Only the registered GET/HEAD endpoints interpret the cookie.
func PersonalTaskArtifactContext(c *gin.Context) {
	if !singleTrustedHTTPSOrigin(c) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "code": "AUTH_ORIGIN_FORBIDDEN", "message": "request origin is not allowed"})
		return
	}
	identity, rowID, ok := personalMediaRequest(c)
	if !ok {
		return
	}
	if strings.TrimSpace(c.Param("artifact_key")) != "video" {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	task, err := model.ReadPersonalTaskArtifact(c.Request.Context(), identity, rowID)
	if err != nil || !personalNativeVideoAvailable(c, task) {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	rawTicket, ticket, err := service.IssueTaskMediaTicket(identity, rowID, "video", model.TaskMediaResultFingerprint(task))
	if err != nil {
		writePersonalMediaError(c, err)
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name: service.TaskMediaCookieName, Value: rawTicket,
		MaxAge: int(service.TaskMediaTicketTTL / time.Second), Expires: time.Unix(ticket.ExpiresAt, 0),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	c.Status(http.StatusNoContent)
}

func personalNativeVideoAvailable(c *gin.Context, task *model.Task) bool {
	if !legacyVideoAvailable(task) || !task.ResultRetrievable() {
		return false
	}
	rawURL := strings.TrimSpace(task.GetResultURL())
	source, err := url.Parse(rawURL)
	return err == nil && source.Host != "" && (source.Scheme == "http" || source.Scheme == "https") &&
		!isTaskMediaFallbackLoop(rawURL, task.TaskID) && !isSelfTaskMediaURL(c, source)
}

func personalNativeVideoConfigured() bool {
	return common.SessionCookieSecure && len(common.SessionCookieTrustedURLs) == 1
}

func singleTrustedHTTPSOrigin(c *gin.Context) bool {
	if !personalNativeVideoConfigured() {
		return false
	}
	values := c.Request.Header.Values("Origin")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return false
	}
	origin, err := common.NormalizeOrigin(values[0])
	return err == nil && origin == common.SessionCookieTrustedURLs[0]
}

func PersonalMidjourneyImage(c *gin.Context) {
	identity, rowID, ok := personalMediaRequest(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	task, err := model.ReadPersonalMidjourneyImage(ctx, identity, rowID)
	if err != nil {
		writePersonalMediaError(c, err)
		return
	}
	if task.ImageUrl == "" {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	beforePublish := func() error {
		current, err := model.ReadPersonalMidjourneyImage(ctx, identity, rowID)
		if err != nil {
			return err
		}
		if current.MjId != task.MjId || current.SubmitTime != task.SubmitTime ||
			current.ImageUrl != task.ImageUrl || current.ChannelId != task.ChannelId {
			return gorm.ErrRecordNotFound
		}
		return nil
	}
	var authorizationError error
	descriptor := &relaychannel.TaskContentRequest{URL: task.ImageUrl, Method: c.Request.Method, Credentialless: true}
	err = proxyTaskMediaFromChannel(c, task.ChannelId, "", descriptor, func() error {
		authorizationError = beforePublish()
		return authorizationError
	})
	if authorizationError != nil {
		writePersonalMediaError(c, authorizationError)
	} else if err != nil {
		if err := beforePublish(); err != nil {
			writePersonalMediaError(c, err)
			return
		}
		writeTaskMediaProxyError(c, err)
	}
}

func capturePersonalMidjourneyImage(c *gin.Context, task *model.Midjourney) ([]byte, string, error) {
	fetchContext, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	request := c.Request
	c.Request = request.WithContext(fetchContext)
	defer func() { c.Request = request }()
	rawURL := strings.TrimSpace(task.ImageUrl)
	response, err := requestTaskMedia(c, task.ChannelId, "", rawURL, &relaychannel.TaskContentRequest{
		URL: rawURL, Method: http.MethodGet, Credentialless: true,
	}, nil)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Range") != "" ||
		response.ContentLength > model.PersonalMidjourneyImageMaxBytes {
		return nil, "", errTaskMediaRequestRejected
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, model.PersonalMidjourneyImageMaxBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) == 0 || int64(len(data)) > model.PersonalMidjourneyImageMaxBytes ||
		response.ContentLength >= 0 && response.ContentLength != int64(len(data)) {
		return nil, "", errTaskMediaRequestRejected
	}
	mimeType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", errTaskMediaRequestRejected
	}
	detectedMIME := http.DetectContentType(data)
	if detectedMIME != "image/png" && detectedMIME != "image/jpeg" {
		return nil, "", errTaskMediaRequestRejected
	}
	declaredMIME := strings.ToLower(mimeType)
	if declaredMIME == "image/jpg" {
		declaredMIME = "image/jpeg"
	}
	if declaredMIME != detectedMIME {
		return nil, "", errTaskMediaRequestRejected
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > 4096 || config.Height > 4096 {
		return nil, "", errTaskMediaRequestRejected
	}
	if _, _, err := image.Decode(bytes.NewReader(data)); err != nil {
		return nil, "", errTaskMediaRequestRejected
	}
	return data, detectedMIME, nil
}

func PinPersonalMidjourneyImage(c *gin.Context) {
	identity, rowID, ok := personalMediaRequest(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	existing, err := model.ReadPersonalMidjourneyImageVersion(ctx, identity, int(rowID), model.PersonalMidjourneyImageVersion)
	if err == nil {
		c.JSON(http.StatusOK, existing)
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		writePersonalMediaError(c, err)
		return
	}
	task, err := model.ReadPersonalMidjourneyImage(ctx, identity, rowID)
	if err != nil {
		writePersonalMediaError(c, err)
		return
	}
	if task.Status != "SUCCESS" || task.ImageUrl == "" || task.Progress != "" && task.Progress != "100%" {
		writePersonalMediaError(c, model.ErrMidjourneyImageNotReady)
		return
	}
	data, mimeType, err := capturePersonalMidjourneyImage(c, task)
	if err != nil {
		writeTaskMediaProxyError(c, &taskMediaProxyError{status: http.StatusBadGateway, code: "artifact_upstream_error", message: "Failed to fetch complete image", err: err})
		return
	}
	version, created, err := model.PinPersonalMidjourneyImage(ctx, identity, task, data, mimeType)
	if err != nil {
		if errors.Is(err, model.ErrMidjourneyImageBudgetExceeded) {
			writeTaskArtifactError(c, http.StatusRequestEntityTooLarge, "artifact_storage_limit", "Personal media storage budget exceeded")
			return
		}
		writePersonalMediaError(c, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, version)
}

func PersonalMidjourneyImageVersion(c *gin.Context) {
	identity, rowID, ok := personalMediaRequest(c)
	if !ok {
		return
	}
	if c.Param("version") != strconv.Itoa(model.PersonalMidjourneyImageVersion) {
		writePersonalMediaError(c, gorm.ErrRecordNotFound)
		return
	}
	stored, err := model.ReadPersonalMidjourneyImageVersion(c.Request.Context(), identity, int(rowID), model.PersonalMidjourneyImageVersion)
	if err != nil {
		writePersonalMediaError(c, err)
		return
	}
	c.Header("Content-Type", stored.MIME)
	c.Header("Content-Length", strconv.FormatInt(stored.Length, 10))
	c.Header("ETag", fmt.Sprintf("\"%s\"", stored.Digest))
	setTaskMediaResponseSecurityHeaders(c.Writer.Header())
	c.Status(http.StatusOK)
	if c.Request.Method != http.MethodHead {
		_, _ = c.Writer.Write(stored.Data)
	}
}
