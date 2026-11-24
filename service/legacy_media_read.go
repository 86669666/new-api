package service

import (
	"bytes"
	"net/http"
	"time"

	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

// ServeLegacyMediaContent delivers only the retained representation after
// cutover. A missing or rejected frozen binding must never fall back upstream.
func ServeLegacyMediaContent(c *gin.Context, route model.LegacyMediaRoute) (bool, error) {
	frozen, err := model.ReadLegacyMediaContent(c.Request.Context(), route, time.Now())
	if err != nil || frozen == nil {
		return false, err
	}
	if !time.Now().Before(frozen.ExpiresAt) {
		return false, model.ErrLegacyMediaUnproven
	}
	c.Header("Cache-Control", "private, no-store")
	c.Header("Content-Security-Policy", "sandbox; default-src 'none'")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Type", frozen.MIME)
	c.Header("ETag", `"`+frozen.Digest+`"`)
	if route.Family == model.LegacyMidjourneyImage {
		c.Data(http.StatusOK, frozen.MIME, frozen.Data)
	} else {
		http.ServeContent(legacyMediaResponseWriter{c.Writer}, c.Request, "", time.Time{}, bytes.NewReader(frozen.Data))
	}
	return true, nil
}

// ServeContent removes Cache-Control on range and precondition errors.
type legacyMediaResponseWriter struct {
	http.ResponseWriter
}

func (w legacyMediaResponseWriter) WriteHeader(status int) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.ResponseWriter.WriteHeader(status)
}
