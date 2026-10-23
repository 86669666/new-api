package relay

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/gin-gonic/gin"
)

// HandleOAuthDerivedSelectedText is the default-closed HTTP boundary. No
// immutable spending policy has been installed. A classified identity or the
// four-field authority reader is NOT a spending permission. This entry has no
// Reserve/Claim, transport, legacy billing, refund or retry path.
// The controller must return after this call, before installing legacy defers.
func HandleOAuthDerivedSelectedText(c *gin.Context, format types.RelayFormat) {
	defer c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": types.OpenAIError{
		Message: i18n.T(c, i18n.MsgTokenStatusUnavailable), Type: "new_api_error",
	}})
	kind, userID, tokenID := middleware.OAuthTokenPrincipal(c)
	if kind != model.OAuthDerivedTokenBound || userID <= 0 || tokenID <= 0 ||
		format != types.RelayFormatOpenAI || c.Request.Method != http.MethodPost || c.Request.URL.Path != "/v1/chat/completions" {
		return
	}
	storage, err := common.GetBodyStorage(c)
	if err != nil {
		return
	}
	body, err := storage.Bytes()
	if err != nil {
		return
	}
	if _, err = helper.ValidateOAuthDerivedTextRequest(body); err != nil {
		return
	}
	// Absent immutable server policy means deny, even with a valid raw request
	// and successful channel selection. No request/header/config flag can open it.
}
