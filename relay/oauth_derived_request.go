package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// OAuthDerivedTextPolicy is copied into the chat handler at router construction.
// It is never loaded from a client, channel override, or live pricing setting.
type OAuthDerivedTextPolicy struct {
	SourcePolicyHash string
	Model            string
	Group            string
	ChannelID        int
	Endpoint         string
	MaxCompletion    int
	ModelRatio       float64
	CompletionRatio  float64
	GroupRatio       float64
	CacheRatio       float64
}

// HandleOAuthDerivedSelectedText owns the complete derived request. The caller
// returns before entering any legacy debit, refund, or retry code.
func HandleOAuthDerivedSelectedText(c *gin.Context, format types.RelayFormat, policy *OAuthDerivedTextPolicy) {
	defer func() {
		if !c.Writer.Written() {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": types.OpenAIError{
				Message: i18n.T(c, i18n.MsgTokenStatusUnavailable), Type: "new_api_error",
			}})
		}
	}()
	kind, userID, tokenID := middleware.OAuthTokenPrincipal(c)
	if policy == nil || kind != model.OAuthDerivedTokenBound || userID <= 0 || tokenID <= 0 ||
		format != types.RelayFormatOpenAI || c.Request.Method != http.MethodPost || c.Request.URL.Path != "/v1/chat/completions" ||
		c.Request.URL.RawQuery != "" {
		return
	}
	channelID := common.GetContextKeyInt(c, constant.ContextKeyChannelId)
	endpoint := strings.TrimSuffix(common.GetContextKeyString(c, constant.ContextKeyChannelBaseUrl), "/") + "/v1/chat/completions"
	mapping := strings.TrimSpace(common.GetContextKeyString(c, constant.ContextKeyChannelModelMapping))
	channelKey := common.GetContextKeyString(c, constant.ContextKeyChannelKey)
	settings, hasSettings := common.GetContextKeyType[dto.ChannelSettings](c, constant.ContextKeyChannelSetting)
	extra, hasExtra := common.GetContextKeyType[dto.ChannelOtherSettings](c, constant.ContextKeyChannelOtherSetting)
	if channelID <= 0 || channelID != policy.ChannelID || endpoint != policy.Endpoint || channelKey == "" ||
		common.GetContextKeyString(c, constant.ContextKeyUsingGroup) != policy.Group ||
		common.GetContextKeyString(c, constant.ContextKeyOriginalModel) != policy.Model ||
		common.GetContextKeyInt(c, constant.ContextKeyChannelType) != constant.ChannelTypeOpenAI ||
		common.GetContextKeyBool(c, constant.ContextKeyChannelIsMultiKey) ||
		common.GetContextKeyString(c, constant.ContextKeyChannelOrganization) != "" ||
		(mapping != "" && mapping != "{}") ||
		len(common.GetContextKeyStringMap(c, constant.ContextKeyChannelParamOverride)) != 0 ||
		len(common.GetContextKeyStringMap(c, constant.ContextKeyChannelHeaderOverride)) != 0 ||
		!hasSettings || !hasExtra || settings.SystemPrompt != "" || settings.SystemPromptOverride ||
		settings.Proxy != "" || settings.TLSInsecureSkipVerify || settings.PassThroughBodyEnabled ||
		settings.ForceFormat || settings.ThinkingToContent || extra.AdvancedCustom != nil {
		return
	}
	for _, ratio := range []float64{policy.ModelRatio, policy.CompletionRatio, policy.GroupRatio, policy.CacheRatio} {
		if ratio <= 0 || math.IsNaN(ratio) || math.IsInf(ratio, 0) {
			return
		}
	}
	if policy.CacheRatio > 1 {
		return
	}
	storage, err := common.GetBodyStorage(c)
	if err != nil {
		return
	}
	body, err := storage.Bytes()
	if err != nil || len(body) > 64<<10 || !utf8.Valid(body) {
		return
	}
	// No channel adapter transforms this path. The bytes validated here are
	// hashed below and copied by the one-shot sender before reserving funds.
	request, err := helper.ValidateOAuthDerivedTextRequest(body)
	if err != nil || request.Model != policy.Model {
		return
	}
	meta := request.GetTokenCountMeta()
	if meta.MaxTokens <= 0 || meta.MaxTokens > policy.MaxCompletion {
		return
	}
	prompt, err := service.CountRequestToken(c, meta, &relaycommon.RelayInfo{RelayFormat: format})
	if err != nil || prompt <= 0 || prompt > common.MaxQuota-meta.MaxTokens {
		return
	}
	requestID := c.GetString(common.RequestIdKey)
	if requestID == "" {
		return
	}
	ctx := c.Request.Context()
	facts, err := model.ReadOAuthDerivedTextAuthority(ctx, userID, tokenID)
	if err != nil || facts.PolicyHash != policy.SourcePolicyHash {
		return
	}
	route, err := common.Marshal([]any{http.MethodPost, endpoint, channelID, policy.Model})
	if err != nil {
		return
	}
	refHash := sha256.Sum256([]byte("newapi.oauth.text.receipt.v1\x00" + requestID))
	routeHash, bodyHash := sha256.Sum256(route), sha256.Sum256(body)
	facts.Model, facts.ChannelID = policy.Model, channelID
	facts.RouteHash, facts.BodyHash = hex.EncodeToString(routeHash[:]), hex.EncodeToString(bodyHash[:])
	facts.ModelRatio, facts.CompletionRatio, facts.GroupRatio, facts.CacheRatio = policy.ModelRatio, policy.CompletionRatio, policy.GroupRatio, policy.CacheRatio
	facts.PromptEstimate, facts.MaxCompletion = prompt, meta.MaxTokens
	upperUsage, err := common.Marshal(map[string]int{
		"prompt_tokens": prompt, "completion_tokens": meta.MaxTokens, "total_tokens": prompt + meta.MaxTokens,
	})
	if err != nil {
		return
	}
	reserve, _, err := service.CalculateOAuthDerivedTextQuota(*facts, upperUsage)
	if err != nil || reserve <= 0 {
		return
	}
	ref := hex.EncodeToString(refHash[:])
	resp, err := service.SendSelectedOAuthDerivedText(ctx, ref, *facts, reserve, service.OAuthDerivedTextSelectedRequest{
		URL: endpoint, APIKey: channelKey, Body: body,
	})
	if err != nil {
		return
	}
	// The consumer publishes only after settlement. A partial write is already
	// terminal. Returning leaves any unresolved durable receipt for reconciliation.
	_ = consumeOAuthDerivedTextResponse(ctx, ref, policy.Model, resp, c.Writer)
}
