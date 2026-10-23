package service

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	relaytypes "github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
)

var ErrOAuthDerivedTextClosed = errors.New("OAuth derived text spending is not enabled")

// No boolean, configuration or client field opens this boundary. Root must
// integrate the selected producer/transport and SQL-only writer cutover first.
func ReserveOAuthDerivedText(context.Context, string, model.OAuthTextFacts, int) (*model.OAuthDerivedTextCharge, error) {
	return nil, ErrOAuthDerivedTextClosed
}
func ClaimOAuthDerivedText(context.Context, string, model.OAuthTextFacts, int) (*model.OAuthTextSendPermit, error) {
	return nil, ErrOAuthDerivedTextClosed
}

// CalculateOAuthDerivedTextQuota supports only standard OpenAI text and cache
// reads. The caller supplies the raw usage object, before any fallback estimates
// or DTO conversions. Unknown usage fields fail closed, including cache-write,
// audio, image, reasoning, prediction, tools and provider-specific cost fields.
func CalculateOAuthDerivedTextQuota(f model.OAuthTextFacts, rawUsage []byte) (int, model.OAuthTextUsage, error) {
	var u model.OAuthTextUsage
	if len(rawUsage) == 0 || len(rawUsage) > 8388608 || f.Model == "" || strings.HasSuffix(f.Model, "search-preview") {
		return 0, u, model.ErrOAuthTextCharge
	}
	for _, ratio := range []float64{f.ModelRatio, f.CompletionRatio, f.GroupRatio, f.CacheRatio} {
		if ratio < 0 || math.IsNaN(ratio) || math.IsInf(ratio, 0) {
			return 0, u, model.ErrOAuthTextCharge
		}
	}
	fields, err := common.DecodeRawJSONObject(rawUsage)
	if err != nil {
		return 0, u, model.ErrOAuthTextCharge
	}
	for name := range fields {
		switch name {
		case "prompt_tokens", "completion_tokens", "total_tokens", "prompt_tokens_details", "completion_tokens_details":
		default:
			return 0, u, model.ErrOAuthTextCharge
		}
	}
	for name, dest := range map[string]*int{"prompt_tokens": &u.Prompt, "completion_tokens": &u.Completion, "total_tokens": &u.Total} {
		var value *int
		if common.Unmarshal(fields[name], &value) != nil || value == nil {
			return 0, u, model.ErrOAuthTextCharge
		}
		*dest = *value
	}
	for _, name := range []string{"prompt_tokens_details", "completion_tokens_details"} {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		details, err := common.DecodeRawJSONObject(raw)
		if err != nil {
			return 0, u, model.ErrOAuthTextCharge
		}
		for key, value := range details {
			if name != "prompt_tokens_details" || key != "cached_tokens" {
				return 0, u, model.ErrOAuthTextCharge
			}
			var cached *int
			if common.Unmarshal(value, &cached) != nil || cached == nil {
				return 0, u, model.ErrOAuthTextCharge
			}
			u.Cached = *cached
		}
	}
	if u.Prompt <= 0 || u.Prompt > common.MaxQuota || u.Completion < 0 || u.Completion > common.MaxQuota-u.Prompt || u.Total != u.Prompt+u.Completion || u.Cached < 0 || u.Cached > u.Prompt {
		return 0, u, model.ErrOAuthTextCharge
	}
	info := &relaycommon.RelayInfo{
		RelayFormat: relaytypes.RelayFormatOpenAI, OriginModelName: f.Model, StartTime: time.Now(),
		PriceData: types.PriceData{ModelRatio: f.ModelRatio, CompletionRatio: f.CompletionRatio, CacheRatio: f.CacheRatio, GroupRatioInfo: types.GroupRatioInfo{GroupRatio: f.GroupRatio}},
	}
	usage := &dto.Usage{PromptTokens: u.Prompt, CompletionTokens: u.Completion, TotalTokens: u.Total}
	usage.PromptTokensDetails.CachedTokens = u.Cached
	summary := calculateTextQuotaSummary(&gin.Context{}, info, usage)
	if info.QuotaClamp != nil {
		return 0, u, model.ErrOAuthTextCharge
	}
	return summary.Quota, u, nil
}

// Historical obligations survive admission closure. Actual is recomputed from
// persisted price facts and raw usage, never accepted as a caller-supplied price.
func FinalizeOAuthDerivedText(ctx context.Context, ref string, rawUsage []byte) (*model.OAuthDerivedTextCharge, error) {
	charge, err := model.ReadOAuthDerivedTextCharge(ctx, ref)
	if err != nil {
		return nil, err
	}
	var f model.OAuthTextFacts
	if err = common.UnmarshalJsonStr(charge.Facts, &f); err != nil {
		return nil, err
	}
	actual, usage, err := CalculateOAuthDerivedTextQuota(f, rawUsage)
	if err != nil {
		return nil, err
	}
	return model.FinalizeOAuthDerivedTextSnapshot(ctx, ref, actual, usage, charge.Fingerprint)
}
