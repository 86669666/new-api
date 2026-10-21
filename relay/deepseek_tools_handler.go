package relay

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/logger"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

// This is a gateway bound, not a promise about a provider's maximum payload.
const toolsSearchResponseLimit = 16 * 1024 * 1024

func DeepSeekToolsHelper(c *gin.Context, info *relaycommon.RelayInfo) *types.NewAPIError {
	info.InitChannelMeta(c)
	if info.ChannelType != constant.ChannelTypeDeepSeek {
		return types.NewError(errors.New("channel does not support /v1/tools/search"), types.ErrorCodeInvalidRequest)
	}
	request, ok := info.Request.(*dto.DeepSeekToolsRequest)
	if !ok || request.Model != constant.DeepSeekSearchModel || info.OriginModelName != constant.DeepSeekSearchModel {
		return types.NewOpenAIError(errors.New("invalid search subject"), types.ErrorCodeInvalidRequest, 400, types.ErrOptionWithSkipRetry())
	}
	// Do not run generic model mapping: this native protocol has no model field.
	// Administrative body overrides cannot change authorization, grouping or price.
	data, err := relaycommon.ApplyParamOverrideWithRelayInfo(request.RawBody, info)
	if err != nil {
		return newAPIErrorFromParamOverride(err)
	}
	if err = helper.ValidateDeepSeekSearchBody(data); err != nil {
		return types.NewOpenAIError(err, types.ErrorCodeInvalidRequest, 400, types.ErrOptionWithSkipRetry())
	}
	body, closer, err := relaycommon.NewOutboundJSONBody(data)
	if err != nil {
		return types.NewOpenAIError(errors.New("invalid search request body"), types.ErrorCodeConvertRequestFailed, 400, types.ErrOptionWithSkipRetry())
	}
	defer closer.Close()
	parent := c.Request
	ctx, cancel := context.WithTimeout(parent.Context(), 30*time.Second)
	c.Request = parent.WithContext(ctx)
	defer func() { c.Request = parent; cancel() }()
	adaptor := GetAdaptor(info.ApiType)
	if adaptor == nil {
		return types.NewOpenAIError(errors.New("unsupported search channel"), types.ErrorCodeInvalidApiType, 400, types.ErrOptionWithSkipRetry())
	}
	adaptor.Init(info)
	response, err := adaptor.DoRequest(c, info, body)
	if err != nil {
		// A lost response is not proof that the provider did not execute or bill.
		return types.NewOpenAIError(errors.New("upstream search transport failed"), types.ErrorCodeDoRequestFailed, 502, types.ErrOptionWithSkipRetry())
	}
	resp, ok := response.(*http.Response)
	if !ok || resp == nil || resp.Body == nil {
		return types.NewOpenAIError(errors.New("invalid upstream search response"), types.ErrorCodeBadResponse, 502, types.ErrOptionWithSkipRetry())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, toolsSearchResponseLimit+1))
	if err != nil || len(raw) > toolsSearchResponseLimit || ctx.Err() != nil {
		return types.NewOpenAIError(errors.New("incomplete or oversized upstream search response"), types.ErrorCodeReadResponseBodyFailed, 502, types.ErrOptionWithSkipRetry())
	}
	if resp.StatusCode != http.StatusOK {
		status := resp.StatusCode
		if status < 400 || status > 599 {
			status = 502
		}
		failure := types.NewOpenAIError(errors.New("upstream search request failed"), types.ErrorCodeBadResponse, status)
		if resp.StatusCode != 408 && resp.StatusCode != 429 && (resp.StatusCode < 500 || resp.StatusCode > 599) {
			types.ErrOptionWithSkipRetry()(failure)
		}
		return failure
	}
	nonempty, err := validToolsSearchResponse(raw)
	if err != nil {
		return types.NewOpenAIError(errors.New("invalid upstream search result"), types.ErrorCodeBadResponse, 502, types.ErrOptionWithSkipRetry())
	}
	if nonempty {
		// Existing fixed-request pricing works with zero ordinary tokens. This does
		// not add the alpha/web_search_preview surcharge or use result count as Usage.
		service.PostTextConsumeQuota(c, info, &dto.Usage{}, nil)
	} else if info.Billing != nil {
		info.Billing.Refund(c)
	}
	c.Header("Content-Type", "application/json")
	c.Status(http.StatusOK)
	if _, err = c.Writer.Write(raw); err != nil {
		// Billing has settled. A downstream failure must not replay or refund it.
		logger.LogError(c, "search response delivery failed")
	}
	return nil
}

func validToolsSearchResponse(raw []byte) (bool, error) {
	root, err := common.DecodeRawJSONObject(raw)
	if err != nil {
		return false, err
	}
	if common.GetJsonType(root["results"]) != "array" {
		return false, errors.New("results array required")
	}
	var results []common.RawMessage
	if err = common.Unmarshal(root["results"], &results); err != nil {
		return false, err
	}
	for _, raw := range results {
		result, err := common.DecodeRawJSONObject(raw)
		if err != nil {
			return false, err
		}
		for _, key := range []string{"title", "url", "snippet", "summary", "content"} {
			var value string
			if common.GetJsonType(result[key]) != "string" || common.Unmarshal(result[key], &value) != nil {
				return false, errors.New("invalid search string field")
			}
		}
		for _, key := range []string{"site_name", "site_icon", "date"} {
			value, present := result[key]
			if !present {
				return false, errors.New("missing nullable search field")
			}
			if common.GetJsonType(value) == "null" {
				continue
			}
			var text string
			if common.GetJsonType(value) != "string" || common.Unmarshal(value, &text) != nil {
				return false, errors.New("invalid nullable search field")
			}
			if key == "date" {
				if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
					return false, err
				}
			}
		}
		var score float64
		if common.GetJsonType(result["rerank_score"]) != "number" || common.Unmarshal(result["rerank_score"], &score) != nil || math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 3 {
			return false, errors.New("invalid search relevance")
		}
		var authority int
		if common.GetJsonType(result["authority"]) != "number" || common.Unmarshal(result["authority"], &authority) != nil || authority < -1 || authority > 4 {
			return false, errors.New("invalid search authority")
		}
	}
	return len(results) > 0, nil
}
