package controller

import (
	"net/http"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func GetOAuthUserInfo(c *gin.Context) {
	access, ok := middleware.GetOAuthUserInfoAccess(c)
	if !ok {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
		return
	}
	profile, err := access.Read(c.Request.Context())
	if err != nil {
		middleware.WriteOAuthResourceError(c, err)
		return
	}
	data, err := common.Marshal(profile)
	if err != nil {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthResourceUnavailable)
		return
	}
	c.Data(http.StatusOK, "application/json", data)
}

func GetOAuthBalance(c *gin.Context) {
	userID, _, ok := oauthResourceActor(c, "balance:read")
	if !ok {
		return
	}
	quota, used, err := model.OAuthUserQuota(userID)
	if err != nil || common.QuotaPerUnit <= 0 {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthResourceUnavailable)
		return
	}
	common.ApiSuccess(c, gin.H{
		"quota": quota, "used_quota": used, "quota_per_unit": common.QuotaPerUnit,
		"display_amount": float64(quota) / common.QuotaPerUnit,
	})
}

func GetOAuthUsage(c *gin.Context) {
	userID, _, ok := oauthResourceActor(c, "usage:read")
	if !ok {
		return
	}
	pageInfo, err := oauthUsagePage(c)
	if err != nil {
		middleware.WriteOAuthResourceError(c, err)
		return
	}
	filter := logFilterFromQuery(c, false)
	start, err := limitLogTimeRange(filter.StartTimestamp, filter.EndTimestamp)
	if err != nil {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthResourceRequest)
		return
	}
	filter.StartTimestamp = start
	logs, total, err := model.GetUserLogs(userID, filter, pageInfo.GetStartIdx(), pageInfo.GetPageSize())
	if err != nil {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthResourceUnavailable)
		return
	}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(logs)
	common.ApiSuccess(c, pageInfo)
}

func GetOAuthTokens(c *gin.Context) {
	userID, clientID, ok := oauthResourceActor(c, "tokens:read")
	if !ok {
		return
	}
	tokens, err := model.ListOAuthIssuedTokens(userID, clientID)
	if err != nil {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthResourceUnavailable)
		return
	}
	views := make([]gin.H, 0, len(tokens))
	for _, token := range tokens {
		views = append(views, gin.H{
			"id": token.Id, "name": token.Name, "status": token.Status,
			"remain_quota": token.RemainQuota, "used_quota": token.UsedQuota,
			"unlimited_quota": token.UnlimitedQuota, "expired_time": token.ExpiredTime,
			"created_time": token.CreatedTime,
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": views})
}

func PostOAuthToken(c *gin.Context) {
	access, ok := middleware.GetOAuthUserInfoAccess(c)
	if !ok {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
		return
	}
	userID, clientID, err := access.RequireFresh(c.Request.Context(), "tokens:write")
	if err != nil {
		middleware.WriteOAuthResourceScopeError(c, err, "tokens:write")
		return
	}
	plain, first, err := model.IssueOAuthClientToken(userID, clientID, access.IssuedTokenQuota(), access.IssuedTokenExpireDays())
	if err != nil {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthResourceUnavailable)
		return
	}
	item := gin.H{}
	if first {
		item["key"] = plain
	}
	c.JSON(http.StatusOK, gin.H{"data": []gin.H{item}})
}

func oauthResourceActor(c *gin.Context, scope string) (int, string, bool) {
	access, ok := middleware.GetOAuthUserInfoAccess(c)
	if !ok {
		middleware.WriteOAuthResourceError(c, service.ErrOAuthInvalidToken)
		return 0, "", false
	}
	userID, clientID, err := access.RequireFresh(c.Request.Context(), scope)
	if err != nil {
		middleware.WriteOAuthResourceScopeError(c, err, scope)
		return 0, "", false
	}
	return userID, clientID, true
}

func oauthUsagePage(c *gin.Context) (*common.PageInfo, error) {
	query := c.Request.URL.Query()
	raw, present := "", false
	if query.Has("p") {
		raw, present = query.Get("p"), true
	} else if query.Has("page") {
		raw, present = query.Get("page"), true
	}
	if present {
		page, err := strconv.Atoi(raw)
		if err != nil || page < 1 {
			return nil, service.ErrOAuthResourceRequest
		}
	}
	for _, key := range []string{"page_size", "ps", "size"} {
		if !query.Has(key) {
			continue
		}
		size, err := strconv.Atoi(query.Get(key))
		if err != nil || size < 1 || size > 100 {
			return nil, service.ErrOAuthResourceRequest
		}
	}
	return common.GetPageQueryWithPageAlias(c), nil
}
