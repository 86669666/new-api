package controller

import (
	"maps"
	"net/http"
	"slices"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/ratio_setting"

	"github.com/gin-gonic/gin"
)

func filterPricingByUsableGroups(pricing []model.Pricing, usableGroup map[string]string) []model.Pricing {
	if len(pricing) == 0 {
		return pricing
	}
	if len(usableGroup) == 0 {
		return []model.Pricing{}
	}

	filtered := make([]model.Pricing, 0, len(pricing))
	for _, item := range pricing {
		if common.StringsContains(item.EnableGroup, "all") {
			filtered = append(filtered, item)
			continue
		}
		for _, group := range item.EnableGroup {
			if _, ok := usableGroup[group]; ok {
				filtered = append(filtered, item)
				break
			}
		}
	}
	return filtered
}

type pricingWithCapabilityMetadata struct {
	model.Pricing
	model.ModelCapabilityMetadata
}

func projectPricingCapabilityMetadata(pricing []model.Pricing) []pricingWithCapabilityMetadata {
	if pricing == nil {
		return nil
	}
	metadata := model.ModelCapabilityMetadataSnapshot()
	result := make([]pricingWithCapabilityMetadata, len(pricing))
	for i, item := range pricing {
		result[i] = pricingWithCapabilityMetadata{Pricing: item, ModelCapabilityMetadata: metadata[item.ModelName]}
	}
	return result
}

func GetPricing(c *gin.Context) {
	if selected, trusted := middleware.TokenPricingRequest(c); selected {
		c.Header("Cache-Control", "private, no-store")
		token, ownerGroup, authenticated := middleware.GetReadOnlyToken(c)
		if !trusted || !authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Invalid Bearer token"})
			return
		}
		writeTokenPricing(c, token, ownerGroup)
		return
	}
	pricing := model.GetPricing()
	userId, exists := c.Get("id")
	usableGroup := map[string]string{}
	groupRatio := map[string]float64{}
	maps.Copy(groupRatio, ratio_setting.GetGroupRatioCopy())
	var group string
	if exists {
		user, err := model.GetUserCache(userId.(int))
		if err == nil {
			group = user.Group
			for g := range groupRatio {
				ratio, ok := ratio_setting.GetGroupGroupRatio(group, g)
				if ok {
					groupRatio[g] = ratio
				}
			}
		}
	}

	usableGroup = service.GetUserUsableGroups(group)
	pricing = filterPricingByUsableGroups(pricing, usableGroup)
	// check groupRatio contains usableGroup
	for group := range ratio_setting.GetGroupRatioCopy() {
		if _, ok := usableGroup[group]; !ok {
			delete(groupRatio, group)
		}
	}

	c.JSON(200, gin.H{
		"success":            true,
		"data":               projectPricingCapabilityMetadata(pricing),
		"vendors":            model.GetVendors(),
		"group_ratio":        groupRatio,
		"usable_group":       usableGroup,
		"supported_endpoint": model.GetSupportedEndpointMap(),
		"auto_groups":        service.GetUserAutoGroup(group),
		"pricing_version":    "a42d372ccf0b5dd13ecf71203521f9d2",
	})
}

func writeTokenPricing(c *gin.Context, token model.Token, ownerGroup string) {
	group := token.Group
	if group == "" {
		group = ownerGroup
	}
	permitted := service.GetUserUsableGroups(ownerGroup)
	candidates := []string{}
	autoGroups := []string{}
	if group == "auto" {
		if _, allowed := permitted["auto"]; allowed {
			custom, err := token.GetAutoGroups()
			if err == nil {
				if len(custom) == 0 {
					candidates = service.GetUserAutoGroup(ownerGroup)
				} else {
					candidates = service.FilterUserTokenAutoGroups(ownerGroup, custom)
				}
			}
		}
	} else if service.IsUserSelectableGroup(ownerGroup, group) {
		candidates = append(candidates, group)
	}
	candidates = slices.DeleteFunc(candidates, func(candidate string) bool { return candidate == "all" })
	if group == "auto" {
		autoGroups = candidates
	}
	usableGroups := make(map[string]string, len(candidates))
	groupRatios := make(map[string]float64, len(candidates))
	for _, candidate := range candidates {
		usableGroups[candidate] = permitted[candidate]
		groupRatios[candidate] = service.GetUserGroupRatio(ownerGroup, candidate)
	}
	cached := model.GetPricing()
	pricing := make([]model.Pricing, 0, len(cached))
	for _, item := range cached {
		groups := make([]string, 0, len(candidates))
		all := slices.Contains(item.EnableGroup, "all")
		for _, candidate := range candidates {
			if all || slices.Contains(item.EnableGroup, candidate) {
				groups = append(groups, candidate)
			}
		}
		if len(groups) == 0 {
			continue
		}
		item.EnableGroup = groups
		pricing = append(pricing, item)
	}
	c.JSON(http.StatusOK, gin.H{
		"success":            true,
		"data":               projectPricingCapabilityMetadata(pricing),
		"group":              group,
		"vendors":            model.GetVendors(),
		"group_ratio":        groupRatios,
		"usable_group":       usableGroups,
		"supported_endpoint": model.GetSupportedEndpointMap(),
		"auto_groups":        autoGroups,
		"pricing_version":    "a42d372ccf0b5dd13ecf71203521f9d2",
	})
}

func ResetModelRatio(c *gin.Context) {
	defaultStr := ratio_setting.DefaultModelRatio2JSONString()
	err := model.UpdateOption("ModelRatio", defaultStr)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	err = ratio_setting.UpdateModelRatioByJSONString(defaultStr)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccessT(c, "Model ratios reset", nil)
}
