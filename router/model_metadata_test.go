package router

import (
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModelMetadataDeclarationContract(t *testing.T) {
	for _, raw := range []string{
		`{"m":{"capabilities":null}}`, `{"m":{"capabilities":["vision",null]}}`,
		`{"m":{"capabilities":["vision","vision"]}}`, `{"m":{"capabilities":["VISION"]}}`,
		`{"m":{"capabilities":["tool_use"]}}`, `{"m":{"Capabilities":[]}}`,
		`{"m":{"capabilities":[],"capabilities":["tools"]}}`,
		`{"m":{"capabilities":["vision"],"vision":false}}`,
		`{"m":{"capabilities":[],"tool_use":true}}`,
		`{"m":{"capabilities":["reasoning"],"reasoning":false}}`,
		`{"m":{"input_modalities":["text","text"]}}`, `{"m":{"input_modalities":["unknown"]}}`,
		`{"m":{"output_modalities":["IMAGE"]}}`, `{"m":{"output_modalities":"text"}}`,
		`{"m":{"context_length":10,"max_output_tokens":11}}`,
		`{"m":{"display_name":""}}`, `{"m":{"display_name":" padded "}}`,
		`{"m":{"display_name":"bad\nname"}}`, `{"m":{"description":"bad\u0000text"}}`,
		`{"m":{"description":null}}`, `{"m":{"metadata_source":{"kind":"official"}}}`,
	} {
		_, err := model.ParseModelCapabilityMetadata(raw)
		require.Error(t, err, raw)
	}
	for _, field := range []string{"display_name", "description"} {
		raw, err := common.Marshal(map[string]any{"m": map[string]string{field: strings.Repeat("x", 4097)}})
		require.NoError(t, err)
		_, err = model.ParseModelCapabilityMetadata(string(raw))
		require.Error(t, err, field)
	}
	legacy, err := model.ParseModelCapabilityMetadata(`{"m":{"vision":false}}`)
	require.NoError(t, err)
	assert.Nil(t, legacy["m"].Capabilities, "one known boolean does not establish a complete set")
	assert.Nil(t, legacy["m"].Reasoning)
	assert.Nil(t, legacy["m"].InputModalities)
	assert.Equal(t, false, *legacy["m"].Vision)

	first, err := model.ParseModelCapabilityMetadata(`{"m":{"capabilities":["vision","tools","web_search","structured_output"],"input_modalities":["text","image"],"output_modalities":[],"display_name":"Model M","description":"Declared description"}}`)
	require.NoError(t, err)
	second, err := model.ParseModelCapabilityMetadata(`{"m":{"description":"Declared description","display_name":"Model M","output_modalities":[],"input_modalities":["image","text"],"tool_use":true,"reasoning":false,"vision":true,"capabilities":["structured_output","web_search","tools","vision"]},"unrelated":{"reasoning":false}}`)
	require.NoError(t, err)
	assert.Equal(t, first["m"], second["m"], "set ordering and redundant consistent booleans do not change the declaration version")
	assert.Equal(t, []string{"structured_output", "tools", "vision", "web_search"}, *first["m"].Capabilities)
	assert.Equal(t, false, *first["m"].Reasoning)
	assert.Equal(t, "administrator", first["m"].Source.Kind)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, first["m"].Source.Version)
	empty, err := model.ParseModelCapabilityMetadata(`{"m":{"capabilities":[],"input_modalities":[],"output_modalities":[],"description":""}}`)
	require.NoError(t, err)
	encoded, err := common.Marshal(empty["m"])
	require.NoError(t, err)
	var projected map[string]any
	require.NoError(t, common.Unmarshal(encoded, &projected))
	assert.Equal(t, []any{}, projected["capabilities"])
	assert.Equal(t, []any{}, projected["input_modalities"])
	assert.Equal(t, []any{}, projected["output_modalities"])
	assert.Equal(t, "", projected["description"])
	assert.Equal(t, false, projected["vision"])
	assert.Equal(t, false, projected["reasoning"])
	assert.Equal(t, false, projected["tool_use"])
}

// The existing dedicated fixture exercises the actual router, authorization,
// option persistence and response encoder on each explicitly supplied dialect.
func TestModelMetadataCatalogueHTTP(t *testing.T) {
	f := newOrganizationProfileFixture(t, "g19-model-capability-metadata")
	require.NoError(t, f.db.AutoMigrate(&model.Model{}, &model.Vendor{}, &model.Channel{}, &model.Ability{}))
	common.OptionMapRWMutex.Lock()
	previousOptions := common.OptionMap
	common.OptionMap = map[string]string{}
	common.OptionMapRWMutex.Unlock()
	previousSelfUse := operation_setting.SelfUseModeEnabled
	operation_setting.SelfUseModeEnabled = true
	t.Cleanup(func() {
		common.OptionMapRWMutex.Lock()
		common.OptionMap = previousOptions
		common.OptionMapRWMutex.Unlock()
		operation_setting.SelfUseModeEnabled = previousSelfUse
		model.InvalidatePricingCache()
	})
	for _, snapshot := range []struct {
		before  string
		restore func(string) error
		next    string
	}{
		{setting.UserUsableGroups2JSONString(), setting.UpdateUserUsableGroupsByJSONString, `{"default":"Default","g1":"One","g2":"Two","auto":"Auto"}`},
		{setting.AutoGroups2JsonString(), setting.UpdateAutoGroupsByJsonString, `["g1","g2"]`},
		{ratio_setting.GroupRatio2JSONString(), ratio_setting.UpdateGroupRatioByJSONString, `{"default":1,"g1":2,"g2":3}`},
		{ratio_setting.ModelPrice2JSONString(), ratio_setting.UpdateModelPriceByJSONString, `{"catalog-model":0.05,"catalog-empty":0.06,"catalog-partial":0.07,"vendor/catalog-model":0.08,"CATALOG-MODEL":0.09,"catalog-hidden":0.10,"gpt-4o":0.11}`},
	} {
		t.Cleanup(func() { require.NoError(t, snapshot.restore(snapshot.before)) })
		require.NoError(t, snapshot.restore(snapshot.next))
	}
	special := ratio_setting.GetGroupRatioSetting().GroupSpecialUsableGroup
	previousSpecial := special.ReadAll()
	special.Clear()
	t.Cleanup(func() { special.Clear(); special.AddAll(previousSpecial) })
	require.NoError(t, model.UpdateOption("HeaderNavModules", `{"pricing":true}`))
	for _, name := range []string{"catalog-model", "catalog-empty", "catalog-partial", "vendor/catalog-model", "CATALOG-MODEL", "catalog-hidden", "gpt-4o"} {
		require.NoError(t, f.db.Create(&model.Model{ModelName: name, Description: "Catalog description", Status: 1, SyncOfficial: 1}).Error)
		channel := model.Channel{Type: constant.ChannelTypeOpenAI, Name: name, Key: "unused", Status: common.ChannelStatusEnabled}
		require.NoError(t, f.db.Create(&channel).Error)
		group := "g1"
		if name == "catalog-hidden" {
			group = "g2"
		}
		require.NoError(t, f.db.Create(&model.Ability{Group: group, Model: name, ChannelId: channel.Id, Enabled: true}).Error)
	}
	var relay model.Token
	require.NoError(t, f.db.Where("user_id = ?", f.users["owner"].Id).First(&relay).Error)
	require.NoError(t, f.db.Model(&relay).Updates(map[string]any{"group": "g1", "unlimited_quota": true}).Error)
	limitedKey, err := common.GenerateRandomCharsKey(40)
	require.NoError(t, err)
	require.NoError(t, f.db.Create(&model.Token{UserId: relay.UserId, Key: limitedKey, Group: "g1", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true, ModelLimitsEnabled: true, ModelLimits: "catalog-model,catalog-hidden,not-enabled"}).Error)
	f.bearer["limited"] = "sk-" + limitedKey
	model.InvalidatePricingCache()
	const declaration = `{"catalog-model":{"context_length":128000,"max_output_tokens":8192,"capabilities":["vision","tools","reasoning","web_search","structured_output"],"input_modalities":["text","image"],"output_modalities":["text"],"display_name":"Administrator model","description":"Administrator description"},"catalog-empty":{"capabilities":[],"input_modalities":[],"output_modalities":[],"description":""},"catalog-partial":{"reasoning":false},"catalog-hidden":{"capabilities":["vision"]},"gpt-4o":{"display_name":"Static model declaration"}}`
	write := func(t *testing.T, raw string) map[string]any {
		t.Helper()
		body, err := common.Marshal(map[string]string{"key": model.ModelCapabilityMetadataOptionKey, "value": raw})
		require.NoError(t, err)
		status, _, result := f.request(t, http.MethodPut, "/api/option/", "root", string(body), nil)
		require.Equal(t, http.StatusOK, status)
		return result
	}
	read := func(t *testing.T, path, actor string) map[string]map[string]any {
		t.Helper()
		status, headers, result := f.request(t, http.MethodGet, path, actor, "", nil)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, true, result["success"])
		if path == "/api/pricing" {
			assert.Equal(t, "private, no-store", headers.Get("Cache-Control"))
		}
		items, ok := result["data"].([]any)
		require.True(t, ok)
		byName := make(map[string]map[string]any, len(items))
		for _, item := range items {
			row, ok := item.(map[string]any)
			require.True(t, ok)
			field := "id"
			if path == "/api/pricing" {
				field = "model_name"
			}
			name, ok := row[field].(string)
			require.True(t, ok)
			byName[name] = row
		}
		return byName
	}
	paths := []string{"/api/pricing", "/v1/models"}
	baseline := make(map[string]map[string]map[string]any, len(paths))
	for _, path := range paths {
		baseline[path] = read(t, path, "relay")
	}
	cached, err := common.Marshal(model.GetPricing())
	require.NoError(t, err)
	status, _, _ := f.request(t, http.MethodGet, "/v1/models", "", "", nil)
	assert.Equal(t, http.StatusUnauthorized, status)
	status, _, _ = f.request(t, http.MethodGet, "/v1/models", "sk-invalid", "", nil)
	assert.Equal(t, http.StatusUnauthorized, status)
	for _, actor := range []string{"", "owner", "relay"} {
		body, err := common.Marshal(map[string]string{"key": model.ModelCapabilityMetadataOptionKey, "value": declaration})
		require.NoError(t, err)
		status, _, result := f.request(t, http.MethodPut, "/api/option/", actor, string(body), nil)
		assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, status)
		assert.Equal(t, false, result["success"])
	}
	require.Equal(t, true, write(t, declaration)["success"])
	fields := []string{"context_length", "max_output_tokens", "capabilities", "vision", "reasoning", "tool_use", "input_modalities", "output_modalities", "display_name", "metadata_source"}
	var source any
	for _, path := range paths {
		rows := read(t, path, "relay")
		require.Contains(t, rows, "catalog-model")
		exact := rows["catalog-model"]
		encoded, err := common.Marshal(exact)
		require.NoError(t, err)
		t.Logf("path=%s declared_row=%s", path, encoded)
		assert.Equal(t, float64(128000), exact["context_length"])
		assert.Equal(t, float64(8192), exact["max_output_tokens"])
		assert.Equal(t, []any{"reasoning", "structured_output", "tools", "vision", "web_search"}, exact["capabilities"])
		assert.Equal(t, []any{"image", "text"}, exact["input_modalities"])
		assert.Equal(t, []any{"text"}, exact["output_modalities"])
		assert.Equal(t, true, exact["vision"])
		assert.Equal(t, true, exact["reasoning"])
		assert.Equal(t, true, exact["tool_use"])
		assert.Equal(t, "Administrator model", exact["display_name"])
		assert.Equal(t, "Administrator description", exact["description"])
		if source == nil {
			source = exact["metadata_source"]
		}
		assert.Equal(t, source, exact["metadata_source"], "both entry points identify the same declaration")
		assert.Equal(t, []any{}, rows["catalog-empty"]["capabilities"])
		assert.Equal(t, []any{}, rows["catalog-empty"]["input_modalities"])
		assert.Equal(t, []any{}, rows["catalog-empty"]["output_modalities"])
		assert.Equal(t, "", rows["catalog-empty"]["description"])
		assert.Equal(t, false, rows["catalog-empty"]["vision"])
		assert.Equal(t, false, rows["catalog-empty"]["reasoning"])
		assert.Equal(t, false, rows["catalog-empty"]["tool_use"])
		assert.NotContains(t, rows, "catalog-hidden")
		assert.Equal(t, false, rows["catalog-partial"]["reasoning"])
		for _, name := range []string{"vendor/catalog-model", "CATALOG-MODEL", "catalog-partial"} {
			for _, field := range fields {
				if name == "catalog-partial" && (field == "reasoning" || field == "metadata_source") {
					continue
				}
				assert.NotContains(t, rows[name], field, name)
			}
		}
		for name, row := range rows {
			for _, field := range fields {
				delete(row, field)
			}
			if path == "/api/pricing" {
				row["description"] = baseline[path][name]["description"]
			} else {
				delete(row, "description")
			}
		}
		assert.Equal(t, baseline[path], rows, "original pricing, owners and endpoint order remain exact")
	}
	limited := read(t, "/v1/models", "limited")
	assert.Len(t, limited, 1, "metadata cannot widen token model or group visibility")
	assert.Contains(t, limited, "catalog-model")
	cacheAfter, err := common.Marshal(model.GetPricing())
	require.NoError(t, err)
	assert.Equal(t, cached, cacheAfter, "shared pricing data remains unchanged")
	status, _, static := f.request(t, http.MethodGet, "/v1/models/gpt-4o", "relay", "", nil)
	require.Equal(t, http.StatusOK, status)
	assert.NotContains(t, static, "display_name", "list enrichment must not mutate the static model map")
	before := read(t, "/v1/models", "relay")
	var stored model.Option
	require.NoError(t, f.db.Where(&model.Option{Key: model.ModelCapabilityMetadataOptionKey}).First(&stored).Error)
	common.OptionMapRWMutex.RLock()
	optionsBefore := maps.Clone(common.OptionMap)
	common.OptionMapRWMutex.RUnlock()
	for _, invalid := range []string{
		`{"catalog-model":{"capabilities":["tools"],"tool_use":false}}`,
		`{"catalog-model":{"capabilities":["tools","tools"]}}`,
		`{"catalog-model":{"input_modalities":["unknown"]}}`,
		`{"catalog-model":{"display_name":"bad\nname"}}`,
	} {
		result := write(t, invalid)
		assert.Equal(t, false, result["success"])
		assert.Equal(t, "Invalid parameters", result["message"])
		var unchanged model.Option
		require.NoError(t, f.db.Where(&model.Option{Key: model.ModelCapabilityMetadataOptionKey}).First(&unchanged).Error)
		assert.Equal(t, stored, unchanged)
		common.OptionMapRWMutex.RLock()
		optionsAfter := maps.Clone(common.OptionMap)
		common.OptionMapRWMutex.RUnlock()
		assert.Equal(t, optionsBefore, optionsAfter)
		assert.Equal(t, before, read(t, "/v1/models", "relay"))
	}
	require.Equal(t, true, write(t, `{"catalog-model":{"display_name":"Replacement"}}`)["success"])
	for _, path := range paths {
		rows := read(t, path, "relay")
		assert.Equal(t, "Replacement", rows["catalog-model"]["display_name"])
		assert.NotEqual(t, source, rows["catalog-model"]["metadata_source"])
		assert.NotContains(t, rows["catalog-model"], "capabilities")
		assert.NotContains(t, rows["catalog-empty"], "capabilities")
		assert.NotContains(t, rows["catalog-partial"], "reasoning")
	}
	// Invalid persisted configuration fails closed instead of serving old claims.
	common.OptionMapRWMutex.Lock()
	common.OptionMap[model.ModelCapabilityMetadataOptionKey] = `{"catalog-model":{"capabilities":["invalid"]}}`
	common.OptionMapRWMutex.Unlock()
	for _, path := range paths {
		assert.Equal(t, baseline[path], read(t, path, "relay"))
	}
	require.Equal(t, true, write(t, `{}`)["success"])
	for _, path := range paths {
		assert.Equal(t, baseline[path], read(t, path, "relay"))
	}
}
