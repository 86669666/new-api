package controller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type tokenAPIResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type tokenPageResponse struct {
	Items []tokenResponseItem `json:"items"`
}

type tokenResponseItem struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Key    string `json:"key"`
	Status int    `json:"status"`
}

type tokenKeyResponse struct {
	Key string `json:"key"`
}

type sqliteColumnInfo struct {
	Name string `gorm:"column:name"`
	Type string `gorm:"column:type"`
}

type legacyToken struct {
	Id                 int    `gorm:"primaryKey"`
	UserId             int    `gorm:"index"`
	Key                string `gorm:"column:key;type:char(48);uniqueIndex"`
	Status             int    `gorm:"default:1"`
	Name               string `gorm:"index"`
	CreatedTime        int64  `gorm:"bigint"`
	AccessedTime       int64  `gorm:"bigint"`
	ExpiredTime        int64  `gorm:"bigint;default:-1"`
	RemainQuota        int    `gorm:"default:0"`
	UnlimitedQuota     bool
	ModelLimitsEnabled bool
	ModelLimits        string  `gorm:"type:text"`
	AllowIps           *string `gorm:"default:''"`
	UsedQuota          int     `gorm:"default:0"`
	Group              string  `gorm:"column:group;default:''"`
	CrossGroupRetry    bool
	DeletedAt          gorm.DeletedAt `gorm:"index"`
}

func (legacyToken) TableName() string {
	return "tokens"
}

func openTokenControllerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	gin.SetMode(gin.TestMode)
	common.SetDatabaseTypes(common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	common.RedisEnabled = false

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	model.DB = db
	model.LOG_DB = db

	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})

	return db
}

func migrateTokenControllerTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()

	if err := db.AutoMigrate(&model.Token{}); err != nil {
		t.Fatalf("failed to migrate token table: %v", err)
	}
}

func setupTokenControllerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db := openTokenControllerTestDB(t)
	migrateTokenControllerTestDB(t, db)
	return db
}

func openTokenControllerExternalDB(t *testing.T, dialect string, dsn string) (*gorm.DB, *bool) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	common.RedisEnabled = false

	var (
		db     *gorm.DB
		dbType common.DatabaseType
		err    error
	)
	switch dialect {
	case "mysql":
		dbType = common.DatabaseTypeMySQL
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	case "postgres":
		dbType = common.DatabaseTypePostgreSQL
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	default:
		t.Fatalf("unsupported dialect %q", dialect)
	}
	common.SetDatabaseTypes(dbType, dbType)
	if err != nil {
		t.Fatalf("failed to open %s db: %v", dialect, err)
	}

	model.DB = db
	model.LOG_DB = db

	if db.Migrator().HasTable("tokens") {
		t.Skipf("refusing to run %s migration compatibility test against external database because tokens table already exists", dialect)
	}

	managedTokensTable := new(bool)

	t.Cleanup(func() {
		if *managedTokensTable && db.Migrator().HasTable("tokens") {
			_ = db.Migrator().DropTable("tokens")
		}
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})

	return db, managedTokensTable
}

func seedToken(t *testing.T, db *gorm.DB, userID int, name string, rawKey string) *model.Token {
	t.Helper()

	token := &model.Token{
		UserId:         userID,
		Name:           name,
		Key:            rawKey,
		Status:         common.TokenStatusEnabled,
		CreatedTime:    1,
		AccessedTime:   1,
		ExpiredTime:    -1,
		RemainQuota:    100,
		UnlimitedQuota: true,
		Group:          "default",
	}
	if err := db.Create(token).Error; err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	return token
}

func newAuthenticatedContext(t *testing.T, method string, target string, body any, userID int) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()

	var requestBody *bytes.Reader
	if body != nil {
		payload, err := common.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		requestBody = bytes.NewReader(payload)
	} else {
		requestBody = bytes.NewReader(nil)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, requestBody)
	if body != nil {
		ctx.Request.Header.Set("Content-Type", "application/json")
	}
	ctx.Set("id", userID)
	ctx.Set("auth_identity", service.AuthIdentity{UserID: userID})
	return ctx, recorder
}

func decodeAPIResponse(t *testing.T, recorder *httptest.ResponseRecorder) tokenAPIResponse {
	t.Helper()

	var response tokenAPIResponse
	if err := common.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode api response: %v", err)
	}
	return response
}

func getSQLiteColumnType(t *testing.T, db *gorm.DB, tableName string, columnName string) string {
	t.Helper()

	var columns []sqliteColumnInfo
	if err := db.Raw("PRAGMA table_info(" + tableName + ")").Scan(&columns).Error; err != nil {
		t.Fatalf("failed to inspect %s schema: %v", tableName, err)
	}

	for _, column := range columns {
		if column.Name == columnName {
			return strings.ToLower(column.Type)
		}
	}

	t.Fatalf("column %s not found in %s schema", columnName, tableName)
	return ""
}

func getTokenKeyColumnType(t *testing.T, db *gorm.DB, dialect string) string {
	t.Helper()

	switch dialect {
	case "sqlite":
		return getSQLiteColumnType(t, db, "tokens", "key")
	case "mysql":
		var columnType string
		if err := db.Raw(`SELECT COLUMN_TYPE FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`,
			"tokens", "key").Scan(&columnType).Error; err != nil {
			t.Fatalf("failed to inspect mysql token key column: %v", err)
		}
		return strings.ToLower(columnType)
	case "postgres":
		var dataType string
		var maxLength sql.NullInt64
		if err := db.Raw(`SELECT data_type, character_maximum_length
			FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`,
			"tokens", "key").Row().Scan(&dataType, &maxLength); err != nil {
			t.Fatalf("failed to inspect postgres token key column: %v", err)
		}
		switch strings.ToLower(dataType) {
		case "character varying":
			return fmt.Sprintf("varchar(%d)", maxLength.Int64)
		case "character":
			return fmt.Sprintf("char(%d)", maxLength.Int64)
		default:
			if maxLength.Valid {
				return fmt.Sprintf("%s(%d)", strings.ToLower(dataType), maxLength.Int64)
			}
			return strings.ToLower(dataType)
		}
	default:
		t.Fatalf("unsupported dialect %q", dialect)
		return ""
	}
}

func getTokenAutoGroupsColumnType(t *testing.T, db *gorm.DB, dialect string) string {
	t.Helper()

	switch dialect {
	case "sqlite":
		return getSQLiteColumnType(t, db, "tokens", "auto_groups")
	case "mysql":
		var columnType string
		if err := db.Raw(`SELECT DATA_TYPE FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`,
			"tokens", "auto_groups").Scan(&columnType).Error; err != nil {
			t.Fatalf("failed to inspect mysql token auto_groups column: %v", err)
		}
		return strings.ToLower(columnType)
	case "postgres":
		var dataType string
		if err := db.Raw(`SELECT data_type FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`,
			"tokens", "auto_groups").Scan(&dataType).Error; err != nil {
			t.Fatalf("failed to inspect postgres token auto_groups column: %v", err)
		}
		return strings.ToLower(dataType)
	default:
		t.Fatalf("unsupported dialect %q", dialect)
		return ""
	}
}

func runTokenMigrationCompatibilityTest(t *testing.T, db *gorm.DB, dialect string, managedTokensTable *bool) {
	t.Helper()

	legacyKey := strings.Repeat("a", 48)
	longKey := strings.Repeat("b", 64)

	if err := db.AutoMigrate(&legacyToken{}); err != nil {
		t.Fatalf("failed to create legacy token schema: %v", err)
	}
	if managedTokensTable != nil {
		*managedTokensTable = true
	}
	if err := db.Create(&legacyToken{
		UserId:             7,
		Key:                legacyKey,
		Status:             common.TokenStatusEnabled,
		Name:               "legacy-token",
		CreatedTime:        1,
		AccessedTime:       1,
		ExpiredTime:        -1,
		RemainQuota:        100,
		UnlimitedQuota:     true,
		ModelLimitsEnabled: false,
		ModelLimits:        "",
		AllowIps:           common.GetPointer(""),
		UsedQuota:          0,
		Group:              "default",
		CrossGroupRetry:    false,
	}).Error; err != nil {
		t.Fatalf("failed to seed legacy token row: %v", err)
	}

	if got := getTokenKeyColumnType(t, db, dialect); got != "char(48)" {
		t.Fatalf("expected legacy key column type char(48), got %q", got)
	}

	migrateTokenControllerTestDB(t, db)

	if got := getTokenKeyColumnType(t, db, dialect); got != "varchar(128)" {
		t.Fatalf("expected migrated key column type varchar(128), got %q", got)
	}
	if !db.Migrator().HasColumn(&model.Token{}, "auto_groups") {
		t.Fatal("expected migration to add auto_groups column")
	}
	if got := getTokenAutoGroupsColumnType(t, db, dialect); got != "text" {
		t.Fatalf("expected migrated auto_groups column type text, got %q", got)
	}

	var migratedToken model.Token
	if err := db.First(&migratedToken, "name = ?", "legacy-token").Error; err != nil {
		t.Fatalf("failed to load migrated token row: %v", err)
	}
	if migratedToken.Key != legacyKey {
		t.Fatalf("expected migrated token key %q, got %q", legacyKey, migratedToken.Key)
	}
	if migratedToken.Name != "legacy-token" {
		t.Fatalf("expected migrated token name to be preserved, got %q", migratedToken.Name)
	}
	if migratedToken.AutoGroups != "" {
		t.Fatalf("expected legacy token to inherit global Auto groups, got %q", migratedToken.AutoGroups)
	}
	require.True(t, db.Migrator().HasColumn(&model.Token{}, "allow_user_quota_query"))
	assert.False(t, migratedToken.AllowUserQuotaQuery, "tokens created before the upgrade keep user quota queries off")

	inserted := model.Token{
		UserId:             8,
		Name:               "long-token",
		Key:                longKey,
		Status:             common.TokenStatusEnabled,
		CreatedTime:        1,
		AccessedTime:       1,
		ExpiredTime:        -1,
		RemainQuota:        200,
		UnlimitedQuota:     true,
		ModelLimitsEnabled: false,
		ModelLimits:        "",
		AllowIps:           common.GetPointer(""),
		UsedQuota:          0,
		Group:              "default",
		CrossGroupRetry:    false,
	}
	if err := db.Create(&inserted).Error; err != nil {
		t.Fatalf("failed to insert long token after migration: %v", err)
	}

	var fetched model.Token
	if err := db.First(&fetched, "id = ?", inserted.Id).Error; err != nil {
		t.Fatalf("failed to fetch long token after migration: %v", err)
	}
	if fetched.Key != longKey {
		t.Fatalf("expected long token key %q, got %q", longKey, fetched.Key)
	}
}

func TestTokenAutoMigrateUsesVarchar128KeyColumn(t *testing.T) {
	db := setupTokenControllerTestDB(t)

	if got := getTokenKeyColumnType(t, db, "sqlite"); got != "varchar(128)" {
		t.Fatalf("expected key column type varchar(128), got %q", got)
	}
	if got := getSQLiteColumnType(t, db, "tokens", "auto_groups"); got != "text" {
		t.Fatalf("expected auto_groups column type text, got %q", got)
	}
}

func TestTokenMigrationFromChar48ToVarchar128(t *testing.T) {
	db := openTokenControllerTestDB(t)
	runTokenMigrationCompatibilityTest(t, db, "sqlite", nil)
}

func TestTokenMigrationFromChar48ToVarchar128MySQL(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set TEST_MYSQL_DSN to run mysql migration compatibility test")
	}

	db, managedTokensTable := openTokenControllerExternalDB(t, "mysql", dsn)
	runTokenMigrationCompatibilityTest(t, db, "mysql", managedTokensTable)
}

func TestTokenMigrationFromChar48ToVarchar128Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set TEST_POSTGRES_DSN to run postgres migration compatibility test")
	}

	db, managedTokensTable := openTokenControllerExternalDB(t, "postgres", dsn)
	runTokenMigrationCompatibilityTest(t, db, "postgres", managedTokensTable)
}

func TestGetAllTokensMasksKeyInResponse(t *testing.T) {
	db := setupTokenControllerTestDB(t)
	token := seedToken(t, db, 1, "list-token", "abcd1234efgh5678")
	seedToken(t, db, 2, "other-user-token", "zzzz1234yyyy5678")

	ctx, recorder := newAuthenticatedContext(t, http.MethodGet, "/api/token/?p=1&size=10", nil, 1)
	GetAllTokens(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var page tokenPageResponse
	if err := common.Unmarshal(response.Data, &page); err != nil {
		t.Fatalf("failed to decode token page response: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected exactly one token, got %d", len(page.Items))
	}
	if page.Items[0].Key != token.GetMaskedKey() {
		t.Fatalf("expected masked key %q, got %q", token.GetMaskedKey(), page.Items[0].Key)
	}
	if strings.Contains(recorder.Body.String(), token.Key) {
		t.Fatalf("list response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestSearchTokensMasksKeyInResponse(t *testing.T) {
	db := setupTokenControllerTestDB(t)
	token := seedToken(t, db, 1, "searchable-token", "ijkl1234mnop5678")

	ctx, recorder := newAuthenticatedContext(t, http.MethodGet, "/api/token/search?keyword=searchable-token&p=1&size=10", nil, 1)
	SearchTokens(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var page tokenPageResponse
	if err := common.Unmarshal(response.Data, &page); err != nil {
		t.Fatalf("failed to decode search response: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected exactly one search result, got %d", len(page.Items))
	}
	if page.Items[0].Key != token.GetMaskedKey() {
		t.Fatalf("expected masked search key %q, got %q", token.GetMaskedKey(), page.Items[0].Key)
	}
	if strings.Contains(recorder.Body.String(), token.Key) {
		t.Fatalf("search response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestGetTokenMasksKeyInResponse(t *testing.T) {
	db := setupTokenControllerTestDB(t)
	token := seedToken(t, db, 1, "detail-token", "qrst1234uvwx5678")

	ctx, recorder := newAuthenticatedContext(t, http.MethodGet, "/api/token/"+strconv.Itoa(token.Id), nil, 1)
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(token.Id)}}
	GetToken(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var detail tokenResponseItem
	if err := common.Unmarshal(response.Data, &detail); err != nil {
		t.Fatalf("failed to decode token detail response: %v", err)
	}
	if detail.Key != token.GetMaskedKey() {
		t.Fatalf("expected masked detail key %q, got %q", token.GetMaskedKey(), detail.Key)
	}
	if strings.Contains(recorder.Body.String(), token.Key) {
		t.Fatalf("detail response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestUpdateTokenMasksKeyInResponse(t *testing.T) {
	db := setupTokenOwnerTestDB(t)
	token := seedToken(t, db, 1, "editable-token", "yzab1234cdef5678")

	body := map[string]any{
		"id":                   token.Id,
		"name":                 "updated-token",
		"expired_time":         -1,
		"remain_quota":         100,
		"unlimited_quota":      true,
		"model_limits_enabled": false,
		"model_limits":         "",
		"group":                "default",
		"cross_group_retry":    false,
	}

	ctx, recorder := newAuthenticatedContext(t, http.MethodPut, "/api/token/", body, 1)
	UpdateToken(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var detail tokenResponseItem
	if err := common.Unmarshal(response.Data, &detail); err != nil {
		t.Fatalf("failed to decode token update response: %v", err)
	}
	if detail.Key != token.GetMaskedKey() {
		t.Fatalf("expected masked update key %q, got %q", token.GetMaskedKey(), detail.Key)
	}
	if strings.Contains(recorder.Body.String(), token.Key) {
		t.Fatalf("update response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestGetTokenKeyRequiresOwnershipAndReturnsFullKey(t *testing.T) {
	db := setupTokenOwnerTestDB(t)
	token := seedToken(t, db, 1, "owned-token", "owner1234token5678")

	authorizedCtx, authorizedRecorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/"+strconv.Itoa(token.Id)+"/key", nil, 1)
	authorizedCtx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(token.Id)}}
	GetTokenKey(authorizedCtx)

	authorizedResponse := decodeAPIResponse(t, authorizedRecorder)
	if !authorizedResponse.Success {
		t.Fatalf("expected authorized key fetch to succeed, got message: %s", authorizedResponse.Message)
	}

	var keyData tokenKeyResponse
	if err := common.Unmarshal(authorizedResponse.Data, &keyData); err != nil {
		t.Fatalf("failed to decode token key response: %v", err)
	}
	if keyData.Key != token.GetFullKey() {
		t.Fatalf("expected full key %q, got %q", token.GetFullKey(), keyData.Key)
	}

	unauthorizedCtx, unauthorizedRecorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/"+strconv.Itoa(token.Id)+"/key", nil, 2)
	unauthorizedCtx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(token.Id)}}
	GetTokenKey(unauthorizedCtx)

	unauthorizedResponse := decodeAPIResponse(t, unauthorizedRecorder)
	if unauthorizedResponse.Success {
		t.Fatalf("expected unauthorized key fetch to fail")
	}
	if strings.Contains(unauthorizedRecorder.Body.String(), token.Key) {
		t.Fatalf("unauthorized key response leaked raw token key: %s", unauthorizedRecorder.Body.String())
	}
}

func TestTokenAllowUserQuotaQueryOnCreateAndUpdate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		stored *bool // nil creates the token through the API
		field  any   // nil omits allow_user_quota_query from the request
		want   bool
	}{
		{name: "create without the field turns it on", target: "/api/token/", want: true},
		{name: "create with false keeps it off", target: "/api/token/", field: false},
		{name: "update without the field keeps it on", target: "/api/token/", stored: common.GetPointer(true), want: true},
		{name: "update without the field keeps it off", target: "/api/token/", stored: common.GetPointer(false)},
		{name: "update turns it off", target: "/api/token/", stored: common.GetPointer(true), field: false},
		{name: "update turns it on", target: "/api/token/", stored: common.GetPointer(false), field: true, want: true},
		{name: "status update leaves it alone", target: "/api/token/?status_only=true", stored: common.GetPointer(true), field: false, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTokenOwnerTestDB(t)
			body := map[string]any{"name": "quota-query", "expired_time": -1, "unlimited_quota": true, "status": common.TokenStatusEnabled}
			if tc.field != nil {
				body["allow_user_quota_query"] = tc.field
			}
			var recorder *httptest.ResponseRecorder
			if tc.stored == nil {
				var ctx *gin.Context
				ctx, recorder = newAuthenticatedContext(t, http.MethodPost, tc.target, body, 1)
				AddToken(ctx)
			} else {
				token := seedToken(t, db, 1, "quota-query", "quota-query-key")
				require.NoError(t, db.Model(token).Update("allow_user_quota_query", *tc.stored).Error)
				body["id"] = token.Id
				var ctx *gin.Context
				ctx, recorder = newAuthenticatedContext(t, http.MethodPut, tc.target, body, 1)
				UpdateToken(ctx)
			}
			response := decodeAPIResponse(t, recorder)
			require.True(t, response.Success, response.Message)

			var saved model.Token
			require.NoError(t, db.Where("name = ?", "quota-query").First(&saved).Error)
			assert.Equal(t, tc.want, saved.AllowUserQuotaQuery)
			if tc.stored != nil {
				var returned struct {
					AllowUserQuotaQuery bool `json:"allow_user_quota_query"`
				}
				require.NoError(t, common.Unmarshal(response.Data, &returned))
				assert.Equal(t, tc.want, returned.AllowUserQuotaQuery)
			}
		})
	}
}

func TestGetTokenUsageFollowsTheUserQuotaSwitchAndIPWhitelist(t *testing.T) {
	for _, tc := range []struct {
		name          string
		allow         bool
		expired       bool
		exhausted     bool
		group         string
		allowIps      string
		remoteAddr    string
		wantStatus    int
		wantUserQuota bool
	}{
		{name: "switch off", group: "Named group", remoteAddr: "203.0.113.7:4321", wantStatus: http.StatusOK},
		{name: "switch on without IP whitelist", allow: true, remoteAddr: "203.0.113.7:4321", wantStatus: http.StatusOK, wantUserQuota: true},
		{name: "switch on with matching IP whitelist", group: "auto", allow: true, allowIps: "198.51.100.1\n203.0.113.0/24", remoteAddr: "203.0.113.7:4321", wantStatus: http.StatusOK, wantUserQuota: true},
		{name: "expired key with the switch on", allow: true, expired: true, remoteAddr: "203.0.113.7:4321", wantStatus: http.StatusOK, wantUserQuota: true},
		{name: "exhausted key remains readable", exhausted: true, remoteAddr: "203.0.113.7:4321", wantStatus: http.StatusOK},
		{name: "switch on from an IP outside the whitelist", allow: true, allowIps: "198.51.100.1", remoteAddr: "203.0.113.7:4321", wantStatus: http.StatusForbidden},
		{name: "switch off from an IP outside the whitelist", allowIps: "198.51.100.1", remoteAddr: "203.0.113.7:4321", wantStatus: http.StatusForbidden},
		{name: "unresolved client IP with a whitelist", allow: true, allowIps: "203.0.113.0/24", remoteAddr: "unresolved", wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTokenControllerTestDB(t)
			require.NoError(t, db.AutoMigrate(&model.User{}))
			// Initialize production column quoting for the token key lookup.
			t.Setenv("LOG_SQL_DSN", "")
			require.NoError(t, model.InitLogDB())
			user := &model.User{Username: "quota-owner", Password: "placeholder", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "owner-group", Quota: 12345, UsedQuota: 678, AuthVersion: 1, AffCode: "quota-owner"}
			require.NoError(t, db.Create(user).Error)
			token := seedToken(t, db, user.Id, "usage-token", "usagekey1234")
			updates := map[string]any{"allow_user_quota_query": tc.allow, "allow_ips": tc.allowIps, "used_quota": 30, "group": tc.group}
			if tc.expired {
				updates["status"], updates["expired_time"] = common.TokenStatusExpired, 1
			}
			if tc.exhausted {
				updates["status"], updates["remain_quota"] = common.TokenStatusExhausted, 0
			}
			require.NoError(t, db.Model(token).Updates(updates).Error)

			router := gin.New()
			router.GET("/api/usage/token/", middleware.TokenAuthReadOnly(), GetTokenUsage)
			request := httptest.NewRequest(http.MethodGet, "/api/usage/token/", nil)
			request.Header.Set("Authorization", "Bearer sk-usagekey1234")
			request.RemoteAddr = tc.remoteAddr
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			require.Equal(t, tc.wantStatus, recorder.Code, recorder.Body.String())
			assert.Equal(t, "private, no-store", recorder.Header().Get("Cache-Control"))
			if tc.wantStatus != http.StatusOK {
				assert.NotContains(t, recorder.Body.String(), "total_available")
				return
			}
			var response struct {
				Code bool                       `json:"code"`
				Data map[string]json.RawMessage `json:"data"`
			}
			require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &response))
			require.True(t, response.Code, recorder.Body.String())
			fields := []string{"expires_at", "group", "model_limits", "model_limits_enabled", "name", "object", "total_available", "total_granted", "total_used", "unlimited_quota"}
			if tc.wantUserQuota {
				fields = append(fields, "user_quota")
			}
			assert.Equal(t, fields, slices.Sorted(maps.Keys(response.Data)))
			wantGroup := tc.group
			if wantGroup == "" {
				wantGroup = user.Group
			}
			var group string
			require.NoError(t, common.Unmarshal(response.Data["group"], &group))
			assert.Equal(t, wantGroup, group)
			available, expires := 100, 0
			if tc.exhausted {
				available = 0
			}
			if tc.expired {
				expires = 1
			}
			assert.JSONEq(t, strconv.Itoa(available), string(response.Data["total_available"]))
			assert.JSONEq(t, strconv.Itoa(available+30), string(response.Data["total_granted"]))
			assert.JSONEq(t, `30`, string(response.Data["total_used"]))
			assert.JSONEq(t, strconv.Itoa(expires), string(response.Data["expires_at"]))
			if tc.wantUserQuota {
				assert.JSONEq(t, `{"total_available":12345,"total_used":678}`, string(response.Data["user_quota"]))
			}
		})
	}
}

func TestGetTokenUsageAuthenticatedSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		headers    []string
		status     int
	}{
		{name: "lowercase bearer", headers: []string{"bearer sk-snapshotkey"}, status: 200},
		{name: "existing bearer without sk prefix", headers: []string{"Bearer snapshotkey"}, status: 200},
		{name: "missing header", status: 401},
		{name: "raw key", headers: []string{"sk-snapshotkey"}, status: 401},
		{name: "dash suffix", headers: []string{"Bearer sk-snapshotkey-channel"}, status: 401},
		{name: "duplicate header", headers: []string{"Bearer sk-snapshotkey", "Bearer sk-otherkey"}, status: 401},
		{name: "comma list", headers: []string{"Bearer sk-snapshotkey, Bearer sk-otherkey"}, status: 401},
		{name: "extra space", headers: []string{"Bearer  sk-snapshotkey"}, status: 401},
		{name: "trailing space", headers: []string{"Bearer sk-snapshotkey "}, status: 401},
		{name: "leading NBSP on bare credential", headers: []string{"Bearer \u00a0snapshotkey"}, status: 401},
		{name: "trailing NBSP", headers: []string{"Bearer sk-snapshotkey\u00a0"}, status: 401},
		{name: "leading EM SPACE on bare credential", headers: []string{"Bearer \u2003snapshotkey"}, status: 401},
		{name: "trailing EM SPACE", headers: []string{"Bearer sk-snapshotkey\u2003"}, status: 401},
		{name: "unsupported scheme case", headers: []string{"BEARER sk-snapshotkey"}, status: 401},
		{name: "disabled token", mode: "disabled", status: 401},
		{name: "deleted token", mode: "deleted", status: 401},
		{name: "unknown token", headers: []string{"Bearer sk-unknownkey"}, status: 401},
		{name: "disabled owner", mode: "banned", status: 403},
		{name: "database failure", mode: "database_failure", status: 500},
		{name: "header changed after authentication", mode: "replace_header", status: 200},
		{name: "owner group snapshot", mode: "replace_owner_group", status: 200},
		{name: "no lookup after authentication", mode: "no_lookup", status: 200},
		{name: "quota query failure retains legacy error", mode: "quota_failure", status: 200},
		{name: "missing typed context", mode: "missing_context", status: 401},
		{name: "malformed typed context", mode: "malformed_context", status: 401},
		{name: "mismatched context identity", mode: "mismatched_context", status: 401},
		{name: "dashboard JWT is not an sk key", mode: "jwt", status: 401},
		{name: "PAT is not an sk key", mode: "pat", status: 401},
		{name: "dashboard context cannot replace sk owner", mode: "mixed_valid", status: 200},
		{name: "dashboard context cannot rescue invalid sk", mode: "mixed_invalid", status: 401},
		{name: "shared log raw syntax unchanged", mode: "log", headers: []string{"sk-snapshotkey"}, status: 200},
		{name: "shared log suffix syntax unchanged", mode: "log", headers: []string{"Bearer sk-snapshotkey-channel"}, status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTokenControllerTestDB(t)
			require.NoError(t, db.AutoMigrate(&model.User{}))
			t.Setenv("LOG_SQL_DSN", "")
			require.NoError(t, model.InitLogDB())
			if tc.mode == "log" {
				require.NoError(t, db.AutoMigrate(&model.Log{}))
			}
			owner := &model.User{Username: "private-owner", Password: "placeholder", Group: "Owner group", Status: common.UserStatusEnabled, Role: common.RoleCommonUser, AuthVersion: 1, AffCode: "owner"}
			other := &model.User{Username: "other-private-owner", Password: "placeholder", Group: "Other owner group", Status: common.UserStatusEnabled, Role: common.RoleRootUser, AuthVersion: 1, AffCode: "other"}
			require.NoError(t, db.Create(owner).Error)
			require.NoError(t, db.Create(other).Error)
			token := seedToken(t, db, owner.Id, "Visible token name", "snapshotkey")
			otherToken := seedToken(t, db, other.Id, "Other token name", "otherkey")
			require.NoError(t, db.Model(token).Update("group", "Named group").Error)
			switch tc.mode {
			case "disabled":
				require.NoError(t, db.Model(token).Update("status", common.TokenStatusDisabled).Error)
			case "deleted":
				require.NoError(t, db.Delete(token).Error)
			case "banned":
				require.NoError(t, db.Model(owner).Update("status", common.UserStatusDisabled).Error)
			case "replace_owner_group":
				require.NoError(t, db.Model(token).Update("group", "").Error)
			case "quota_failure":
				require.NoError(t, db.Model(token).Update("allow_user_quota_query", true).Error)
			}
			blockQueries := func(tx *gorm.DB) { tx.AddError(errors.New("fixture database failure")) }
			if tc.mode == "database_failure" {
				require.NoError(t, db.Callback().Query().Before("gorm:query").Register("usage-fixture-failure", blockQueries))
			}
			t.Cleanup(func() { require.NoError(t, db.Callback().Query().Remove("usage-fixture-failure")) })
			headers := tc.headers
			if headers == nil && tc.mode != "" {
				headers = []string{"Bearer sk-snapshotkey"}
			}
			var dashboardJWT, pat string
			if tc.mode == "jwt" || tc.mode == "pat" || strings.HasPrefix(tc.mode, "mixed_") {
				require.NoError(t, db.AutoMigrate(&model.UserSession{}, &model.SessionRevocationEvent{}, &model.UserAccessToken{}))
				previousSecret := common.SessionSecret
				common.SessionSecret = "usage-only-test-signing-key"
				t.Cleanup(func() { common.SessionSecret = previousSecret })
				session := &model.UserSession{SID: "other-dashboard-session", UserID: other.Id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: "placeholder", LoginMethod: "password", ExpiresAt: time.Now().Add(time.Hour).Unix()}
				require.NoError(t, model.CreateUserSession(session))
				var err error
				dashboardJWT, _, err = service.IssueAccessToken(service.AuthIdentity{UserID: other.Id, SessionID: session.SID, UserAuthVersion: 1, SessionVersion: 1})
				require.NoError(t, err)
				pat = model.AccessTokenPrefix + strings.Repeat("p", 43)
				accessToken := &model.UserAccessToken{Name: "fixture PAT", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
				require.NoError(t, accessToken.SetScopes([]string{"profile:read"}))
				require.NoError(t, model.CreateUserAccessToken(other.Id, accessToken, service.AccessTokenMaxPerUser))
				switch tc.mode {
				case "jwt":
					headers = []string{"Bearer " + dashboardJWT}
				case "pat":
					headers = []string{"Bearer " + pat}
				case "mixed_invalid":
					headers = []string{"Bearer sk-unknownkey"}
				}
			}
			router := gin.New()
			handlers := []gin.HandlerFunc{middleware.TokenAuthReadOnly()}
			if tc.mode == "missing_context" {
				handlers = nil
			}
			handlers = append(handlers, func(c *gin.Context) {
				switch tc.mode {
				case "replace_header":
					c.Request.Header.Set("Authorization", "Bearer sk-otherkey")
				case "replace_owner_group":
					require.NoError(t, db.Model(owner).Update("group", "Changed group").Error)
				case "no_lookup", "quota_failure":
					require.NoError(t, db.Callback().Query().Before("gorm:query").Register("usage-fixture-failure", blockQueries))
				case "missing_context":
					c.Set("id", owner.Id)
					c.Set("token_id", token.Id)
					c.Set("token_key", token.Key)
				case "malformed_context":
					c.Set("read_only_token_identity", "not an authenticated snapshot")
				case "mismatched_context":
					c.Set("id", other.Id)
					c.Set("token_id", otherToken.Id)
				}
			})
			path := "/api/usage/token/"
			if tc.mode == "log" {
				path = "/api/log/token"
				handlers = append(handlers, GetLogByKey)
			} else {
				handlers = append(handlers, GetTokenUsage)
			}
			router.GET(path, handlers...)
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.RemoteAddr = "203.0.113.7:4321"
			for _, header := range headers {
				request.Header.Add("Authorization", header)
			}
			if strings.HasPrefix(tc.mode, "mixed_") {
				request.Header.Set("X-Auth-Session", dashboardJWT)
				request.AddCookie(&http.Cookie{Name: "session", Value: dashboardJWT})
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			require.Equal(t, tc.status, recorder.Code)
			for _, secret := range []string{token.Key, otherToken.Key, owner.Username, other.Username, dashboardJWT, pat} {
				if secret != "" {
					assert.NotContains(t, recorder.Body.String(), secret)
				}
			}
			var response map[string]any
			require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &response))
			if tc.mode == "log" {
				assert.Equal(t, true, response["success"])
				assert.Empty(t, recorder.Header().Get("Cache-Control"))
				return
			}
			assert.Equal(t, "private, no-store", recorder.Header().Get("Cache-Control"))
			if tc.status != http.StatusOK || tc.mode == "quota_failure" {
				assert.Equal(t, false, response["success"])
				assert.NotContains(t, response, "data")
				return
			}
			require.Equal(t, true, response["code"])
			data, ok := response["data"].(map[string]any)
			require.True(t, ok)
			wantGroup := "Named group"
			if tc.mode == "replace_owner_group" {
				wantGroup = "Owner group"
			}
			assert.Equal(t, wantGroup, data["group"])
			assert.Equal(t, token.Name, data["name"])
			assert.NotContains(t, data, "user_quota")
			assert.NotContains(t, data, "auto_groups")
		})
	}
}

func TestGetTokenPricingProjection(t *testing.T) {
	previousDB, previousLog := model.DB, model.LOG_DB
	previousMainType, previousLogType := common.MainDatabaseType(), common.LogDatabaseType()
	previousRedis, previousSecret := common.RedisEnabled, common.SessionSecret
	db := setupTokenControllerTestDB(t)
	t.Cleanup(func() {
		model.InvalidatePricingCache()
		model.DB, model.LOG_DB = previousDB, previousLog
		common.SetDatabaseTypes(previousMainType, previousLogType)
		common.RedisEnabled, common.SessionSecret = previousRedis, previousSecret
	})
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.SessionRevocationEvent{}, &model.AuditLog{}, &model.UserAccessToken{}, &model.Option{}, &model.Channel{}, &model.Ability{}, &model.Model{}, &model.Vendor{}))
	t.Setenv("LOG_SQL_DSN", "")
	require.NoError(t, model.InitLogDB())
	common.SessionSecret = "pricing-fixture-session-signing-secret"

	for _, settingSnapshot := range []struct {
		before  string
		restore func(string) error
		next    string
	}{
		{setting.UserUsableGroups2JSONString(), setting.UpdateUserUsableGroupsByJSONString, `{"g1":"Group one","g2":"Group two","g3":"Group three","auto":"Auto","no-ratio":"Unavailable ratio"}`},
		{setting.AutoGroups2JsonString(), setting.UpdateAutoGroupsByJsonString, `["g3","g2","g1","g3","revoked"]`},
		{strconv.Itoa(setting.GetMaxTokenAutoGroups()), setting.UpdateMaxTokenAutoGroups, "2"},
		{ratio_setting.GroupRatio2JSONString(), ratio_setting.UpdateGroupRatioByJSONString, `{"g1":2,"g2":3,"g3":4,"owner-a":1.6,"owner-b":2.2,"private-group":9}`},
		{ratio_setting.GroupGroupRatio2JSONString(), ratio_setting.UpdateGroupGroupRatioByJSONString, `{"owner-a":{"g1":0.25,"g2":0.5,"g3":0.75,"owner-a":1.125},"owner-b":{"g2":1.75},"g1":{"g1":9,"g2":99}}`},
		{ratio_setting.ModelPrice2JSONString(), ratio_setting.UpdateModelPriceByJSONString, `{"pricing-fixed":0.05}`},
		{ratio_setting.ModelRatio2JSONString(), ratio_setting.UpdateModelRatioByJSONString, `{"pricing-mixed":2.5,"pricing-only-b":4.5,"pricing-owner":6.5}`},
		{ratio_setting.CompletionRatio2JSONString(), ratio_setting.UpdateCompletionRatioByJSONString, `{"pricing-mixed":1.75}`},
		{ratio_setting.CacheRatio2JSONString(), ratio_setting.UpdateCacheRatioByJSONString, `{"pricing-mixed":0.1}`},
	} {
		t.Cleanup(func() { require.NoError(t, settingSnapshot.restore(settingSnapshot.before)) })
		require.NoError(t, settingSnapshot.restore(settingSnapshot.next))
	}
	special := ratio_setting.GetGroupRatioSetting().GroupSpecialUsableGroup
	originalSpecial := special.ReadAll()
	special.Clear()
	t.Cleanup(func() { special.Clear(); special.AddAll(originalSpecial) })
	common.OptionMapRWMutex.Lock()
	if common.OptionMap == nil {
		common.OptionMap = map[string]string{}
	}
	previousNav, hadNav := common.OptionMap["HeaderNavModules"]
	common.OptionMapRWMutex.Unlock()
	t.Cleanup(func() {
		common.OptionMapRWMutex.Lock()
		defer common.OptionMapRWMutex.Unlock()
		if hadNav {
			common.OptionMap["HeaderNavModules"] = previousNav
		} else {
			delete(common.OptionMap, "HeaderNavModules")
		}
	})

	owner := &model.User{Username: "pricing-private-owner", Password: "unused", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1, Group: "owner-a", AffCode: "pricinga"}
	other := &model.User{Username: "pricing-private-root", Password: "unused", Role: common.RoleRootUser, Status: common.UserStatusEnabled, AuthVersion: 1, Group: "owner-b", AffCode: "pricingb"}
	require.NoError(t, db.Create(owner).Error)
	require.NoError(t, db.Create(other).Error)
	userSession, err := service.CreateLoginSession(owner.Id, "password", "203.0.113.7", "pricing-fixture")
	require.NoError(t, err)
	rootSession, err := service.CreateLoginSession(other.Id, "password", "203.0.113.7", "pricing-fixture")
	require.NoError(t, err)
	token := seedToken(t, db, owner.Id, "Pricing token", "pricingkeya")
	rootToken := seedToken(t, db, other.Id, "Root pricing token", "pricingkeyb")
	require.NoError(t, db.Model(token).Update("group", "g1").Error)
	require.NoError(t, db.Model(rootToken).Update("group", "g2").Error)
	patRaw := model.AccessTokenPrefix + strings.Repeat("p", 43)
	pat := &model.UserAccessToken{Name: "Pricing PAT", TokenHash: model.AccessTokenFingerprint(patRaw), TokenHint: model.AccessTokenHint(patRaw)}
	require.NoError(t, pat.SetScopes([]string{"profile:read"}))
	require.NoError(t, model.CreateUserAccessToken(owner.Id, pat, service.AccessTokenMaxPerUser))

	channel := &model.Channel{Type: constant.ChannelTypeOpenAI, Name: "pricing-fixture", Key: "unused-channel-key", Status: common.ChannelStatusEnabled}
	require.NoError(t, db.Create(channel).Error)
	vendor := &model.Vendor{Name: "Fixture vendor"}
	require.NoError(t, db.Create(vendor).Error)
	for _, entry := range []struct {
		name   string
		groups []string
	}{
		{"pricing-fixed", []string{"all"}},
		{"pricing-mixed", []string{"g1", "g2", "private-group"}},
		{"pricing-only-b", []string{"g2"}},
		{"pricing-owner", []string{"owner-a"}},
	} {
		require.NoError(t, db.Create(&model.Model{ModelName: entry.name, Description: "Fixture metadata", VendorID: vendor.Id, Status: 1, NameRule: model.NameRuleExact}).Error)
		for _, group := range entry.groups {
			require.NoError(t, db.Create(&model.Ability{Group: group, Model: entry.name, ChannelId: channel.Id, Enabled: true}).Error)
		}
	}
	model.InvalidatePricingCache()
	cacheWire, err := common.Marshal(model.GetPricing())
	require.NoError(t, err)
	var cache []model.Pricing
	require.NoError(t, common.Unmarshal(cacheWire, &cache))
	require.Len(t, cache, 4)
	byModel := make(map[string]model.Pricing, len(cache))
	for _, item := range cache {
		byModel[item.ModelName] = item
	}
	require.Equal(t, 0.05, byModel["pricing-fixed"].ModelPrice)
	require.Equal(t, 2.5, byModel["pricing-mixed"].ModelRatio)
	require.Equal(t, 1.75, byModel["pricing-mixed"].CompletionRatio)
	require.NotNil(t, byModel["pricing-mixed"].CacheRatio)

	perform := func(t *testing.T, policy string, headers []string, cookie bool, afterAuth gin.HandlerFunc) (*httptest.ResponseRecorder, map[string]any, int) {
		t.Helper()
		common.OptionMapRWMutex.Lock()
		common.OptionMap["HeaderNavModules"] = policy
		common.OptionMapRWMutex.Unlock()
		handled := 0
		router := gin.New()
		router.GET("/api/pricing", middleware.HeaderNavModuleAuth("pricing"), func(c *gin.Context) {
			handled++
			if afterAuth != nil {
				afterAuth(c)
			}
			GetPricing(c)
		})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/pricing", nil)
		request.RemoteAddr = "203.0.113.7:1234"
		for _, header := range headers {
			request.Header.Add("Authorization", header)
		}
		if cookie {
			request.AddCookie(&http.Cookie{Name: service.RefreshCookieName, Value: rootSession.RefreshToken})
			request.Header.Set("X-Auth-Session", rootSession.AccessToken)
		}
		router.ServeHTTP(recorder, request)
		var body map[string]any
		require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &body))
		for _, secret := range []string{token.Key, rootToken.Key, userSession.AccessToken, rootSession.AccessToken, rootSession.RefreshToken, patRaw, owner.Username, other.Username} {
			assert.NotContains(t, recorder.Body.String(), secret)
		}
		return recorder, body, handled
	}
	projection := func(t *testing.T, body map[string]any, selected, base string, candidates []string) {
		t.Helper()
		assert.Equal(t, selected, body["group"])
		assert.ElementsMatch(t, []string{"success", "data", "group", "vendors", "group_ratio", "usable_group", "supported_endpoint", "auto_groups", "pricing_version"}, slices.Collect(maps.Keys(body)))
		for _, field := range []string{"group_ratio", "usable_group"} {
			collection, ok := body[field].(map[string]any)
			require.True(t, ok, field)
			assert.ElementsMatch(t, candidates, slices.Collect(maps.Keys(collection)))
		}
		for _, candidate := range candidates {
			assert.Equal(t, service.GetUserGroupRatio(base, candidate), body["group_ratio"].(map[string]any)[candidate])
		}
		groups, ok := body["auto_groups"].([]any)
		require.True(t, ok)
		expectedAuto := []string{}
		if selected == "auto" {
			expectedAuto = candidates
		}
		require.Len(t, groups, len(expectedAuto))
		for i, group := range expectedAuto {
			assert.Equal(t, group, groups[i])
		}
		wire, err := common.Marshal(body["data"])
		require.NoError(t, err)
		var actual []model.Pricing
		require.NoError(t, common.Unmarshal(wire, &actual))
		require.NotNil(t, actual)
		expected := make(map[string]model.Pricing)
		for _, original := range cache {
			groups := []string{}
			for _, candidate := range candidates {
				if slices.Contains(original.EnableGroup, "all") || slices.Contains(original.EnableGroup, candidate) {
					groups = append(groups, candidate)
				}
			}
			if len(groups) > 0 {
				original.EnableGroup = groups
				expected[original.ModelName] = original
			}
		}
		require.Len(t, actual, len(expected))
		for _, item := range actual {
			assert.Equal(t, expected[item.ModelName], item)
			assert.NotContains(t, item.EnableGroup, "all")
			assert.NotContains(t, item.EnableGroup, "private-group")
		}
		after, err := common.Marshal(model.GetPricing())
		require.NoError(t, err)
		assert.JSONEq(t, string(cacheWire), string(after))
	}
	const public = `{"pricing":{"enabled":true,"requireAuth":false}}`
	const login = `{"pricing":{"enabled":true,"requireAuth":true}}`
	const disabled = `{"pricing":{"enabled":false,"requireAuth":false}}`
	for _, policy := range []struct {
		name, raw string
		statuses  []int
	}{
		{"public", public, []int{200, 200, 200, 200, 200}},
		{"login", login, []int{401, 200, 200, 403, 403}},
		{"disabled", disabled, []int{403, 403, 200, 403, 403}},
	} {
		for i, principal := range []struct{ name, credential string }{
			{"anonymous", ""}, {"dashboard user", "Bearer " + userSession.AccessToken}, {"dashboard root", "Bearer " + rootSession.AccessToken},
			{"sk", "Bearer sk-" + token.Key}, {"root sk", "Bearer sk-" + rootToken.Key},
		} {
			t.Run(policy.name+"/"+principal.name, func(t *testing.T) {
				var headers []string
				if principal.credential != "" {
					headers = []string{principal.credential}
				}
				recorder, body, handled := perform(t, policy.raw, headers, false, nil)
				require.Equal(t, policy.statuses[i], recorder.Code)
				if i >= 3 {
					assert.Equal(t, "private, no-store", recorder.Header().Get("Cache-Control"))
				}
				if recorder.Code != 200 {
					assert.Zero(t, handled)
					assert.NotContains(t, body, "data")
					assert.NotContains(t, body, "group")
					return
				}
				assert.Equal(t, 1, handled)
				if i < 3 {
					assert.NotContains(t, body, "group")
				} else if i == 3 {
					projection(t, body, "g1", "owner-a", []string{"g1"})
				} else {
					projection(t, body, "g2", "owner-b", []string{"g2"})
				}
			})
		}
	}
	t.Run("mixed cookie and canonical bearer", func(t *testing.T) {
		for _, policy := range []string{public, login, disabled} {
			recorder, body, handled := perform(t, policy, []string{"bearer sk-" + token.Key}, true, nil)
			assert.Equal(t, "private, no-store", recorder.Header().Get("Cache-Control"))
			if policy == public {
				require.Equal(t, 200, recorder.Code)
				assert.Equal(t, 1, handled)
				projection(t, body, "g1", "owner-a", []string{"g1"})
			} else {
				require.Equal(t, 403, recorder.Code)
				assert.Zero(t, handled)
				assert.NotContains(t, body, "data")
			}
		}
		recorder, body, handled := perform(t, public, []string{"Bearer sk-unknownkey"}, true, nil)
		assert.Equal(t, 401, recorder.Code)
		assert.Equal(t, "private, no-store", recorder.Header().Get("Cache-Control"))
		assert.Zero(t, handled)
		assert.NotContains(t, body, "data")
	})
	for _, tc := range []struct {
		name    string
		headers []string
	}{
		{"raw", []string{"sk-" + token.Key}}, {"wrong scheme", []string{"Basic sk-" + token.Key}},
		{"uppercase prefix", []string{"Bearer SK-" + token.Key}}, {"uppercase scheme", []string{"BEARER sk-" + token.Key}},
		{"empty", []string{"Bearer sk-"}}, {"suffix", []string{"Bearer sk-" + token.Key + "-channel"}},
		{"duplicate sk first", []string{"Bearer sk-" + token.Key, "Bearer " + rootSession.AccessToken}},
		{"duplicate dashboard first", []string{"Bearer " + rootSession.AccessToken, "Bearer sk-" + token.Key}},
		{"comma mixed", []string{"Bearer " + rootSession.AccessToken + ", Bearer sk-" + token.Key}},
		{"leading space", []string{" Bearer sk-" + token.Key}}, {"extra separator", []string{"Bearer  sk-" + token.Key}},
		{"trailing space", []string{"Bearer sk-" + token.Key + " "}}, {"NBSP leading", []string{"Bearer \u00a0sk-" + token.Key}},
		{"NBSP trailing", []string{"Bearer sk-" + token.Key + "\u00a0"}}, {"EM SPACE leading", []string{"\u2003Bearer sk-" + token.Key}},
		{"EM SPACE trailing", []string{"Bearer sk-" + token.Key + "\u2003"}}, {"NBSP separator", []string{"Bearer\u00a0sk-" + token.Key}},
		{"embedded control", []string{"Bearer sk-" + token.Key + "\tother"}},
	} {
		t.Run("syntax/"+tc.name, func(t *testing.T) {
			recorder, body, handled := perform(t, public, tc.headers, true, nil)
			assert.Equal(t, 401, recorder.Code)
			assert.Equal(t, "private, no-store", recorder.Header().Get("Cache-Control"))
			assert.Zero(t, handled)
			assert.NotContains(t, body, "data")
			assert.NotContains(t, body, "group")
		})
	}
	for _, tc := range []struct {
		name         string
		tokenUpdates map[string]any
		banned       bool
		status       int
	}{
		{"expired", map[string]any{"status": common.TokenStatusExpired, "expired_time": time.Now().Unix() - 60}, false, 200},
		{"exhausted", map[string]any{"status": common.TokenStatusExhausted, "remain_quota": 0, "unlimited_quota": false}, false, 200},
		{"disabled", map[string]any{"status": common.TokenStatusDisabled}, false, 401},
		{"IP mismatch", map[string]any{"allow_ips": "198.51.100.1"}, false, 403},
		{"owner disabled", nil, true, 403},
	} {
		t.Run("readonly/"+tc.name, func(t *testing.T) {
			t.Cleanup(func() {
				require.NoError(t, db.Model(token).Updates(map[string]any{"status": common.TokenStatusEnabled, "expired_time": -1, "remain_quota": 100, "unlimited_quota": true, "allow_ips": ""}).Error)
				require.NoError(t, db.Model(owner).Update("status", common.UserStatusEnabled).Error)
			})
			if tc.tokenUpdates != nil {
				require.NoError(t, db.Model(token).Updates(tc.tokenUpdates).Error)
			}
			if tc.banned {
				require.NoError(t, db.Model(owner).Update("status", common.UserStatusDisabled).Error)
			}
			recorder, body, handled := perform(t, public, []string{"Bearer sk-" + token.Key}, false, nil)
			require.Equal(t, tc.status, recorder.Code)
			assert.Equal(t, "private, no-store", recorder.Header().Get("Cache-Control"))
			if tc.status == 200 {
				assert.Equal(t, 1, handled)
				projection(t, body, "g1", "owner-a", []string{"g1"})
			} else {
				assert.Zero(t, handled)
				assert.NotContains(t, body, "data")
			}
		})
	}
	for _, tc := range []struct {
		name, selected, auto, revoke string
		candidates                   []string
	}{
		{"inherited owner", "", "", "", []string{"owner-a"}},
		{"auto empty", "auto", "", "", []string{"g3", "g2", "g1"}},
		{"auto null", "auto", "null", "", []string{"g3", "g2", "g1"}},
		{"auto empty array", "auto", "[]", "", []string{"g3", "g2", "g1"}},
		{"custom filters before limit", "auto", `["revoked","g2","g2","g3","g1"]`, "", []string{"g2", "g3"}},
		{"malformed custom", "auto", `{broken`, "", []string{}},
		{"revoked custom", "auto", `["revoked"]`, "", []string{}},
		{"auto permission revoked", "auto", "", "auto", []string{}},
		{"named permission revoked", "g1", "", "g1", []string{}},
		{"missing ratio", "no-ratio", "", "", []string{}},
	} {
		t.Run("groups/"+tc.name, func(t *testing.T) {
			t.Cleanup(func() {
				require.NoError(t, db.Model(token).Updates(map[string]any{"group": "g1", "auto_groups": ""}).Error)
				special.Clear()
			})
			require.NoError(t, db.Model(token).Updates(map[string]any{"group": tc.selected, "auto_groups": tc.auto}).Error)
			if tc.revoke != "" {
				special.Set("owner-a", map[string]string{"-:" + tc.revoke: ""})
			}
			recorder, body, handled := perform(t, public, []string{"Bearer sk-" + token.Key}, false, nil)
			require.Equal(t, 200, recorder.Code)
			assert.Equal(t, 1, handled)
			selected := tc.selected
			if selected == "" {
				selected = "owner-a"
			}
			projection(t, body, selected, "owner-a", tc.candidates)
		})
	}
	for _, mode := range []string{"missing snapshot", "malformed snapshot", "mismatched token", "malformed branch marker", "replace header"} {
		t.Run("snapshot/"+mode, func(t *testing.T) {
			recorder, body, handled := perform(t, public, []string{"Bearer sk-" + token.Key}, false, func(c *gin.Context) {
				switch mode {
				case "missing snapshot":
					delete(c.Keys, "read_only_token_identity")
				case "malformed snapshot":
					c.Set("read_only_token_identity", token)
				case "mismatched token":
					c.Set("token_id", rootToken.Id)
				case "malformed branch marker":
					c.Set("pricing_token_branch", "untrusted")
				case "replace header":
					c.Request.Header.Set("Authorization", "Bearer sk-"+rootToken.Key)
				}
			})
			assert.Equal(t, 1, handled)
			assert.Equal(t, "private, no-store", recorder.Header().Get("Cache-Control"))
			if mode == "replace header" {
				require.Equal(t, 200, recorder.Code)
				projection(t, body, "g1", "owner-a", []string{"g1"})
			} else {
				assert.Equal(t, 401, recorder.Code)
				assert.NotContains(t, body, "data")
			}
		})
	}
	t.Run("interleaved cache and dashboard compatibility", func(t *testing.T) {
		var baselines []string
		for _, headers := range [][]string{nil, {"Bearer " + userSession.AccessToken}, {"Bearer " + rootSession.AccessToken}, {"Bearer " + patRaw}} {
			recorder, body, handled := perform(t, public, headers, false, nil)
			require.Equal(t, 200, recorder.Code)
			assert.Equal(t, 1, handled)
			assert.NotContains(t, body, "group")
			baselines = append(baselines, recorder.Body.String())
		}
		for _, selection := range []struct{ key, group, base string }{{token.Key, "g1", "owner-a"}, {rootToken.Key, "g2", "owner-b"}} {
			recorder, body, _ := perform(t, public, []string{"Bearer sk-" + selection.key}, false, nil)
			require.Equal(t, 200, recorder.Code)
			projection(t, body, selection.group, selection.base, []string{selection.group})
		}
		for i, headers := range [][]string{nil, {"Bearer " + userSession.AccessToken}, {"Bearer " + rootSession.AccessToken}, {"Bearer " + patRaw}} {
			recorder, _, _ := perform(t, public, headers, false, nil)
			require.Equal(t, 200, recorder.Code)
			assert.JSONEq(t, baselines[i], recorder.Body.String())
		}
		assert.JSONEq(t, baselines[1], baselines[3])
	})
}

func TestAPITokenAuditDatabaseMatrix(t *testing.T) {
	for _, database := range []struct {
		name, env string
		typ       common.DatabaseType
	}{
		{"sqlite", "", common.DatabaseTypeSQLite},
		{"mysql", "AUDIT_MYSQL_DSN", common.DatabaseTypeMySQL},
		{"postgres", "AUDIT_POSTGRES_DSN", common.DatabaseTypePostgreSQL},
	} {
		for _, separateLog := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/separate_log=%v", database.name, separateLog), func(t *testing.T) {
				dsn := os.Getenv(database.env)
				if database.env != "" && dsn == "" {
					t.Skip(database.env + " is not configured")
				}
				previousDB, previousLogDB := model.DB, model.LOG_DB
				previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
				previousRedis, previousMaster, previousSecret := common.RedisEnabled, common.IsMasterNode, common.SessionSecret
				t.Cleanup(func() {
					model.DB, model.LOG_DB = previousDB, previousLogDB
					common.SetDatabaseTypes(previousMain, previousLog)
					common.RedisEnabled, common.IsMasterNode, common.SessionSecret = previousRedis, previousMaster, previousSecret
				})
				common.RedisEnabled, common.IsMasterNode = false, true
				common.SessionSecret = "api-token-audit-test-secret"
				t.Setenv("LOG_SQL_DSN", "")
				db, _ := oauthBirthFixture(t)
				require.Equal(t, database.name, db.Dialector.Name())
				model.DB = db
				common.SetDatabaseTypes(database.typ, database.typ)
				require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.SessionRevocationEvent{}, &model.Token{}, &model.UserAccessToken{}))
				// Initialize production column quoting as well as the existing audit table.
				require.NoError(t, model.InitLogDB())
				if separateLog {
					logDB, _ := newAuditTestDatabase(t, database.name, dsn)
					model.LOG_DB = logDB
					require.NoError(t, model.MigrateAuditLogs())
				}
				versionSQL := "SELECT version()"
				if database.name == "sqlite" {
					versionSQL = "SELECT sqlite_version()"
				}
				var version string
				require.NoError(t, db.Raw(versionSQL).Scan(&version).Error)
				t.Logf("database version: %s", version)
				verifyAPITokenAudit(t)
				if separateLog {
					var count int64
					require.NoError(t, db.Model(&model.AuditLog{}).Count(&count).Error)
					assert.Zero(t, count, "all audit events must use the configured log database")
				}
			})
		}
	}
}

func verifyAPITokenAudit(t *testing.T) {
	t.Helper()
	user := &model.User{Username: "token-owner", Password: "placeholder", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: "token-owner"}
	require.NoError(t, model.DB.Create(user).Error)
	pat, _ := createScopedAccessToken(t, user.Id, time.Now().Unix()+3600, "api_key:reveal")
	other := &model.User{Username: "other-owner", Password: "placeholder", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: "other-owner"}
	require.NoError(t, model.DB.Create(other).Error)
	session := &model.UserSession{SID: "token-audit-session", UserID: user.Id, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: "placeholder", LoginMethod: "password", LastActiveAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, model.CreateUserSession(session))
	jwt, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: user.Id, SessionID: session.SID, UserAuthVersion: 1, SessionVersion: 1})
	require.NoError(t, err)
	router := gin.New()
	router.Use(middleware.RequestId(), middleware.AccessTokenAudit())
	tokenRoutes := router.Group("/api/token", middleware.UserAuth(), middleware.TokenOperationAudit())
	tokenRoutes.POST("/", AddToken)
	tokenRoutes.PUT("/", UpdateToken)
	tokenRoutes.DELETE("/:id", DeleteToken)
	tokenRoutes.POST("/batch", DeleteTokenBatch)
	tokenRoutes.POST("/batch/keys", GetTokenKeysBatch)
	tokenRoutes.POST("/:id/key", func(c *gin.Context) {
		if c.GetHeader("X-Test-Limit") != "" {
			c.AbortWithStatusJSON(429, gin.H{"success": false})
			return
		}
		c.Next()
	}, GetTokenKey)
	tokenRoutes.GET("/", GetAllTokens)
	tokenRoutes.GET("/:id", GetToken)
	tokenRoutes.GET("/search", SearchTokens)
	router.GET("/api/audit/self", middleware.UserAuth(), GetAuditLogs)

	for index, tc := range []struct {
		name, method, path, body, action string
		success                          bool
		params                           string
		initialStatus                    int
		failWrite, rateLimit, usePAT     bool
	}{
		{name: "create", method: "POST", path: "/", body: `{"name":"created","expired_time":-1,"unlimited_quota":true}`, action: "token.create", success: true},
		{name: "invalid create", method: "POST", path: "/", body: `{"name":"attempt","remain_quota":-1}`, action: "token.create", params: `{"name":"attempt"}`},
		{name: "malformed body", method: "POST", path: "/", body: `{"key":"raw-body-secret"`, action: "token.create", params: `{}`},
		{name: "validation error exceeds audit buffer", method: "POST", path: "/", body: `{"remain_quota":` + strings.Repeat("9", 64*1024) + `}`, action: "token.create", params: `{}`},
		{name: "create storage failure", method: "POST", path: "/", body: `{"name":"attempt","unlimited_quota":true}`, action: "token.create", params: `{"name":"attempt"}`, failWrite: true},
		{name: "normalized update", method: "PUT", path: "/", body: `{"id":$id,"name":"renamed","expired_time":-1,"remain_quota":200,"unlimited_quota":true,"group":"default","cross_group_retry":true,"allow_ips":""}`, action: "token.update", success: true, params: `{"id":$id,"name":"renamed","changed_fields":["name","remain_quota","group","cross_group_retry","auto_groups"]}`},
		{name: "configuration values stay private", method: "PUT", path: "/", body: `{"id":$id,"name":"owned","expired_time":42,"remain_quota":100,"unlimited_quota":false,"model_limits_enabled":true,"model_limits":"private-model-configuration","allow_ips":"203.0.113.57","group":"auto","cross_group_retry":true}`, action: "token.update", success: true, params: `{"id":$id,"name":"owned","changed_fields":["expired_time","unlimited_quota","model_limits_enabled","model_limits","allow_ips"]}`},
		{name: "unchanged update", method: "PUT", path: "/", body: `{"id":$id,"name":"owned","expired_time":-1,"remain_quota":100,"unlimited_quota":true,"group":"auto","cross_group_retry":true,"allow_ips":""}`, action: "token.update", success: true, params: `{"id":$id,"name":"owned","changed_fields":[]}`},
		{name: "user quota query update", method: "PUT", path: "/", body: `{"id":$id,"name":"owned","expired_time":-1,"remain_quota":100,"unlimited_quota":true,"group":"auto","cross_group_retry":true,"allow_ips":"","allow_user_quota_query":true}`, action: "token.update", success: true, params: `{"id":$id,"name":"owned","changed_fields":["allow_user_quota_query"]}`},
		{name: "successful response exceeds audit buffer", method: "PUT", path: "/", body: `{"id":$id,"name":"owned","expired_time":-1,"remain_quota":100,"unlimited_quota":true,"group":"auto","cross_group_retry":true,"allow_ips":"","model_limits":"` + strings.Repeat("m", 64*1024-128) + `"}`, action: "token.update", success: true, params: `{"id":$id,"name":"owned","changed_fields":["model_limits"]}`},
		{name: "update storage failure", method: "PUT", path: "/", body: `{"id":$id,"name":"failed-rename","unlimited_quota":true}`, action: "token.update", params: `{"id":$id,"name":"owned"}`, failWrite: true},
		{name: "foreign update", method: "PUT", path: "/", body: `{"id":$other,"name":"forged-name","unlimited_quota":true}`, action: "token.update", params: `{"id":$other}`},
		{name: "disable", method: "PUT", path: "/?status_only=true", body: `{"id":$id,"status":2}`, action: "token.status_update", success: true, params: `{"id":$id,"name":"owned","from":1,"to":2}`},
		{name: "enable", method: "PUT", path: "/?status_only=true", body: `{"id":$id,"status":1}`, action: "token.status_update", success: true, params: `{"id":$id,"name":"owned","from":2,"to":1}`, initialStatus: common.TokenStatusDisabled},
		{name: "expired enable", method: "PUT", path: "/?status_only=true", body: `{"id":$id,"status":1}`, action: "token.status_update", params: `{"id":$id,"name":"owned"}`, initialStatus: common.TokenStatusExpired},
		{name: "delete", method: "DELETE", path: "/$id", action: "token.delete", success: true, params: `{"id":$id,"name":"owned"}`},
		{name: "foreign delete", method: "DELETE", path: "/$other", action: "token.delete", params: `{"id":$other}`},
		{name: "missing delete", method: "DELETE", path: "/999999", action: "token.delete", params: `{"id":999999}`},
		{name: "key view", method: "POST", path: "/$id/key", action: "token.key_view", success: true, params: `{"id":$id,"name":"owned"}`},
		{name: "PAT key view", method: "POST", path: "/$id/key", action: "token.key_view", success: true, params: `{"id":$id,"name":"owned"}`, usePAT: true},
		{name: "foreign key view", method: "POST", path: "/$other/key", action: "token.key_view", params: `{"id":$other}`},
		{name: "rate limited key view", method: "POST", path: "/$id/key", action: "token.key_view", params: `{"id":$id}`, rateLimit: true},
		{name: "batch delete partial and duplicate", method: "POST", path: "/batch", body: `{"ids":[$id,$id,$other,999999]}`, action: "token.delete_batch", success: true, params: `{"requested_ids":[$id,$id,$other,999999],"total":4,"count":1}`},
		{name: "empty batch delete", method: "POST", path: "/batch", body: `{"ids":[]}`, action: "token.delete_batch", params: `{"requested_ids":[],"total":0}`},
		{name: "batch keys partial and duplicate", method: "POST", path: "/batch/keys", body: `{"ids":[$id,$id,$other,999999]}`, action: "token.key_view_batch", success: true, params: `{"requested_ids":[$id,$id,$other,999999],"total":4,"count":1,"returned_ids":[$id]}`},
		{name: "batch keys no matches", method: "POST", path: "/batch/keys", body: `{"ids":[$other,999999]}`, action: "token.key_view_batch", success: true, params: `{"requested_ids":[$other,999999],"total":2,"count":0,"returned_ids":[]}`},
		{name: "empty batch keys", method: "POST", path: "/batch/keys", body: `{"ids":[]}`, action: "token.key_view_batch", params: `{"requested_ids":[],"total":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			empty := ""
			owned := &model.Token{UserId: user.Id, Name: "owned", Key: fmt.Sprintf("owned-key-secret-%d", index), Status: common.TokenStatusEnabled, ExpiredTime: -1, RemainQuota: 100, UnlimitedQuota: true, Group: "auto", CrossGroupRetry: true, AutoGroups: `["default"]`, AllowIps: &empty}
			if tc.initialStatus != 0 {
				owned.Status = tc.initialStatus
			}
			if owned.Status == common.TokenStatusExpired {
				owned.ExpiredTime = 1
			}
			foreign := &model.Token{UserId: other.Id, Name: "private-foreign-name", Key: fmt.Sprintf("foreign-key-secret-%d", index)}
			require.NoError(t, model.DB.Create(owned).Error)
			require.NoError(t, model.DB.Create(foreign).Error)
			replace := strings.NewReplacer("$id", strconv.Itoa(owned.Id), "$other", strconv.Itoa(foreign.Id))
			if tc.failWrite {
				fail := func(tx *gorm.DB) {
					if tx.Statement.Table == "tokens" {
						_ = tx.AddError(errors.New("raw-storage-error-secret"))
					}
				}
				if tc.method == "POST" {
					require.NoError(t, model.DB.Callback().Create().Before("gorm:create").Register("token-audit:fail", fail))
					t.Cleanup(func() { require.NoError(t, model.DB.Callback().Create().Remove("token-audit:fail")) })
				} else {
					require.NoError(t, model.DB.Callback().Update().Before("gorm:update").Register("token-audit:fail", fail))
					t.Cleanup(func() { require.NoError(t, model.DB.Callback().Update().Remove("token-audit:fail")) })
				}
			}
			request := httptest.NewRequest(tc.method, "/api/token"+replace.Replace(tc.path), strings.NewReader(replace.Replace(tc.body)))
			credential := jwt
			if tc.usePAT {
				credential = pat
			}
			request.Header.Set("Authorization", "Bearer "+credential)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("User-Agent", "api-token-audit-client")
			request.RemoteAddr = "192.0.2.12:4321"
			if tc.rateLimit {
				request.Header.Set("X-Test-Limit", "1")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if strings.Contains(tc.name, "exceeds audit buffer") {
				assert.Greater(t, response.Body.Len(), 64*1024)
			}
			var events []model.AuditLog
			require.NoError(t, model.LOG_DB.Where("request_id = ?", response.Header().Get(common.RequestIdKey)).Find(&events).Error)
			expectedEvents := 1
			if tc.usePAT {
				expectedEvents = 2
			}
			require.Len(t, events, expectedEvents)
			var operation *model.AuditLog
			for i := range events {
				if events[i].Category == model.AuditCategorySecurity {
					require.Nil(t, operation, "one operation event per request")
					operation = &events[i]
				} else {
					assert.Equal(t, model.AuditCategoryAccessToken, events[i].Category)
					assert.Equal(t, model.AccessTokenFingerprint(pat), events[i].TokenRef)
				}
			}
			require.NotNil(t, operation)
			assert.Equal(t, tc.action, operation.Action)
			assert.Equal(t, tc.success, operation.Success)
			assert.Equal(t, response.Code, operation.Status)
			if tc.rateLimit {
				assert.Equal(t, 429, response.Code)
			} else {
				assert.Equal(t, 200, response.Code)
				assert.Equal(t, tc.success, decodeAPIResponse(t, response).Success)
			}
			assert.Equal(t, user.Id, operation.UserId)
			assert.Equal(t, user.Username, operation.Username)
			assert.Equal(t, common.RoleCommonUser, operation.ActorRole)
			assert.Equal(t, "192.0.2.12", operation.Ip)
			assert.Equal(t, "api-token-audit-client", operation.UserAgent)
			assert.Equal(t, tc.method, operation.Method)
			expectedRoute := strings.NewReplacer("$id", ":id", "$other", ":id", "999999", ":id").Replace(strings.Split(tc.path, "?")[0])
			assert.Equal(t, "/api/token"+expectedRoute, operation.Route)
			assert.NotEmpty(t, operation.RequestId)
			assert.Empty(t, operation.TokenRef)
			assert.Nil(t, operation.Other.AdminInfo)
			authMethod := "session"
			if tc.usePAT {
				authMethod = "access_token"
			}
			assert.Equal(t, authMethod, operation.AuthMethod)
			require.NotNil(t, operation.Other.Op)
			assert.Equal(t, tc.action, operation.Other.Op.Action)
			params, err := common.Marshal(operation.Other.Op.Params)
			require.NoError(t, err)
			if tc.name == "create" {
				var created model.Token
				require.NoError(t, model.DB.Where("user_id = ? AND name = ?", user.Id, "created").First(&created).Error)
				assert.JSONEq(t, fmt.Sprintf(`{"id":%d,"name":"created"}`, created.Id), string(params))
				assert.NotContains(t, string(params), created.Key)
			} else if tc.params == `{}` {
				assert.Empty(t, operation.Other.Op.Params)
			} else {
				assert.JSONEq(t, replace.Replace(tc.params), string(params))
			}
			encoded, err := common.Marshal(events)
			require.NoError(t, err)
			for _, secret := range []string{pat, jwt, owned.Key, foreign.Key, foreign.Name, "raw-body-secret", "raw-storage-error-secret", "private-model-configuration", "203.0.113.57", "Authorization"} {
				assert.NotContains(t, string(encoded), secret)
			}
			if tc.action == "token.key_view" && tc.success {
				assert.Contains(t, response.Body.String(), owned.GetFullKey())
			}
		})
	}

	t.Run("bounded batch metadata", func(t *testing.T) {
		ids := make([]int, 101)
		for i := range ids {
			ids[i] = 10000 + i
		}
		body, err := common.Marshal(TokenBatch{Ids: ids})
		require.NoError(t, err)
		for _, path := range []string{"/api/token/batch", "/api/token/batch/keys"} {
			request := httptest.NewRequest("POST", path, bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+jwt)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			var event model.AuditLog
			require.NoError(t, model.LOG_DB.Where("request_id = ?", response.Header().Get(common.RequestIdKey)).First(&event).Error)
			var params struct {
				IDs       []int `json:"requested_ids"`
				Truncated bool  `json:"requested_ids_truncated"`
				Total     int   `json:"total"`
				Count     *int  `json:"count"`
			}
			encoded, err := common.Marshal(event.Other.Op.Params)
			require.NoError(t, err)
			require.NoError(t, common.Unmarshal(encoded, &params))
			assert.Equal(t, ids[:100], params.IDs)
			assert.True(t, params.Truncated)
			assert.Equal(t, 101, params.Total)
			assert.Equal(t, path == "/api/token/batch", event.Success)
			if event.Success {
				require.NotNil(t, params.Count)
				assert.Zero(t, *params.Count)
			} else {
				assert.Nil(t, params.Count)
			}
		}
	})

	t.Run("reads and unauthenticated writes add no operation audit", func(t *testing.T) {
		for _, tc := range []struct{ method, path, credential string }{
			{"GET", "/api/token/", jwt}, {"GET", "/api/token/search?keyword=private-search", jwt},
			{"GET", "/api/token/999999", jwt}, {"POST", "/api/token/", ""},
		} {
			response := auditRequest(router, tc.method, tc.path, tc.credential)
			var count int64
			require.NoError(t, model.LOG_DB.Model(&model.AuditLog{}).Where("request_id = ?", response.Header().Get(common.RequestIdKey)).Count(&count).Error)
			assert.Zero(t, count)
		}
	})

	t.Run("self audit excludes other owners", func(t *testing.T) {
		model.RecordAuditLog(nil, model.AuditLog{UserId: other.Id, Username: other.Username, ActorRole: common.RoleCommonUser, Category: model.AuditCategorySecurity, Action: "token.delete", Content: "other-user-audit", Success: true})
		response := auditRequest(router, "GET", "/api/audit/self?category=security&page_size=100", jwt)
		assert.Equal(t, 200, response.Code)
		assert.Contains(t, response.Body.String(), "token.create")
		assert.NotContains(t, response.Body.String(), "other-user-audit")
	})

	t.Run("audit storage failure preserves operation result", func(t *testing.T) {
		require.NoError(t, model.LOG_DB.Callback().Create().Before("gorm:create").Register("token-audit:log-fail", func(tx *gorm.DB) {
			if tx.Statement.Table == "audit_logs" {
				_ = tx.AddError(errors.New("audit unavailable"))
			}
		}))
		t.Cleanup(func() { require.NoError(t, model.LOG_DB.Callback().Create().Remove("token-audit:log-fail")) })
		request := httptest.NewRequest("POST", "/api/token/", strings.NewReader(`{"name":"audit-down","unlimited_quota":true}`))
		request.Header.Set("Authorization", "Bearer "+jwt)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.True(t, decodeAPIResponse(t, response).Success)
		var count int64
		require.NoError(t, model.DB.Model(&model.Token{}).Where("name = ?", "audit-down").Count(&count).Error)
		assert.EqualValues(t, 1, count)
	})
}

// A production bootstrap CLI, outside the service UID, owns the seal and its
// single-database journal. These tests never invent provenance history.
func tokenOwnerStore(t *testing.T) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.Init())
	oldDB, oldLog := model.DB, model.LOG_DB
	oldMain, oldLogKind := common.MainDatabaseType(), common.LogDatabaseType()
	oldRedis, oldMaster, oldReady := common.RedisEnabled, common.IsMasterNode, model.OAuthCleanupReady()
	db, _ := oauthBirthFixture(t)
	t.Cleanup(func() {
		model.DB, model.LOG_DB = oldDB, oldLog
		common.SetDatabaseTypes(oldMain, oldLogKind)
		common.RedisEnabled, common.IsMasterNode = oldRedis, oldMaster
		require.NoError(t, model.InitOAuthCleanupStore(oldReady))
	})
	model.DB, model.LOG_DB = db, db
	common.SetDatabaseTypes(common.DatabaseType(db.Dialector.Name()), common.DatabaseType(db.Dialector.Name()))
	common.RedisEnabled, common.IsMasterNode = false, false
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.SessionRevocationEvent{}, &model.UserAccessToken{}, &model.OAuthGrant{}, &model.OAuthOperation{}, &model.OAuthArtifact{}, &model.OAuthCleanupJob{}, &model.OAuthDerivedTextCharge{}, &model.AuditLog{}))
	require.NoError(t, model.InitOAuthCleanupStore(true))
	require.NoError(t, model.ValidateOAuthDerivedTokenStore(context.Background()))
	pool, err := db.DB()
	require.NoError(t, err)
	if db.Dialector.Name() == "sqlite" {
		pool.SetMaxOpenConns(1)
	}
	var version string
	q := "SELECT version()"
	if db.Dialector.Name() == "sqlite" {
		q = "SELECT sqlite_version()"
	}
	require.NoError(t, db.Raw(q).Scan(&version).Error)
	t.Logf("owner lifecycle engine=%s version=%s", db.Dialector.Name(), version)
	return db
}

func setupTokenOwnerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := tokenOwnerStore(t)
	for id := 1; id <= 2; id++ {
		require.NoError(t, db.Create(&model.User{Id: id, Username: fmt.Sprintf("owner-%d", id), AffCode: fmt.Sprintf("own-%d", id), AuthVersion: 1, Status: common.UserStatusEnabled, Group: "default"}).Error)
	}
	return db
}

func ownerDerivedFixture(t *testing.T, db *gorm.DB, userID int, suffix string, unused bool) (*model.OAuthGrant, *model.OAuthDerivedTokenSource, *model.Token) {
	t.Helper()
	now := time.Now().Unix()
	grant := &model.OAuthGrant{Issuer: "https://issuer.example", GrantID: "grant-" + suffix, ConsentRef: model.OAuthDerivedTokenKeyRef("consent-" + suffix), UserID: userID, Subject: strconv.Itoa(userID), ClientID: "client-" + suffix, OriginSID: "owner-session", UserAuthVersion: 1, SessionVersion: 1, Scopes: `["tokens:read","tokens:write"]`, PolicyHash: strings.Repeat("a", 64), Revision: 1, State: "active", CreatedAt: now - 5, ApprovedAt: now - 4, ExpiresAt: now + 1800}
	grant.GrantRef = model.OAuthGrantRef(grant.Issuer, grant.GrantID)
	require.NoError(t, db.Create(grant).Error)
	var count int64
	require.NoError(t, db.Model(&model.OAuthDerivedTokenSource{}).Count(&count).Error)
	source := &model.OAuthDerivedTokenSource{GrantRef: grant.GrantRef, UserID: userID, SchemaVersion: 1, QuotaLimit: 1000, ExpiresAt: now + 600, PolicyHash: strings.Repeat("a", 64), BindingHash: strings.Repeat("b", 64), VerifiedAt: now - 10, ProofExpiresAt: now + 40, PermitDeadline: now + 40, VerifiedMethod: "password", ProofFlowID: count + 1}
	var token *model.Token
	if !unused {
		key, err := common.GenerateKey()
		require.NoError(t, err)
		token = &model.Token{UserId: userID, Key: key, Name: "derived-" + suffix, Status: common.TokenStatusEnabled, RemainQuota: 1000, ExpiredTime: source.ExpiresAt}
		require.NoError(t, token.Insert())
		created := now - 1
		keyRef, idem, request := model.OAuthDerivedTokenKeyRef(key), model.OAuthDerivedTokenKeyRef("idem-"+suffix), model.OAuthDerivedTokenKeyRef("req-"+suffix)
		source.TokenID, source.KeyRef, source.IdemHash, source.RequestHash, source.CreatedAt = &token.Id, &keyRef, &idem, &request, &created
	}
	require.NoError(t, db.Create(source).Error)
	return grant, source, token
}

func ownerLifecycleRouter(t *testing.T, db *gorm.DB) (*gin.Engine, string) {
	t.Helper()
	session := &model.UserSession{SID: "owner-session", UserID: 1, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive, RefreshHash: "unused-fixture-hash", LoginMethod: "password", LastActiveAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 3600}
	require.NoError(t, model.CreateUserSession(session))
	jwt, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: 1, SessionID: session.SID, UserAuthVersion: 1, SessionVersion: 1})
	require.NoError(t, err)
	r := gin.New()
	g := r.Group("/api/token", middleware.UserAuth())
	g.POST("/:id/key", GetTokenKey)
	g.POST("/batch/keys", GetTokenKeysBatch)
	g.PUT("/", UpdateToken)
	g.DELETE("/:id", DeleteToken)
	g.POST("/batch", DeleteTokenBatch)
	return r, jwt
}

func TestOAuthDerivedTokenOwnerLifecycle(t *testing.T) {
	t.Run("owner_reveal_and_mutation", func(t *testing.T) {
		db := setupTokenOwnerTestDB(t)
		r, jwt := ownerLifecycleRouter(t, db)
		_, source, derived := ownerDerivedFixture(t, db, 1, "one", false)
		manual := seedToken(t, db, 1, "manual", "owner-manual-secret")
		request := func(method, path string, body any) *httptest.ResponseRecorder {
			data, err := common.Marshal(body)
			require.NoError(t, err)
			req := httptest.NewRequest(method, path, bytes.NewReader(data))
			req.Header.Set("Authorization", "Bearer "+jwt)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			return w
		}
		for _, tc := range []struct {
			path   string
			body   any
			status int
			secret bool
		}{
			{fmt.Sprintf("/api/token/%d/key", manual.Id), nil, 200, true},
			{fmt.Sprintf("/api/token/%d/key", derived.Id), nil, 403, false},
			{"/api/token/batch/keys", TokenBatch{Ids: []int{manual.Id, derived.Id}}, 403, false},
		} {
			w := request("POST", tc.path, tc.body)
			require.Equal(t, tc.status, w.Code)
			assert.NotContains(t, w.Body.String(), derived.Key)
			if tc.secret {
				assert.Contains(t, w.Body.String(), manual.Key)
			} else {
				assert.NotContains(t, w.Body.String(), manual.Key)
				assert.False(t, decodeAPIResponse(t, w).Success)
			}
		}
		for _, body := range []any{
			gin.H{"id": derived.Id, "remain_quota": 2000}, gin.H{"id": derived.Id, "expired_time": -1}, gin.H{"id": derived.Id, "model_limits": "extra"},
		} {
			w := request("PUT", "/api/token/", body)
			assert.Equal(t, 403, w.Code)
		}
		w := request("PUT", "/api/token/?status_only=true", gin.H{"id": derived.Id, "status": common.TokenStatusDisabled})
		require.Equal(t, 200, w.Code)
		require.True(t, decodeAPIResponse(t, w).Success)
		require.NoError(t, db.First(derived, derived.Id).Error)
		assert.Equal(t, common.TokenStatusDisabled, derived.Status)
		assert.Equal(t, 1000, derived.RemainQuota)
		require.NoError(t, db.First(source, "grant_ref = ?", source.GrantRef).Error)
		require.NotNil(t, source.TerminalReason)
		assert.Equal(t, "disabled", *source.TerminalReason)
		w = request("PUT", "/api/token/?status_only=true", gin.H{"id": derived.Id, "status": common.TokenStatusEnabled})
		assert.Equal(t, 403, w.Code)
		w = request("POST", "/api/token/batch", TokenBatch{Ids: []int{manual.Id, derived.Id}})
		require.True(t, decodeAPIResponse(t, w).Success)
		require.NoError(t, db.Unscoped().First(derived, derived.Id).Error)
		assert.True(t, derived.DeletedAt.Valid)
		require.NoError(t, db.First(source, "grant_ref = ?", source.GrantRef).Error)
		assert.Equal(t, "deleted", *source.TerminalReason)
		assert.NotNil(t, source.CreatedAt)
		// Physical loss is not a valid soft-deleted result, even with a tombstone.
		require.NoError(t, db.Unscoped().Delete(derived).Error)
		w = request("POST", fmt.Sprintf("/api/token/%d/key", derived.Id), nil)
		assert.Equal(t, 503, w.Code)
		assert.NotContains(t, w.Body.String(), derived.Key)
		w = request("DELETE", fmt.Sprintf("/api/token/%d", derived.Id), nil)
		assert.Equal(t, 503, w.Code)
		var user model.User
		require.NoError(t, db.First(&user, 1).Error)
		assert.Zero(t, user.Quota)
		assert.Zero(t, user.UsedQuota)
		var charges int64
		require.NoError(t, db.Model(&model.OAuthDerivedTextCharge{}).Count(&charges).Error)
		assert.Zero(t, charges)
	})
	t.Run("revoke_and_rollback", func(t *testing.T) {
		db := setupTokenOwnerTestDB(t)
		grant, source, token := ownerDerivedFixture(t, db, 1, "revoke", false)
		other, otherSource, otherToken := ownerDerivedFixture(t, db, 1, "other", false)
		unusedGrant, unused, _ := ownerDerivedFixture(t, db, 1, "unused", true)
		for _, table := range []string{"oauth_derived_token_sources", "tokens", "o_auth_cleanup_jobs"} {
			require.NoError(t, db.Callback().Update().After("gorm:update").Register("owner:rollback", func(tx *gorm.DB) {
				if tx.Statement.Table == table {
					tx.AddError(errors.New("forced rollback"))
				}
			}))
			require.NoError(t, db.Callback().Create().After("gorm:create").Register("owner:rollback", func(tx *gorm.DB) {
				if tx.Statement.Table == table {
					tx.AddError(errors.New("forced rollback"))
				}
			}))
			require.Error(t, model.RevokeOAuth(context.Background(), 1, "grant", grant.GrantRef))
			require.NoError(t, db.Callback().Update().Remove("owner:rollback"))
			require.NoError(t, db.Callback().Create().Remove("owner:rollback"))
			require.NoError(t, db.First(grant, "grant_ref = ?", grant.GrantRef).Error)
			assert.Zero(t, grant.RevokedAt)
			require.NoError(t, db.First(source, "grant_ref = ?", source.GrantRef).Error)
			assert.Nil(t, source.TerminalAt)
			require.NoError(t, db.First(token, token.Id).Error)
			assert.Equal(t, common.TokenStatusEnabled, token.Status)
		}
		require.NoError(t, model.RevokeOAuth(context.Background(), 1, "grant", grant.GrantRef))
		require.NoError(t, db.First(source, "grant_ref = ?", source.GrantRef).Error)
		require.NotNil(t, source.TerminalReason)
		assert.Equal(t, "revoked", *source.TerminalReason)
		require.NoError(t, db.First(token, token.Id).Error)
		assert.Equal(t, common.TokenStatusDisabled, token.Status)
		require.NoError(t, db.First(other, "grant_ref = ?", other.GrantRef).Error)
		assert.Zero(t, other.RevokedAt)
		require.NoError(t, db.First(otherSource, "grant_ref = ?", otherSource.GrantRef).Error)
		assert.Nil(t, otherSource.TerminalAt)
		require.NoError(t, db.First(otherToken, otherToken.Id).Error)
		assert.Equal(t, common.TokenStatusEnabled, otherToken.Status)
		require.NoError(t, model.RevokeOAuth(context.Background(), 1, "grant", unusedGrant.GrantRef))
		require.NoError(t, db.First(unused, "grant_ref = ?", unused.GrantRef).Error)
		require.NotNil(t, unused.TerminalReason)
		assert.Equal(t, "revoked", *unused.TerminalReason)
		assert.Nil(t, unused.TokenID)
		// Readiness off must not turn retained source state into a no-op.
		require.NoError(t, model.InitOAuthCleanupStore(false))
		require.Error(t, model.RevokeOAuth(context.Background(), 1, "user", ""))
	})
	t.Run("disable_delete_rollback", func(t *testing.T) {
		db := setupTokenOwnerTestDB(t)
		_, source, token := ownerDerivedFixture(t, db, 1, "rollback", false)
		require.NoError(t, db.Callback().Update().After("gorm:update").Register("owner:fail", func(tx *gorm.DB) {
			if tx.Statement.Table == "tokens" {
				tx.AddError(errors.New("failure after SQL update"))
			}
		}))
		token.Status = common.TokenStatusDisabled
		require.Error(t, token.UpdateForOwner(true))
		require.NoError(t, db.Callback().Update().Remove("owner:fail"))
		require.NoError(t, db.First(source, "grant_ref = ?", source.GrantRef).Error)
		assert.Nil(t, source.TerminalAt)
		require.NoError(t, db.First(token, token.Id).Error)
		assert.Equal(t, common.TokenStatusEnabled, token.Status)
		require.NoError(t, db.Callback().Delete().After("gorm:delete").Register("owner:fail", func(tx *gorm.DB) { tx.AddError(errors.New("failure after SQL delete")) }))
		require.Error(t, token.Delete())
		require.NoError(t, db.Callback().Delete().Remove("owner:fail"))
		require.NoError(t, db.Unscoped().First(token, token.Id).Error)
		assert.False(t, token.DeletedAt.Valid)
		require.NoError(t, db.First(source, "grant_ref = ?", source.GrantRef).Error)
		assert.Nil(t, source.TerminalAt)
	})
	t.Run("unknown_is_not_manual", func(t *testing.T) {
		db := setupTokenOwnerTestDB(t)
		_, source, derived := ownerDerivedFixture(t, db, 1, "unknown", false)
		manual := seedToken(t, db, 1, "manual", "unknown-manual-key")
		// Invalid binding must reject an entire mixed batch, never yield manual data.
		require.NoError(t, db.Model(source).UpdateColumn("key_ref", strings.Repeat("0", 64)).Error)
		tokens, err := model.GetTokenKeysByIds([]int{manual.Id, derived.Id}, 1)
		require.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
		assert.Nil(t, tokens)
		ctx, w := newAuthenticatedContext(t, "POST", "/api/token/batch/keys", TokenBatch{Ids: []int{manual.Id, derived.Id}}, 1)
		GetTokenKeysBatch(ctx)
		assert.Equal(t, 503, w.Code)
		assert.NotContains(t, w.Body.String(), manual.Key)
		assert.NotContains(t, w.Body.String(), derived.Key)
		// Missing source table is a real SQL error, not proof of manual origin.
		require.NoError(t, db.Migrator().DropTable(&model.OAuthDerivedTokenSource{}))
		tokens, err = model.GetTokenKeysByIds([]int{manual.Id}, 1)
		require.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
		assert.Nil(t, tokens)
		ctx, w = newAuthenticatedContext(t, "POST", "/api/token/batch/keys", TokenBatch{Ids: []int{manual.Id}}, 1)
		GetTokenKeysBatch(ctx)
		assert.Equal(t, 503, w.Code)
		assert.NotContains(t, w.Body.String(), "oauth_derived_token_sources")
		assert.NotContains(t, w.Body.String(), manual.Key)
		// Transaction begin failures have the same safe unknown contract.
		pool, err := db.DB()
		require.NoError(t, err)
		require.NoError(t, pool.Close())
		tokens, err = model.GetTokenKeysByIds([]int{manual.Id}, 1)
		require.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
		assert.Nil(t, tokens)
		_, err = model.GetTokenForOwner(manual.Id, 1)
		require.ErrorIs(t, err, model.ErrOAuthDerivedTokenUnknown)
		ctx, w = newAuthenticatedContext(t, "POST", "/api/token/batch/keys", TokenBatch{Ids: []int{manual.Id}}, 1)
		GetTokenKeysBatch(ctx)
		assert.Equal(t, 503, w.Code)
		assert.NotContains(t, w.Body.String(), "database is closed")
		assert.NotContains(t, w.Body.String(), manual.Key)
	})

	t.Run("same_user_creation_limit", func(t *testing.T) {
		db := setupTokenOwnerTestDB(t)
		old := operation_setting.GetTokenSetting().MaxUserTokens
		operation_setting.GetTokenSetting().MaxUserTokens = 1
		t.Cleanup(func() { operation_setting.GetTokenSetting().MaxUserTokens = old })
		start := make(chan struct{})
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Go(func() {
				<-start
				token := &model.Token{UserId: 1, Key: fmt.Sprintf("manual-default-%d", i), UnlimitedQuota: true, ExpiredTime: -1}
				results <- token.Insert()
			})
		}
		close(start)
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			}
		}
		assert.Equal(t, 1, success)
		var count int64
		require.NoError(t, db.Model(&model.Token{}).Where("user_id = ?", 1).Count(&count).Error)
		assert.EqualValues(t, 1, count)
	})
	t.Run("registration_default_token", func(t *testing.T) {
		db := setupTokenOwnerTestDB(t)
		register, password, email, generate, bonus := common.RegisterEnabled, common.PasswordRegisterEnabled, common.EmailVerificationEnabled, constant.GenerateDefaultToken, common.QuotaForNewUser
		common.RegisterEnabled, common.PasswordRegisterEnabled, common.EmailVerificationEnabled, constant.GenerateDefaultToken, common.QuotaForNewUser = true, true, false, true, 0
		t.Cleanup(func() {
			common.RegisterEnabled, common.PasswordRegisterEnabled, common.EmailVerificationEnabled, constant.GenerateDefaultToken, common.QuotaForNewUser = register, password, email, generate, bonus
		})
		ctx, w := newAuthenticatedContext(t, "POST", "/api/user/register", gin.H{"username": "new-owner", "password": "only-test-password-987"}, 0)
		Register(ctx)
		require.True(t, decodeAPIResponse(t, w).Success)
		var user model.User
		require.NoError(t, db.Where("username = ?", "new-owner").First(&user).Error)
		var tokens []model.Token
		require.NoError(t, db.Where("user_id = ?", user.Id).Find(&tokens).Error)
		require.Len(t, tokens, 1)
		assert.True(t, tokens[0].UnlimitedQuota)
		assert.EqualValues(t, -1, tokens[0].ExpiredTime)
		assert.Equal(t, 500000, tokens[0].RemainQuota)
		assert.NotEmpty(t, tokens[0].Key)
		assert.NotContains(t, w.Body.String(), tokens[0].Key)
	})

	t.Run("historical_finalize_after_revoke", func(t *testing.T) {
		db := setupTokenOwnerTestDB(t)
		_, jwt := ownerLifecycleRouter(t, db)
		require.NotEmpty(t, jwt)
		grant, source, token := ownerDerivedFixture(t, db, 1, "settle", false)
		require.NoError(t, db.Model(&model.User{}).Where("id = ?", 1).Update("quota", 1000).Error)
		facts := model.OAuthTextFacts{GrantRef: grant.GrantRef, UserID: 1, TokenID: token.Id, PolicyHash: source.PolicyHash, Model: "gpt-test", ChannelID: 1, RouteHash: strings.Repeat("c", 64), BodyHash: strings.Repeat("d", 64), ModelRatio: 1, CompletionRatio: 1, GroupRatio: 1, CacheRatio: 1, PromptEstimate: 10, MaxCompletion: 10}
		ref := strings.Repeat("e", 64)
		_, err := model.ReserveOAuthDerivedText(context.Background(), ref, facts, 80)
		require.NoError(t, err)
		_, err = model.ClaimOAuthDerivedText(context.Background(), ref, facts, 80)
		require.NoError(t, err)
		require.NoError(t, model.RevokeOAuth(context.Background(), 1, "grant", grant.GrantRef))
		for range 2 {
			out, err := model.FinalizeOAuthDerivedText(context.Background(), ref, 60, model.OAuthTextUsage{Prompt: 10, Completion: 10, Total: 20})
			require.NoError(t, err)
			assert.Equal(t, "settled", out.State)
			assert.Equal(t, 1, out.PayerID)
		}
		var user model.User
		require.NoError(t, db.First(&user, 1).Error)
		assert.Equal(t, 940, user.Quota)
		require.NoError(t, db.First(token, token.Id).Error)
		assert.Equal(t, 940, token.RemainQuota)
		assert.Equal(t, 60, token.UsedQuota)
		assert.Equal(t, common.TokenStatusDisabled, token.Status)
	})
}
