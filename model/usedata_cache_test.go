package model

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// The pre-cache fork schema, retained to exercise upgrades with existing data.
type quotaDataBeforeCache struct {
	Id        int    `json:"id"`
	UserID    int    `gorm:"index"`
	Username  string `gorm:"index:idx_qdt_model_user_name,priority:2;size:64;default:''"`
	ModelName string `gorm:"index:idx_qdt_model_user_name,priority:1;size:64;default:''"`
	CreatedAt int64  `gorm:"bigint;index:idx_qdt_created_at,priority:2"`
	UseGroup  string `gorm:"index;size:64;default:''"`
	TokenID   int    `gorm:"index;default:0"`
	ChannelID int    `gorm:"index;default:0"`
	NodeName  string `gorm:"index;size:64;default:''"`
	TokenUsed int    `gorm:"default:0"`
	Count     int    `gorm:"default:0"`
	Quota     int    `gorm:"default:0"`
}

func (quotaDataBeforeCache) TableName() string { return "quota_data" }

// DSNs must identify disposable, dedicated databases, never an application DB.
func TestDashboardCacheUsageDatabase(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			var driver gorm.Dialector
			switch dialect {
			case "sqlite":
				driver = sqlite.Open(":memory:")
			case "mysql":
				if os.Getenv("TEST_MYSQL_DSN") == "" {
					t.Skip("TEST_MYSQL_DSN is not configured")
				}
				driver = mysql.Open(os.Getenv("TEST_MYSQL_DSN"))
			case "postgres":
				if os.Getenv("TEST_POSTGRES_DSN") == "" {
					t.Skip("TEST_POSTGRES_DSN is not configured")
				}
				driver = postgres.Open(os.Getenv("TEST_POSTGRES_DSN"))
			}
			db, err := gorm.Open(driver, &gorm.Config{})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			sqlDB.SetMaxOpenConns(1)
			t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
			versionSQL := "SELECT version()"
			if dialect == "sqlite" {
				versionSQL = "SELECT sqlite_version()"
			}
			var version string
			require.NoError(t, db.Raw(versionSQL).Scan(&version).Error)
			t.Logf("database version: %s", version)
			previousDB, previousCache := DB, CacheQuotaData
			DB, CacheQuotaData = db, make(map[string]*QuotaData)
			t.Cleanup(func() { DB, CacheQuotaData = previousDB, previousCache })
			for _, source := range []string{"fresh", "fork-before-cache", "release-rc48"} {
				t.Run(source, func(t *testing.T) {
					require.NoError(t, db.Migrator().DropTable(&QuotaData{}))
					t.Cleanup(func() { assert.NoError(t, db.Migrator().DropTable(&QuotaData{})) })
					if source == "fork-before-cache" {
						require.NoError(t, db.AutoMigrate(&quotaDataBeforeCache{}))
						require.NoError(t, db.Create(&quotaDataBeforeCache{Id: 11, UserID: 9, Username: "legacy", ModelName: "legacy", CreatedAt: 3600, TokenUsed: 40, Count: 2, Quota: 50}).Error)
					}
					// rc.48 has the same QuotaData schema as this isolated upstream port.
					if source == "release-rc48" {
						require.NoError(t, db.AutoMigrate(&QuotaData{}))
						require.NoError(t, db.Create(&QuotaData{Id: 11, UserID: 9, Username: "legacy", ModelName: "legacy", CreatedAt: 3600, TokenUsed: 40, Count: 2, Quota: 50}).Error)
					}
					for range 2 {
						require.NoError(t, db.AutoMigrate(&QuotaData{}))
					}
					if source != "fresh" {
						var historical QuotaData
						require.NoError(t, db.First(&historical, 11).Error)
						assert.Equal(t, 40, historical.TokenUsed)
						assert.Equal(t, 2, historical.Count)
						assert.Equal(t, 50, historical.Quota)
						assert.Zero(t, historical.CacheReadTokens)
						assert.Zero(t, historical.CacheCreationTokens)
					}
					for _, index := range []string{"idx_quota_data_user_id", "idx_qdt_model_user_name", "idx_qdt_created_at", "idx_quota_data_use_group", "idx_quota_data_token_id", "idx_quota_data_channel_id", "idx_quota_data_node_name"} {
						assert.True(t, db.Migrator().HasIndex(&QuotaData{}, index), index)
					}
					params := QuotaDataLogParams{UserID: 1, Username: "alice", ModelName: "model", CreatedAt: 3601, Quota: 10, TokenUsed: 100, CacheReadTokens: 30, CacheCreationTokens: 7, UseGroup: "default", TokenID: 2, ChannelID: 3, NodeName: "node"}
					LogQuotaData(params)
					LogQuotaData(params)
					SaveQuotaDataCache()
					LogQuotaData(params)
					SaveQuotaDataCache()
					params.ChannelID = 4
					params.CacheReadTokens, params.CacheCreationTokens = -1, -2
					LogQuotaData(params)
					SaveQuotaDataCache()
					var dimensionRows []QuotaData
					require.NoError(t, db.Where("user_id = ?", 1).Order("channel_id").Find(&dimensionRows).Error)
					require.Len(t, dimensionRows, 2)
					assert.Equal(t, int64(90), dimensionRows[0].CacheReadTokens)
					assert.Equal(t, int64(21), dimensionRows[0].CacheCreationTokens)
					assert.Zero(t, dimensionRows[1].CacheReadTokens)
					assert.Zero(t, dimensionRows[1].CacheCreationTokens)
					queries := []func() ([]*QuotaData, error){
						func() ([]*QuotaData, error) { return GetQuotaDataByUsername("alice", 3600, 7200) },
						func() ([]*QuotaData, error) { return GetQuotaDataByUserId(1, 3600, 7200) },
						func() ([]*QuotaData, error) { return GetQuotaDataGroupByUser(3600, 7200) },
						func() ([]*QuotaData, error) { return GetAllQuotaDates(3600, 7200, "") },
					}
					for i, query := range queries {
						t.Run(fmt.Sprintf("query-%d", i), func(t *testing.T) {
							rows, err := query()
							require.NoError(t, err)
							var found *QuotaData
							for _, row := range rows {
								if row.Username == "alice" || row.ModelName == "model" {
									found = row
								}
							}
							require.NotNil(t, found)
							assert.Equal(t, int64(90), found.CacheReadTokens)
							assert.Equal(t, int64(21), found.CacheCreationTokens)
							assert.Equal(t, 400, found.TokenUsed)
							assert.Equal(t, 4, found.Count)
							assert.Equal(t, 40, found.Quota)
						})
					}
				})
			}
		})
	}
}

func TestDashboardCacheUsageConsumeLog(t *testing.T) {
	truncateTables(t)
	oldExport, oldCache := common.DataExportEnabled, CacheQuotaData
	common.DataExportEnabled, CacheQuotaData = true, make(map[string]*QuotaData)
	t.Cleanup(func() { common.DataExportEnabled, CacheQuotaData = oldExport, oldCache })
	require.NoError(t, DB.Create(&User{Id: 678, Username: "cache-user"}).Error)
	for _, other := range []*LogOther{nil, {public: map[string]any{"cache_tokens": 17, "cache_write_tokens": 13, "cache_creation_5m_tokens": 5, "cache_creation_1h_tokens": 8}}} {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Set("username", "cache-user")
		RecordConsumeLog(ctx, 678, RecordConsumeLogParams{PromptTokens: 100, CompletionTokens: 20, ModelName: "cache-model", Quota: 10, Other: other})
	}
	SaveQuotaDataCache()
	var row QuotaData
	require.NoError(t, DB.Where("user_id = ?", 678).First(&row).Error)
	assert.Equal(t, int64(17), row.CacheReadTokens)
	assert.Equal(t, int64(13), row.CacheCreationTokens)
	assert.Equal(t, 240, row.TokenUsed)
	assert.Equal(t, 20, row.Quota)
}
