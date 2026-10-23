package model

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestOAuthDerivedTextChargeFormalMigration(t *testing.T) {
	oldDB, oldLog := DB, LOG_DB
	oldMainType, oldLogType := common.MainDatabaseType(), common.LogDatabaseType()
	t.Cleanup(func() {
		DB, LOG_DB = oldDB, oldLog
		common.SetMainDatabaseType(oldMainType)
		common.SetLogDatabaseType(oldLogType)
		initCol()
	})
	for _, target := range []**gorm.DB{&DB, &LOG_DB} {
		db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "migration.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		require.NoError(t, err)
		*target = db
		sqlDB, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, sqlDB.Close()) })
	}
	common.SetMainDatabaseType(common.DatabaseTypeSQLite)
	common.SetLogDatabaseType(common.DatabaseTypeSQLite)
	initCol()
	require.NoError(t, migrateDB())
	require.NoError(t, migrateLOGDB())
	require.True(t, DB.Migrator().HasTable(&OAuthDerivedTextCharge{}))
	assert.False(t, LOG_DB.Migrator().HasTable(&OAuthDerivedTextCharge{}))
	actual := 7
	rows := []OAuthDerivedTextCharge{
		{Ref: strings.Repeat("a", 64), UserID: 1, Reserve: 11, State: "reserved", Version: 1, Facts: "{}", Usage: "{}"},
		{Ref: strings.Repeat("b", 64), UserID: 1, Reserve: 11, Actual: &actual, State: "settled", Version: 3, Facts: "{}", Usage: "{}"},
	}
	require.NoError(t, DB.Create(&rows).Error)
	for range 2 {
		require.NoError(t, migrateDB())
		require.NoError(t, migrateLOGDB())
		var got []OAuthDerivedTextCharge
		require.NoError(t, DB.Order("ref").Find(&got).Error)
		assert.Equal(t, rows, got)
		assert.True(t, DB.Migrator().HasIndex(&OAuthDerivedTextCharge{}, "idx_oauth_text_user_state"))
		assert.False(t, LOG_DB.Migrator().HasTable(&OAuthDerivedTextCharge{}))
		duplicate := rows[0]
		assert.Error(t, DB.Create(&duplicate).Error, "historical reference must remain unique")
	}
}
