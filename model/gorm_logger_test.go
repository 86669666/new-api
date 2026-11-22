package model

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/proto"
	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 保护契约:数据库驱动错误消息可能内联数据值,非 DEBUG 下日志只保留错误码。
func TestSanitizeDBErrorStripsDriverMessage(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		want   string
		leaked string
	}{
		{
			name:   "mysql duplicate entry",
			err:    &mysql.MySQLError{Number: 1062, Message: "Duplicate entry 'secret-value' for key 'users.idx'"},
			want:   "mysql error 1062",
			leaked: "secret-value",
		},
		{
			name:   "postgres unique violation",
			err:    &pgconn.PgError{Code: "23505", Message: "duplicate key value", Detail: "Key (k)=(secret-value) already exists."},
			want:   "postgres error SQLSTATE 23505",
			leaked: "secret-value",
		},
		{
			name:   "invalid postgres state is kept out of logs",
			err:    &pgconn.PgError{Code: "fixture-private-data", Message: "invalid diagnostic"},
			want:   "postgres error",
			leaked: "fixture-private-data",
		},
		{
			name:   "postgres pooler prepared statement conflict gets remediation hint",
			err:    &pgconn.PgError{Severity: "FATAL", Code: "08P01", Message: "prepared statement name is already in use: stmt_secret-value"},
			want:   "postgres error SQLSTATE 08P01: prepared statement conflict with a transaction-pooling proxy (PgBouncer/Neon/Supabase); other clients sharing this database must disable prepared statements, or upgrade PgBouncer to >=1.21 with max_prepared_statements enabled",
			leaked: "secret-value",
		},
		{
			name:   "clickhouse exception",
			err:    &proto.Exception{Code: 241, Message: "Memory limit exceeded while processing 'secret-value'"},
			want:   "clickhouse error 241",
			leaked: "secret-value",
		},
		{
			name:   "wrapped driver error",
			err:    fmt.Errorf("exec failed: %w", &mysql.MySQLError{Number: 1064, Message: "syntax error near 'secret-value'"}),
			want:   "mysql error 1064",
			leaked: "secret-value",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeDBError(tc.err)
			require.Error(t, got)
			assert.Equal(t, tc.want, got.Error())
			assert.NotContains(t, got.Error(), tc.leaked)
		})
	}
}

func TestSanitizeDBErrorSQLiteDriver(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	execErr := db.Exec("INSERT INTO missing_table (k) VALUES (?)", "secret-value").Error
	require.Error(t, execErr)

	got := sanitizeDBError(execErr)
	assert.Regexp(t, `^sqlite error \d+$`, got.Error())
	assert.NotContains(t, got.Error(), "secret-value")
}

func TestSanitizeDBErrorClassifiesNonDriverErrors(t *testing.T) {
	const marker = "fixture-private-diagnostic"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"scan", fmt.Errorf("cannot scan value %q into column", marker), "database operation failed"},
		{"network", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New(marker)}, "database network error"},
		{"timeout", fmt.Errorf("%s: %w", marker, context.DeadlineExceeded), "context deadline exceeded"},
		{"canceled", fmt.Errorf("%s: %w", marker, context.Canceled), "context canceled"},
		{"bad connection", fmt.Errorf("%s: %w", marker, driver.ErrBadConn), "driver: bad connection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorContains(t, tc.err, marker)
			assert.EqualError(t, sanitizeDBError(tc.err), tc.want)
		})
	}
}

// Exercise the two logging modes through GORM and SQLite. The SQL engine
// still receives its arguments and the caller still receives driver errors.
func TestGormLoggerEndToEndSanitizedOutput(t *testing.T) {
	t.Setenv("SQL_SLOW_THRESHOLD_MS", "0")
	previousDebug := common.DebugEnabled
	t.Cleanup(func() { common.DebugEnabled = previousDebug })

	for _, tc := range []struct {
		name  string
		debug bool
	}{{"default", false}, {"debug", true}} {
		t.Run(tc.name, func(t *testing.T) {
			const value = "fixture-sql-binding-%2B"
			common.DebugEnabled = tc.debug
			var logs bytes.Buffer
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: newGormLogger(&logs)})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
			if tc.debug {
				db = db.Debug()
			}

			var actual string
			require.NoError(t, db.Raw("SELECT ? AS value", value).Scan(&actual).Error)
			assert.Equal(t, value, actual)
			if tc.debug {
				assert.Contains(t, logs.String(), "operation=SELECT")
				assert.Contains(t, logs.String(), "[rows:1]")
			} else {
				assert.Empty(t, logs.String())
			}
			assert.NotContains(t, logs.String(), value)

			logs.Reset()
			queryErr := db.Exec("SELECT * FROM missing_table WHERE k = ?", value).Error
			require.ErrorContains(t, queryErr, "no such table")
			assert.Contains(t, logs.String(), "operation=SELECT")
			assert.Contains(t, logs.String(), "sqlite error")
			assert.Contains(t, logs.String(), "gorm_logger_test.go")
			assert.NotContains(t, logs.String(), value)
			assert.NotContains(t, logs.String(), "no such table")
			assert.NotContains(t, logs.String(), "missing_table")
		})
	}

	t.Run("slow trace", func(t *testing.T) {
		t.Setenv("SQL_SLOW_THRESHOLD_MS", "1")
		var logs bytes.Buffer
		newGormLogger(&logs).Trace(t.Context(), time.Now().Add(-time.Second), func() (string, int64) {
			return "/* fixture-private-sql-comment */ select 'fixture-private-binding'", -1
		}, nil)
		assert.Contains(t, logs.String(), "SLOW SQL")
		assert.Contains(t, logs.String(), "[rows:-]")
		assert.Contains(t, logs.String(), "operation=OTHER")
		assert.NotContains(t, logs.String(), "fixture-private-sql-comment")
		assert.NotContains(t, logs.String(), "fixture-private-binding")
	})
}

func TestTaskAccountingDoesNotRepeatDatabaseErrorDetails(t *testing.T) {
	const fixture = "fixture-private-billing-error"
	var output bytes.Buffer
	common.LogWriterMu.Lock()
	oldWriter := gin.DefaultWriter
	gin.DefaultWriter = &output
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter = oldWriter
		common.LogWriterMu.Unlock()
	})

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&User{}, &Channel{}, &Log{}))

	oldDB, oldLogDB, oldRedis := DB, LOG_DB, common.RedisEnabled
	oldBatch := common.BatchUpdateEnabled
	DB, LOG_DB, common.RedisEnabled = db, db, false
	common.BatchUpdateEnabled = false
	t.Cleanup(func() {
		DB, LOG_DB, common.RedisEnabled = oldDB, oldLogDB, oldRedis
		common.BatchUpdateEnabled = oldBatch
	})
	failWrite := func(tx *gorm.DB) {
		tx.AddError(&mysql.MySQLError{Number: 1062, Message: fixture})
	}
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("fixture:log_write", failWrite))
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register("fixture:usage_write", failWrite))

	RecordTaskBillingLog(RecordTaskBillingLogParams{LogType: LogTypeRefund, Quota: 1})
	UpdateUserUsedQuota(1, -1)
	updateUserUsedQuotaAndRequestCount(1, -1, 0)
	UpdateChannelUsedQuota(1, -1)

	assert.Contains(t, output.String(), "failed to record task billing log: mysql error 1062")
	assert.Contains(t, output.String(), "failed to update user used quota: mysql error 1062")
	assert.Contains(t, output.String(), "failed to update user used quota and request count: mysql error 1062")
	assert.Contains(t, output.String(), "delta_quota=-1, error=mysql error 1062")
	assert.NotContains(t, output.String(), fixture)
}
