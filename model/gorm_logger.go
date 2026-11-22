package model

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/proto"
	"github.com/QuantumNous/new-api/common"
	sqlitedriver "github.com/glebarez/go-sqlite"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	defaultSlowThresholdMs = 200
	maxSlowThresholdMs     = 60 * 60 * 1000
)

func newGormConfig(prepareStmt bool) *gorm.Config {
	return &gorm.Config{
		PrepareStmt: prepareStmt,
		Logger:      newGormLogger(os.Stdout),
	}
}

func newGormLogger(w io.Writer) logger.Interface {
	slowThresholdMs := common.GetEnvOrDefault("SQL_SLOW_THRESHOLD_MS", defaultSlowThresholdMs)
	if slowThresholdMs < 0 || slowThresholdMs > maxSlowThresholdMs {
		common.SysError(common.LogText("invalid SQL_SLOW_THRESHOLD_MS %d (allowed 0-%d, 0 disables slow query log), using default %d", slowThresholdMs, maxSlowThresholdMs, defaultSlowThresholdMs))
		slowThresholdMs = defaultSlowThresholdMs
	}
	// 在 Writer 层脱敏而非包装 logger.Interface:后者会让 gorm 的 FileWithLineNum
	// 把所有 SQL 日志的调用点归因到包装层自身,且需转发 ParamsFilter 类型断言。
	return logger.New(&sanitizedLogWriter{delegate: log.New(w, "\r\n", log.LstdFlags)}, logger.Config{
		SlowThreshold:             time.Duration(slowThresholdMs) * time.Millisecond,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
		Colorful:                  true,
	})
}

// ParameterizedQueries covers SQL arguments. Driver and scan errors can also
// contain data values, regardless of the configured SQL log level.
type sanitizedLogWriter struct {
	delegate *log.Logger
}

func (s *sanitizedLogWriter) Printf(format string, args ...any) {
	// GORM's success, slow, and error trace formats all end in the rendered
	// SQL after [rows:%v]. Scan uses a recorder that bypasses ParamsFilter,
	// so even a parameterized logger must discard that final SQL argument.
	if strings.Contains(format, "[%.3fms] ") && strings.Contains(format, "[rows:%v]") && len(args) > 0 {
		last := len(args) - 1
		statement, _ := args[last].(string)
		args[last] = "operation=" + sqlLogOperation(statement)
	}
	for i, arg := range args {
		if err, ok := arg.(error); ok {
			args[i] = sanitizeDBError(err)
		}
	}
	s.delegate.Printf(format, args...)
}

func sqlLogOperation(statement string) string {
	for word := range strings.FieldsSeq(statement) {
		operation := strings.ToUpper(word)
		switch operation {
		case "SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "ALTER",
			"DROP", "TRUNCATE", "SHOW", "PRAGMA", "EXPLAIN", "REPLACE",
			"MERGE", "SET", "BEGIN", "COMMIT", "ROLLBACK":
			return operation
		}
		break
	}
	return "OTHER"
}

var validSQLState = regexp.MustCompile(`^[0-9A-Z]{5}$`)

// sanitizeDBError projects diagnostics without changing the error returned to
// the database caller.
func sanitizeDBError(err error) error {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return fmt.Errorf("mysql error %d", mysqlErr.Number)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if !validSQLState.MatchString(pgErr.Code) {
			return errors.New("postgres error")
		}
		// 08P01 是 PgBouncer 对同连接重名 Parse 的 FATAL,42P05 是原生 PostgreSQL 的
		// duplicate_prepared_statement;都指向预处理语句与事务池代理不兼容。
		if pgErr.Code == "08P01" || pgErr.Code == "42P05" {
			return fmt.Errorf("postgres error SQLSTATE %s: prepared statement conflict with a transaction-pooling proxy (PgBouncer/Neon/Supabase); other clients sharing this database must disable prepared statements, or upgrade PgBouncer to >=1.21 with max_prepared_statements enabled", pgErr.Code)
		}
		return fmt.Errorf("postgres error SQLSTATE %s", pgErr.Code)
	}
	var chErr *proto.Exception
	if errors.As(err, &chErr) {
		return fmt.Errorf("clickhouse error %d", chErr.Code)
	}
	var sqliteErr *sqlitedriver.Error
	if errors.As(err, &sqliteErr) {
		return fmt.Errorf("sqlite error %d", sqliteErr.Code())
	}
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, driver.ErrBadConn):
		return driver.ErrBadConn
	}
	var networkErr *net.OpError
	if errors.As(err, &networkErr) {
		return errors.New("database network error")
	}
	return errors.New("database operation failed")
}
