#!/usr/bin/env python3
"""Build actual release/candidate fixtures and execute an explicit database phase manifest.

Only exported source copies receive the generated test entry. Each phase is a new
process. A missing engine/phase is an incomplete matrix, even if SQLite passes.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import tarfile
import time
import tempfile
from urllib.parse import urlsplit, unquote, quote

from run_isolated_databases import (terminate_group, guarded_communicate, docker_command,
                                    OwnedRelay, RelayIdentityError, ClickHouseAuth, CLICKHOUSE_IMAGE, CLICKHOUSE_CLIENT,
                                    validate_inherited_environment)

RELEASE = '633b4c5b190dc1af99a2814391354d86948e7943'
COMBINATIONS = (('sqlite', 'same'), ('mysql', 'same'), ('postgres', 'same'),
                ('mysql', 'sqlite'), ('sqlite', 'mysql'), ('sqlite', 'postgres'), ('sqlite', 'clickhouse'))
PHASES = ('fresh_seed', 'fresh_restart', 'release_seed', 'backup', 'candidate_start_1',
          'candidate_start_2', 'fault_clone', 'fault_inject', 'migration_rejected',
          'restore_new', 'release_readback')
FIXTURE = r'''package fixture

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"sort"
	"testing"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/clickhouse"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/migrator"
)

func connect(t *testing.T, kind, dsn string) *gorm.DB {
	t.Helper()
	var dialector gorm.Dialector
	switch kind {
	case "sqlite":
		dialector = sqlite.Open(dsn)
	case "mysql":
		dialector = mysql.Open(dsn)
	case "postgres":
		dialector = postgres.Open(dsn)
	case "clickhouse":
		dialector = clickhouse.Open(dsn)
	default:
		t.Fatalf("unsupported engine %s", kind)
	}
	db, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	return db
}

type postgresTableIdentity struct {
	SchemaName string
	TableName  string
	TableOID   int64 `gorm:"column:table_oid"`
}

type postgresIndexColumn struct {
	SchemaName           string
	TableName            string
	TableOID             int64 `gorm:"column:table_oid"`
	IndexSchema          string
	IndexName            string
	IndexOID             int64 `gorm:"column:index_oid"`
	Position             int
	ColumnCount          int
	KeyCount             int
	AttributeNumber      int
	ColumnName           string
	Unique               sql.NullBool
	Primary              sql.NullBool
	Valid                sql.NullBool
	Ready                sql.NullBool
	Live                 sql.NullBool
	Expression           sql.NullBool
	Partial              sql.NullBool
	Exclusion            sql.NullBool
	Immediate            sql.NullBool
	NullsNotDistinct     sql.NullBool
	DefaultOpclass       sql.NullBool
	DefaultCollation     sql.NullBool
	DefaultOrder         sql.NullBool
	Predicate            sql.NullString
	PredicateKnown       sql.NullBool
	Definition           string
	KeyDefinition        string
	AccessMethod         string
	ConstraintID         sql.NullInt64
	ConstraintName       sql.NullString
	ConstraintKind       sql.NullString
	ConstraintDeferrable sql.NullBool
	ConstraintDeferred   sql.NullBool
	ConstraintValidated  sql.NullBool
	ConstraintDefinition sql.NullString
}

// Catalog OIDs bind identity within one collection only. They never enter the
// cross-database snapshot. Missing/NULL booleans remain unknown after GORM Scan.
// Version-specific columns use to_jsonb so this SQL remains parseable on 9.6.
const postgresIndexColumnsSQL = `
SELECT tn.nspname AS schema_name, t.relname AS table_name, t.oid::bigint AS table_oid,
 ixn.nspname AS index_schema, ix.relname AS index_name, ix.oid::bigint AS index_oid,
 k.position, i.indnatts AS column_count,
 COALESCE((to_jsonb(i)->>'indnkeyatts')::int, i.indnatts) AS key_count,
 k.attnum AS attribute_number, COALESCE(a.attname, '') AS column_name,
 i.indisunique AS "unique", i.indisprimary AS "primary",
 i.indisvalid AS valid, i.indisready AS ready, i.indislive AS live,
 i.indexprs IS NOT NULL AS expression, i.indpred IS NOT NULL AS partial,
 i.indisexclusion AS exclusion, i.indimmediate AS immediate,
 COALESCE((to_jsonb(i)->>'indnullsnotdistinct')::boolean, false) AS nulls_not_distinct,
 opc.opcdefault AS default_opclass,
 i.indcollation[(k.position-1)::int] = a.attcollation AS default_collation,
 i.indoption[(k.position-1)::int] = 0 AS default_order,
 pg_catalog.pg_get_expr(i.indpred, i.indrelid, false) AS predicate, true AS predicate_known,
 pg_catalog.pg_get_indexdef(ix.oid, 0, false) AS definition,
 pg_catalog.pg_get_indexdef(ix.oid, k.position::int, false) AS key_definition,
 am.amname AS access_method,
 con.oid::bigint AS constraint_id, con.conname AS constraint_name, con.contype::text AS constraint_kind,
 con.condeferrable AS constraint_deferrable, con.condeferred AS constraint_deferred,
 con.convalidated AS constraint_validated, pg_catalog.pg_get_constraintdef(con.oid, false) AS constraint_definition
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class t ON t.oid = i.indrelid
JOIN pg_catalog.pg_namespace tn ON tn.oid = t.relnamespace
JOIN pg_catalog.pg_class ix ON ix.oid = i.indexrelid
JOIN pg_catalog.pg_namespace ixn ON ixn.oid = ix.relnamespace
JOIN pg_catalog.pg_am am ON am.oid = ix.relam
CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, position)
LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum AND NOT a.attisdropped
LEFT JOIN pg_catalog.pg_opclass opc ON opc.oid = i.indclass[(k.position-1)::int]
LEFT JOIN pg_catalog.pg_constraint con ON con.conindid = ix.oid AND con.conrelid = t.oid AND con.contype IN ('p','u')
WHERE t.oid = ? AND tn.nspname = ? AND t.relname = ? AND t.relkind = 'r' AND ix.relkind = 'i'
ORDER BY ix.oid, k.position
LIMIT 4097`

type postgresPhysicalIndex struct {
	migrator.Index
	Metadata map[string]any
}

func postgresOrderedIndexes(table postgresTableIdentity, rows []postgresIndexColumn) ([]gorm.Index, error) {
	if table.TableOID <= 0 || table.SchemaName == "" || table.TableName == "" {
		return nil, fmt.Errorf("invalid PostgreSQL table identity")
	}
	result := []gorm.Index{}
	seen := map[string]int64{}
	var current *postgresPhysicalIndex
	var previous postgresIndexColumn
	for _, row := range rows {
		if row.TableOID != table.TableOID || row.SchemaName != table.SchemaName || row.TableName != table.TableName || row.IndexSchema != table.SchemaName || row.IndexName == "" || row.IndexOID <= 0 {
			return nil, fmt.Errorf("foreign or invalid PostgreSQL index identity")
		}
		for _, flag := range []sql.NullBool{row.Unique, row.Primary, row.Valid, row.Ready, row.Live, row.Expression, row.Partial, row.Exclusion, row.Immediate, row.NullsNotDistinct, row.DefaultOpclass, row.DefaultCollation, row.DefaultOrder, row.PredicateKnown} {
			if !flag.Valid {
				return nil, fmt.Errorf("unknown PostgreSQL index metadata: %s", row.IndexName)
			}
		}
		if !row.Valid.Bool || !row.Ready.Bool || !row.Live.Bool || row.Expression.Bool || row.Exclusion.Bool || !row.Immediate.Bool || row.NullsNotDistinct.Bool || !row.DefaultOpclass.Bool || !row.DefaultCollation.Bool || !row.DefaultOrder.Bool || row.AccessMethod != "btree" || row.Definition == "" || row.KeyDefinition == "" || !row.PredicateKnown.Bool || row.ColumnCount <= 0 || row.KeyCount != row.ColumnCount || row.AttributeNumber <= 0 || row.ColumnName == "" || (row.Primary.Bool && !row.Unique.Bool) {
			return nil, fmt.Errorf("unsupported or invalid PostgreSQL index metadata: %s", row.IndexName)
		}
		if row.Partial.Bool != row.Predicate.Valid || (row.Partial.Bool && (table.TableName != "prefill_groups" || row.IndexName != "uk_prefill_name" || row.ColumnCount != 1 || row.ColumnName != "name" || !row.Unique.Bool || row.Primary.Bool || row.Predicate.String != "(deleted_at IS NULL)")) {
			return nil, fmt.Errorf("unsupported PostgreSQL index predicate: %s", row.IndexName)
		}
		if row.ConstraintID.Valid {
			if row.ConstraintID.Int64 <= 0 || !row.ConstraintName.Valid || row.ConstraintName.String == "" || !row.ConstraintKind.Valid || (row.ConstraintKind.String != "p" && row.ConstraintKind.String != "u") || !row.ConstraintDeferrable.Valid || row.ConstraintDeferrable.Bool || !row.ConstraintDeferred.Valid || row.ConstraintDeferred.Bool || !row.ConstraintValidated.Valid || !row.ConstraintValidated.Bool || !row.ConstraintDefinition.Valid || row.ConstraintDefinition.String == "" || !row.Unique.Bool || row.Primary.Bool != (row.ConstraintKind.String == "p") || row.Partial.Bool {
				return nil, fmt.Errorf("unsupported PostgreSQL index constraint: %s", row.IndexName)
			}
		} else if row.Primary.Bool || row.ConstraintName.Valid || row.ConstraintKind.Valid || row.ConstraintDeferrable.Valid || row.ConstraintDeferred.Valid || row.ConstraintValidated.Valid || row.ConstraintDefinition.Valid {
			return nil, fmt.Errorf("incomplete PostgreSQL index constraint: %s", row.IndexName)
		}
		if current == nil || row.IndexOID != previous.IndexOID {
			if current != nil && len(current.ColumnList) != previous.ColumnCount {
				return nil, fmt.Errorf("incomplete PostgreSQL index: %s", previous.IndexName)
			}
			if _, exists := seen[row.IndexName]; exists {
				return nil, fmt.Errorf("duplicate PostgreSQL index identity: %s", row.IndexName)
			}
			if current != nil && row.IndexOID <= previous.IndexOID {
				return nil, fmt.Errorf("unordered PostgreSQL index identities")
			}
			seen[row.IndexName] = row.IndexOID
			metadata := map[string]any{"primary": row.Primary.Bool, "primary_known": row.Primary.Valid, "partial": row.Partial.Bool, "partial_known": row.Partial.Valid, "predicate": row.Predicate.String, "predicate_known": row.PredicateKnown.Bool, "predicate_null": !row.Predicate.Valid, "definition": row.Definition, "access_method": row.AccessMethod, "constraint": nil}
			if row.ConstraintID.Valid {
				metadata["constraint"] = map[string]any{"name": row.ConstraintName.String, "kind": row.ConstraintKind.String, "deferrable": row.ConstraintDeferrable.Bool, "deferred": row.ConstraintDeferred.Bool, "validated": row.ConstraintValidated.Bool, "definition": row.ConstraintDefinition.String}
			}
			current = &postgresPhysicalIndex{Index: migrator.Index{TableName: table.TableName, NameValue: row.IndexName, PrimaryKeyValue: row.Primary, UniqueValue: row.Unique}, Metadata: metadata}
			result = append(result, current)
		} else {
			header, prior := row, previous
			header.Position = 0
			prior.Position = 0
			header.AttributeNumber = 0
			prior.AttributeNumber = 0
			header.ColumnName = ""
			prior.ColumnName = ""
			header.KeyDefinition = ""
			prior.KeyDefinition = ""
			if header != prior {
				return nil, fmt.Errorf("inconsistent PostgreSQL index identity: %s", row.IndexName)
			}
		}
		if row.Position != len(current.ColumnList)+1 || row.Position > row.ColumnCount {
			return nil, fmt.Errorf("invalid PostgreSQL index key ordinal: %s", row.IndexName)
		}
		current.ColumnList = append(current.ColumnList, row.ColumnName)
		previous = row
	}
	if current != nil && len(current.ColumnList) != previous.ColumnCount {
		return nil, fmt.Errorf("incomplete PostgreSQL index: %s", previous.IndexName)
	}
	return result, nil
}

// Bounded catalog-only diagnostics are emitted before semantic validation, including
// failures. Error text from drivers is deliberately excluded (it may contain a DSN).
func writePostgresDiagnostic(w io.Writer, diagnostic map[string]any) error {
	encoded, err := common.Marshal(diagnostic)
	if err != nil || len(encoded) > 4*1024*1024 {
		_, writeErr := fmt.Fprintln(w, `A03_POSTGRES_CATALOG {"diagnostic_incomplete":true,"category":"serialization_or_size_limit"}`)
		if writeErr != nil {
			return fmt.Errorf("PostgreSQL diagnostic incomplete: write failed")
		}
		return fmt.Errorf("PostgreSQL diagnostic incomplete: serialization or size limit")
	}
	n, err := fmt.Fprintf(w, "A03_POSTGRES_CATALOG %s\n", encoded)
	if err != nil || n != len(encoded)+len("A03_POSTGRES_CATALOG \n") {
		return fmt.Errorf("PostgreSQL diagnostic incomplete: write failed")
	}
	return nil
}

func collectPostgresIndexes(db *gorm.DB, table string, w io.Writer) (postgresTableIdentity, []postgresIndexColumn, error) {
	role := "main"
	if db == model.LOG_DB && db != model.DB {
		role = "log"
	}
	diagnostic := map[string]any{"phase": os.Getenv("A03_PHASE"), "role": role, "table": table, "metadata_available": false, "diagnostic_incomplete": false, "search_path": "public"}
	var identities []postgresTableIdentity
	var rows []postgresIndexColumn
	category := "transaction_query"
	err := db.Transaction(func(tx *gorm.DB) error {
		// SET LOCAL scopes deparser qualification to this transaction and this connection.
		if err := tx.Exec("SET LOCAL search_path TO public").Error; err != nil {
			return err
		}
		var version string
		category = "server_version_query"
		if err := tx.Raw("SELECT version()").Scan(&version).Error; err != nil {
			return err
		}
		diagnostic["server_version"] = version
		category = "table_identity_query"
		if err := tx.Raw(`SELECT n.nspname AS schema_name, c.relname AS table_name, c.oid::bigint AS table_oid
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema() AND c.relname = ? AND c.relkind = 'r'`, table).Scan(&identities).Error; err != nil {
			return err
		}
		diagnostic["identities"] = identities
		if len(identities) != 1 || identities[0].TableName != table {
			category = "table_identity_unavailable"
			return fmt.Errorf("table identity unavailable")
		}
		identity := identities[0]
		category = "index_catalog_query"
		if err := tx.Raw(postgresIndexColumnsSQL, identity.TableOID, identity.SchemaName, identity.TableName).Scan(&rows).Error; err != nil {
			return err
		}
		diagnostic["rows"] = rows
		diagnostic["metadata_available"] = true
		if len(rows) > 4096 {
			category = "catalog_row_limit"
			return fmt.Errorf("catalog row limit exceeded")
		}
		category = "transaction_commit"
		return nil
	})
	if err != nil {
		diagnostic["category"] = category
		diagnostic["diagnostic_incomplete"] = true
	}
	if writeErr := writePostgresDiagnostic(w, diagnostic); writeErr != nil {
		return postgresTableIdentity{}, nil, writeErr
	}
	if err != nil {
		return postgresTableIdentity{}, nil, fmt.Errorf("PostgreSQL catalog unavailable: %s", category)
	}
	return identities[0], rows, nil
}

func fixtureIndexes(db *gorm.DB, table string) ([]gorm.Index, error) {
	if db.Dialector.Name() != "postgres" {
		return db.Migrator().GetIndexes(table)
	}
	identity, rows, err := collectPostgresIndexes(db, table, os.Stdout)
	if err != nil {
		return nil, err
	}
	return postgresOrderedIndexes(identity, rows)
}

func schema(t *testing.T, db *gorm.DB, kind string) []any {
	t.Helper()
	var tables []string
	var err error
	if kind == "clickhouse" {
		err = db.Raw("SELECT table_name FROM information_schema.tables WHERE table_schema = currentDatabase() AND table_type = 'BASE TABLE'").Scan(&tables).Error
	} else {
		tables, err = db.Migrator().GetTables()
	}
	require.NoError(t, err)
	if kind == "clickhouse" {
		require.NotEmpty(t, tables, "ClickHouse fixture table inventory must not be empty")
	}
	sort.Strings(tables)
	result := []any{}
	for _, table := range tables {
		if table == "sqlite_sequence" {
			continue
		}
		if kind == "clickhouse" {
			var ddl string
			require.NoError(t, db.Raw("SHOW CREATE TABLE "+table).Scan(&ddl).Error)
			result = append(result, map[string]any{"table": table, "ddl": ddl})
			continue
		}
		columns, err := db.Migrator().ColumnTypes(table)
		require.NoError(t, err)
		cols := []any{}
		for _, c := range columns {
			nullable, nok := c.Nullable()
			pk, pok := c.PrimaryKey()
			length, lok := c.Length()
			def, dok := c.DefaultValue()
			cols = append(cols, map[string]any{"name": c.Name(), "type": c.DatabaseTypeName(), "nullable": nullable, "nullable_known": nok, "pk": pk, "pk_known": pok, "length": length, "length_known": lok, "default": def, "default_known": dok})
		}
		indexes, err := fixtureIndexes(db, table)
		require.NoError(t, err)
		sort.Slice(indexes, func(i, j int) bool { return indexes[i].Name() < indexes[j].Name() })
		idx := []any{}
		for _, i := range indexes {
			u, known := i.Unique()
			entry := map[string]any{"name": i.Name(), "columns": i.Columns(), "unique": u, "known": known}
			if pg, ok := i.(*postgresPhysicalIndex); ok {
				for key, value := range pg.Metadata {
					entry[key] = value
				}
			}
			idx = append(idx, entry)
		}
		result = append(result, map[string]any{"table": table, "columns": cols, "indexes": idx})
	}
	return result
}

func TestReleasedDatabaseGate(t *testing.T) {
	require.Equal(t, "isolated-ci", os.Getenv("NEWAPI_TEST_PROFILE"))
	if os.Getenv("A03_ENGINE") == "sqlite" {
		var version string
		db := connect(t, "sqlite", os.Getenv("SQLITE_PATH"))
		require.NoError(t, db.Raw("SELECT sqlite_version()").Scan(&version).Error)
		t.Log("actual SQLite library version=" + version)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		require.NoError(t, sqlDB.Close())
	}
	kind, logkind, phase := os.Getenv("A03_ENGINE"), os.Getenv("A03_LOG_ENGINE"), os.Getenv("A03_PHASE")
	common.InitEnv()
	common.RedisEnabled = false
	common.MemoryCacheEnabled = false
	ratio_setting.InitRatioSettings()
	if phase == "read" || phase == "fault" {
		dsn := os.Getenv("SQL_DSN")
		if kind == "sqlite" {
			dsn = common.SQLitePath
		}
		model.DB = connect(t, kind, dsn)
		if logkind == "same" {
			model.LOG_DB = model.DB
		} else {
			logdsn := os.Getenv("LOG_SQL_DSN")
			if logkind == "sqlite" {
				logdsn = common.SQLitePath
			}
			model.LOG_DB = connect(t, logkind, logdsn)
		}
	} else {
		err := model.InitDB()
		if phase == "expect_failure" {
			require.Error(t, err, "duplicate key fixture must prevent migration")
			require.NoError(t, os.WriteFile(os.Getenv("A03_RESULT"), []byte(`{"migration_rejected":true}`), 0600))
			return
		}
		require.NoError(t, err)
		require.NoError(t, authz.Init(model.DB))
		if common.PasswordLoginEncryptionEnabled {
			require.NoError(t, model.InitPasswordEncryption())
		}
		model.CheckSetup()
		require.NoError(t, model.MigrateRetiredFrontendOptions())
		model.InitOptionMap()
		require.NoError(t, model.InitLogDB())
	}
	defer func() { require.NoError(t, model.CloseDB()) }()
	model.DB.Logger = logger.Default.LogMode(logger.Silent)
	model.LOG_DB.Logger = logger.Default.LogMode(logger.Silent)
	for _, db := range []*gorm.DB{model.DB, model.LOG_DB} {
		if db.Dialector.Name() == "postgres" {
			tables, err := db.Migrator().GetTables()
			if err != nil || len(tables) > 128 {
				require.NoError(t, writePostgresDiagnostic(os.Stdout, map[string]any{"phase": phase, "diagnostic_incomplete": true, "category": "table_inventory_unavailable_or_limit", "table_count": len(tables)}))
				t.Fatal("PostgreSQL table inventory unavailable or limit exceeded")
			}
			sort.Strings(tables)
			for _, table := range tables {
				_, _, err := collectPostgresIndexes(db, table, os.Stdout)
				require.NoError(t, err)
			}
		}
	}
	if phase == "fault" {
		require.NoError(t, model.DB.Migrator().DropIndex(&model.Token{}, "idx_tokens_key"))
		var token model.Token
		require.NoError(t, model.DB.First(&token).Error)
		token.Id = 0
		token.Name = "duplicate-fixture"
		require.NoError(t, model.DB.Create(&token).Error)
		require.NoError(t, os.WriteFile(os.Getenv("A03_RESULT"), []byte(`{"fault_injected":true}`), 0600))
		return
	}
	if phase == "seed" {
		users := []model.User{{Username: "fixture-zero", Password: "unusable-fixture-hash", DisplayName: "零值中文", AffCode: "fixture-zero", Quota: 0},
			{Username: "fixture-wallet", Password: "unusable-fixture-hash", DisplayName: "迁移保全", AffCode: "fixture-wallet", Quota: 4294967301, UsedQuota: 7, Remark: "UTF8 中文 🧪", Setting: `{"fixture":true}`}}
		for i := range users {
			require.NoError(t, model.DB.Create(&users[i]).Error)
		}
		require.NoError(t, model.DB.Model(&users[1]).Update("deleted_at", time.Unix(1700000000, 0).UTC()).Error)
		token := model.Token{UserId: users[0].Id, Key: "disabled-fixture-key", Status: 2, Name: "fixture-token", CreatedTime: 1700000000, ExpiredTime: 1, RemainQuota: 0, ModelLimitsEnabled: true, ModelLimits: "fixture-model", Group: "default"}
		require.NoError(t, model.DB.Create(&token).Error)
		setting := `{"force_format":true}`
		require.NoError(t, model.DB.Create(&model.Channel{Type: 1, Key: "unusable-fixture-key", Status: 2, Name: "fixture-channel", Models: "fixture-model", Group: "default", Setting: &setting}).Error)
		require.NoError(t, model.LOG_DB.Create(&model.Log{UserId: users[0].Id, CreatedAt: 1700000000, Type: model.LogTypeConsume, Content: "fixture 中文", Username: users[0].Username, Quota: 0, PromptTokens: 0, CompletionTokens: 1, RequestId: "fixture-usage", Other: `{"fixture":true}`}).Error)
		if logkind == "clickhouse" {
			// Exercise the released writer; populated AuditOther cannot use raw GORM Create on ClickHouse.
			model.RecordAuditLog(nil, model.AuditLog{
				EventId: "fixture-audit", RequestId: "fixture-audit-request", UserId: users[0].Id, Username: users[0].Username,
				ActorRole: common.RoleCommonUser, CreatedAt: 1700000000, Category: model.AuditCategoryOperation,
				Action: "fixture", Content: "fixture 审计", Success: false,
				Other: model.AuditOther{
					Op: &model.AuditOperation{Action: "fixture-json", Params: model.AuditFields{
						"empty_array": []int64{}, "enabled": false, "nested": map[string]any{"label": "fixture"},
						"signed": []int64{9007199254740993, 0}, "unsigned": []uint64{18446744073709551615, 0}, "zero": int64(0),
					}},
					RootInfo: model.AuditFields{"generation": uint64(18446744073709551615)},
				},
			})
		} else {
			require.NoError(t, model.LOG_DB.Create(&model.AuditLog{EventId: "fixture-audit", UserId: users[0].Id, Username: users[0].Username, CreatedAt: 1700000000, Category: model.AuditCategoryOperation, Action: "fixture", Content: "fixture 审计", Success: false}).Error)
		}
	}
	var users []model.User
	require.NoError(t, model.DB.Unscoped().Order("id").Find(&users).Error)
	require.Len(t, users, 2)
	assert.Equal(t, 0, users[0].Quota)
	assert.Equal(t, 4294967301, users[1].Quota)
	assert.True(t, users[1].DeletedAt.Valid)
	assert.Equal(t, "UTF8 中文 🧪", users[1].Remark)
	var visible int64
	require.NoError(t, model.DB.Model(&model.User{}).Count(&visible).Error)
	assert.EqualValues(t, 1, visible)
	duplicate := model.User{Username: users[0].Username, Password: "unusable-fixture-hash", AffCode: "different"}
	require.Error(t, model.DB.Create(&duplicate).Error, "username uniqueness must survive")
	var tokens []model.Token
	require.NoError(t, model.DB.Order("id").Find(&tokens).Error)
	require.Len(t, tokens, 1)
	assert.Equal(t, 0, tokens[0].RemainQuota)
	assert.False(t, tokens[0].UnlimitedQuota)
	duplicateToken := tokens[0]
	duplicateToken.Id = 0
	require.Error(t, model.DB.Create(&duplicateToken).Error, "token key uniqueness must survive")
	deletedDuplicate := model.User{Username: users[1].Username, Password: "unusable-fixture-hash", AffCode: "different-deleted"}
	require.Error(t, model.DB.Create(&deletedDuplicate).Error, "soft-deleted usernames remain reserved")
	var channels []model.Channel
	require.NoError(t, model.DB.Order("id").Find(&channels).Error)
	require.Len(t, channels, 1)
	var logs []model.Log
	require.NoError(t, model.LOG_DB.Where("request_id = ?", "fixture-usage").Find(&logs).Error)
	require.Len(t, logs, 1)
	assert.Equal(t, "fixture 中文", logs[0].Content)
	assert.Equal(t, 0, logs[0].Quota)
	assert.Equal(t, 1, logs[0].CompletionTokens)
	var audits []model.AuditLog
	auditQuery := model.LOG_DB.Where("event_id = ?", "fixture-audit")
	if logkind == "clickhouse" {
		// Logical fixture snapshot only; default native compatibility has its separate probe.
		auditQuery = auditQuery.WithContext(chdriver.Context(auditQuery.Statement.Context, chdriver.WithSettings(chdriver.Settings{
			"output_format_native_write_json_as_string": 1,
			"output_format_json_quote_64bit_integers":   0,
		})))
	}
	require.NoError(t, auditQuery.Find(&audits).Error)
	require.Len(t, audits, 1)
	assert.False(t, audits[0].Success)
	assert.Equal(t, "fixture 审计", audits[0].Content)
	// Only nonsecret representative values are emitted, never credential fields.
	data := map[string]any{"zero_quota": users[0].Quota, "wallet_quota": users[1].Quota, "used_quota": users[1].UsedQuota, "remark": users[1].Remark, "deleted": users[1].DeletedAt.Valid, "visible_users": visible, "token_count": len(tokens), "token_quota": tokens[0].RemainQuota, "token_limits": tokens[0].ModelLimits, "channel_setting": channels[0].Setting, "usage_content": logs[0].Content, "usage_quota": logs[0].Quota, "usage_tokens": logs[0].CompletionTokens, "audit_content": audits[0].Content, "audit_success": audits[0].Success}
	if logkind == "clickhouse" {
		// AuditFields retains RawMessage; compare exact JSON numbers, booleans and keys without float64.
		auditOther, err := common.Marshal(audits[0].Other)
		require.NoError(t, err)
		require.Equal(t, `{"op":{"action":"fixture-json","params":{"empty_array":[],"enabled":false,"nested":{"label":"fixture"},"signed":[9007199254740993,0],"unsigned":[18446744073709551615,0],"zero":0}},"root_info":{"generation":18446744073709551615}}`, string(auditOther))
		data["audit_other"] = audits[0].Other
	}
	var version, logversion string
	versionSQL := "SELECT version()"
	if kind == "sqlite" {
		versionSQL = "SELECT sqlite_version()"
	}
	require.NoError(t, model.DB.Raw(versionSQL).Scan(&version).Error)
	actualLog := logkind
	if actualLog == "same" {
		actualLog = kind
	}
	logSQL := "SELECT version()"
	if actualLog == "sqlite" {
		logSQL = "SELECT sqlite_version()"
	}
	require.NoError(t, model.LOG_DB.Raw(logSQL).Scan(&logversion).Error)
	result := map[string]any{"data": data, "schema_main": schema(t, model.DB, kind), "schema_log": schema(t, model.LOG_DB, actualLog), "engine_version": version, "log_version": logversion, "phase": phase}
	if logkind == "clickhouse" {
		result["audit_read_mode"] = "fixture_clickhouse_json_text"
	}
	encoded, err := common.Marshal(result)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(os.Getenv("A03_RESULT"), encoded, 0600))
	fmt.Println("fixture data, schema and uniqueness checked")
}
'''

ORGANIZATION_SUBCHECKS = ('organization_restore', 'organization_old_readback', 'organization_fault',
                          'organization_rejected', 'organization_recovered', 'organization_recovery_restart')

ORGANIZATION_TABLES = frozenset(('organizations', 'organization_members', 'organization_invitations',
                                'organization_ownership_transfers', 'organization_events'))

ORGANIZATION_FIXTURE = r'''
// Persistence-only fixtures: domain authorization/lifecycle semantics are tested separately.
func organizationState(t *testing.T, phase, logkind string) map[string]any {
 t.Helper()
 models := []any{&model.Organization{}, &model.OrganizationMember{}, &model.OrganizationInvitation{}, &model.OrganizationOwnershipTransfer{}, &model.OrganizationEvent{}}
 names := []string{}
 for _, value := range models {
  stmt := &gorm.Statement{DB:model.DB}; require.NoError(t, stmt.Parse(value)); names = append(names, stmt.Table)
  require.True(t, model.DB.Migrator().HasTable(value), "missing organization primary table")
  if logkind != "same" { require.False(t, model.LOG_DB.Migrator().HasTable(stmt.Table), "organization table leaked into independent log DB") }
  columns, err := model.DB.Migrator().ColumnTypes(value); require.NoError(t, err)
  actual := []string{}; for _, column := range columns { actual = append(actual,column.Name()) }
  require.ElementsMatch(t,stmt.Schema.DBNames,actual,"complete organization columns")
  indexes,err := fixtureIndexes(model.DB,stmt.Table); require.NoError(t,err)
  present := map[string]gorm.Index{}
  for _, index := range indexes { primary,known:=index.PrimaryKey(); if model.DB.Dialector.Name()=="postgres" { require.True(t,known,"PostgreSQL primary metadata required") }; if !known || !primary { present[index.Name()]=index } }
  expected := stmt.Schema.ParseIndexes()
  require.Len(t,present,len(expected),"unexpected organization index")
  for _, index := range expected {
   got,ok:=present[index.Name]; require.True(t,ok,"missing organization index %s",index.Name)
   columns:=[]string{}; for _,field:=range index.Fields { columns=append(columns,field.DBName) }
   require.Equal(t,columns,got.Columns()); unique,known:=got.Unique(); require.True(t,known); require.Equal(t,index.Class=="UNIQUE",unique)
  }
 }
 sort.Strings(names)
 if phase == "seed" || phase == "upgrade_seed" {
  for _,value:=range models { var count int64; require.NoError(t,model.DB.Model(value).Count(&count).Error); require.Zero(t,count,"refuse to reseed existing organization data") }
  org:=model.Organization{ID:4101,Name:"持久化组织",CreatedByUserID:1,OwnerUserID:1,Revision:7,OwnershipVersion:2,SelfDisabledAt:101,SelfDisabledReason:"fixture-self",PlatformDisabledAt:102,PlatformDisabledReason:"fixture-platform",CreatedAt:100,UpdatedAt:103}
  member:=model.OrganizationMember{ID:4201,OrganizationID:4101,UserID:1,Role:"admin",Revision:4,JoinedAt:100,UpdatedAt:103,RemovalReason:"fixture"}
  invitation:=model.OrganizationInvitation{ID:4301,OrganizationID:4101,TargetUserID:2,InviterUserID:1,InviterMemberRevision:4,Role:"member",Generation:3,Status:"declined",ExpiresAt:200,ResolvedAt:150,CreatedAt:100,UpdatedAt:150,ResolutionReason:"fixture"}
  transfer:=model.OrganizationOwnershipTransfer{ID:4401,OrganizationID:4101,FromUserID:1,ToUserID:2,Generation:2,OwnerVersion:2,FromMemberRevision:4,ToMemberRevision:3,Status:"cancelled",ExpiresAt:300,ResolvedAt:151,CreatedAt:100,UpdatedAt:151,ResolutionReason:"fixture"}
  event:=model.OrganizationEvent{ID:4501,OrganizationID:4101,OrganizationRevision:7,ActorUserID:1,Action:"fixture-persistence",SubjectUserID:2,ObjectKind:"invitation",ObjectID:4301,ObjectGeneration:3,BeforeState:"pending",AfterState:"declined",ReasonCode:"fixture",Role:"member",ExpiresAt:200,CreatedAt:150}
  for _,value:=range []any{&org,&member,&invitation,&transfer,&event} { require.NoError(t,model.DB.Create(value).Error) }
 }
 var orgs []model.Organization; var members []model.OrganizationMember; var invitations []model.OrganizationInvitation; var transfers []model.OrganizationOwnershipTransfer; var events []model.OrganizationEvent
 for _,value:=range []any{&orgs,&members,&invitations,&transfers,&events} { require.NoError(t,model.DB.Order("id").Find(value).Error) }
 require.Len(t,orgs,1);require.Len(t,members,1);require.Len(t,invitations,1);require.Len(t,transfers,1);require.Len(t,events,1)
 member:=members[0];member.ID=0;require.Error(t,model.DB.Create(&member).Error,"org/user uniqueness")
 invitation:=invitations[0];invitation.ID=0;require.Error(t,model.DB.Create(&invitation).Error,"org/target uniqueness")
 transfer:=transfers[0];transfer.ID=0;require.Error(t,model.DB.Create(&transfer).Error,"org/transfer uniqueness")
 return map[string]any{"tables":names,"organizations":orgs,"members":members,"invitations":invitations,"transfers":transfers,"events":events}
}

func organizationPartialFault(t *testing.T) {
 t.Helper()
 for _,value:=range []any{&model.Organization{},&model.OrganizationMember{},&model.OrganizationInvitation{},&model.OrganizationOwnershipTransfer{},&model.OrganizationEvent{}} { require.False(t,model.DB.Migrator().HasTable(value)) }
 require.NoError(t,model.DB.AutoMigrate(&model.Organization{},&model.OrganizationMember{}))
 require.NoError(t,model.DB.Migrator().DropIndex(&model.OrganizationMember{},"uq_org_member"))
 for range 2 { require.NoError(t,model.DB.Create(&model.OrganizationMember{OrganizationID:4101,UserID:1,Role:"member",Revision:1}).Error) }
}
'''

# Release production sources stay fixed at rc.44; shared metadata instrumentation is rebuilt for both fixtures.
CANDIDATE_FIXTURE = FIXTURE.replace('if phase == "read" || phase == "fault" {',
    'if phase == "read" || phase == "fault" || phase == "org_fault" {')
CANDIDATE_FIXTURE = CANDIDATE_FIXTURE.replace('if phase == "expect_failure" {',
    'if phase == "expect_failure" || phase == "expect_org_failure" {')
CANDIDATE_FIXTURE = CANDIDATE_FIXTURE.replace('require.Error(t, err, "duplicate key fixture must prevent migration")',
    'require.Error(t, err, "duplicate key fixture must prevent migration")\n\t\t\tif phase == "expect_org_failure" { require.Regexp(t, "(?i)(unique|duplicate)", err.Error()); var count int64; require.NoError(t, model.DB.Model(&model.OrganizationMember{}).Count(&count).Error); require.EqualValues(t, 2, count); require.False(t, model.DB.Migrator().HasIndex(&model.OrganizationMember{}, "uq_org_member")) }')
CANDIDATE_FIXTURE = CANDIDATE_FIXTURE.replace('if phase == "fault" {\n',
    'if phase == "org_fault" { organizationPartialFault(t); require.NoError(t, os.WriteFile(os.Getenv("A03_RESULT"), []byte(`{"partial_organization_fault":true}`), 0600)); return }\n\tif phase == "fault" {\n')
CANDIDATE_FIXTURE = CANDIDATE_FIXTURE.replace('\tvar users []model.User',
    '\torganization := organizationState(t, phase, logkind)\n\tvar users []model.User')
CANDIDATE_FIXTURE = CANDIDATE_FIXTURE.replace('"data": data, "schema_main":',
    '"organization": organization, "data": data, "schema_main":') + ORGANIZATION_FIXTURE



def execute(command, *, cwd=None, env=None, timeout=300, input_bytes=None, guard=None):
    if guard is not None:
        guard()
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = guarded_communicate(process, timeout=timeout, input_bytes=input_bytes, guard=guard)
    except BaseException as error:
        cleanup = terminate_group(process)
        error.process_cleanup_error = '; '.join(filter(None, [getattr(error, 'process_cleanup_error', None), cleanup])) or None
        raise
    return process.returncode, stdout, stderr


def export_sources(source, destination, revision=None):
    if destination.exists():
        raise ValueError('export destination already exists; refusing overwrite')
    destination.mkdir(parents=True)
    code, archive, error = execute(['git', 'archive', revision or 'HEAD'], cwd=source)
    if code:
        raise RuntimeError('git archive failed')
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(destination, filter='data')
    if revision is None:
        code, data, _ = execute(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=source)
        if code:
            raise RuntimeError('candidate file enumeration failed')
        for name in data.decode().split('\0'):
            if not name or name == 'AGENTS.md':
                continue
            path = source / name
            target = destination / name
            if path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
            elif not path.exists() and target.exists():
                target.unlink()
    fixture = destination / 'a03fixture'
    fixture.mkdir()
    (fixture / 'released_test.go').write_text(FIXTURE if revision is not None else CANDIDATE_FIXTURE)


def required_manifest():
    return [{'main': main, 'log': log, 'phase': phase} for main, log in COMBINATIONS for phase in PHASES]


def clean_environment():
    # No .env is loaded. Children receive a minimal allowlist, never app credentials.
    return {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'TMPDIR', 'GOCACHE', 'GOMODCACHE',
            'DEVELOPER_DIR', 'SDKROOT', 'CGO_ENABLED', 'GOPROXY', 'GOSUMDB', 'GOTOOLCHAIN')}


def fixture_input_identity(source):
    files = {}
    for path in sorted(source.rglob('*')):
        relative = str(path.relative_to(source))
        embedded = relative.startswith(('plugins/tasks/', 'i18n/locales/', 'common/limiter/lua/')) or relative == 'common/log_text.zh-CN.json'
        if path.is_file() and (path.suffix == '.go' or path.name in ('go.mod', 'go.sum') or embedded):
            files[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def validate_built_fixture(runtime, kind, source):
    receipt_path = runtime / (kind + '-fixture.receipt.json')
    receipt = json.loads(receipt_path.read_text())
    binary = runtime / (kind + '-fixture')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != receipt['binary_sha256']:
        raise ValueError('fixture binary differs from build receipt')
    exported = runtime / (kind + '-source')
    if fixture_input_identity(exported) != receipt['build_inputs']:
        raise ValueError('exported source, embed resources or module locks differ from build receipt')
    if (exported / 'a03fixture/released_test.go').read_text() != (FIXTURE if kind == 'release' else CANDIDATE_FIXTURE):
        raise ValueError('fixture source differs from this harness')
    if kind == 'candidate':
        current = fixture_input_identity(source)
        built = {k:v for k,v in receipt['build_inputs'].items() if not k.startswith('a03fixture/')}
        if current != built:
            raise ValueError('candidate source, embed resources or module locks changed since fixture build')
    if receipt['release_commit'] != RELEASE:
        raise ValueError('release build provenance mismatch')


def build_fixture(source, output, evidence, go):
    env = dict(clean_environment(), GOWORK='off', GOFLAGS='-mod=readonly')
    before = {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in ('go.mod', 'go.sum')}
    cmd = [str(go), 'test', '-c', '-o', str(output), './a03fixture']
    code, out, err = execute(cmd, cwd=source, env=env, timeout=600)
    (evidence / (output.name + '.build.stdout')).write_bytes(out)
    (evidence / (output.name + '.build.stderr')).write_bytes(err)
    after = {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in before}
    (evidence / (output.name + '.build.json')).write_text(json.dumps({'command':cmd,'exit_code':code,'locks_before':before,'locks_after':after}, indent=2))
    if code or before != after:
        raise RuntimeError('fixture build failed or module locks changed: ' + output.name)
    receipt = {'release_commit':RELEASE, 'source':str(source), 'binary_sha256':hashlib.sha256(output.read_bytes()).hexdigest(), 'build_inputs':fixture_input_identity(source)}
    output.with_name(output.name + '.receipt.json').write_text(json.dumps(receipt,indent=2))



class OwnedStores:
    """No caller-supplied DSNs or database names; derive endpoints from owned containers."""
    def __init__(self, runtime, binding=None):
        self.runtime = runtime
        self.created = []
        self.resources = []
        self.containers = {}
        self.ports = {}
        self.docker = []
        self.relays = []
        self.relay_records = []
        self.relay_receipt = None
        self.relay_initialization_error = None
        self.cleaning = False
        self.clickhouse_auth = None
        if binding is None:
            return
        validate_inherited_environment(os.environ)
        if 'clickhouse' in binding['containers']:
            if set(binding['containers']) != {'clickhouse'}:
                raise ValueError('ClickHouse runs alone in the serial isolated profile')
            self.clickhouse_auth = ClickHouseAuth(binding['clickhouse_auth_directory'])
        elif 'clickhouse_auth_directory' in binding:
            raise ValueError('non-ClickHouse bindings cannot adopt credentials')
        config = Path(binding['docker_config'])
        project = binding['project']
        if not re.fullmatch(r'newapi-ci-[a-z0-9-]+', project):
            raise ValueError('invalid owned Compose project')
        self.docker = docker_command(config, binding['context'])
        context = json.loads(self.call(['context','inspect']))
        if len(context)!=1 or context[0]['Endpoints']['docker']['Host']!='unix://'+str(Path.home()/'.colima/newapi-a03/docker.sock'):
            raise ValueError('wrong Docker socket')
        expected = {'mysql': 'sha256:213bbfaf699693a40a20a12bb4342d2589a15a3dc7153db698eaed252a92458e',
                    'postgres': 'sha256:91a22c143801df42c2e4a8f9926eab5e48f39f40beb5220b7c29d4478263c341'}
        for engine, identity in binding['containers'].items():
            if engine not in ('mysql','postgres','clickhouse') or not re.fullmatch(r'[a-f0-9]{12,64}', identity):
                raise ValueError('invalid engine/container identity')
            data=json.loads(self.call(['inspect',identity]))[0]
            labels=data['Config'].get('Labels',{})
            if labels.get('com.docker.compose.project')!=project or labels.get('com.docker.compose.service')!=engine:
                raise ValueError('container is not owned by the declared project/service')
            image=data['Config']['Image']
            if engine in expected:
                if not image.endswith('@'+expected[engine]):raise ValueError('fixed official image mismatch')
            elif image != CLICKHOUSE_IMAGE:
                raise ValueError('fixed ClickHouse image mismatch')
            self.containers[engine] = identity
        receipt = self.runtime / 'owned-relays.json'
        with receipt.open('x') as output:
            json.dump({'relays': [], 'initialization_error': None}, output)
        self.relay_receipt = receipt
        try:
            for engine, identity in self.containers.items():
                arguments = (self.docker, project, engine, identity,
                             Path(binding['image_evidence']) / (engine + '-cache') / 'inspect-receipt.json')
                relay = (OwnedRelay(*arguments, clickhouse_auth=self.clickhouse_auth) if engine == 'clickhouse'
                         else OwnedRelay(*arguments))
                self.relays.append(relay)
                self.relay_records.append({'engine': engine, 'container_id': identity, 'project': project,
                                           'state': 'starting', 'cleanup_attempts': []})
                self.save_relay_ownership()
                self.ports[engine] = relay.start()
                self.relay_records[-1]['state'] = 'running'
                self.save_relay_ownership()
        except BaseException as error:
            if self.clickhouse_auth:
                self.clickhouse_auth.sanitize_error(error)
            original_cleanup = getattr(error, 'process_cleanup_error', None)
            self.relay_initialization_error = {'error_type': type(error).__name__, 'error': str(error),
                                               'process_cleanup_error': original_cleanup}
            failures = []
            try:
                self.save_relay_ownership()
            except BaseException as persistence:
                failures.append({'operation': 'ownership_receipt', 'error_type': type(persistence).__name__,
                                 'error': str(persistence)})
            failures.extend(self.close_relays())
            if failures:
                error.process_cleanup_error = '; '.join(filter(None, [original_cleanup, str(failures)]))
            raise

    def save_relay_ownership(self):
        """Keep allocated identities after close clears the live process and port fields."""
        if self.relay_receipt is None:
            return
        for relay, record in zip(self.relays, self.relay_records):
            receipt = relay.receipt if isinstance(relay.receipt, dict) else {}
            initial = relay.initial if isinstance(relay.initial, dict) else {}
            record['identity'] = initial or receipt or record.get('identity', {})
            process = relay.process
            pid = getattr(process, 'pid', None) if process is not None else receipt.get('pid')
            port = relay.port if isinstance(relay.port, int) else receipt.get('local_port')
            if isinstance(pid, int):
                record['pid'] = pid
            if isinstance(port, int):
                record['local_port'] = port
            if isinstance(relay.boot, str):
                record['boot_id'] = relay.boot
        self.relay_receipt.write_text(json.dumps({'relays': self.relay_records,
            'initialization_error': self.relay_initialization_error}, indent=2))

    def check_routes(self):
        if self.clickhouse_auth is not None:
            self.clickhouse_auth.validate()
        for relay in self.relays:
            if self.cleaning:
                # Cleanup uses Docker exec, but must still bind the original container/network.
                if relay.snapshot() != relay.initial:
                    raise RelayIdentityError('owned database identity changed before cleanup')
            else:
                relay.check()

    def close_relays(self):
        errors = []
        for relay, record in reversed(list(zip(self.relays, self.relay_records))):
            if record['state'] == 'closed':
                continue
            try:
                self.save_relay_ownership()
            except BaseException as error:
                errors.append({'operation': 'ownership_receipt', 'engine': record['engine'],
                               'error_type': type(error).__name__, 'error': str(error)})
            try:
                relay.close()
                record['state'] = 'closed'
                record['cleanup_attempts'].append({'status': 'closed'})
            except BaseException as error:
                record['state'] = 'cleanup_unknown'
                failure = {'operation': 'relay_cleanup', 'engine': record['engine'],
                           'error_type': type(error).__name__, 'error': str(error)}
                record['cleanup_attempts'].append({'status': 'unknown', **failure})
                errors.append(failure)
            try:
                self.save_relay_ownership()
            except BaseException as error:
                errors.append({'operation': 'ownership_receipt', 'engine': record['engine'],
                               'error_type': type(error).__name__, 'error': str(error)})
        return errors

    def validate_driver_environment(self, env):
        """Bind every accepted DSN slot to a created database and its owned relay."""
        slots = {'SQL_DSN': None, 'LOG_SQL_DSN': None, 'AUDIT_CLICKHOUSE_DSN': 'clickhouse',
                 'AUDIT_MYSQL_DSN': 'mysql', 'AUDIT_POSTGRES_DSN': 'postgres',
                 'TEST_MYSQL_DSN': 'mysql', 'TEST_POSTGRES_DSN': 'postgres'}
        allowed = set(slots) | {
            'PATH', 'HOME', 'TMPDIR', 'GOCACHE', 'GOMODCACHE', 'DEVELOPER_DIR', 'SDKROOT',
            'CGO_ENABLED', 'GOPROXY', 'GOSUMDB', 'GOTOOLCHAIN', 'GOWORK', 'DEFAULT_LANGUAGE',
            'NEWAPI_TEST_PROFILE', 'NEWAPI_REQUIRE_DATABASES', 'TEST_TASK_DB_DIALECT', 'TEST_ORGANIZATION_DIALECT',
            'SQLITE_PATH', 'A03_ENGINE', 'A03_LOG_ENGINE', 'A03_PHASE', 'A03_RESULT',
            'NODE_TYPE', 'PASSWORD_LOGIN_ENCRYPTION_ENABLED', 'SQL_MAX_OPEN_CONNS', 'SQL_MAX_IDLE_CONNS'}
        if set(env) - allowed or env.get('NEWAPI_TEST_PROFILE') != 'isolated-ci':
            raise ValueError('driver requires the restricted isolated environment')
        if not env.get('SQL_DSN'):
            raise ValueError('driver primary database must be explicit')
        sqlite_path = env.get('SQLITE_PATH')
        if sqlite_path is not None:
            path = Path(sqlite_path)
            if (('sqlite', sqlite_path) not in self.created or not path.is_absolute()
                    or path.resolve() != path or path.parent != self.runtime.resolve()
                    or (path.exists() and not path.is_file())):
                raise ValueError('driver SQLite path is not owned by this run')
        for slot, required_engine in slots.items():
            if slot not in env:
                continue
            value = env[slot]
            if value == 'local' and required_engine is None:
                if sqlite_path is None:
                    raise ValueError('driver SQLite path must be explicit')
                continue
            matched = False
            for engine, name in self.created:
                if engine == 'sqlite' or (required_engine and engine != required_engine):
                    continue
                if (engine not in self.ports or engine not in self.containers
                        or not any(record.get('engine') == engine and record.get('state') == 'running'
                                   and record.get('container_id') == self.containers[engine]
                                   and relay.port == self.ports[engine]
                                   for relay, record in zip(self.relays, self.relay_records))
                        or not any(resource.get('engine') == engine and resource.get('name') == name
                                   and resource.get('container') == self.containers[engine]
                                   and resource.get('absent_before_create') is True
                                   and resource.get('state') == 'created' for resource in self.resources)):
                    continue
                expected = self.dsn(engine, name)
                if engine == 'clickhouse':
                    # Canonical native URL only: no aliases, alternate host spelling, query,
                    # fragment, user override or connection options. Only password may vary.
                    try:
                        parsed = urlsplit(value)
                        password = unquote(parsed.password) if parsed.password is not None else None
                        credentials = 'default' + (':' + quote(password, safe='') if password is not None else '')
                        expected = f'clickhouse://{credentials}@127.0.0.1:{self.ports[engine]}/{name}'
                    except ValueError:
                        continue
                if value == expected:
                    matched = True
                    break
            if not matched:
                raise ValueError('driver DSN is not bound to a created database and owned relay')

    def run_test(self, command, *, cwd, env, timeout):
        """Guard and sanitize driver test output before any evidence writer sees it."""
        env = dict(env)  # Freeze the validated environment actually passed to the child.
        command = list(command)
        auth = self.clickhouse_auth
        secrets = auth.secret_values(env) if auth else ()
        try:
            self.validate_driver_environment(env)
            if not command or any(not isinstance(part, str) for part in command):
                raise ValueError('driver argv must contain only explicit strings')
            if auth:
                auth.validate()
                if any(auth.redact(str(part), secrets) != str(part) or 'clickhouse://' in str(part)
                       for part in command):
                    raise ValueError('ClickHouse credentials must never appear in argv')
            code, out, err = execute(command, cwd=cwd, env=env, timeout=timeout, guard=self.check_routes)
        except BaseException as error:
            if auth:
                auth.sanitize_error(error, secrets)
            raise
        from database_gate import redact_output
        output = []
        for value in (out, err):
            text = redact_output(value.decode(errors='replace'), env)
            output.append((auth.redact(text, secrets) if auth else text).encode())
        return code, *output

    def call(self, args, data=None, timeout=120):
        if self.clickhouse_auth:
            self.clickhouse_auth.validate()
        try:
            code,out,err=execute(self.docker+args,timeout=timeout,input_bytes=data,
                                 guard=self.check_routes if self.relays else None)
        except BaseException as error:
            if self.clickhouse_auth:
                self.clickhouse_auth.sanitize_error(error)
            raise
        if code:raise RuntimeError('owned Docker operation failed, exit '+str(code))
        return out

    def sql(self, engine, query, database=None):
        prefix=['exec','-i',self.containers[engine]]
        if engine=='mysql':command=['mysql','-uroot','--batch','--skip-column-names']+([database] if database else [])
        elif engine=='postgres':command=['psql','-U','postgres','-v','ON_ERROR_STOP=1','-At','-d',database or 'postgres']
        else:
            self.clickhouse_auth.validate()
            command=['clickhouse-client','--config-file',CLICKHOUSE_CLIENT,'--multiquery']+(['--database',database] if database else [])
        return self.call(prefix+command,query.encode())

    def database_exists(self, engine, name):
        if not re.fullmatch(r'newapi_ci_[a-z0-9_]+', name):
            raise ValueError('unsafe generated database name')
        catalog, column = {'mysql': ('information_schema.schemata', 'schema_name'),
                           'postgres': ('pg_database', 'datname'),
                           'clickhouse': ('system.databases', 'name')}[engine]
        value = self.sql(engine, f"SELECT count(*) FROM {catalog} WHERE {column} = '{name}'").strip()
        if value not in (b'0', b'1'):
            raise RuntimeError('database existence result is not an exact boolean count')
        return value == b'1'

    def save_resources(self):
        (self.runtime / 'database-ownership.json').write_text(json.dumps(self.resources, indent=2))

    def create(self, engine, name):
        if not re.fullmatch(r'newapi_ci_[a-z0-9_]+',name):raise ValueError('unsafe generated database name')
        if engine=='sqlite':
            path=self.runtime/(name+'.db')
            if path.exists():raise ValueError('owned SQLite path already exists')
            self.created.append((engine,str(path)));return str(path)
        if engine not in self.containers:raise RuntimeError('owned '+engine+' runtime unavailable')
        if self.database_exists(engine, name):
            raise ValueError('database existed before this run; refusing ownership')
        resource = {'engine': engine, 'name': name, 'container': self.containers[engine],
                    'absent_before_create': True, 'state': 'create_pending'}
        self.resources.append(resource)
        self.save_resources()  # Persist intent before a possibly committed remote CREATE.
        self.created.append((engine, name))
        query='CREATE DATABASE '+name
        if engine=='mysql':query+=' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
        try:
            self.sql(engine, query)
            resource['state'] = 'created'
        except BaseException as error:
            resource['state'] = 'create_unknown'
            resource['create_error_type'] = type(error).__name__
            raise
        finally:
            self.save_resources()
        return name

    def dsn(self, engine, name):
        if engine=='sqlite':return name
        port=self.ports[engine]
        if engine=='mysql':return f'root@tcp(127.0.0.1:{port})/{name}?parseTime=true'
        if engine=='postgres':return f'postgres://postgres@127.0.0.1:{port}/{name}?sslmode=disable'
        return self.clickhouse_auth.dsn(port, name)

    def backup(self, engine, name, target):
        if engine=='sqlite':
            with sqlite3.connect(name) as source, sqlite3.connect(target) as dest:source.backup(dest)
        elif engine=='mysql':
            data=self.call(['exec',self.containers[engine],'mysqldump','-uroot','--single-transaction','--set-gtid-purged=OFF','--routines','--events','--triggers',name])
            target.write_bytes(data)
        elif engine=='postgres':
            target.write_bytes(self.call(['exec',self.containers[engine],'pg_dump','-U','postgres','--format=custom','--no-owner',name]))
        else:
            target.mkdir()
            tables=self.sql(engine,'SHOW TABLES FORMAT TSVRaw',name).decode().splitlines()
            for table in tables:
                if not re.fullmatch(r'[a-z0-9_]+',table):raise ValueError('unexpected ClickHouse table name')
                ddl=self.sql(engine,'SHOW CREATE TABLE '+table+' FORMAT TSVRaw',name)
                (target/(table+'.sql')).write_bytes(ddl)
                (target/(table+'.native')).write_bytes(self.sql(engine,'SELECT * FROM '+table+' FORMAT Native',name))
            (target/'manifest.json').write_text(json.dumps({'database':name,'tables':tables}))

    def restore(self, engine, target, backup):
        if engine=='sqlite':
            with sqlite3.connect(backup) as source, sqlite3.connect(target) as dest:source.backup(dest)
        elif engine=='mysql':
            self.call(['exec','-i',self.containers[engine],'mysql','-uroot',target],backup.read_bytes())
        elif engine=='postgres':
            self.call(['exec','-i',self.containers[engine],'pg_restore','-U','postgres','--no-owner','--exit-on-error','-d',target],backup.read_bytes())
        else:
            meta=json.loads((backup/'manifest.json').read_text())
            for table in meta['tables']:
                ddl=clickhouse_database_identity((backup/(table+'.sql')).read_text(), meta['database'], target)
                self.sql(engine,ddl,target)
                self.call(['exec','-i',self.containers[engine],'clickhouse-client','--config-file',CLICKHOUSE_CLIENT,'--database',target,'--query','INSERT INTO '+table+' FORMAT Native'],(backup/(table+'.native')).read_bytes())

    def cleanup(self):
        errors=[]
        self.cleaning = True
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            for resource in reversed(self.resources):
                engine, name = resource['engine'], resource['name']
                if resource['state'] == 'absent_after_cleanup':
                    continue
                try:
                    if not resource['absent_before_create'] or resource['container'] != self.containers[engine]:
                        raise ValueError('database ownership cannot be established')
                    if self.database_exists(engine, name):
                        self.sql(engine, 'DROP DATABASE '+name)
                    if self.database_exists(engine, name):
                        raise RuntimeError('database remains after cleanup')
                    resource['state'] = 'absent_after_cleanup'
                except BaseException as error:
                    resource['state'] = 'cleanup_unknown'
                    errors.append({'engine':engine, 'name':name, 'error_type':type(error).__name__,
                                   'error':str(error), 'process_cleanup_error':getattr(error, 'process_cleanup_error', None)})
                self.save_resources()
        finally:
            errors.extend(self.close_relays())
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
        return errors


def clickhouse_database_identity(ddl, database, replacement):
    """Change only SHOW CREATE's leading table database identifier, never its structure."""
    if not re.fullmatch(r'newapi_ci_[a-z0-9_]+', database):
        raise ValueError('unexpected ClickHouse database identity')
    pattern = r'^(CREATE TABLE (?:IF NOT EXISTS )?)(?:`' + re.escape(database) + r'`|' + re.escape(database) + r')\.'
    value, count = re.subn(pattern, lambda match: match[1] + replacement + '.', ddl, count=1)
    if count != 1:
        raise ValueError('ClickHouse DDL lacks the exact owned database qualifier')
    return value


def normalized_schema(schema, engine, database):
    if engine != 'clickhouse':
        return schema
    return [dict(table, ddl=clickhouse_database_identity(table['ddl'], database, '__owned_database__')) for table in schema]


def verify_release_schema(old, current, organization_reference=None):
    """Preserve existing structure and accept only the frozen candidate's known addition."""
    old_tables = {table['table']: table for table in old}
    current_tables = {table['table']: table for table in current}
    allowed = ORGANIZATION_TABLES if organization_reference is not None else set()
    if old_tables.keys() & allowed or current_tables.keys() != old_tables.keys() | allowed:
        raise ValueError('release table set changed without the exact approved migration')
    if organization_reference is not None:
        reference = {table['table']: table for table in organization_reference}
        if not ORGANIZATION_TABLES <= reference.keys():
            raise ValueError('fresh organization schema reference is incomplete')
        for name in ORGANIZATION_TABLES:
            if current_tables[name] != reference[name]:
                raise ValueError('organization columns/indexes differ from validated fresh schema: '+name)
    for name, before in old_tables.items():
        after = current_tables[name]
        if 'ddl' in before:
            if before != after:
                raise ValueError('release ClickHouse structure changed: '+name)
            continue
        for field in ('columns', 'indexes'):
            previous = {item['name']: item for item in before[field]}
            present = {item['name']: item for item in after[field]}
            for key, value in previous.items():
                if present.get(key) != value:
                    raise ValueError('release '+field+' changed or disappeared: '+name+'.'+key)
            additions = present.keys() - previous.keys()
            allowed = {'allow_user_quota_query'} if field == 'columns' and name == 'tokens' else set()
            if not additions <= allowed:
                raise ValueError('unapproved schema addition: '+name+'.'+field)


def run_phase(binary, phase, main, log, stores, main_db, log_db, evidence, label):
    env=dict(clean_environment(),NEWAPI_TEST_PROFILE='isolated-ci',A03_ENGINE=main,A03_LOG_ENGINE=log,
             A03_PHASE=phase,A03_RESULT=str(evidence/(label+'.snapshot.json')),NODE_TYPE='master',
             PASSWORD_LOGIN_ENCRYPTION_ENABLED='false',SQL_MAX_OPEN_CONNS='2',SQL_MAX_IDLE_CONNS='1',
             GOWORK='off',DEFAULT_LANGUAGE='en')
    env['SQL_DSN']='local' if main=='sqlite' else stores.dsn(main,main_db)
    if main=='sqlite':env['SQLITE_PATH']=main_db
    if log!='same':
        env['LOG_SQL_DSN']='local' if log=='sqlite' else stores.dsn(log,log_db)
        if log=='sqlite':env['SQLITE_PATH']=log_db
    command=[str(binary),'-test.run=^TestReleasedDatabaseGate$','-test.v','-test.timeout=120s']
    auth = stores.clickhouse_auth
    if auth is None:
        # Keep the accepted non-CH execution and evidence path unchanged.
        code,out,err=execute(command,cwd=stores.runtime,env=env,timeout=135,guard=stores.check_routes)
        text=(out+err).decode(errors='replace')
        for key in ('SQL_DSN','LOG_SQL_DSN'):
            if env.get(key) and env[key]!='local':text=text.replace(env[key],'[owned-dsn]')
        (evidence/(label+'.log')).write_text(text)
        (evidence/(label+'.command.json')).write_text(json.dumps({'command':command,'exit_code':code,'engine':main,'log_engine':log,'phase':phase},indent=2))
        result=Path(env['A03_RESULT'])
        if code or '--- SKIP:' in text or '--- PASS: TestReleasedDatabaseGate' not in text or not result.exists():
            raise RuntimeError(label+' failed or missing required test result')
        return json.loads(result.read_text())
    # The fixture's direct result write stays private until checked; never promote a secret-bearing snapshot.
    private = tempfile.TemporaryDirectory(prefix='phase-result-', dir=stores.runtime)
    public_result = Path(env['A03_RESULT'])
    env['A03_RESULT'] = str(Path(private.name) / 'result.json')
    try:
        code,out,err=stores.run_test(command,cwd=stores.runtime,env=env,timeout=135)
        from database_gate import redact_output
        text = (out+err).decode(errors='replace')
        (evidence/(label+'.log')).write_text(text)
        (evidence/(label+'.command.json')).write_text(json.dumps({'command':command,'exit_code':code,'engine':main,'log_engine':log,'phase':phase},indent=2))
        result=Path(env['A03_RESULT'])
        if code or '--- SKIP:' in text or '--- PASS: TestReleasedDatabaseGate' not in text or not result.exists():
            raise RuntimeError(label+' failed or missing required test result')
        raw = result.read_text()
        if auth.redact(raw) != raw or redact_output(raw, env) != raw:
            raise RuntimeError('secret-bearing fixture result refused')
        value = json.loads(raw)
        public_result.write_text(raw)
        return value
    finally:
        private.cleanup()


def run_matrix(runtime, evidence, bindings=None, *, fail_fast=False):
    stores=None
    records=[];organization_checks=[];primary_error=None;cleanup=[];run_id=hashlib.sha256(str(runtime).encode()).hexdigest()[:8]
    try:
        stores=OwnedStores(runtime,bindings)
        for main,log in COMBINATIONS:
            prefix=main+'_'+log;done=set()
            try:
                for engine in (main,log):
                    if engine not in ('sqlite','same') and engine not in stores.containers:
                        raise RuntimeError('owned '+engine+' runtime unavailable')
                def create_pair(suffix):
                    first=stores.create(main,'newapi_ci_'+run_id+'_'+prefix+'_'+suffix)
                    second=first if log=='same' else stores.create(log,'newapi_ci_'+run_id+'_'+prefix+'_'+suffix+'_log')
                    return first,second
                def phase(name,kind,mode,pair,additional=False):
                    value=run_phase(runtime/(kind+'-fixture'),mode,main,log,stores,*pair,evidence,prefix+'_'+name)
                    for key, engine, database in (('schema_main', main, pair[0]), ('schema_log', main if log == 'same' else log, pair[1])):
                        if key in value:
                            value[key] = normalized_schema(value[key], engine, database)
                    if additional:
                        organization_checks.append({'main':main,'log':log,'check':name,'status':'pass'})
                    else:
                        records.append({'main':main,'log':log,'phase':name,'status':'pass'});done.add(name)
                    return value
                fresh=create_pair('fresh')
                first=phase('fresh_seed','candidate','seed',fresh)
                second=phase('fresh_restart','candidate','verify',fresh)
                for key in ('data','schema_main','schema_log','organization'):
                    if first[key]!=second[key]:raise RuntimeError('fresh restart changed '+key)
                upgrade=create_pair('upgrade')
                old=phase('release_seed','release','seed',upgrade)
                backup_main=runtime/(prefix+'.main.backup');stores.backup(main,upgrade[0],backup_main)
                backup_log=backup_main
                if log!='same':backup_log=runtime/(prefix+'.log.backup');stores.backup(log,upgrade[1],backup_log)
                records.append({'main':main,'log':log,'phase':'backup','status':'pass','quiescence':'all writer processes exited; sequential main/log snapshots'});done.add('backup')
                fresh_schema = first['schema_main']
                first=phase('candidate_start_1','candidate','upgrade_seed',upgrade)
                second=phase('candidate_start_2','candidate','verify',upgrade)
                if first['data']!=old['data'] or second['data']!=old['data']:raise RuntimeError('release data changed during migration')
                for key in ('schema_main','schema_log'):
                    verify_release_schema(old[key], first[key], fresh_schema if key == 'schema_main' or log == 'same' else None)
                    if first[key]!=second[key]:raise RuntimeError('second candidate initialization changed '+key)
                if first['organization'] != second['organization']:
                    raise RuntimeError('organization data changed during repeated production initialization')
                # Back up the migrated database as well as the original release; prove new rows survive.
                org_backup=runtime/(prefix+'.organization.backup');stores.backup(main,upgrade[0],org_backup)
                org_restored=create_pair('organization_restored');stores.restore(main,org_restored[0],org_backup)
                if log!='same':stores.restore(log,org_restored[1],backup_log)
                org_read=phase('organization_restore','candidate','verify',org_restored,additional=True)
                if org_read['organization']!=first['organization'] or org_read['data']!=old['data']:
                    raise RuntimeError('organization backup/restore changed rows')
                legacy_read=phase('organization_old_readback','release','read',org_restored,additional=True)
                if legacy_read['data']!=old['data']:
                    raise RuntimeError('old binary cannot read existing data after organization backup/restore')
                for key in ('schema_main','schema_log'):
                    if org_read[key]!=first[key] or legacy_read[key]!=first[key]:
                        raise RuntimeError('organization backup/restore or old readback changed '+key)
                partial=create_pair('organization_fault');stores.restore(main,partial[0],backup_main)
                if log!='same':stores.restore(log,partial[1],backup_log)
                phase('organization_fault','candidate','org_fault',partial,additional=True)
                phase('organization_rejected','candidate','expect_org_failure',partial,additional=True)
                # Repair only the two known synthetic duplicate rows, then retry production migration twice.
                if main!='sqlite':
                    stores.sql(main,'DELETE FROM organization_members WHERE organization_id = 4101 AND user_id = 1',partial[0])
                else:
                    with sqlite3.connect(partial[0]) as connection:connection.execute('DELETE FROM organization_members WHERE organization_id = 4101 AND user_id = 1')
                recovered=phase('organization_recovered','candidate','upgrade_seed',partial,additional=True)
                repeated=phase('organization_recovery_restart','candidate','verify',partial,additional=True)
                if recovered['organization']!=first['organization'] or repeated['organization']!=first['organization']:
                    raise RuntimeError('partial organization migration recovery changed representative rows')
                for key in ('data','schema_main','schema_log'):
                    if recovered[key]!=first[key] or repeated[key]!=first[key]:
                        raise RuntimeError('partial organization migration recovery changed '+key)
                fault=create_pair('fault');stores.restore(main,fault[0],backup_main)
                if log!='same':stores.restore(log,fault[1],backup_log)
                records.append({'main':main,'log':log,'phase':'fault_clone','status':'pass'});done.add('fault_clone')
                phase('fault_inject','release','fault',fault)
                phase('migration_rejected','candidate','expect_failure',fault)
                restored=create_pair('restored');stores.restore(main,restored[0],backup_main)
                if log!='same':stores.restore(log,restored[1],backup_log)
                records.append({'main':main,'log':log,'phase':'restore_new','status':'pass'});done.add('restore_new')
                readback=phase('release_readback','release','read',restored)
                for key in ('data','schema_main','schema_log'):
                    if readback[key]!=old[key]:raise RuntimeError('old-source restore readback differs: '+key)
            except Exception as error:
                if isinstance(error, RelayIdentityError) or getattr(error, 'process_cleanup_error', None):
                    raise  # Do not continue while an earlier fixture process may still be alive.
                if primary_error is None:
                    primary_error = {'error_type':type(error).__name__, 'error':str(error),
                                     'process_cleanup_error':getattr(error, 'process_cleanup_error', None)}
                # A comparison failure invalidates the combination, even if its process exited zero.
                records.append({'main':main,'log':log,'phase':'combination_validation','status':'fail','error':str(error),'process_cleanup_error':getattr(error, 'process_cleanup_error', None)})
                for phase_name in PHASES:
                    if phase_name not in done:records.append({'main':main,'log':log,'phase':phase_name,'status':'blocked','reason':str(error)})
            (evidence/'matrix-results.json').write_text(json.dumps(records,indent=2))
            if fail_fast and primary_error is not None:
                break  # Normal unwinding lets OwnedStores finish its bounded cleanup.
    except BaseException as error:
        failure = {'error_type':type(error).__name__, 'error':str(error),
                   'process_cleanup_error':getattr(error, 'process_cleanup_error', None)}
        if primary_error is None:
            primary_error = failure
        else:
            primary_error.setdefault('subsequent_errors', []).append(failure)
    finally:
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            # Always publish the entire required manifests; unattempted is never pass.
            recorded={(x['main'],x['log'],x['phase']) for x in records}
            checked={(x['main'],x['log'],x['check']) for x in organization_checks}
            reason = primary_error['error'] if primary_error else 'combination not completed'
            for main, log in COMBINATIONS:
                for phase_name in PHASES:
                    if (main,log,phase_name) not in recorded:
                        records.append({'main':main,'log':log,'phase':phase_name,'status':'blocked','reason':reason})
                for check in ORGANIZATION_SUBCHECKS:
                    if (main,log,check) not in checked:
                        organization_checks.append({'main':main,'log':log,'check':check,'status':'blocked','reason':reason})
            (evidence/'matrix-results.json').write_text(json.dumps(records,indent=2))
            (evidence/'organization-migration-results.json').write_text(json.dumps(organization_checks,indent=2))
            try:
                cleanup=stores.cleanup() if stores is not None else []
            except BaseException as error:
                cleanup.append({'error_type':type(error).__name__,'error':str(error),
                                'process_cleanup_error':getattr(error,'process_cleanup_error',None)})
            (evidence/'database-cleanup.json').write_text(json.dumps({'created':stores.created if stores is not None else [],'errors':cleanup,
                'primary_error':primary_error, 'sqlite_files':'retained under runtime; process cleanup status reported separately'},indent=2))
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    passed={(x['main'],x['log'],x['phase']) for x in records if x['status']=='pass'}
    required={(x['main'],x['log'],x['phase']) for x in required_manifest()}
    organization_required={(main,log,name) for main,log in COMBINATIONS for name in ORGANIZATION_SUBCHECKS}
    organization_passed={(x['main'],x['log'],x['check']) for x in organization_checks if x['status']=='pass'}
    complete=organization_required<=organization_passed and required<=passed and primary_error is None and not cleanup and not any(x['status']!='pass' for x in records)
    (evidence/'matrix-verdict.json').write_text(json.dumps({'complete':complete,'required_count':len(required),'passed_count':len(passed),'organization_required_subchecks':len(organization_required),'organization_passed_subchecks':len(organization_passed),'remote_ci':'not_run','primary_error':primary_error},indent=2))
    return complete


def run_organization_matrix(source, go, stores, evidence, dialects=('sqlite', 'mysql', 'postgres')):
    """Dedicated empty databases; the Go fixture owns tables, this runner owns the databases."""
    from database_gate import validate_organization_events, organization_required_leaves
    required_count = sum(len(organization_required_leaves(dialect)) for dialect in ('sqlite', 'mysql', 'postgres'))
    results = []
    (evidence / 'organization-verdict.json').write_text(json.dumps({'complete':False,
        'required_dialects':['sqlite','mysql','postgres'],'required_leaf_count':required_count,'passed_leaf_count':0},indent=2))
    for dialect in dialects:
        if dialect not in ('sqlite', 'mysql', 'postgres'):
            raise ValueError('unsupported organization dialect')
        main = stores.create('sqlite', 'newapi_ci_organization_' + dialect + '_main')
        env = dict(clean_environment(), GOWORK='off', NEWAPI_TEST_PROFILE='isolated-ci',
                   NEWAPI_REQUIRE_DATABASES='1', TEST_ORGANIZATION_DIALECT=dialect,
                   SQL_DSN='local', SQLITE_PATH=main)
        if dialect != 'sqlite':
            database = stores.create(dialect, 'newapi_ci_organization_' + dialect)
            env['TEST_' + dialect.upper() + '_DSN'] = stores.dsn(dialect, database)
        command = [str(go), 'test', '-count=1', '-json', '-timeout=5m', './model', '-run',
                   '^TestOrganizationLifecycleDatabaseMatrix$/^' + dialect + '$']
        code, out, err = stores.run_test(command, cwd=source, env=env, timeout=360)
        (evidence / ('organization-' + dialect + '.jsonl')).write_bytes(out)
        (evidence / ('organization-' + dialect + '.stderr')).write_bytes(err)
        (evidence / ('organization-' + dialect + '.command.json')).write_text(json.dumps(
            {'command':command, 'cwd':str(source), 'exit_code':code, 'dialect':dialect,
             'strict':True, 'empty_database_created_by_runner':dialect != 'sqlite'}, indent=2))
        events = [json.loads(line) for line in out.decode().splitlines() if line.startswith('{')]
        required = validate_organization_events(events, code, dialect)
        results.append({'dialect':dialect, 'status':'pass', 'required_leaves':required})
        (evidence / 'organization-results.json').write_text(json.dumps(results,indent=2))
    complete = {r['dialect'] for r in results} == {'sqlite','mysql','postgres'}
    (evidence / 'organization-verdict.json').write_text(json.dumps({'complete':complete,
        'required_dialects':['sqlite','mysql','postgres'],'required_leaf_count':required_count,
        'passed_leaf_count':sum(len(r['required_leaves']) for r in results)},indent=2))
    return complete


def run_regression_contracts(source, go, stores, evidence, dialects=('sqlite','mysql','postgres')):
    """Retain P1/S0, deletion, and independent log requirements on the composed source."""
    from database_gate import TESTS, CONTROLLER_REQUIRED, DELETION_REQUIRED, validate_required_events
    if not dialects or len(set(dialects))!=len(dialects) or set(dialects)-{'sqlite','mysql','postgres','clickhouse'}:
        raise ValueError('invalid regression dialect set')
    main=stores.create('sqlite','newapi_ci_regression_main')
    env=dict(clean_environment(),GOWORK='off',NEWAPI_TEST_PROFILE='isolated-ci',NEWAPI_REQUIRE_DATABASES='1',
             SQL_DSN='local',SQLITE_PATH=main)
    for dialect in dialects:
        if dialect=='sqlite':continue
        name=stores.create(dialect,'newapi_ci_regression_'+dialect)
        dsn=stores.dsn(dialect,name)
        env['AUDIT_'+dialect.upper()+'_DSN']=dsn
        if dialect!='clickhouse':env['TEST_'+dialect.upper()+'_DSN']=dsn
    jobs=[]
    primary=tuple(d for d in dialects if d!='clickhouse')
    if primary:
        required={f'{test}/{dialect}' for test in TESTS for dialect in primary}
        jobs.append(('strict-model','model','^('+'|'.join(TESTS)+')$/^('+'|'.join(primary)+')$',required,{}))
        jobs.append(('deletion-controller','controller','^(TestSecurityAccountDeletion|TestManageUserOrganization|TestManageUserDelete)',DELETION_REQUIRED,{}))
        model_required={'TestHardDeleteUserFailsClosedWhenAuthFenceCannotPublish',
                        'TestHardDeleteUserPublishesTombstoneAndPurgesAuthenticationData',
                        'TestDisablingUserKeepsAccessTokensAndDeletingRemovesThem'}
        jobs.append(('deletion-model','model','^('+'|'.join(sorted(model_required))+')$',model_required,{}))
        for dialect in primary:
            jobs.append(('controller-'+dialect,'controller','^('+'|'.join(sorted(CONTROLLER_REQUIRED))+')$',
                         CONTROLLER_REQUIRED,{'TEST_TASK_DB_DIALECT':dialect}))
    matrix_required={f'TestLogExportDatabaseMatrix/{d}' for d in dialects}
    matrix_required|={f'TestAuditDatabaseMatrix/{d}/upgrade={upgrade}' for d in primary for upgrade in ('false','true')}
    matrix_required|={f'TestIndependentAuditLogStores/{d}/upgrade={upgrade}' for d in dialects if d!='sqlite' for upgrade in ('false','true')}
    jobs.append(('controller-log-matrices','controller','^(TestAuditDatabaseMatrix|TestIndependentAuditLogStores|TestLogExportDatabaseMatrix)$/^('+'|'.join(dialects)+')$',matrix_required,{}))
    results=[]
    try:
        for name,package,selector,required,extra in jobs:
            command=[str(go),'test','-count=1','-json','-timeout=10m','./'+package,'-run',selector]
            code,out,err=stores.run_test(command,cwd=source,env=dict(env,**extra),timeout=660)
            (evidence/(name+'.jsonl')).write_bytes(out);(evidence/(name+'.stderr')).write_bytes(err)
            (evidence/(name+'.command.json')).write_text(json.dumps({'command':command,'cwd':str(source),
                'exit_code':code,'required':sorted(required)},indent=2))
            events=[json.loads(line) for line in out.decode().splitlines() if line.startswith('{')]
            passed=validate_required_events(events,code,'github.com/QuantumNous/new-api/'+package,required)
            results.append({'name':name,'required':sorted(required),'passed':passed,'status':'pass'})
    finally:
        (evidence/'regression-results.json').write_text(json.dumps({'dialects':dialects,'results':results,
            'selected_complete':len(results)==len(jobs),'all_primary_dialects':set(primary)=={'sqlite','mysql','postgres'},
            'clickhouse_included':'clickhouse' in dialects},indent=2))
    return results

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--organization-contracts', action='store_true')
    parser.add_argument('--bindings', type=Path)
    parser.add_argument('--reuse-built', action='store_true')
    parser.add_argument('--fail-fast', action='store_true', help='Stop after the first failed combination and finish owned cleanup normally')
    args = parser.parse_args()
    for path in (args.source, args.runtime, args.evidence, args.go):
        if not path.is_absolute():
            raise ValueError('absolute owner paths are required')
    args.runtime.mkdir(parents=True, exist_ok=True);args.evidence.mkdir(parents=True, exist_ok=True)
    try:
        if args.reuse_built:
            for kind in ('release','candidate'):
                validate_built_fixture(args.runtime, kind, args.source)
        manifest = args.evidence / 'required-matrix.json'
        if manifest.exists():
            raise ValueError('use a new evidence run directory; never overwrite matrix results')
        manifest.write_text(json.dumps({'release':RELEASE,'combinations':COMBINATIONS,'required':required_manifest(),'organization_subchecks':ORGANIZATION_SUBCHECKS},indent=2))
        if not args.reuse_built:
            export_sources(args.source,args.runtime/'release-source',RELEASE)
            export_sources(args.source,args.runtime/'candidate-source')
            for kind in ('release','candidate'):
                build_fixture(args.runtime/(kind+'-source'),args.runtime/(kind+'-fixture'),args.evidence,args.go)
        for kind in ('release','candidate'):
            validate_built_fixture(args.runtime, kind, args.source)
        if args.prepare_only:
            print('fixtures compiled; database matrix NOT RUN')
            return
        binding=json.loads(args.bindings.read_text()) if args.bindings else None
        if args.organization_contracts:
            contract_runtime=args.runtime/'organization-contracts';contract_runtime.mkdir()
            stores = OwnedStores(contract_runtime,binding)
            primary=None
            try:
                if not run_organization_matrix(args.source,args.go,stores,args.evidence):
                    raise RuntimeError('organization three-dialect matrix incomplete')
                run_regression_contracts(args.source,args.go,stores,args.evidence)
            except BaseException as error:
                primary=error
                raise
            finally:
                cleanup=stores.cleanup()
                (args.evidence/'organization-cleanup.json').write_text(json.dumps(cleanup,indent=2))
                if cleanup:
                    if primary is not None:primary.process_cleanup_error=str(cleanup)
                    else:raise RuntimeError('organization cleanup unknown')
        if not run_matrix(args.runtime,args.evidence,binding,fail_fast=args.fail_fast):
            raise SystemExit('required matrix incomplete; inspect matrix-results.json')
    except BaseException as error:
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            (args.evidence/'cli-failure.json').write_text(json.dumps({'error_type':type(error).__name__,
                'error':str(error), 'process_cleanup_error':getattr(error, 'process_cleanup_error', None)},indent=2))
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
        raise


def cancel(signum, frame):
    raise KeyboardInterrupt('received signal '+str(signum))


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, cancel)
    main()
