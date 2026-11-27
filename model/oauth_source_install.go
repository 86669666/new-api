package model

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"

	"gorm.io/gorm"
)

//go:embed oauth_source_postgres.sql
var oauthSourcePostgresSQL string

//go:embed oauth_source_mysql.sql
var oauthSourceMySQL string

// Runs from the trusted installer, against an existing, verified birth journal.
func installOAuthSourceOperations(ctx context.Context, engine, target, journal, role, attestor, issuer string) error {
	if os.Geteuid() != 0 || !bootstrapName.MatchString(target) || !bootstrapName.MatchString(role) ||
		attestor != "" && (!bootstrapName.MatchString(attestor) || attestor == role) ||
		issuer != "" && (attestor == "" || !bootstrapName.MatchString(issuer) || issuer == attestor || issuer == role) {
		return errOAuthBootstrap
	}
	j, err := readOAuthBirthJournal(journal, false)
	if err != nil || j.Engine != engine || j.Target != target || j.Phase != "READY" {
		return errOAuthBootstrap
	}
	dsn, endpoint, err := oauthBootstrapDSN(engine, os.Getenv("BOOTSTRAP_ADMIN_DSN"), target)
	if err != nil || j.Endpoint != endpoint {
		return errOAuthBootstrap
	}
	db, err := openOAuthBootstrapDB(engine, dsn)
	if err != nil {
		return errOAuthBootstrap
	}
	pool, err := db.DB()
	if err != nil {
		return errOAuthBootstrap
	}
	defer pool.Close()
	db = db.WithContext(ctx)
	if err := validateOAuthBirth(db, j, true); err != nil {
		return errOAuthBootstrap
	}
	if err := validateOAuthDerivedTokenSchema(db); err != nil {
		return errOAuthBootstrap
	}
	switch engine {
	case "postgres":
		if err := installPostgresOAuthSourceOperations(db, role); err != nil || attestor == "" {
			return err
		}
		return db.Transaction(func(tx *gorm.DB) error {
			if err := installOAuthIssueAttestations(tx, target, role, attestor); err != nil || issuer == "" {
				return err
			}
			return installOAuthFirstKey(tx, target, role, attestor, issuer)
		})
	case "mysql":
		return db.Connection(func(conn *gorm.DB) error {
			if err := installMySQLOAuthSourceOperations(conn, target, role); err != nil || attestor == "" {
				return err
			}
			if err := installOAuthIssueAttestations(conn, target, role, attestor); err != nil || issuer == "" {
				return err
			}
			return installOAuthFirstKey(conn, target, role, attestor, issuer)
		})
	}
	return errOAuthBootstrap
}

func installPostgresOAuthSourceOperations(db *gorm.DB, role string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var restricted bool
		if err := tx.Raw(`SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_roles r
			WHERE r.rolname = ? AND NOT EXISTS (
				SELECT 1 FROM pg_catalog.pg_roles effective
				WHERE (effective.oid = r.oid OR pg_catalog.pg_has_role(r.oid, effective.oid, 'MEMBER'))
				  AND (effective.rolname = current_user OR effective.rolsuper OR effective.rolcreaterole OR effective.rolbypassrls
				    OR effective.oid = (SELECT relowner FROM pg_catalog.pg_class
				          WHERE oid = 'public.oauth_derived_token_sources'::regclass)
				    OR pg_catalog.has_table_privilege(effective.oid, 'public.oauth_derived_token_sources', 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
				    OR pg_catalog.has_any_column_privilege(effective.oid, 'public.oauth_derived_token_sources', 'INSERT,UPDATE'))
			)
		)`, role).Scan(&restricted).Error; err != nil || !restricted {
			return errOAuthBootstrap
		}
		for _, statement := range strings.Split(oauthSourcePostgresSQL, "\n-- statement\n") {
			if err := tx.Exec(statement).Error; err != nil {
				return errOAuthBootstrap
			}
		}
		var owned bool
		if err := tx.Raw(`SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace
			WHERE nspname = 'newapi_oauth_source'
			  AND nspowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
			  AND NOT pg_catalog.has_schema_privilege(CAST(? AS name), oid, 'CREATE'))`, role).Scan(&owned).Error; err != nil || !owned {
			return errOAuthBootstrap
		}
		// Only the reader and terminal action are available to the gateway.
		// The reservation requires a separately trusted attestation producer.
		q := `"` + role + `"`
		if err := tx.Raw(`SELECT count(*) = 3 AND bool_and(prosecdef AND proowner =
			(SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user))
			FROM pg_catalog.pg_proc WHERE oid IN (
				'newapi_oauth_source.lock_sources(bigint,text)'::regprocedure,
				'newapi_oauth_source.terminal_source(bigint,text,text,bigint)'::regprocedure,
				'newapi_oauth_source.reserve_source(bigint,text,bigint,bigint,bigint,text,text)'::regprocedure
			)`).Scan(&owned).Error; err != nil || !owned {
			return errOAuthBootstrap
		}
		for _, statement := range []string{
			"GRANT USAGE ON SCHEMA newapi_oauth_source TO " + q,
			"GRANT SELECT ON public.oauth_derived_token_sources TO " + q,
			"GRANT EXECUTE ON FUNCTION newapi_oauth_source.lock_sources(bigint,text), " +
				"newapi_oauth_source.terminal_source(bigint,text,text,bigint) TO " + q,
			"REVOKE EXECUTE ON FUNCTION newapi_oauth_source.reserve_source(bigint,text,bigint,bigint,bigint,text,text) FROM " + q,
		} {
			if err := tx.Exec(statement).Error; err != nil {
				return errOAuthBootstrap
			}
		}
		const reserve = "newapi_oauth_source.reserve_source(bigint,text,bigint,bigint,bigint,text,text)"
		if err := tx.Raw(`SELECT NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r, pg_catalog.pg_roles effective
			WHERE r.rolname = ? AND (effective.oid = r.oid OR pg_catalog.pg_has_role(r.oid, effective.oid, 'MEMBER'))
			  AND pg_catalog.has_function_privilege(effective.oid, CAST(? AS regprocedure), 'EXECUTE'))`, role, reserve).Scan(&restricted).Error; err != nil || !restricted {
			return errOAuthBootstrap
		}
		return nil
	})
}

func installMySQLOAuthSourceOperations(db *gorm.DB, target, role string) error {
	var tables int
	if err := db.Raw(`SELECT count(*) FROM information_schema.tables
		WHERE table_schema = ? AND table_name IN ('oauth_derived_token_sources', 'tokens', 'users',
			'user_sessions', 'oauth_grants', 'auth_flows') AND engine = 'InnoDB'`, target).Scan(&tables).Error; err != nil || tables != 6 {
		return errOAuthBootstrap
	}
	principal := "'" + role + "'@'localhost'"
	var definer string
	if err := db.Raw("SELECT CURRENT_USER()").Scan(&definer).Error; err != nil || definer == role+"@localhost" {
		return errOAuthBootstrap
	}
	var version string
	if err := db.Raw("SELECT VERSION()").Scan(&version).Error; err != nil {
		return errOAuthBootstrap
	}
	if !strings.HasPrefix(version, "5.7.") {
		var roles string
		if err := db.Raw("SELECT @@GLOBAL.mandatory_roles").Scan(&roles).Error; err != nil || roles != "" {
			return errOAuthBootstrap
		}
	}
	var grants []string
	if err := db.Raw("SHOW GRANTS FOR " + principal).Scan(&grants).Error; err != nil {
		return errOAuthBootstrap
	}
	for _, grant := range grants {
		privileges, object, found := strings.Cut(grant, " ON ")
		object, _, qualified := strings.Cut(object, " TO ")
		if !found || !qualified || strings.Contains(grant, "WITH GRANT OPTION") || privileges == "GRANT PROXY" {
			return errOAuthBootstrap
		}
		if object == "PROCEDURE `"+target+"`.`newapi_oauth_reserve_source`" {
			// Never adopt an account that can call reservation using app-writable proof rows.
			return errOAuthBootstrap
		}
		switch {
		case object == "*.*":
			if privileges != "GRANT USAGE" && privileges != "GRANT SELECT" {
				return errOAuthBootstrap
			}
		case strings.HasSuffix(object, ".*"):
			// MySQL permits wildcard database names in grants. Check all such
			// grants instead of assuming a textual match with this database.
			if privileges != "GRANT SELECT" {
				return errOAuthBootstrap
			}
		case object == "`"+target+"`.`oauth_derived_token_sources`":
			if privileges != "GRANT SELECT" {
				return errOAuthBootstrap
			}
		case strings.HasPrefix(object, "`"+target+"`.`"):
			for _, ddl := range []string{"ALL PRIVILEGES", "CREATE", "ALTER", "DROP", "TRIGGER"} {
				if strings.Contains(privileges, ddl) {
					return errOAuthBootstrap
				}
			}
		}
	}
	routines := []string{"newapi_oauth_lock_sources", "newapi_oauth_terminal_source", "newapi_oauth_reserve_source"}
	sqlText := strings.ReplaceAll(oauthSourceMySQL, "@database@", "`"+target+"`")
	statements := strings.Split(sqlText, "\n-- statement\n")
	for index, name := range routines {
		if err := installMySQLOAuthRoutine(db, target, definer, name, strings.TrimSpace(statements[index])); err != nil {
			return err
		}
	}
	// Keep reservation installer-only until the attestation producer exists.
	for _, name := range routines[:2] {
		if err := db.Exec("GRANT EXECUTE ON PROCEDURE `" + target + "`.`" + name + "` TO " + principal).Error; err != nil {
			return errOAuthBootstrap
		}
	}
	return db.Exec("GRANT SELECT ON `" + target + "`.`oauth_derived_token_sources` TO " + principal).Error
}

func installMySQLOAuthRoutine(db *gorm.DB, target, definer, name, statement string) error {
	_, expected, _ := strings.Cut(statement, "\nBEGIN")
	var installed struct {
		Present int
		Matches int
	}
	if err := db.Raw(`SELECT count(*) AS present,
		coalesce(sum(BINARY trim(routine_definition) = BINARY ?
		  AND BINARY definer = BINARY ? AND security_type = 'DEFINER'), 0) AS matches
		FROM information_schema.routines WHERE routine_schema = ? AND routine_name = ?
		AND routine_type = 'PROCEDURE'`, "BEGIN"+expected, definer, target, name).Scan(&installed).Error; err != nil {
		return errOAuthBootstrap
	}
	if installed.Present != 0 {
		// A resumed installer adopts the exact definer, signature and body.
		if installed.Present != 1 || installed.Matches != 1 {
			return fmt.Errorf("protected source routine %s has a different definition: %w", name, errOAuthBootstrap)
		}
		head, _, _ := strings.Cut(statement, "\nSQL SECURITY")
		_, signature, _ := strings.Cut(head, "(")
		declarations := strings.Split(strings.TrimSuffix(strings.TrimSpace(signature), ")"), ",")
		var parameters []struct {
			Mode       string
			Name       string
			DataType   string
			Definition string
			Length     *int64
		}
		if err := db.Raw(`SELECT parameter_mode AS mode, parameter_name AS name,
			data_type AS data_type, dtd_identifier AS definition, character_maximum_length AS length
			FROM information_schema.parameters WHERE specific_schema = ? AND specific_name = ?
			AND routine_type = 'PROCEDURE' ORDER BY ordinal_position`, target, name).Scan(&parameters).Error; err != nil || len(parameters) != len(declarations) {
			return fmt.Errorf("protected source routine %s has unreadable parameters: %w", name, errOAuthBootstrap)
		}
		for i, parameter := range parameters {
			words := strings.Fields(declarations[i])
			if len(words) != 3 || parameter.Mode != words[0] || parameter.Name != words[1] {
				return fmt.Errorf("protected source routine %s parameter %d has a different declaration: %w", name, i+1, errOAuthBootstrap)
			}
			switch words[2] {
			case "BIGINT":
				if parameter.DataType != "bigint" || strings.Contains(parameter.Definition, "unsigned") {
					return fmt.Errorf("protected source routine %s parameter %d has a different integer type: %w", name, i+1, errOAuthBootstrap)
				}
			case "VARCHAR(64)":
				if parameter.DataType != "varchar" || parameter.Length == nil || *parameter.Length != 64 {
					return errOAuthBootstrap
				}
			case "VARCHAR(32)":
				if parameter.DataType != "varchar" || parameter.Length == nil || *parameter.Length != 32 {
					return errOAuthBootstrap
				}
			default:
				return errOAuthBootstrap
			}
		}
		return nil
	}
	if err := db.Exec(statement).Error; err != nil {
		return errOAuthBootstrap
	}
	return nil
}
