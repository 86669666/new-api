package model

import (
	_ "embed"
	"strings"

	"gorm.io/gorm"
)

//go:embed oauth_issue_postgres.sql
var oauthIssuePostgresSQL string

//go:embed oauth_issue_mysql.sql
var oauthIssueMySQL string

func installOAuthIssueAttestations(db *gorm.DB, target, gateway, writer string) error {
	if !bootstrapName.MatchString(target) || !bootstrapName.MatchString(gateway) ||
		!bootstrapName.MatchString(writer) || gateway == writer {
		return errOAuthBootstrap
	}
	postgres := db.Dialector.Name() == "postgres"
	var table string
	if postgres {
		table = "public." + oauthIssueAttestationTable
		if err := db.Exec("SET LOCAL search_path = public").Error; err != nil {
			return errOAuthBootstrap
		}
	} else if db.Dialector.Name() == "mysql" {
		table = "`" + target + "`.`" + oauthIssueAttestationTable + "`"
	} else {
		return errOAuthBootstrap
	}
	hasTable := db.Migrator().HasTable(&OAuthIssueAttestation{})
	var hasRoutine bool
	if postgres {
		if err := db.Raw(`SELECT pg_catalog.to_regprocedure(
			'newapi_oauth_source.reserve_attested_source(bigint,text)') IS NOT NULL`).Row().Scan(&hasRoutine); err != nil {
			return errOAuthBootstrap
		}
	} else if err := db.Raw(`SELECT EXISTS (SELECT 1 FROM information_schema.routines
		WHERE routine_schema = ? AND routine_name = 'newapi_oauth_reserve_attested_source' AND routine_type = 'PROCEDURE')`,
		target).Row().Scan(&hasRoutine); err != nil {
		return errOAuthBootstrap
	}
	// A pre-existing relation without an installer-owned procedure has no
	// trustworthy origin. In MySQL a verified procedure can be left by an
	// interrupted install and has no service grant until the table is ready.
	if hasTable && !hasRoutine || postgres && hasRoutine && !hasTable {
		return errOAuthBootstrap
	}
	if !postgres {
		if err := prepareMySQLOAuthIssueInstaller(db, target, gateway, writer, table); err != nil {
			return err
		}
	}
	if !hasTable {
		if err := db.Migrator().CreateTable(&OAuthIssueAttestation{}); err != nil {
			return errOAuthBootstrap
		}
	}
	for _, index := range []struct{ name, column string }{
		{"", "grant_ref"},
		{"uq_oauth_attest_consent", "consent_ref"},
		{"uq_oauth_attest_proof", "proof_digest"},
		{"uq_oauth_attest_flow", "proof_flow_id"},
	} {
		// PostgreSQL names its primary index explicitly even though the
		// selector chooses the primary key by category.
		if err := validateOAuthDerivedTokenIndex(db, oauthIssueAttestationTable, index.name, []string{index.column}, true); err != nil {
			return errOAuthBootstrap
		}
	}
	if postgres {
		if err := db.Exec("REVOKE ALL ON " + table + " FROM PUBLIC").Error; err != nil {
			return errOAuthBootstrap
		}
		var safe bool
		if err := db.Raw(`SELECT
			EXISTS (SELECT FROM pg_catalog.pg_class WHERE oid = CAST(? AS regclass) AND relkind = 'r'
				AND relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user))
			AND EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = ? AND rolname <> current_user
				AND NOT rolsuper AND NOT rolcreaterole AND NOT rolbypassrls
				AND NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members WHERE member = pg_roles.oid)
				AND NOT EXISTS (SELECT FROM pg_catalog.pg_roles login WHERE login.rolcanlogin AND NOT login.rolsuper
					AND login.rolname <> current_user AND login.oid <> pg_roles.oid
					AND pg_catalog.pg_has_role(login.oid, pg_roles.oid, 'MEMBER')))
			AND NOT EXISTS (
				SELECT FROM pg_catalog.pg_roles r, pg_catalog.pg_roles e
				WHERE r.rolname = ? AND (r.oid = e.oid OR pg_catalog.pg_has_role(r.oid,e.oid,'MEMBER'))
				AND (e.rolname = ? OR pg_catalog.has_table_privilege(e.oid, ?, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
					OR pg_catalog.has_any_column_privilege(e.oid, ?, 'SELECT,INSERT,UPDATE,REFERENCES')))
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_trigger
				WHERE tgrelid = CAST(? AS regclass) AND NOT tgisinternal)
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_roles e, pg_catalog.pg_class c
				WHERE c.oid = CAST(? AS regclass) AND e.oid <> c.relowner AND NOT e.rolsuper AND e.rolname <> ?
				  AND EXISTS (SELECT FROM pg_catalog.pg_roles login
					WHERE login.rolcanlogin AND NOT login.rolsuper AND login.oid <> c.relowner
					AND (login.oid = e.oid OR pg_catalog.pg_has_role(login.oid, e.oid, 'MEMBER')))
				  AND (pg_catalog.has_table_privilege(e.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
					OR pg_catalog.has_any_column_privilege(e.oid,c.oid,'INSERT,UPDATE')))
			AND NOT pg_catalog.has_table_privilege(CAST(? AS name), ?, 'SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
			AND NOT pg_catalog.has_any_column_privilege(CAST(? AS name), ?, 'SELECT,UPDATE,REFERENCES')`,
			table, writer, gateway, writer, table, table, table, table, writer, writer, table, writer, table).Scan(&safe).Error; err != nil || !safe {
			return errOAuthBootstrap
		}
		const reserve = "newapi_oauth_source.reserve_attested_source(bigint,text)"
		if hasRoutine {
			if err := db.Raw(`SELECT prosecdef AND proowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
				FROM pg_catalog.pg_proc WHERE oid = CAST(? AS regprocedure)`, reserve).Row().Scan(&safe); err != nil || !safe {
				return errOAuthBootstrap
			}
		}
		if err := db.Exec(oauthIssuePostgresSQL).Error; err != nil {
			return errOAuthBootstrap
		}
		if err := db.Raw(`SELECT prosecdef AND proowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
			FROM pg_catalog.pg_proc WHERE oid = CAST(? AS regprocedure)`, reserve).Row().Scan(&safe); err != nil || !safe {
			return errOAuthBootstrap
		}
		if err := db.Exec("REVOKE ALL ON FUNCTION " + reserve + " FROM PUBLIC").Error; err != nil {
			return errOAuthBootstrap
		}
		if err := db.Exec("GRANT EXECUTE ON FUNCTION " + reserve + " TO \"" + gateway + "\"").Error; err != nil {
			return errOAuthBootstrap
		}
		if err := db.Exec("GRANT USAGE ON SCHEMA public TO \"" + writer + "\"").Error; err != nil {
			return errOAuthBootstrap
		}
		return db.Exec("GRANT INSERT ON " + table + " TO \"" + writer + "\"").Error
	}
	var engine string
	if err := db.Raw(`SELECT engine FROM information_schema.tables
		WHERE table_schema = ? AND table_name = ?`, target, oauthIssueAttestationTable).Scan(&engine).Error; err != nil || engine != "InnoDB" {
		return errOAuthBootstrap
	}
	var exclusive bool
	if err := db.Raw(`SELECT
		NOT EXISTS (SELECT 1 FROM information_schema.triggers
			WHERE event_object_schema = ? AND event_object_table = ?)
		AND NOT EXISTS (SELECT 1 FROM information_schema.table_privileges
			WHERE table_schema = ? AND table_name = ?
			  AND privilege_type <> 'SELECT' AND grantee <> ?)
		AND NOT EXISTS (SELECT 1 FROM information_schema.column_privileges
			WHERE table_schema = ? AND table_name = ? AND privilege_type <> 'SELECT')`,
		target, oauthIssueAttestationTable, target, oauthIssueAttestationTable, "'"+writer+"'@'localhost'",
		target, oauthIssueAttestationTable).Row().Scan(&exclusive); err != nil || !exclusive {
		return errOAuthBootstrap
	}

	const routine = "newapi_oauth_reserve_attested_source"
	qualified := "`" + target + "`.`" + routine + "`"
	if err := db.Exec("GRANT EXECUTE ON PROCEDURE " + qualified + " TO '" + gateway + "'@'localhost'").Error; err != nil {
		return errOAuthBootstrap
	}
	return db.Exec("GRANT INSERT ON " + table + " TO '" + writer + "'@'localhost'").Error
}

func prepareMySQLOAuthIssueInstaller(db *gorm.DB, target, gateway, writer, table string) error {
	for _, account := range []string{gateway, writer} {
		principal := "'" + account + "'@'localhost'"
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
			if object == "*.*" && privileges == "GRANT USAGE" {
				continue
			}
			if account == writer {
				if object != table || privileges != "GRANT INSERT" {
					return errOAuthBootstrap
				}
			} else if object == table || object == "*.*" || strings.HasSuffix(object, ".*") {
				return errOAuthBootstrap
			}
		}
	}
	// Audit effective database and global grants as well as the table ACL.
	// Global principals with grantable CREATE USER are trusted DB administrators.
	var exclusive bool
	if err := db.Raw(`SELECT NOT EXISTS (
			SELECT 1 FROM information_schema.schema_privileges p
			WHERE (p.table_schema = ? OR ? LIKE p.table_schema)
			  AND p.privilege_type IN ('INSERT','UPDATE','DELETE','CREATE','DROP','ALTER','TRIGGER','CREATE ROUTINE','ALTER ROUTINE','CREATE TEMPORARY TABLES','EXECUTE')
			  AND NOT EXISTS (SELECT 1 FROM information_schema.user_privileges a
				WHERE a.grantee = p.grantee AND a.privilege_type = 'CREATE USER' AND a.is_grantable = 'YES'))
		AND NOT EXISTS (
			SELECT 1 FROM information_schema.user_privileges p
			WHERE p.privilege_type IN ('INSERT','UPDATE','DELETE','CREATE','DROP','ALTER','TRIGGER','CREATE ROUTINE','ALTER ROUTINE','CREATE TEMPORARY TABLES','EXECUTE')
			  AND NOT EXISTS (SELECT 1 FROM information_schema.user_privileges a
				WHERE a.grantee = p.grantee AND a.privilege_type = 'CREATE USER' AND a.is_grantable = 'YES'))`,
		target, target).Row().Scan(&exclusive); err != nil || !exclusive {
		return errOAuthBootstrap
	}
	var definer string
	if err := db.Raw("SELECT CURRENT_USER()").Row().Scan(&definer); err != nil {
		return errOAuthBootstrap
	}
	const routine = "newapi_oauth_reserve_attested_source"
	if err := installMySQLOAuthRoutine(db, target, definer, routine,
		strings.TrimSpace(strings.ReplaceAll(oauthIssueMySQL, "@database@", "`"+target+"`"))); err != nil {
		return err
	}
	return nil
}

// Check the actual login capability at startup so an owner or a second
// general-purpose application credential cannot be used as an attestor.
func oauthIssueWriterRestricted(db *gorm.DB, target string) bool {
	if db.Dialector.Name() == "postgres" {
		var restricted bool
		err := db.Raw(`SELECT EXISTS (SELECT FROM pg_catalog.pg_roles r WHERE r.rolname = current_user
			AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolbypassrls
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members WHERE member = r.oid)
			AND pg_catalog.has_schema_privilege(r.oid, 'public', 'USAGE')
			AND pg_catalog.has_table_privilege(r.oid, 'public.oauth_derived_issue_attestations', 'INSERT')
			AND NOT pg_catalog.has_table_privilege(r.oid, 'public.oauth_derived_issue_attestations', 'SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
			AND NOT pg_catalog.has_any_column_privilege(r.oid, 'public.oauth_derived_issue_attestations', 'SELECT,UPDATE,REFERENCES')
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> 'oauth_derived_issue_attestations'
				AND (c.relowner = r.oid OR pg_catalog.has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
					OR pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE')))
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
				WHERE n.nspname = 'newapi_oauth_source' AND pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE')))`).Row().Scan(&restricted)
		return err == nil && restricted
	}
	table := "`" + target + "`.`" + oauthIssueAttestationTable + "`"
	var grants []string
	if err := db.Raw("SHOW GRANTS").Scan(&grants).Error; err != nil {
		return false
	}
	insert := false
	for _, grant := range grants {
		head, _, ok := strings.Cut(grant, " TO ")
		if !ok || strings.Contains(grant, "WITH GRANT OPTION") {
			return false
		}
		switch head {
		case "GRANT USAGE ON *.*":
		case "GRANT INSERT ON " + table:
			insert = true
		default:
			return false
		}
	}
	return insert
}
