package model

import (
	_ "embed"
	"slices"
	"strings"

	"gorm.io/gorm"
)

//go:embed oauth_first_key_postgres.sql
var oauthFirstKeyPostgresSQL string

//go:embed oauth_first_key_mysql.sql
var oauthFirstKeyMySQL string

const (
	issueGrantLock = "newapi_oauth_source.lock_issue_grant(bigint,text)"
	issueComplete  = "newapi_oauth_source.complete_issue(bigint,text,bigint,text,text,text,bigint)"
	issueReadLock  = "newapi_oauth_source.lock_sources(bigint,text)"
)

func issueReadTables(db *gorm.DB) ([]string, error) {
	var tables []string
	for _, row := range []any{&OAuthGrant{}, &OAuthOperation{},
		&OAuthCleanupJob{}, &SessionRevocationEvent{}, &OAuthDerivedTokenSource{},
		&OAuthDerivedTokenHistory{}, &OAuthDerivedTokenBootstrapIdentity{}} {
		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(row); err != nil || !bootstrapName.MatchString(stmt.Table) {
			return nil, errOAuthBootstrap
		}
		tables = append(tables, stmt.Table)
	}
	return tables, nil
}

func installOAuthFirstKey(db *gorm.DB, target, gateway, attestor, issuer string) error {
	if !bootstrapName.MatchString(target) || !bootstrapName.MatchString(gateway) ||
		!bootstrapName.MatchString(attestor) || !bootstrapName.MatchString(issuer) || issuer == gateway || issuer == attestor {
		return errOAuthBootstrap
	}
	tables, err := issueReadTables(db)
	if err != nil {
		return err
	}
	switch db.Dialector.Name() {
	case "postgres":
		var safe bool
		if err := db.Raw(`SELECT EXISTS (SELECT FROM pg_catalog.pg_roles r WHERE r.rolname = ?
			AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolbypassrls
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members WHERE member = r.oid)
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_roles login
				WHERE login.rolcanlogin AND NOT login.rolsuper AND login.rolname <> current_user AND login.oid <> r.oid
				AND pg_catalog.pg_has_role(login.oid,r.oid,'MEMBER')))`, issuer).Row().Scan(&safe); err != nil || !safe {
			return errOAuthBootstrap
		}
		for _, statement := range strings.Split(oauthFirstKeyPostgresSQL, "\n-- statement\n") {
			if err := db.Exec(statement).Error; err != nil {
				return errOAuthBootstrap
			}
		}
		if err := db.Raw(`SELECT count(*) = 2 AND bool_and(prosecdef AND proowner =
			(SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user))
			FROM pg_catalog.pg_proc WHERE oid IN (CAST(? AS regprocedure),CAST(? AS regprocedure))`,
			issueGrantLock, issueComplete).Row().Scan(&safe); err != nil || !safe {
			return errOAuthBootstrap
		}
		role := "\"" + issuer + "\""
		for _, statement := range []string{
			"REVOKE ALL ON FUNCTION " + issueGrantLock + "," + issueComplete + " FROM PUBLIC,\"" + gateway + "\",\"" + attestor + "\"",
			"GRANT USAGE ON SCHEMA public,newapi_oauth_source TO " + role,
			"GRANT EXECUTE ON FUNCTION " + issueGrantLock + "," + issueComplete + "," + issueReadLock + " TO " + role,
			"GRANT INSERT, SELECT (id,user_id,deleted_at) ON public.tokens TO " + role,
			"GRANT SELECT (id,status,auth_version,deleted_at) ON public.users TO " + role,
			"GRANT SELECT (sid,user_id,status,revoked_at,expires_at,version,user_auth_version) ON public.user_sessions TO " + role,
		} {
			if err := db.Exec(statement).Error; err != nil {
				return errOAuthBootstrap
			}
		}
		var seq string
		if err := db.Raw("SELECT pg_catalog.pg_get_serial_sequence('public.tokens','id')").Row().Scan(&seq); err != nil || seq == "" {
			return errOAuthBootstrap
		}
		if err := db.Exec("GRANT USAGE ON SEQUENCE " + seq + " TO " + role).Error; err != nil {
			return errOAuthBootstrap
		}
		for _, table := range tables {
			if err := db.Exec("GRANT SELECT ON public.\"" + table + "\" TO " + role).Error; err != nil {
				return errOAuthBootstrap
			}
		}
		if err := db.Raw(`SELECT NOT EXISTS (SELECT FROM pg_catalog.pg_roles r, pg_catalog.pg_roles e, pg_catalog.pg_proc p
			WHERE (r.rolcanlogin OR r.rolname IN (?,?)) AND NOT r.rolsuper AND r.rolname <> current_user AND r.rolname <> ?
			AND (r.oid = e.oid OR pg_catalog.pg_has_role(r.oid,e.oid,'MEMBER'))
			AND p.oid IN (CAST(? AS regprocedure),CAST(? AS regprocedure))
			AND pg_catalog.has_function_privilege(e.oid,p.oid,'EXECUTE'))`,
			gateway, attestor, issuer, issueGrantLock, issueComplete).Row().Scan(&safe); err != nil || !safe {
			return errOAuthBootstrap
		}
		return nil
	case "mysql":
		var definer string
		if err := db.Raw("SELECT CURRENT_USER()").Row().Scan(&definer); err != nil || definer == issuer+"@localhost" {
			return errOAuthBootstrap
		}
		procedures := []string{"newapi_oauth_lock_issue_grant", "newapi_oauth_complete_issue"}
		base := "`" + target + "`."
		role := "'" + issuer + "'@'localhost'"
		if !mysqlFirstKeyIssuerGrants(db, target, "SHOW GRANTS FOR "+role, false) {
			return errOAuthBootstrap
		}
		for _, other := range []string{gateway, attestor} {
			var grants []string
			if err := db.Raw("SHOW GRANTS FOR '" + other + "'@'localhost'").Scan(&grants).Error; err != nil {
				return errOAuthBootstrap
			}
			for _, grant := range grants {
				for _, procedure := range procedures {
					if strings.Contains(grant, " ON PROCEDURE "+base+"`"+procedure+"` TO ") {
						return errOAuthBootstrap
					}
				}
			}
		}
		var version string
		if err := db.Raw("SELECT VERSION()").Row().Scan(&version); err != nil {
			return errOAuthBootstrap
		}
		var exclusive bool
		if !strings.HasPrefix(version, "5.7.") {
			if err := db.Raw("SELECT NOT EXISTS (SELECT FROM_USER FROM mysql.role_edges WHERE FROM_USER = ? AND FROM_HOST = 'localhost')",
				issuer).Row().Scan(&exclusive); err != nil || !exclusive {
				return errOAuthBootstrap
			}
		}
		if err := db.Raw(`SELECT NOT EXISTS (SELECT 1 FROM mysql.procs_priv
			WHERE Db = ? AND Routine_type = 'PROCEDURE' AND Routine_name IN (?,?)
			  AND FIND_IN_SET('Execute',Proc_priv) <> 0 AND CONCAT(User,'@',Host) <> ?
			  AND NOT (User = ? AND Host = 'localhost'))`,
			target, procedures[0], procedures[1], definer, issuer).Row().Scan(&exclusive); err != nil || !exclusive {
			return errOAuthBootstrap
		}
		statements := strings.Split(strings.ReplaceAll(oauthFirstKeyMySQL, "@database@", "`"+target+"`"), "\n-- statement\n")
		for i, name := range procedures {
			if err := installMySQLOAuthRoutine(db, target, definer, name, strings.TrimSpace(statements[i])); err != nil {
				return err
			}
		}
		for _, table := range tables {
			if err := db.Exec("GRANT SELECT ON " + base + "`" + table + "` TO " + role).Error; err != nil {
				return errOAuthBootstrap
			}
		}
		for _, statement := range []string{
			"GRANT INSERT, SELECT (id,user_id,deleted_at) ON " + base + "`tokens`",
			"GRANT SELECT (id,status,auth_version,deleted_at) ON " + base + "`users`",
			"GRANT SELECT (sid,user_id,status,revoked_at,expires_at,version,user_auth_version) ON " + base + "`user_sessions`",
		} {
			if err := db.Exec(statement + " TO " + role).Error; err != nil {
				return errOAuthBootstrap
			}
		}
		for _, name := range append(procedures, "newapi_oauth_lock_sources") {
			if err := db.Exec("GRANT EXECUTE ON PROCEDURE " + base + "`" + name + "` TO " + role).Error; err != nil {
				return errOAuthBootstrap
			}
		}
		return nil
	default:
		return errOAuthBootstrap
	}
}

func oauthFirstKeyIssuerRestricted(db *gorm.DB, target string) bool {
	if db.Dialector.Name() == "mysql" {
		return mysqlFirstKeyIssuerGrants(db, target, "SHOW GRANTS", true)
	}
	var safe bool
	err := db.Raw(`SELECT EXISTS (SELECT FROM pg_catalog.pg_roles r
		WHERE r.rolname = current_user AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolbypassrls
		AND NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members WHERE member = r.oid)
		AND pg_catalog.has_function_privilege(r.oid,?, 'EXECUTE')
		AND pg_catalog.has_function_privilege(r.oid,?, 'EXECUTE')
		AND pg_catalog.has_table_privilege(r.oid,'public.tokens','INSERT')
		AND NOT pg_catalog.has_table_privilege(r.oid,'public.tokens','UPDATE,DELETE,TRUNCATE,TRIGGER')
		AND NOT pg_catalog.has_column_privilege(r.oid,'public.tokens','key','SELECT')
		AND NOT pg_catalog.has_column_privilege(r.oid,'public.users','access_token','SELECT')
		AND NOT pg_catalog.has_column_privilege(r.oid,'public.users','password','SELECT')
		AND NOT EXISTS (SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> 'tokens'
			AND (c.relowner = r.oid OR pg_catalog.has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
				OR pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE'))))`, issueGrantLock, issueComplete).Row().Scan(&safe)
	return err == nil && safe
}

func mysqlFirstKeyIssuerGrants(db *gorm.DB, target, query string, installed bool) bool {
	tables, err := issueReadTables(db)
	if err != nil {
		return false
	}
	var grants []string
	if err := db.Raw(query).Scan(&grants).Error; err != nil {
		return false
	}
	base := "`" + target + "`."
	allowed := map[string]string{
		"*.*":                    "GRANT USAGE",
		base + "`tokens`":        "GRANT SELECT (deleted_at, id, user_id), INSERT",
		base + "`users`":         "GRANT SELECT (auth_version, deleted_at, id, status)",
		base + "`user_sessions`": "GRANT SELECT (expires_at, revoked_at, sid, status, user_auth_version, user_id, version)",
		"PROCEDURE " + base + "`newapi_oauth_lock_issue_grant`": "GRANT EXECUTE",
		"PROCEDURE " + base + "`newapi_oauth_lock_sources`":     "GRANT EXECUTE",
		"PROCEDURE " + base + "`newapi_oauth_complete_issue`":   "GRANT EXECUTE",
	}
	for _, table := range tables {
		allowed[base+"`"+table+"`"] = "GRANT SELECT"
	}
	checked := make(map[string]bool, len(grants))
	for _, grant := range grants {
		privilege, object, ok := strings.Cut(grant, " ON ")
		object, _, qualified := strings.Cut(object, " TO ")
		privilege = strings.ReplaceAll(privilege, "`", "")
		if selection, hasColumns := strings.CutPrefix(privilege, "GRANT SELECT ("); hasColumns {
			columns, remaining, closed := strings.Cut(selection, ")")
			if !closed {
				return false
			}
			// MySQL 5.7 does not guarantee the column order in SHOW GRANTS.
			names := strings.Split(columns, ", ")
			slices.Sort(names)
			privilege = "GRANT SELECT (" + strings.Join(names, ", ") + ")" + remaining
		}
		if !ok || !qualified || strings.Contains(grant, "WITH GRANT OPTION") || allowed[object] != privilege {
			return false
		}
		checked[object] = true
	}
	return !installed || len(checked) == len(allowed)
}
