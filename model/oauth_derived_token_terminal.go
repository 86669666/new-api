package model

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"gorm.io/gorm"
)

// These operations are installed only by the permanent, root-owned bootstrap
// CLI. They join the caller's transaction and never manufacture provenance.
// An uninstalled database retains its previous permission boundary; it is not
// upgraded by an ordinary gateway connection.
const oauthTerminalSchema = "newapi_terminal"

func oauthTerminalBodies(engine string) (string, string) {
	if engine == "postgres" {
		return `DECLARE v bigint; r text;
BEGIN
 IF p_user IS NULL OR p_user<=0 OR p_grant IS NULL OR p_grant !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'terminal operation refused'; END IF;
 SELECT id INTO STRICT v FROM public.users WHERE id=p_user FOR UPDATE;
 SELECT grant_ref INTO STRICT r FROM public.oauth_grants WHERE grant_ref=p_grant AND user_id=p_user FOR UPDATE;
 SELECT grant_ref INTO STRICT r FROM public.oauth_derived_token_sources WHERE grant_ref=p_grant AND user_id=p_user FOR UPDATE;
 RETURN 1;
END`, `DECLARE s public.oauth_derived_token_sources%ROWTYPE; t public.tokens%ROWTYPE; n bigint; g text;
BEGIN
 IF p_action NOT IN ('revoked','disabled','deleted') OR p_action IS NULL THEN RAISE EXCEPTION 'terminal operation refused'; END IF;
 PERFORM newapi_terminal.lock_v1(p_user,p_grant);
 SELECT * INTO STRICT s FROM public.oauth_derived_token_sources WHERE grant_ref=p_grant AND user_id=p_user;
 SELECT state INTO STRICT g FROM public.oauth_grants WHERE grant_ref=p_grant AND user_id=p_user;
 n := floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF s.schema_version<>1 OR s.verified_at>n OR s.verified_at<=0 OR (s.terminal_at IS NULL)<>(s.terminal_reason IS NULL) OR s.terminal_at>n OR (s.terminal_reason IS NOT NULL AND s.terminal_reason NOT IN ('revoked','disabled','deleted')) THEN RAISE EXCEPTION 'terminal operation refused'; END IF;
 IF p_action='revoked' AND g<>'revoked' THEN RAISE EXCEPTION 'terminal operation refused'; END IF;
 IF s.token_id IS NULL THEN
  IF p_action<>'revoked' OR s.key_ref IS NOT NULL OR s.idem_hash IS NOT NULL OR s.request_hash IS NOT NULL OR s.created_at IS NOT NULL THEN RAISE EXCEPTION 'terminal operation refused'; END IF;
 ELSE
  SELECT * INTO STRICT t FROM public.tokens WHERE id=s.token_id AND user_id=p_user FOR UPDATE;
  IF s.key_ref IS NULL OR s.idem_hash IS NULL OR s.request_hash IS NULL OR s.created_at IS NULL OR s.created_at>n OR t.unlimited_quota OR t.expired_time<=0 OR t.remain_quota::numeric+t.used_quota::numeric<>s.quota_limit THEN RAISE EXCEPTION 'terminal operation refused'; END IF;
 END IF;
 IF s.terminal_at IS NULL OR (p_action='deleted' AND s.terminal_reason<>'deleted') THEN
  UPDATE public.oauth_derived_token_sources SET terminal_at=n,terminal_reason=p_action WHERE grant_ref=p_grant AND user_id=p_user;
 END IF;
 IF s.token_id IS NOT NULL THEN UPDATE public.tokens SET status=2 WHERE id=s.token_id AND user_id=p_user; END IF;
 RETURN 1;
END`
	}
	return `BEGIN
 DECLARE v BIGINT;
 DECLARE r CHAR(64);
 DECLARE EXIT HANDLER FOR NOT FOUND SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='terminal operation refused';
 IF p_user IS NULL OR p_user<=0 OR p_grant IS NULL OR CHAR_LENGTH(p_grant)<>64 OR UNHEX(p_grant) IS NULL OR BINARY p_grant<>BINARY LOWER(HEX(UNHEX(p_grant))) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='terminal operation refused'; END IF;
 SELECT id INTO v FROM users WHERE id=p_user FOR UPDATE;
 SELECT grant_ref INTO r FROM oauth_grants WHERE grant_ref=p_grant AND user_id=p_user FOR UPDATE;
 SELECT grant_ref INTO r FROM oauth_derived_token_sources WHERE grant_ref=p_grant AND user_id=p_user FOR UPDATE;
 RETURN 1;
END`, `BEGIN
 DECLARE v BIGINT;
 DECLARE tid BIGINT;
 DECLARE created BIGINT;
 DECLARE verified BIGINT;
 DECLARE ended BIGINT;
 DECLARE why VARCHAR(32);
 DECLARE kr CHAR(64);
 DECLARE ih CHAR(64);
 DECLARE rh CHAR(64);
 DECLARE lim BIGINT;
 DECLARE ver INT;
 DECLARE n BIGINT;
 DECLARE g VARCHAR(32);
 DECLARE unlimited_flag BOOLEAN;
 DECLARE expiry BIGINT;
 DECLARE remaining BIGINT;
 DECLARE used BIGINT;
 DECLARE EXIT HANDLER FOR NOT FOUND SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='terminal operation refused';
 IF p_action IS NULL OR BINARY p_action NOT IN ('revoked','disabled','deleted') THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='terminal operation refused'; END IF;
 SET v=nat_lock_v1(p_user,p_grant);
 SELECT token_id,created_at,verified_at,terminal_at,terminal_reason,key_ref,idem_hash,request_hash,quota_limit,schema_version INTO tid,created,verified,ended,why,kr,ih,rh,lim,ver FROM oauth_derived_token_sources WHERE grant_ref=p_grant AND user_id=p_user;
 SELECT state INTO g FROM oauth_grants WHERE grant_ref=p_grant AND user_id=p_user;
 SET n=UNIX_TIMESTAMP();
 IF ver<>1 OR verified>n OR verified<=0 OR (ended IS NULL)<>(why IS NULL) OR ended>n OR (why IS NOT NULL AND BINARY why NOT IN ('revoked','disabled','deleted')) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='terminal operation refused'; END IF;
 IF p_action='revoked' AND BINARY g<>'revoked' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='terminal operation refused'; END IF;
 IF tid IS NULL THEN
  IF p_action<>'revoked' OR kr IS NOT NULL OR ih IS NOT NULL OR rh IS NOT NULL OR created IS NOT NULL THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='terminal operation refused'; END IF;
 ELSE
  SELECT unlimited_quota,expired_time,remain_quota,used_quota INTO unlimited_flag,expiry,remaining,used FROM tokens WHERE id=tid AND user_id=p_user FOR UPDATE;
  IF kr IS NULL OR ih IS NULL OR rh IS NULL OR created IS NULL OR created>n OR unlimited_flag OR expiry<=0 OR CAST(remaining AS DECIMAL(30,0))+CAST(used AS DECIMAL(30,0))<>lim THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='terminal operation refused'; END IF;
 END IF;
 IF ended IS NULL OR (p_action='deleted' AND why<>'deleted') THEN
  UPDATE oauth_derived_token_sources SET terminal_at=n,terminal_reason=p_action WHERE grant_ref=p_grant AND user_id=p_user;
 END IF;
 IF tid IS NOT NULL THEN UPDATE tokens SET status=2 WHERE id=tid AND user_id=p_user; END IF;
 RETURN 1;
END`
}

func oauthTerminalDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Function source is catalog data, never an error string or caller assertion.
// PostgreSQL catalogs expose definitions to an EXECUTE-only principal. MySQL's
// fixed definer attestor reads only these two routines' definitions.
func oauthTerminalInstalled(tx *gorm.DB) (bool, error) {
	engine := tx.Dialector.Name()
	if engine != "postgres" && engine != "mysql" {
		return false, nil
	}
	lockBody, applyBody := oauthTerminalBodies(engine)
	if engine == "postgres" {
		var rows []struct {
			Name, Body, Owner                     string
			Definer                               bool
			Config, Args, Language                string
			ReturnType                            int
			OwnerUnsafe, PublicExecute, Grantable bool
		}
		err := tx.Raw(`SELECT p.proname AS name,p.prosrc AS body,r.rolname AS owner,p.prosecdef AS definer,array_to_string(p.proconfig,',') AS config, p.proargtypes::text AS args, p.prorettype AS return_type, l.lanname AS language,
(r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls) AS owner_unsafe,
EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,
EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner AND a.is_grantable) AS grantable
FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid=p.proowner JOIN pg_catalog.pg_language l ON l.oid=p.prolang
WHERE n.nspname='newapi_terminal' ORDER BY p.proname`).Scan(&rows).Error
		if err != nil {
			return false, ErrOAuthDerivedTokenUnknown
		}
		if len(rows) == 0 {
			return false, nil
		}
		if len(rows) != 2 {
			return false, ErrOAuthDerivedTokenUnknown
		}
		var identity OAuthDerivedTokenBootstrapIdentity
		if tx.Where("id = ? AND version = ?", 1, 1).First(&identity).Error != nil || !oauthDerivedDigest(identity.NamespaceBindingHash) {
			return false, ErrOAuthDerivedTokenUnknown
		}
		expectedOwner := "nat_" + oauthTerminalDigest(identity.NamespaceBindingHash)[:24]
		for _, row := range rows {
			args := "20 25"
			expected := lockBody
			if row.Name == "apply_v1" {
				expected = applyBody
				args = "20 25 25"
			} else if row.Name != "lock_v1" {
				return false, ErrOAuthDerivedTokenUnknown
			}
			if row.Body != expected || !row.Definer || row.Config != "search_path=pg_catalog, pg_temp" || row.Owner != expectedOwner || row.OwnerUnsafe || row.PublicExecute || row.Grantable || row.Args != args || row.ReturnType != 23 || row.Language != "plpgsql" {
				return false, ErrOAuthDerivedTokenUnknown
			}
		}
		return true, nil
	}
	var identity OAuthDerivedTokenBootstrapIdentity
	if tx.Where("id = ? AND version = ?", 1, 1).First(&identity).Error != nil || !oauthDerivedDigest(identity.NamespaceBindingHash) {
		return false, ErrOAuthDerivedTokenUnknown
	}
	owner := "nat_" + oauthTerminalDigest(identity.NamespaceBindingHash)[:24] + "@localhost"
	var routines []struct{ Name, Owner, Security, Access, Kind string }
	if tx.Raw("SELECT ROUTINE_NAME AS name,DEFINER AS owner,SECURITY_TYPE AS security,SQL_DATA_ACCESS AS access,ROUTINE_TYPE AS kind FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME IN ('nat_lock_v1','nat_apply_v1','nat_attest_v1')").Scan(&routines).Error != nil {
		return false, ErrOAuthDerivedTokenUnknown
	}
	if len(routines) == 0 {
		return false, nil
	}
	if len(routines) != 3 {
		return false, ErrOAuthDerivedTokenUnknown
	}
	for _, routine := range routines {
		access := "MODIFIES SQL DATA"
		if routine.Name == "nat_attest_v1" {
			access = "READS SQL DATA"
		}
		if routine.Owner != owner || routine.Security != "DEFINER" || routine.Kind != "FUNCTION" || routine.Access != access {
			return false, ErrOAuthDerivedTokenUnknown
		}
	}
	var got string
	if tx.Raw("SELECT nat_attest_v1()").Scan(&got).Error != nil || got != oauthTerminalDigest(lockBody)+":"+oauthTerminalDigest(applyBody)+":"+oauthTerminalDigest(oauthMySQLTerminalAttestation()) {
		return false, ErrOAuthDerivedTokenUnknown
	}
	return true, nil
}

// The installer independently verifies this exact body. At runtime it is a
// trusted, immutable definer object; a database owner remains a trust principal,
// not an adversary that a function can authenticate through its own return value.
func oauthMySQLTerminalAttestation() string {
	return `BEGIN
 DECLARE a LONGTEXT;
 DECLARE b LONGTEXT;
 DECLARE c LONGTEXT;
 SELECT ROUTINE_DEFINITION INTO a FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME='nat_lock_v1' AND SECURITY_TYPE='DEFINER';
 SELECT ROUTINE_DEFINITION INTO b FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME='nat_apply_v1' AND SECURITY_TYPE='DEFINER';
 SELECT ROUTINE_DEFINITION INTO c FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME='nat_attest_v1' AND SECURITY_TYPE='DEFINER';
 RETURN CONCAT(SHA2(a,256),':',SHA2(b,256),':',SHA2(c,256));
END`
}

func oauthTerminalTransaction(tx *gorm.DB) bool {
	if tx == nil || tx.Statement == nil {
		return false
	}
	pool := tx.Statement.ConnPool
	if prepared, ok := pool.(*gorm.PreparedStmtTX); ok && prepared != nil {
		pool = prepared.Tx
	}
	transaction, ok := pool.(*sql.Tx)
	return ok && transaction != nil
}

func lockOAuthTerminalSource(tx *gorm.DB, userID int, grantRef string) (bool, error) {
	if tx != nil && tx.Dialector.Name() == "sqlite" {
		return false, nil
	}
	if !oauthTerminalTransaction(tx) || userID <= 0 || !oauthDerivedDigest(grantRef) {
		return false, ErrOAuthDerivedTokenUnknown
	}
	installed, err := oauthTerminalInstalled(tx)
	if err != nil {
		return false, err
	}
	if !installed {
		return false, nil
	}
	statement := "SELECT newapi_terminal.lock_v1(?,?)"
	if tx.Dialector.Name() == "mysql" {
		statement = "SELECT nat_lock_v1(?,?)"
	}
	if tx.Exec(statement, userID, grantRef).Error != nil {
		return true, ErrOAuthDerivedTokenUnknown
	}
	return true, nil
}

func applyOAuthTerminal(tx *gorm.DB, source *OAuthDerivedTokenSource, action string) (bool, error) {
	if tx != nil && tx.Dialector.Name() == "sqlite" {
		return false, nil
	}
	if !oauthTerminalTransaction(tx) {
		return false, ErrOAuthDerivedTokenUnknown
	}
	installed, err := oauthTerminalInstalled(tx)
	if err != nil || !installed {
		return installed, err
	}
	if source == nil || source.UserID <= 0 || !oauthDerivedDigest(source.GrantRef) || (action != "revoked" && action != "disabled" && action != "deleted") {
		return true, ErrOAuthDerivedTokenUnknown
	}
	statement := "SELECT newapi_terminal.apply_v1(?,?,?)"
	args := []any{source.UserID, source.GrantRef, action}
	operation := tx
	if tx.Dialector.Name() == "mysql" {
		// MySQL's prepared invocation can check the invoker's table privileges
		// for this modifying definer function. Use the text protocol for this
		// fixed operation only: a positive integer, canonical hex digest and
		// one of three literal actions, never caller-controlled SQL or quoting.
		statement = fmt.Sprintf("SELECT nat_apply_v1(%d,'%s','%s')", source.UserID, source.GrantRef, action)
		args = nil
		operation = tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		if prepared, ok := operation.Statement.ConnPool.(*gorm.PreparedStmtTX); ok {
			// Reuse the same outer transaction; do not open another connection
			// or let GORM prepare this deliberately parameter-free statement.
			operation.Statement.ConnPool = prepared.Tx
		}
	}
	if operation.Exec(statement, args...).Error != nil {
		return true, ErrOAuthDerivedTokenUnknown
	}
	if tx.Where("grant_ref = ? AND user_id = ?", source.GrantRef, source.UserID).First(source).Error != nil {
		return true, ErrOAuthDerivedTokenUnknown
	}
	return true, nil
}

// prepareOAuthTerminalStores runs only after the permanent installer has
// verified the existing READY birth and acquired its protected namespace lock.
// Missing optional OAuth stores use their existing model migration definitions;
// existing stores are never altered here. MySQL DDL can commit independently:
// an interrupted preparation is resumable, but grants and executable capability
// are withheld until all stores pass the normal read-only startup validation.
func prepareOAuthTerminalStores(db *gorm.DB, out io.Writer) error {
	engine := db.Dialector.Name()
	if os.Geteuid() != 0 || (engine != "postgres" && engine != "mysql") {
		return errOAuthBootstrap
	}
	models := []any{&OAuthGrant{}, &OAuthOperation{}, &OAuthArtifact{}, &OAuthCleanupJob{}}
	tables := []string{"oauth_grants", "o_auth_operations", "o_auth_artifacts", "o_auth_cleanup_jobs"}
	present := make([]bool, len(tables))
	for i, table := range tables {
		var count int64
		query := "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=? AND table_type='BASE TABLE'"
		if engine == "postgres" {
			query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=? AND table_type='BASE TABLE'"
		}
		if db.Raw(query, table).Scan(&count).Error != nil || count > 1 {
			return errOAuthBootstrap
		}
		present[i] = count == 1
	}
	facts := make(map[string]bool, len(tables))
	for i, table := range tables {
		facts[table] = present[i]
	}
	encoded, err := common.Marshal(struct {
		Prerequisites map[string]bool `json:"terminal_prerequisites_before"`
	}{facts})
	if err != nil {
		return errOAuthBootstrap
	}
	if _, err = fmt.Fprintln(out, string(encoded)); err != nil {
		return errOAuthBootstrap
	}
	for i, value := range models {
		if !present[i] && db.AutoMigrate(value) != nil {
			return errOAuthBootstrap
		}
	}
	// Reuse the formal schema/uniqueness validators with migrations disabled.
	// This is the offline CLI process, never a gateway initialization path.
	oldDB, oldMaster, oldCleanup := DB, common.IsMasterNode, oauthCleanupDB.Load()
	DB, common.IsMasterNode = db, false
	defer func() { DB, common.IsMasterNode = oldDB, oldMaster; oauthCleanupDB.Store(oldCleanup) }()
	if InitOAuthGrantStore(true) != nil {
		return errOAuthBootstrap
	}
	return nil
}

// installOAuthTerminal is an offline migration of executable objects, not a
// new birth. The caller already holds the protected journal/namespace locks
// and has validated the original READY journal against this exact database.
func installOAuthTerminal(db *gorm.DB, j *oauthBirthJournal) error {
	engine := db.Dialector.Name()
	role := os.Getenv("BOOTSTRAP_TERMINAL_ROLE")
	if (engine != "postgres" && engine != "mysql") || !bootstrapName.MatchString(role) {
		return errOAuthBootstrap
	}
	lockBody, applyBody := oauthTerminalBodies(engine)
	owner := "nat_" + oauthTerminalDigest(j.Binding)[:24]
	if engine == "postgres" {
		installed, err := oauthTerminalInstalled(db)
		if err != nil {
			return err
		}
		if installed {
			return verifyOAuthTerminalPrincipal(db, role, owner)
		}
		return db.Transaction(func(tx *gorm.DB) error {
			var count int64
			if tx.Raw("SELECT COUNT(*) FROM pg_roles WHERE rolname=?", owner).Scan(&count).Error != nil || count != 0 {
				return errOAuthBootstrap
			}
			statements := []string{
				"CREATE ROLE " + owner + " NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
				"CREATE SCHEMA newapi_terminal",
				"REVOKE ALL ON SCHEMA newapi_terminal FROM PUBLIC",
				"GRANT USAGE ON SCHEMA public,newapi_terminal TO " + owner,
				"GRANT SELECT ON public.users,public.oauth_grants,public.tokens,public.oauth_derived_token_sources TO " + owner,
				"GRANT UPDATE(auth_version) ON public.users TO " + owner,
				"GRANT UPDATE(revision) ON public.oauth_grants TO " + owner,
				"GRANT UPDATE(status) ON public.tokens TO " + owner,
				"GRANT UPDATE(terminal_at,terminal_reason) ON public.oauth_derived_token_sources TO " + owner,
				"CREATE FUNCTION newapi_terminal.lock_v1(p_user bigint,p_grant text) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$" + lockBody + "$body$",
				"CREATE FUNCTION newapi_terminal.apply_v1(p_user bigint,p_grant text,p_action text) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$" + applyBody + "$body$",
				"ALTER FUNCTION newapi_terminal.lock_v1(bigint,text) OWNER TO " + owner,
				"ALTER FUNCTION newapi_terminal.apply_v1(bigint,text,text) OWNER TO " + owner,
				"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA newapi_terminal FROM PUBLIC",
				"GRANT USAGE ON SCHEMA newapi_terminal TO " + role,
				"GRANT EXECUTE ON FUNCTION newapi_terminal.lock_v1(bigint,text),newapi_terminal.apply_v1(bigint,text,text) TO " + role,
			}
			for _, s := range statements {
				if tx.Exec(s).Error != nil {
					return errOAuthBootstrap
				}
			}
			return verifyOAuthTerminalPrincipal(tx, role, owner)
		})
	}
	// Fixed account/host and validated database identifiers only. No credentials
	// are generated, printed or granted to the gateway; the definer is locked.
	var database string
	if db.Raw("SELECT DATABASE()").Scan(&database).Error != nil || !bootstrapName.MatchString(database) {
		return errOAuthBootstrap
	}
	principal := "'" + owner + "'@'localhost'"
	service := "'" + role + "'@'localhost'"
	// MySQL DDL implicitly commits. Reentry accepts only the birth-bound
	// locked principal and exact already-created objects; collisions, extra
	// privileges and altered definitions fail before any grant or replacement.
	var existing int64
	if db.Raw("SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='localhost'", owner).Scan(&existing).Error != nil || existing > 1 {
		return errOAuthBootstrap
	}
	if verifyOAuthTerminalPrincipal(db, role, owner) != nil {
		return errOAuthBootstrap
	}
	if existing == 1 && verifyOAuthTerminalDefiner(db, database, owner) != nil {
		return errOAuthBootstrap
	}
	bodies := map[string]string{"nat_lock_v1": lockBody, "nat_apply_v1": applyBody, "nat_attest_v1": oauthMySQLTerminalAttestation()}
	var objects []struct{ Name, Body, Owner, Security, Kind string }
	if db.Raw("SELECT ROUTINE_NAME AS name,ROUTINE_DEFINITION AS body,DEFINER AS owner,SECURITY_TYPE AS security,ROUTINE_TYPE AS kind FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME IN ('nat_lock_v1','nat_apply_v1','nat_attest_v1')").Scan(&objects).Error != nil {
		return errOAuthBootstrap
	}
	created := make(map[string]bool, len(objects))
	for _, object := range objects {
		if existing != 1 || object.Body != bodies[object.Name] || object.Owner != owner+"@localhost" || object.Security != "DEFINER" || object.Kind != "FUNCTION" || created[object.Name] {
			return errOAuthBootstrap
		}
		created[object.Name] = true
	}
	attest := oauthMySQLTerminalAttestation()
	statements := []string{
		"GRANT SELECT,UPDATE(auth_version) ON `" + database + "`.users TO " + principal,
		"GRANT SELECT,UPDATE(revision) ON `" + database + "`.oauth_grants TO " + principal,
		"GRANT SELECT,UPDATE(status) ON `" + database + "`.tokens TO " + principal,
		"GRANT SELECT,UPDATE(terminal_at,terminal_reason) ON `" + database + "`.oauth_derived_token_sources TO " + principal,
		"CREATE DEFINER=" + principal + " FUNCTION nat_lock_v1(p_user BIGINT,p_grant CHAR(64)) RETURNS INT SQL SECURITY DEFINER MODIFIES SQL DATA " + lockBody,
		"CREATE DEFINER=" + principal + " FUNCTION nat_apply_v1(p_user BIGINT,p_grant CHAR(64),p_action VARCHAR(32)) RETURNS INT SQL SECURITY DEFINER MODIFIES SQL DATA " + applyBody,
		"CREATE DEFINER=" + principal + " FUNCTION nat_attest_v1() RETURNS VARCHAR(194) SQL SECURITY DEFINER READS SQL DATA " + attest,
		"GRANT EXECUTE ON FUNCTION `" + database + "`.nat_lock_v1 TO " + principal,
		"GRANT EXECUTE ON FUNCTION `" + database + "`.nat_apply_v1 TO " + principal,
		"GRANT EXECUTE ON FUNCTION `" + database + "`.nat_attest_v1 TO " + principal,
	}
	for _, name := range []string{"nat_lock_v1", "nat_apply_v1", "nat_attest_v1"} {
		statements = append(statements, "GRANT EXECUTE ON FUNCTION `"+database+"`."+name+" TO "+service)
	}
	if existing == 0 && db.Exec("CREATE USER "+principal+" ACCOUNT LOCK").Error != nil {
		return errOAuthBootstrap
	}
	for _, statement := range statements {
		skip := false
		for name := range created {
			if strings.HasPrefix(statement, "CREATE DEFINER="+principal+" FUNCTION "+name+"(") {
				skip = true
			}
		}
		if !skip && db.Exec(statement).Error != nil {
			return errOAuthBootstrap
		}
	}
	if verifyOAuthTerminalDefiner(db, database, owner) != nil {
		return errOAuthBootstrap
	}
	if ok, err := oauthTerminalInstalled(db); err != nil || !ok {
		return errOAuthBootstrap
	}
	return verifyOAuthTerminalPrincipal(db, role, owner)
}

// This is installer-only inspection of effective direct grants. It accepts a
// subset during interrupted installation, never a broader account or role.
func verifyOAuthTerminalDefiner(db *gorm.DB, database, owner string) error {
	var locked string
	if db.Raw("SELECT account_locked FROM mysql.user WHERE User=? AND Host='localhost'", owner).Scan(&locked).Error != nil || locked != "Y" {
		return errOAuthBootstrap
	}
	grantee := "'" + owner + "'@'localhost'"
	var count int64
	for _, query := range []string{
		"SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=? AND PRIVILEGE_TYPE<>'USAGE'",
		"SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=?",
	} {
		if db.Raw(query, grantee).Scan(&count).Error != nil || count != 0 {
			return errOAuthBootstrap
		}
	}
	var grants []struct{ Schema, Table, Column, Privilege, Grantable string }
	if db.Raw("SELECT TABLE_SCHEMA AS `schema`,TABLE_NAME AS `table`,'' AS `column`,PRIVILEGE_TYPE AS privilege,IS_GRANTABLE AS grantable FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=? UNION ALL SELECT TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE=?", grantee, grantee).Scan(&grants).Error != nil {
		return errOAuthBootstrap
	}
	columns := map[string][]string{"users": {"auth_version"}, "oauth_grants": {"revision"}, "tokens": {"status"}, "oauth_derived_token_sources": {"terminal_at", "terminal_reason"}}
	for _, grant := range grants {
		allowed, known := columns[grant.Table]
		if grant.Schema != database || !known || grant.Grantable != "NO" || (grant.Column == "" && grant.Privilege != "SELECT") || (grant.Column != "" && (grant.Privilege != "UPDATE" || !slices.Contains(allowed, grant.Column))) {
			return errOAuthBootstrap
		}
	}
	if db.Raw("SELECT COUNT(*) FROM mysql.procs_priv WHERE User=? AND Host='localhost' AND (Db<>? OR Routine_type<>'FUNCTION' OR Routine_name NOT IN ('nat_lock_v1','nat_apply_v1','nat_attest_v1') OR Proc_priv<>'Execute')", owner, database).Scan(&count).Error != nil || count != 0 {
		return errOAuthBootstrap
	}
	rows, err := db.Raw("SHOW GRANTS FOR '" + owner + "'@'localhost'").Rows()
	if err != nil {
		return errOAuthBootstrap
	}
	defer rows.Close()
	for rows.Next() {
		var grant string
		if rows.Scan(&grant) != nil || !strings.HasPrefix(grant, "GRANT ") || !strings.Contains(grant, " ON ") || strings.Contains(grant, " WITH GRANT OPTION") {
			return errOAuthBootstrap
		}
	}
	if rows.Err() != nil {
		return errOAuthBootstrap
	}
	return nil
}

func verifyOAuthTerminalPrincipal(db *gorm.DB, role, owner string) error {
	if db.Dialector.Name() == "postgres" {
		var forbidden bool
		err := db.Raw(`SELECT r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
 OR pg_has_role(r.oid,?,'MEMBER') OR has_any_column_privilege(r.oid,'public.oauth_derived_token_sources','UPDATE')
 OR has_table_privilege(r.oid,'public.oauth_derived_token_sources','INSERT,DELETE,TRUNCATE,TRIGGER')
 OR has_schema_privilege(r.oid,'newapi_terminal','CREATE') AS forbidden FROM pg_roles r WHERE r.rolname=?`, owner, role).Scan(&forbidden).Error
		if err != nil || forbidden {
			return errOAuthBootstrap
		}
		var count int64
		if db.Raw("SELECT COUNT(*) FROM pg_roles WHERE rolname=? AND rolcanlogin AND NOT rolsuper", role).Scan(&count).Error != nil || count != 1 {
			return errOAuthBootstrap
		}
		return nil
	}
	var count int64
	if db.Raw("SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='localhost' AND Super_priv='N' AND Grant_priv='N' AND Create_user_priv='N'", role).Scan(&count).Error != nil || count != 1 {
		return errOAuthBootstrap
	}
	// SHOW GRANTS is installer-only. Fail rather than accept a broad database or
	// global grant. A future privilege change requires renewed qualification.
	var grants []string
	rows, err := db.Raw("SHOW GRANTS FOR '" + role + "'@'localhost'").Rows()
	if err != nil {
		return errOAuthBootstrap
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if rows.Scan(&s) != nil {
			return errOAuthBootstrap
		}
		grants = append(grants, s)
	}
	if rows.Err() != nil {
		return errOAuthBootstrap
	}
	for _, s := range grants {
		if !strings.HasPrefix(s, "GRANT ") || !strings.Contains(s, " ON ") || strings.Contains(s, " WITH GRANT OPTION") {
			return errOAuthBootstrap
		}
		if strings.Contains(s, " ON *.*") && !strings.HasPrefix(s, "GRANT USAGE ON") || strings.Contains(s, ".* TO") && !strings.Contains(s, " ON *.*") || strings.Contains(s, "oauth_derived_token_sources") && !strings.HasPrefix(s, "GRANT SELECT ON") {
			return errOAuthBootstrap
		}
	}
	if len(grants) == 0 {
		return fmt.Errorf("%w", errOAuthBootstrap)
	}
	return nil
}
