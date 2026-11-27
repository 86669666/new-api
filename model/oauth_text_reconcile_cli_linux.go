//go:build linux

package model

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// RunOAuthTextReconcile is an offline PostgreSQL administration entry. It
// obtains its authority from OS custody and never starts the gateway.
func RunOAuthTextReconcile(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("oauth-text-reconcile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	journalPath := flags.String("journal", "", "protected READY birth journal")
	ref := flags.String("ref", "", "single charge reference")
	approvalPath := flags.String("approval", "", "root-owned single-charge approval file")
	gateway := flags.String("gateway-role", "", "existing application database role")
	if len(args) == 0 || flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !validOAuthTextReconcileArgs(args[0], *ref, *approvalPath, *gateway) {
		fmt.Fprintln(out, "oauth-text-reconcile inspect|prepare|cancel-reserved --journal ... [--ref ...] [--gateway-role ...] [--approval ...]")
		return 2
	}
	if err := runOAuthTextReconcile(args[0], *journalPath, *ref, *approvalPath, *gateway, out); err != nil {
		fmt.Fprintln(out, "oauth-text-reconcile refused")
		return 1
	}
	return 0
}

func validOAuthTextReconcileArgs(mode, ref, approval, gateway string) bool {
	switch mode {
	case "inspect":
		return oauthDerivedDigest(ref) && approval == "" && gateway == ""
	case "prepare":
		return ref == "" && approval == "" && bootstrapName.MatchString(gateway)
	case "cancel-reserved":
		return oauthDerivedDigest(ref) && approval != "" && bootstrapName.MatchString(gateway)
	default:
		return false
	}
}

func runOAuthTextReconcile(mode, journalPath, ref, approvalPath, gateway string, out io.Writer) error {
	if os.Geteuid() != 0 {
		return ErrOAuthTextCharge
	}
	journal, err := readOAuthBirthJournal(journalPath, false)
	if err != nil || journal.Engine != "postgres" || journal.Phase != "READY" || !bootstrapName.MatchString(journal.Target) {
		return ErrOAuthTextCharge
	}
	var approval oauthTextCancellationApproval
	if mode == "cancel-reserved" {
		approval, err = readOAuthTextCancellationApproval(approvalPath)
		if err != nil || approval.Ref != ref || approval.DatabaseSeal != journal.HistorySeal {
			return ErrOAuthTextCharge
		}
	}

	dsn, endpoint, err := oauthBootstrapDSN("postgres", os.Getenv("OAUTH_TEXT_RECONCILE_DSN"), journal.Target)
	if err != nil || endpoint != journal.Endpoint {
		return ErrOAuthTextCharge
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return ErrOAuthTextCharge
	}
	q := u.Query()
	for key, values := range q {
		if (key != "host" && key != "port" && key != "sslmode") || len(values) != 1 {
			return ErrOAuthTextCharge
		}
	}
	if q.Get("sslmode") != "disable" || os.Getenv("PGSERVICE") != "" || os.Getenv("PGSERVICEFILE") != "" || os.Getenv("PGOPTIONS") != "" {
		return ErrOAuthTextCharge
	}
	pg, err := pgx.ParseConfig(dsn)
	if err != nil || pg.Host != q.Get("host") || pg.Database != journal.Target || pg.TLSConfig != nil || len(pg.Fallbacks) != 0 {
		return ErrOAuthTextCharge
	}
	port := q.Get("port")
	if port == "" {
		port = "5432"
	}
	if strconv.Itoa(int(pg.Port)) != port {
		return ErrOAuthTextCharge
	}
	pg.ConnectTimeout = 5 * time.Second
	pg.RuntimeParams = map[string]string{"search_path": "public"}
	conn := stdlib.OpenDB(*pg)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: conn, PreferSimpleProtocol: true}),
		&gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return ErrOAuthTextCharge
	}
	db = db.WithContext(ctx)
	old := common.MainDatabaseType()
	common.SetMainDatabaseType(common.DatabaseTypePostgreSQL)
	defer common.SetMainDatabaseType(old)
	if mode == "inspect" {
		return db.Transaction(func(tx *gorm.DB) error {
			if err := validateOAuthBirth(tx, journal, true); err != nil {
				return err
			}
			charge, err := readOAuthDerivedTextCharge(ctx, tx, ref)
			if err != nil {
				return err
			}
			return writeOAuthTextReconcileJSON(out, map[string]any{"ref": charge.Ref, "fingerprint": charge.Fingerprint,
				"version": charge.Version, "reserve": charge.Reserve, "state": charge.State, "actual": charge.Actual,
				"claim_at": charge.ClaimAt, "send_deadline": charge.SendDeadline, "database_seal": journal.HistorySeal})
		}, &sql.TxOptions{ReadOnly: true})
	}
	if err := validateOAuthBirth(db, journal, true); err != nil {
		return err
	}
	if mode == "prepare" {
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.AutoMigrate(&oauthTextCancellation{}); err != nil {
				return err
			}
			return checkOAuthTextCancellationStore(tx, gateway)
		})
		if err == nil {
			fmt.Fprintln(out, "oauth-text reconciliation store prepared")
		}
		return err
	}
	if err := checkOAuthTextCancellationStore(db, gateway); err != nil {
		return err
	}
	result, err := cancelReservedOAuthText(ctx, db, approval)
	if err != nil {
		return err
	}
	return writeOAuthTextReconcileJSON(out, result)
}

func writeOAuthTextReconcileJSON(out io.Writer, value any) error {
	raw, err := common.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(raw))
	return err
}

func checkOAuthTextCancellationStore(db *gorm.DB, gateway string) error {
	var safe bool
	err := db.Raw(`SELECT EXISTS (
		SELECT 1 FROM pg_catalog.pg_roles r, pg_catalog.pg_class c, pg_catalog.pg_database d, pg_catalog.pg_namespace n
		WHERE r.rolname = ? AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolbypassrls
		AND c.oid = to_regclass('public.oauth_text_cancellations') AND c.relkind = 'r'
		AND c.relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
		AND d.datname = current_database() AND n.oid = c.relnamespace
		AND NOT pg_catalog.pg_has_role(r.oid, c.relowner, 'MEMBER')
		AND NOT pg_catalog.pg_has_role(r.oid, d.datdba, 'MEMBER')
		AND NOT pg_catalog.pg_has_role(r.oid, n.nspowner, 'MEMBER')
		AND NOT EXISTS (
			SELECT 1 FROM pg_catalog.pg_roles reachable
			WHERE (reachable.oid = r.oid OR pg_catalog.pg_has_role(r.oid, reachable.oid, 'MEMBER'))
			AND (reachable.rolsuper OR reachable.rolcreaterole OR reachable.rolbypassrls
				OR reachable.rolname = 'pg_write_all_data'
				OR pg_catalog.has_table_privilege(reachable.oid, c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
				OR pg_catalog.has_any_column_privilege(reachable.oid, c.oid, 'INSERT,UPDATE'))))`, gateway).Row().Scan(&safe)
	if err != nil || !safe {
		return ErrOAuthTextCharge
	}
	return nil
}

func readOAuthTextCancellationApproval(path string) (oauthTextCancellationApproval, error) {
	var a oauthTextCancellationApproval
	if oauthProtectedPath(path, false) != nil {
		return a, ErrOAuthTextCharge
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return a, ErrOAuthTextCharge
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return a, ErrOAuthTextCharge
	}
	ownership, ok := info.Sys().(*syscall.Stat_t)
	if !ok || ownership.Uid != 0 || ownership.Nlink != 1 {
		return a, ErrOAuthTextCharge
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return a, ErrOAuthTextCharge
	}
	fields, err := common.DecodeRawJSONObject(raw)
	if err != nil || len(fields) != 9 {
		return a, ErrOAuthTextCharge
	}
	for _, key := range []string{"action", "database_seal", "ref", "fingerprint", "version", "reserve", "evidence_sha256", "approved_by", "executed_by"} {
		if _, ok := fields[key]; !ok {
			return a, ErrOAuthTextCharge
		}
	}
	if common.Unmarshal(raw, &a) != nil || !a.valid() {
		return a, ErrOAuthTextCharge
	}
	return a, nil
}
