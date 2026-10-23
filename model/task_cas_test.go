package model

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestMain(m *testing.M) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic("failed to open test db: " + err.Error())
	}
	DB = db
	LOG_DB = db

	common.SetDatabaseTypes(common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	common.BatchUpdateEnabled = false
	common.LogConsumeEnabled = true
	initCol()

	sqlDB, err := db.DB()
	if err != nil {
		panic("failed to get sql.DB: " + err.Error())
	}
	sqlDB.SetMaxOpenConns(1)

	if err := db.AutoMigrate(
		&Task{},
		&User{},
		&Organization{},
		&OrganizationMember{},
		&OrganizationInvitation{},
		&OrganizationOwnershipTransfer{},
		&OrganizationEvent{},
		&UserSession{},
		&SessionRevocationEvent{},
		&AuthFlow{},
		&ExternalIdentityClaim{},
		&Token{},
		&PasskeyCredential{},
		&TwoFA{},
		&TwoFABackupCode{},
		&Log{},
		&Channel{},
		&QuotaData{},
		&Ability{},
		&TopUp{},
		&SubscriptionPlan{},
		&SubscriptionOrder{},
		&UserSubscription{},
		&UserOAuthBinding{},
		&PerfMetric{},
		&SystemInstance{},
		&SystemTask{},
		&SystemTaskLock{},
		&UserAccessToken{},
	); err != nil {
		panic("failed to migrate: " + err.Error())
	}

	os.Exit(m.Run())
}

func truncateTables(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		DB.Exec("DELETE FROM tasks")
		DB.Exec("DELETE FROM auth_flows")
		DB.Exec("DELETE FROM external_identity_claims")
		DB.Exec("DELETE FROM user_sessions")
		DB.Exec("DELETE FROM session_revocation_events")
		DB.Exec("DELETE FROM passkey_credentials")
		DB.Exec("DELETE FROM two_fa_backup_codes")
		DB.Exec("DELETE FROM two_fas")
		DB.Exec("DELETE FROM tokens")
		DB.Exec("DELETE FROM user_access_tokens")
		DB.Exec("DELETE FROM user_oauth_bindings")
		DB.Exec("DELETE FROM users")
		DB.Exec("DELETE FROM logs")
		DB.Exec("DELETE FROM channels")
		DB.Exec("DELETE FROM quota_data")
		DB.Exec("DELETE FROM abilities")
		DB.Exec("DELETE FROM top_ups")
		DB.Exec("DELETE FROM subscription_orders")
		DB.Exec("DELETE FROM subscription_plans")
		DB.Exec("DELETE FROM user_subscriptions")
		DB.Exec("DELETE FROM perf_metrics")
		DB.Exec("DELETE FROM system_instances")
		DB.Exec("DELETE FROM system_task_locks")
		DB.Exec("DELETE FROM system_tasks")
	})
}

func insertTask(t *testing.T, task *Task) {
	t.Helper()
	task.CreatedAt = time.Now().Unix()
	task.UpdatedAt = time.Now().Unix()
	require.NoError(t, DB.Create(task).Error)
}

func TestGetTaskForProtocolObservationScopesOwnerAndPlatform(t *testing.T) {
	truncateTables(t)
	task := &Task{
		TaskID:   "task_protocol_scope",
		UserId:   7,
		Platform: "plugin-a",
		Status:   TaskStatusInProgress,
	}
	insertTask(t, task)

	got, exists, err := GetTaskForProtocolObservation(context.Background(), 7, "plugin-a", task.TaskID)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, task.ID, got.ID)

	for _, query := range []struct {
		userID   int
		platform string
	}{
		{userID: 8, platform: "plugin-a"},
		{userID: 7, platform: "plugin-b"},
	} {
		got, exists, err = GetTaskForProtocolObservation(context.Background(), query.userID, constant.TaskPlatform(query.platform), task.TaskID)
		require.NoError(t, err)
		assert.False(t, exists)
		assert.Nil(t, got)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = GetTaskForProtocolObservation(cancelled, 7, "plugin-a", task.TaskID)
	require.ErrorIs(t, err, context.Canceled)
}

func TestPersonalTaskLookupsNeverResolveOrganizationRows(t *testing.T) {
	truncateTables(t)
	personal := &Task{TaskID: "task_personal_scope", UserId: 7, Platform: "plugin-a", Status: TaskStatusInProgress}
	organization := &Task{TaskID: "task_org_scope", UserId: 7, OrganizationID: 9007199254740993, Platform: "plugin-a", Status: TaskStatusInProgress}
	sharedPersonal := &Task{TaskID: "task_shared_scope", UserId: 7, Platform: "plugin-a", Status: TaskStatusInProgress}
	sharedOrganization := &Task{TaskID: "task_shared_scope", UserId: 8, OrganizationID: 9007199254740993, Platform: "plugin-a", Status: TaskStatusInProgress}
	for _, task := range []*Task{personal, organization, sharedPersonal, sharedOrganization} {
		insertTask(t, task)
	}

	listed := TaskGetAllUserTask(7, 0, 10, SyncTaskQueryParams{})
	ids := make([]int64, 0, len(listed))
	for _, task := range listed {
		ids = append(ids, task.ID)
	}
	assert.ElementsMatch(t, []int64{personal.ID, sharedPersonal.ID}, ids)
	assert.EqualValues(t, 2, TaskCountAllUserTask(7, SyncTaskQueryParams{}))
	assert.EqualValues(t, 0, TaskCountAllUserTask(7, SyncTaskQueryParams{TaskID: organization.TaskID}))

	_, exists, err := GetByTaskId(7, organization.TaskID)
	require.NoError(t, err)
	assert.False(t, exists)
	got, exists, err := GetByTaskId(7, personal.TaskID)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, personal.ID, got.ID)

	batch, err := GetByTaskIdsForPlatforms(7, []constant.TaskPlatform{"plugin-a"}, []string{personal.TaskID, organization.TaskID})
	require.NoError(t, err)
	require.Len(t, batch, 1)
	assert.Equal(t, personal.ID, batch[0].ID)

	_, exists, err = GetTaskForProtocolObservation(context.Background(), 7, "plugin-a", organization.TaskID)
	require.NoError(t, err)
	assert.False(t, exists)

	// Platform administrators keep personal artifact access only.
	_, exists, err = GetByOnlyTaskId(organization.TaskID)
	require.NoError(t, err)
	assert.False(t, exists)
	got, exists, err = GetByOnlyTaskId(personal.TaskID)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, personal.ID, got.ID)

	// Capability uniqueness still spans every owner before the organization check.
	for _, taskID := range []string{organization.TaskID, sharedPersonal.TaskID} {
		_, exists, err = GetUniqueByOnlyTaskId(taskID)
		require.NoError(t, err)
		assert.False(t, exists, taskID)
	}
	got, exists, err = GetUniqueByOnlyTaskId(personal.TaskID)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, personal.ID, got.ID)

	var stored Task
	require.NoError(t, DB.First(&stored, organization.ID).Error)
	stored.Progress = "50%"
	won, err := stored.UpdateWithStatus(TaskStatusInProgress)
	require.NoError(t, err)
	require.True(t, won)
	var reloaded Task
	require.NoError(t, DB.First(&reloaded, organization.ID).Error)
	assert.Equal(t, organization.OrganizationID, reloaded.OrganizationID)
	assert.Equal(t, "50%", reloaded.Progress)
}

// ---------------------------------------------------------------------------
// Snapshot / Equal — pure logic tests (no DB)
// ---------------------------------------------------------------------------

func TestSnapshotEqual_Same(t *testing.T) {
	s := taskSnapshot{
		Status:     TaskStatusInProgress,
		Progress:   "50%",
		StartTime:  1000,
		FinishTime: 0,
		FailReason: "",
		ResultURL:  "",
		Data:       json.RawMessage(`{"key":"value"}`),
	}
	assert.True(t, s.Equal(s))
}

func TestSnapshotEqual_DifferentStatus(t *testing.T) {
	a := taskSnapshot{Status: TaskStatusInProgress, Data: json.RawMessage(`{}`)}
	b := taskSnapshot{Status: TaskStatusSuccess, Data: json.RawMessage(`{}`)}
	assert.False(t, a.Equal(b))
}

func TestSnapshotEqual_DifferentProgress(t *testing.T) {
	a := taskSnapshot{Status: TaskStatusInProgress, Progress: "30%", Data: json.RawMessage(`{}`)}
	b := taskSnapshot{Status: TaskStatusInProgress, Progress: "60%", Data: json.RawMessage(`{}`)}
	assert.False(t, a.Equal(b))
}

func TestSnapshotEqual_DifferentData(t *testing.T) {
	a := taskSnapshot{Status: TaskStatusInProgress, Data: json.RawMessage(`{"a":1}`)}
	b := taskSnapshot{Status: TaskStatusInProgress, Data: json.RawMessage(`{"a":2}`)}
	assert.False(t, a.Equal(b))
}

func TestSnapshotEqual_NilVsEmpty(t *testing.T) {
	a := taskSnapshot{Status: TaskStatusInProgress, Data: nil}
	b := taskSnapshot{Status: TaskStatusInProgress, Data: json.RawMessage{}}
	// bytes.Equal(nil, []byte{}) == true
	assert.True(t, a.Equal(b))
}

func TestSnapshotEqual_PluginStateAndPollFailures(t *testing.T) {
	base := taskSnapshot{
		Status:       TaskStatusInProgress,
		PluginState:  json.RawMessage(`{"req_key":"a"}`),
		PollFailures: 2,
	}
	assert.True(t, base.Equal(taskSnapshot{
		Status:       TaskStatusInProgress,
		PluginState:  json.RawMessage(`{"req_key":"a"}`),
		PollFailures: 2,
	}))
	assert.False(t, base.Equal(taskSnapshot{
		Status:       TaskStatusInProgress,
		PluginState:  json.RawMessage(`{"req_key":"b"}`),
		PollFailures: 2,
	}))
	assert.False(t, base.Equal(taskSnapshot{
		Status:       TaskStatusInProgress,
		PluginState:  json.RawMessage(`{"req_key":"a"}`),
		PollFailures: 3,
	}))
}

func TestSnapshot_Roundtrip(t *testing.T) {
	task := &Task{
		Status:     TaskStatusInProgress,
		Progress:   "42%",
		StartTime:  1234,
		FinishTime: 5678,
		FailReason: "timeout",
		PrivateData: TaskPrivateData{
			ResultURL:    "https://example.com/result.mp4",
			PluginState:  json.RawMessage(`{"req_key":"keep"}`),
			PollFailures: 3,
		},
		Data: json.RawMessage(`{"model":"test-model"}`),
	}
	snap := task.Snapshot()
	assert.Equal(t, task.Status, snap.Status)
	assert.Equal(t, task.Progress, snap.Progress)
	assert.Equal(t, task.StartTime, snap.StartTime)
	assert.Equal(t, task.FinishTime, snap.FinishTime)
	assert.Equal(t, task.FailReason, snap.FailReason)
	assert.Equal(t, task.PrivateData.ResultURL, snap.ResultURL)
	assert.JSONEq(t, string(task.Data), string(snap.Data))
	assert.Equal(t, task.PrivateData.PluginState, snap.PluginState)
	assert.Equal(t, task.PrivateData.PollFailures, snap.PollFailures)
}

// ---------------------------------------------------------------------------
// UpdateWithStatus CAS — DB integration tests
// ---------------------------------------------------------------------------

func TestUpdateWithStatus_Win(t *testing.T) {
	truncateTables(t)

	task := &Task{
		TaskID:   "task_cas_win",
		Status:   TaskStatusInProgress,
		Progress: "50%",
		Data:     json.RawMessage(`{}`),
	}
	insertTask(t, task)

	task.Status = TaskStatusSuccess
	task.Progress = "100%"
	won, err := task.UpdateWithStatus(TaskStatusInProgress)
	require.NoError(t, err)
	assert.True(t, won)

	var reloaded Task
	require.NoError(t, DB.First(&reloaded, task.ID).Error)
	assert.EqualValues(t, TaskStatusSuccess, reloaded.Status)
	assert.Equal(t, "100%", reloaded.Progress)
}

func TestUpdateWithStatus_Lose(t *testing.T) {
	truncateTables(t)

	task := &Task{
		TaskID: "task_cas_lose",
		Status: TaskStatusFailure,
		Data:   json.RawMessage(`{}`),
	}
	insertTask(t, task)

	task.Status = TaskStatusSuccess
	won, err := task.UpdateWithStatus(TaskStatusInProgress) // wrong fromStatus
	require.NoError(t, err)
	assert.False(t, won)

	var reloaded Task
	require.NoError(t, DB.First(&reloaded, task.ID).Error)
	assert.EqualValues(t, TaskStatusFailure, reloaded.Status) // unchanged
}

func TestUpdateWithStatus_ConcurrentWinner(t *testing.T) {
	truncateTables(t)

	task := &Task{
		TaskID: "task_cas_race",
		Status: TaskStatusInProgress,
		Quota:  1000,
		Data:   json.RawMessage(`{}`),
	}
	insertTask(t, task)

	const goroutines = 5
	wins := make([]bool, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			t := &Task{}
			*t = Task{
				ID:       task.ID,
				TaskID:   task.TaskID,
				Status:   TaskStatusSuccess,
				Progress: "100%",
				Quota:    task.Quota,
				Data:     json.RawMessage(`{}`),
			}
			t.CreatedAt = task.CreatedAt
			t.UpdatedAt = time.Now().Unix()
			won, err := t.UpdateWithStatus(TaskStatusInProgress)
			if err == nil {
				wins[idx] = won
			}
		}(i)
	}
	wg.Wait()

	winCount := 0
	for _, w := range wins {
		if w {
			winCount++
		}
	}
	assert.Equal(t, 1, winCount, "exactly one goroutine should win the CAS")
}

func TestUpdateWithStatus_PersistsPluginStateAndPollFailures(t *testing.T) {
	truncateTables(t)

	task := &Task{
		TaskID: "task_cas_plugin_state",
		Status: TaskStatusInProgress,
		Data:   json.RawMessage(`{}`),
		PrivateData: TaskPrivateData{
			PluginState:  json.RawMessage(`{"req_key":"old"}`),
			PollFailures: 1,
		},
	}
	insertTask(t, task)

	task.PrivateData.PluginState = json.RawMessage(`{"req_key":"new"}`)
	task.PrivateData.PollFailures = 4
	won, err := task.UpdateWithStatus(TaskStatusInProgress)
	require.NoError(t, err)
	require.True(t, won)

	var reloaded Task
	require.NoError(t, DB.First(&reloaded, task.ID).Error)
	assert.EqualValues(t, TaskStatusInProgress, reloaded.Status)
	assert.JSONEq(t, `{"req_key":"new"}`, string(reloaded.PrivateData.PluginState))
	assert.Equal(t, 4, reloaded.PrivateData.PollFailures)
}

// This regression exercises the SQL ownership/target boundary independently of
// provider transport. Provider compatibility is a separate integration gate.
func TestWalletTaskDurableObligation(t *testing.T) {
	for _, database := range []common.DatabaseType{common.DatabaseTypeSQLite, common.DatabaseTypeMySQL, common.DatabaseTypePostgreSQL} {
		t.Run(string(database), func(t *testing.T) {
			for _, scenario := range []string{"insert_failure", "adjustment_failure_recovery", "cancel_unclaimed", "claimed_no_refund", "concurrent_recovery", "revoked_before_claim", "expired_before_claim", "deleted_before_claim", "historical_revoked", "unlimited"} {
				t.Run(scenario, func(t *testing.T) {
					db, facts := newSQLWalletFixture(t, database)
					if scenario == "concurrent_recovery" && database != common.DatabaseTypeSQLite {
						pool, err := db.DB()
						require.NoError(t, err)
						pool.SetMaxOpenConns(2)
					}
					task := &Task{TaskID: "task_obligation", UserId: facts.UserID, Platform: "fixture", Status: TaskStatusNotStart, Progress: "0%"}
					if scenario == "insert_failure" {
						require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:task-insert-failure", func(tx *gorm.DB) {
							if tx.Statement.Schema != nil && tx.Statement.Schema.Table == "tasks" {
								tx.AddError(errors.New("injected Task insert failure"))
							}
						}))
						require.Error(t, CreateWalletTaskObligation(context.Background(), task, facts.TokenID, 80))
						var count int64
						require.NoError(t, db.Model(&Task{}).Count(&count).Error)
						assert.Zero(t, count)
						assert.Equal(t, 100, getUserQuotaFromDB(t, facts.UserID))
						assert.Equal(t, 100, getTokenFromDB(t, facts.TokenID).RemainQuota)
						return
					}
					if scenario == "unlimited" {
						require.NoError(t, db.Model(&Token{}).Where("id = ?", facts.TokenID).UpdateColumn("unlimited_quota", true).Error)
					}
					require.NoError(t, CreateWalletTaskObligation(context.Background(), task, facts.TokenID, 80))
					assert.Equal(t, 20, getUserQuotaFromDB(t, facts.UserID))
					if scenario == "cancel_unclaimed" {
						require.NoError(t, CancelUnclaimedWalletTask(context.Background(), task.ID))
						require.NoError(t, CancelUnclaimedWalletTask(context.Background(), task.ID))
						assert.Equal(t, 100, getUserQuotaFromDB(t, facts.UserID))
						require.Error(t, ClaimWalletTaskSend(context.Background(), task.ID))
						return
					}
					if scenario == "revoked_before_claim" || scenario == "expired_before_claim" || scenario == "deleted_before_claim" {
						if scenario == "revoked_before_claim" {
							require.NoError(t, db.Model(&Token{}).Where("id = ?", facts.TokenID).UpdateColumn("status", common.TokenStatusDisabled).Error)
						} else if scenario == "deleted_before_claim" {
							require.NoError(t, db.Delete(&Token{}, facts.TokenID).Error)
						} else {
							require.NoError(t, db.Model(&Token{}).Where("id = ?", facts.TokenID).UpdateColumn("expired_time", int64(1)).Error)
						}
						require.Error(t, ClaimWalletTaskSend(context.Background(), task.ID))
						require.NoError(t, CancelUnclaimedWalletTask(context.Background(), task.ID))
						assert.Equal(t, 100, getUserQuotaFromDB(t, facts.UserID))
						return
					}
					require.NoError(t, ClaimWalletTaskSend(context.Background(), task.ID))
					if scenario == "historical_revoked" {
						require.NoError(t, db.Model(&Token{}).Where("id = ?", facts.TokenID).Updates(map[string]any{"status": common.TokenStatusDisabled, "expired_time": int64(1)}).Error)
					}
					require.Error(t, ClaimWalletTaskSend(context.Background(), task.ID))
					require.Error(t, CancelUnclaimedWalletTask(context.Background(), task.ID))
					for _, amount := range []int{0, 1} {
						ok, err := TryReserveUserQuota(facts.UserID, amount)
						require.Error(t, err)
						assert.False(t, ok)
						ok, err = TryReserveAdditionalUserQuota(facts.UserID, amount)
						require.Error(t, err)
						assert.False(t, ok)
					}
					if scenario == "claimed_no_refund" {
						assert.Equal(t, 20, getUserQuotaFromDB(t, facts.UserID))
						return
					}
					require.NoError(t, db.First(task, task.ID).Error)
					task.Status, task.Progress = TaskStatusSuccess, "100%"
					task.PrivateData.UpstreamTaskID = "accepted_fixture"
					require.NoError(t, StageWalletTaskOutcome(context.Background(), task, 140))
					require.NoError(t, db.First(task, task.ID).Error)
					assert.Equal(t, TaskStatus(TaskStatusUnknown), task.Status)
					p, err := decodeTaskBilling(task)
					require.NoError(t, err)
					assert.Equal(t, 80, p.Applied)
					assert.Equal(t, 140, p.Target)
					assert.True(t, p.TargetKnown)
					if scenario == "adjustment_failure_recovery" {
						require.NoError(t, db.Callback().Update().Before("gorm:update").Register("test:task-adjustment-failure", func(tx *gorm.DB) {
							if tx.Statement.Schema != nil && tx.Statement.Schema.Table == "users" {
								tx.AddError(errors.New("injected User update failure"))
							}
						}))
						require.Error(t, ReconcileWalletTask(context.Background(), task.ID))
						require.NoError(t, db.Callback().Update().Remove("test:task-adjustment-failure"))
						require.NoError(t, db.First(task, task.ID).Error)
						p, err = decodeTaskBilling(task)
						require.NoError(t, err)
						assert.Equal(t, 80, p.Applied)
						assert.Equal(t, 140, p.Target)
						assert.Equal(t, 20, getUserQuotaFromDB(t, facts.UserID))
					}
					var wg sync.WaitGroup
					results := make(chan error, 2)
					for range 2 {
						wg.Go(func() { results <- ReconcileWalletTask(context.Background(), task.ID) })
					}
					wg.Wait()
					close(results)
					for err := range results {
						require.NoError(t, err)
					}
					require.NoError(t, ReconcileWalletTask(context.Background(), task.ID))
					require.NoError(t, db.First(task, task.ID).Error)
					assert.Equal(t, TaskStatus(TaskStatusSuccess), task.Status)
					assert.Equal(t, TaskBillingSettled, task.BillingState)
					assert.Equal(t, 140, task.Quota)
					assert.Equal(t, -40, getUserQuotaFromDB(t, facts.UserID))
					token := getTokenFromDB(t, facts.TokenID)
					assert.Equal(t, -40, token.RemainQuota)
					assert.Equal(t, 140, token.UsedQuota)
				})
			}
		})
	}
}

// Real SQL transactions with an acknowledgement fault at the commit boundary.
// The wrapper never fabricates a successful SQL operation or changes assertions.
type taskCommitFaultPool struct {
	gorm.ConnPool
	after bool
}

func (p taskCommitFaultPool) BeginTx(ctx context.Context, options *sql.TxOptions) (gorm.ConnPool, error) {
	tx, err := p.ConnPool.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	}).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &taskCommitFaultTx{Tx: tx, after: p.after}, nil
}

type taskCommitFaultTx struct {
	*sql.Tx
	after bool
}

func (tx taskCommitFaultTx) Commit() error {
	if tx.after {
		if err := tx.Tx.Commit(); err != nil {
			return err
		}
	} else {
		if err := tx.Tx.Rollback(); err != nil {
			return err
		}
	}
	return errors.New("injected commit acknowledgement failure")
}
func TestWalletTaskCommitAmbiguity(t *testing.T) {
	for _, kind := range []common.DatabaseType{common.DatabaseTypeSQLite, common.DatabaseTypeMySQL, common.DatabaseTypePostgreSQL} {
		t.Run(string(kind), func(t *testing.T) {
			for _, phase := range []string{"intent", "adjustment"} {
				for _, after := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s_after_%t", phase, after), func(t *testing.T) {
						db, facts := newSQLWalletFixture(t, kind)
						task := &Task{TaskID: "commit-obligation", UserId: facts.UserID}
						if phase == "adjustment" {
							require.NoError(t, CreateWalletTaskObligation(context.Background(), task, facts.TokenID, 80))
							require.NoError(t, ClaimWalletTaskSend(context.Background(), task.ID))
							require.NoError(t, db.First(task, task.ID).Error)
							task.Status = TaskStatusSuccess
							task.Progress = "100%"
							require.NoError(t, StageWalletTaskOutcome(context.Background(), task, 140))
						}
						fault := db.Session(&gorm.Session{NewDB: true, Context: context.Background()})
						fault.Statement.ConnPool = taskCommitFaultPool{ConnPool: db.Statement.ConnPool, after: after}
						DB = fault
						var err error
						if phase == "intent" {
							err = CreateWalletTaskObligation(context.Background(), task, facts.TokenID, 80)
						} else {
							err = ReconcileWalletTask(context.Background(), task.ID)
						}
						DB = db
						require.Error(t, err)
						if phase == "intent" {
							var count int64
							require.NoError(t, db.Model(&Task{}).Count(&count).Error)
							if after {
								assert.EqualValues(t, 1, count)
								assert.Equal(t, 20, getUserQuotaFromDB(t, facts.UserID))
								require.NoError(t, CancelUnclaimedWalletTask(context.Background(), task.ID))
								require.NoError(t, CancelUnclaimedWalletTask(context.Background(), task.ID))
							} else {
								assert.Zero(t, count)
							}
							assert.Equal(t, 100, getUserQuotaFromDB(t, facts.UserID))
							assert.Equal(t, 100, getTokenFromDB(t, facts.TokenID).RemainQuota)
						} else {
							require.NoError(t, db.First(task, task.ID).Error)
							if after {
								assert.Equal(t, TaskBillingSettled, task.BillingState)
								assert.Equal(t, -40, getUserQuotaFromDB(t, facts.UserID))
							} else {
								assert.Equal(t, TaskBillingPending, task.BillingState)
								assert.Equal(t, 20, getUserQuotaFromDB(t, facts.UserID))
							}
							require.NoError(t, ReconcileWalletTask(context.Background(), task.ID))
							require.NoError(t, ReconcileWalletTask(context.Background(), task.ID))
							assert.Equal(t, -40, getUserQuotaFromDB(t, facts.UserID))
							assert.Equal(t, -40, getTokenFromDB(t, facts.TokenID).RemainQuota)
						}
					})
				}
			}
		})
	}
}
