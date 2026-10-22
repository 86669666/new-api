package service

import (
	"context"
	"errors"
	"time"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
)

type ClientEventsConfig = operation_setting.ClientEventsConfig

func InitClientEventsConfig() error { return operation_setting.InitClientEventsConfig() }

func CurrentClientEventsConfig() ClientEventsConfig {
	return operation_setting.CurrentClientEventsSnapshot().ClientEventsConfig
}

// ClientEventsCleanupHandler uses the existing master/lease task runner. It
// remains enabled when intake is disabled so old reports do not live forever.
type ClientEventsCleanupHandler struct{}

func (ClientEventsCleanupHandler) Type() string { return "client_events_cleanup" }
func (ClientEventsCleanupHandler) Enabled() bool {
	return operation_setting.CurrentClientEventsSnapshot().Valid
}
func (ClientEventsCleanupHandler) Interval() time.Duration { return time.Hour }
func (ClientEventsCleanupHandler) NewPayload() any         { return struct{}{} }
func (ClientEventsCleanupHandler) Run(ctx context.Context, task *model.SystemTask, runnerID string) {
	snapshot := operation_setting.CurrentClientEventsSnapshot()
	if !snapshot.Valid {
		failSystemTask(task, runnerID, errors.New("Client event cleanup configuration is unavailable."))
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cutoff := time.Now().Add(-time.Duration(snapshot.RetentionDays) * 24 * time.Hour).Unix()
	var deleted int64
	for {
		n, err := model.DeleteClientEventBatch(ctx, cutoff)
		if err != nil {
			failSystemTask(task, runnerID, errors.New("Client event cleanup did not complete."))
			return
		}
		deleted += n
		if n == 0 {
			break
		}
	}
	if err := model.FinishSystemTask(task.TaskID, runnerID, model.SystemTaskStatusSucceeded, map[string]any{"deleted": deleted}, ""); err != nil {
		logSystemTaskLockError(ctx, task, err)
	}
}

func init() { RegisterSystemTaskHandler(ClientEventsCleanupHandler{}) }
