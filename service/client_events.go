package service

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/model"
)

type ClientEventsConfig struct {
	Enabled       bool
	RetentionDays int
	RateLimit     int
}

var currentClientEvents atomic.Pointer[ClientEventsConfig]

func InitClientEventsConfig() error {
	config := ClientEventsConfig{RetentionDays: 30, RateLimit: 60}
	invalid := errors.New("Invalid client events configuration.")
	switch os.Getenv("CLIENT_EVENTS_ENABLED") {
	case "", "false":
	case "true":
		config.Enabled = true
	default:
		return invalid
	}
	for _, item := range []struct {
		key              string
		destination      *int
		minimum, maximum int
	}{
		{"CLIENT_EVENTS_RETENTION_DAYS", &config.RetentionDays, 8, 365},
		{"CLIENT_EVENTS_RATE_LIMIT", &config.RateLimit, 1, 600},
	} {
		if value := os.Getenv(item.key); value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < item.minimum || parsed > item.maximum {
				return invalid
			}
			*item.destination = parsed
		}
	}
	currentClientEvents.Store(&config)
	return nil
}

func CurrentClientEventsConfig() ClientEventsConfig {
	if config := currentClientEvents.Load(); config != nil {
		return *config
	}
	return ClientEventsConfig{RetentionDays: 30, RateLimit: 60}
}

// ClientEventsCleanupHandler uses the existing master/lease task runner. It
// remains enabled when intake is disabled so old reports do not live forever.
type ClientEventsCleanupHandler struct{}

func (ClientEventsCleanupHandler) Type() string            { return "client_events_cleanup" }
func (ClientEventsCleanupHandler) Enabled() bool           { return currentClientEvents.Load() != nil }
func (ClientEventsCleanupHandler) Interval() time.Duration { return time.Hour }
func (ClientEventsCleanupHandler) NewPayload() any         { return struct{}{} }
func (ClientEventsCleanupHandler) Run(ctx context.Context, task *model.SystemTask, runnerID string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cutoff := time.Now().Add(-time.Duration(CurrentClientEventsConfig().RetentionDays) * 24 * time.Hour).Unix()
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
