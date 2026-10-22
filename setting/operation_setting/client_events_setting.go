package operation_setting

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/QuantumNous/new-api/common"
)

const ClientEventsConfigKey = "ClientEventsConfig"

var ErrClientEventsConfig = errors.New("invalid client events configuration")

type ClientEventsConfig struct {
	Enabled       bool `json:"enabled"`
	RetentionDays int  `json:"retention_days"`
	RateLimit     int  `json:"rate_limit"`
}

type ClientEventsSnapshot struct {
	ClientEventsConfig
	Source string `json:"source"`
	Valid  bool   `json:"valid"`
}

var clientEventsFallback atomic.Pointer[ClientEventsConfig]
var clientEventsSnapshot atomic.Pointer[ClientEventsSnapshot]

func IsClientEventsConfigKey(key string) bool {
	return strings.EqualFold(strings.TrimSpace(key), ClientEventsConfigKey)
}

func ParseClientEventsConfig(value string) (ClientEventsConfig, error) {
	var config ClientEventsConfig
	if len(value) > 4096 {
		return config, ErrClientEventsConfig
	}
	fields, err := common.DecodeRawJSONObject([]byte(value))
	if err != nil || len(fields) != 3 {
		return config, ErrClientEventsConfig
	}
	enabled, ok := fields["enabled"]
	if !ok || !(bytes.Equal(bytes.TrimSpace(enabled), []byte("true")) || bytes.Equal(bytes.TrimSpace(enabled), []byte("false"))) {
		return config, ErrClientEventsConfig
	}
	config.Enabled = bytes.Equal(bytes.TrimSpace(enabled), []byte("true"))
	for _, field := range []struct {
		key      string
		min, max int
		target   *int
	}{{"retention_days", 8, 365, &config.RetentionDays}, {"rate_limit", 1, 600, &config.RateLimit}} {
		raw, ok := fields[field.key]
		if !ok {
			return config, ErrClientEventsConfig
		}
		value := strings.TrimSpace(string(raw))
		n, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(n) != value || n < field.min || n > field.max {
			return config, ErrClientEventsConfig
		}
		*field.target = n
	}
	return config, nil
}

// Initialize the fallback only. Intake and cleanup wait for an authoritative
// Option read, so a database outage cannot silently activate startup defaults.
func InitClientEventsConfig() error {
	config := ClientEventsConfig{RetentionDays: 30, RateLimit: 60}
	switch os.Getenv("CLIENT_EVENTS_ENABLED") {
	case "", "false":
	case "true":
		config.Enabled = true
	default:
		return ErrClientEventsConfig
	}
	for _, field := range []struct {
		key      string
		min, max int
		target   *int
	}{{"CLIENT_EVENTS_RETENTION_DAYS", 8, 365, &config.RetentionDays}, {"CLIENT_EVENTS_RATE_LIMIT", 1, 600, &config.RateLimit}} {
		if value := os.Getenv(field.key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < field.min || n > field.max {
				return ErrClientEventsConfig
			}
			*field.target = n
		}
	}
	clientEventsFallback.Store(&config)
	pending := config
	pending.Enabled = false
	clientEventsSnapshot.Store(&ClientEventsSnapshot{ClientEventsConfig: pending, Source: "environment"})
	return nil
}

func CurrentClientEventsSnapshot() ClientEventsSnapshot {
	if snapshot := clientEventsSnapshot.Load(); snapshot != nil {
		return *snapshot
	}
	return ClientEventsSnapshot{ClientEventsConfig: ClientEventsConfig{RetentionDays: 30, RateLimit: 60}, Source: "environment"}
}

// Callers serialize storage reads/writes through publication with one domain
// lock. A read failure keeps the last observed state, including invalid state.
func ApplyClientEventsOption(value *string, readErr error) error {
	if readErr != nil {
		return readErr
	}
	if value == nil {
		config := ClientEventsConfig{RetentionDays: 30, RateLimit: 60}
		if fallback := clientEventsFallback.Load(); fallback != nil {
			config = *fallback
		}
		clientEventsSnapshot.Store(&ClientEventsSnapshot{ClientEventsConfig: config, Source: "environment", Valid: true})
		return nil
	}
	config, err := ParseClientEventsConfig(*value)
	if err != nil {
		previous := CurrentClientEventsSnapshot()
		previous.Enabled = false
		previous.Valid = false
		previous.Source = "option"
		clientEventsSnapshot.Store(&previous)
		return err
	}
	clientEventsSnapshot.Store(&ClientEventsSnapshot{ClientEventsConfig: config, Source: "option", Valid: true})
	return nil
}
