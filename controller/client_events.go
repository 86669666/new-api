package controller

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const clientEventBodyLimit = 256 * 1024

func ReceiveClientEvents(c *gin.Context) {
	credential, ok := middleware.GetClientEventCredential(c)
	if !ok {
		middleware.WriteClientEventError(c, 401)
		return
	}
	if c.Request.ContentLength > clientEventBodyLimit {
		middleware.WriteClientEventError(c, 413)
		return
	}
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, clientEventBodyLimit+1))
	if len(data) > clientEventBodyLimit {
		middleware.WriteClientEventError(c, 413)
		return
	}
	if err != nil {
		middleware.WriteClientEventError(c, 400)
		return
	}
	fields, err := common.DecodeRawJSONObject(data)
	if err != nil {
		middleware.WriteClientEventError(c, 400)
		return
	}
	clientID, valid := clientEventString(fields["client_id"], 36, false)
	id, err := uuid.Parse(clientID)
	if !valid || err != nil || id.String() != strings.ToLower(clientID) {
		middleware.WriteClientEventError(c, 400)
		return
	}
	clientID = id.String()
	if values := c.Request.Header.Values("X-Client-Id"); len(values) > 0 {
		headerID, err := uuid.Parse(values[0])
		if err != nil || headerID.String() != strings.ToLower(values[0]) || headerID.String() != clientID {
			middleware.WriteClientEventError(c, 400)
			return
		}
	}
	channel, valid := clientEventString(fields["channel"], 64, false)
	if !valid || common.GetJsonType(fields["events"]) != "array" {
		middleware.WriteClientEventError(c, 400)
		return
	}
	var rawEvents []common.RawMessage
	if common.Unmarshal(fields["events"], &rawEvents) != nil || len(rawEvents) < 1 || len(rawEvents) > 10 {
		middleware.WriteClientEventError(c, 400)
		return
	}
	received := time.Now().Truncate(time.Millisecond)
	events := make([]model.ClientEvent, 0, len(rawEvents))
	for _, raw := range rawEvents {
		if len(raw) > 64*1024 {
			middleware.WriteClientEventError(c, 413)
			return
		}
		fields, err := common.DecodeRawJSONObject(raw)
		if err != nil {
			middleware.WriteClientEventError(c, 400)
			return
		}
		event, valid, err := normalizedClientEvent(fields, received)
		if err != nil {
			middleware.WriteClientEventError(c, 400)
			return
		}
		if valid {
			event.ClientID, event.Channel = clientID, channel
			events = append(events, event)
		}
	}
	count, err := model.ReceiveClientEvents(c.Request.Context(), credential, c.ClientIP(), events)
	if err != nil {
		middleware.WriteClientEventError(c, middleware.ClientEventErrorStatus(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "count": count})
}

func clientEventString(raw common.RawMessage, maximum int, empty bool) (string, bool) {
	var value string
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || common.Unmarshal(raw, &value) != nil ||
		(!empty && value == "") || utf8.RuneCountInString(value) > maximum || strings.ContainsRune(value, unicode.ReplacementChar) {
		return "", false
	}
	for _, ch := range value {
		if unicode.IsControl(ch) {
			return "", false
		}
	}
	return value, true
}

func clientEventCounter(raw common.RawMessage) (*int64, bool) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return nil, false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return nil, false
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n > 9007199254740991 {
		return nil, false
	}
	return &n, true
}

func normalizedClientEvent(fields map[string]common.RawMessage, received time.Time) (model.ClientEvent, bool, error) {
	event := model.ClientEvent{ReceivedAt: received.Unix(), EventTimeMS: received.UnixMilli()}
	kind, valid := clientEventString(fields["event_type"], 16, false)
	if !valid || (kind != "app_launch" && kind != "app_update" && kind != "token_usage") {
		return event, false, nil
	}
	event.EventType = kind
	if raw, present := fields["timestamp"]; present {
		stamp, valid := clientEventString(raw, 64, false)
		if !valid {
			return event, false, nil
		}
		parsed, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return event, false, nil
		}
		event.EventTimeMS = parsed.UnixMilli()
		if event.EventTimeMS < received.Add(-7*24*time.Hour).UnixMilli() || event.EventTimeMS > received.Add(time.Hour).UnixMilli() {
			return event, false, nil
		}
	}
	if common.GetJsonType(fields["data"]) != "object" {
		return event, false, nil
	}
	data, err := common.DecodeRawJSONObject(fields["data"])
	if err != nil {
		return event, false, err
	}
	if kind != "token_usage" {
		event.AppVersion, valid = clientEventString(data["version"], 32, true)
		if !valid {
			return event, false, nil
		}
		if kind == "app_launch" {
			event.OS, valid = clientEventString(data["os"], 16, false)
			if !valid || (event.OS != "darwin" && event.OS != "win32" && event.OS != "linux") {
				return event, false, nil
			}
		}
		return event, true, nil
	}
	event.Provider, valid = clientEventString(data["provider"], 128, false)
	if !valid {
		return event, false, nil
	}
	event.Model, valid = clientEventString(data["model"], 255, false)
	if !valid {
		return event, false, nil
	}
	event.InputTokens, valid = clientEventCounter(data["input_tokens"])
	if !valid {
		return event, false, nil
	}
	event.OutputTokens, valid = clientEventCounter(data["output_tokens"])
	if !valid || (*event.InputTokens == 0 && *event.OutputTokens == 0) {
		return event, false, nil
	}
	event.Source = "chat"
	if raw, present := data["source"]; present {
		event.Source, valid = clientEventString(raw, 8, false)
		if !valid || (event.Source != "chat" && event.Source != "agent") {
			return event, false, nil
		}
	}
	return event, true, nil
}
