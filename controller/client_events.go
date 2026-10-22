package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
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

var clientEventQuerySlots = make(chan struct{}, 2)

func GetClientEventUsage(c *gin.Context)   { getClientEventStats(c, "usage") }
func GetClientEventClients(c *gin.Context) { getClientEventStats(c, "clients") }

// parseClientEventStatsQuery rejects ambiguous and noncanonical query values.
// The result version binds the normalized window/filters, never page size.
func parseClientEventStatsQuery(raw, kind string, now time.Time) (model.ClientEventStatsQuery, int, int, string, error) {
	query := model.ClientEventStatsQuery{Kind: kind, StartTime: now.Unix() - 7*86400, EndTime: now.Unix()}
	invalid := errors.New("invalid client event query")
	page, size := 1, 50
	if len(raw) > 4096 {
		return query, page, size, "", invalid
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return query, page, size, "", invalid
	}
	limits := map[string]int{"channel": 64}
	if kind == "usage" {
		limits["model"], limits["provider"], limits["source"] = 255, 128, 8
	} else {
		limits["version"], limits["os"] = 32, 16
	}
	for key, list := range values {
		if len(list) != 1 {
			return query, page, size, "", invalid
		}
		value := list[0]
		switch key {
		case "start_time", "end_time", "page", "page_size":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 || strconv.FormatInt(n, 10) != value {
				return query, page, size, "", invalid
			}
			switch key {
			case "start_time":
				query.StartTime = n
			case "end_time":
				query.EndTime = n
			case "page":
				if n < 1 || n > 2000 {
					return query, page, size, "", invalid
				}
				page = int(n)
			case "page_size":
				if n < 1 || n > 100 {
					return query, page, size, "", invalid
				}
				size = int(n)
			}
		case "result_version":
			if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
				return query, page, size, "", invalid
			}
			for _, ch := range value[7:] {
				if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
					return query, page, size, "", invalid
				}
			}
		default:
			limit, ok := limits[key]
			if !ok || value == "" && key != "version" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit || strings.ContainsRune(value, unicode.ReplacementChar) {
				return query, page, size, "", invalid
			}
			for _, ch := range value {
				if unicode.IsControl(ch) {
					return query, page, size, "", invalid
				}
			}
			switch key {
			case "channel":
				query.Channel = value
			case "model":
				query.Model = value
			case "provider":
				query.Provider = value
			case "source":
				if value != "chat" && value != "agent" {
					return query, page, size, "", invalid
				}
				query.Source = value
			case "version":
				query.Version = &value
			case "os":
				if value != "darwin" && value != "win32" && value != "linux" {
					return query, page, size, "", invalid
				}
				query.OS = value
			}
		}
	}
	if values.Has("start_time") != values.Has("end_time") || query.StartTime < 0 || query.StartTime >= query.EndTime || query.EndTime > now.Unix()+3600 || query.EndTime-query.StartTime > 31*86400 || (page-1)*size > 2000 || page > 1 && (!values.Has("start_time") || !values.Has("result_version")) {
		return query, page, size, "", invalid
	}
	return query, page, size, values.Get("result_version"), nil
}

func writeClientEventQueryError(c *gin.Context, status int) {
	code, message := "CLIENT_EVENTS_QUERY_INVALID", "Invalid request"
	fields := gin.H{}
	switch status {
	case 401:
		code, message = "CLIENT_EVENTS_QUERY_UNAUTHORIZED", "Unauthorized"
	case 403:
		code, message = "CLIENT_EVENTS_QUERY_FORBIDDEN", "Unauthorized Access"
	case 409:
		code = "CLIENT_EVENTS_QUERY_CHANGED"
	case 422:
		code = "CLIENT_EVENTS_QUERY_TOO_LARGE"
		fields["max_candidate_rows"], fields["max_groups"] = 50000, 2000
	case 503:
		code, message = "CLIENT_EVENTS_QUERY_UNAVAILABLE", "Internal Server Error!"
	}
	fields["code"] = code
	common.ApiErrorStatus(c, status, common.NewMessage(message), fields)
}

func checkClientEventQueryAuthority(c *gin.Context, ctx context.Context, actor model.ClientEventQueryActor) bool {
	scopes, err := model.ReadClientEventQueryAuthority(ctx, actor)
	if err != nil {
		status := middleware.ClientEventErrorStatus(err)
		if status == 503 {
			common.SysError(common.LogText("client event query authority failed (%T)", err))
		}
		writeClientEventQueryError(c, status)
		return false
	}
	if actor.UseAccessToken && !actor.Legacy && !service.AccessTokenScopeGranted(scopes, "log:read") {
		writeClientEventQueryError(c, 403)
		return false
	}
	return true
}

func getClientEventStats(c *gin.Context, kind string) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	owner, ok := middleware.RequirePersonalResourceOwner(c)
	if !ok {
		return
	}
	actor := model.ClientEventQueryActor{UseAccessToken: c.GetBool("use_access_token"), Legacy: c.GetBool("access_token_legacy"), TokenID: c.GetInt("access_token_id"), TokenRef: c.GetString("access_token_ref")}
	actor.Identity, ok = middleware.GetStepUpIdentity(c)
	if actor.UseAccessToken && actor.Legacy {
		actor.Identity, ok = middleware.GetAuthIdentity(c)
	}
	if !ok || actor.Identity.UserID != owner {
		writeClientEventQueryError(c, 401)
		return
	}
	query, page, size, expected, err := parseClientEventStatsQuery(c.Request.URL.RawQuery, kind, time.Now())
	if err != nil {
		writeClientEventQueryError(c, 400)
		return
	}
	select {
	case clientEventQuerySlots <- struct{}{}:
		defer func() { <-clientEventQuerySlots }()
	default:
		c.Header("Retry-After", "1")
		writeClientEventQueryError(c, 503)
		return
	}
	if !checkClientEventQueryAuthority(c, ctx, actor) {
		return
	}
	result, err := model.QueryClientEventStats(ctx, query)
	if err != nil {
		if errors.Is(err, model.ErrClientEventQueryTooLarge) {
			writeClientEventQueryError(c, 422)
		} else {
			common.SysError(common.LogText("client event aggregation failed (%T)", err))
			writeClientEventQueryError(c, 503)
		}
		return
	}
	var all any = result.Usage
	total := len(result.Usage)
	if kind == "clients" {
		all = result.Clients
		total = len(result.Clients)
	}
	encoded, err := common.Marshal(struct {
		Query model.ClientEventStatsQuery `json:"query"`
		Items any                         `json:"items"`
	}{query, all})
	if err != nil {
		writeClientEventQueryError(c, 503)
		return
	}
	version := fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
	// Recheck even when reporting a changed result; no success payload is written
	// before this direct authority observation and the common deadline check.
	if !checkClientEventQueryAuthority(c, ctx, actor) {
		return
	}
	if ctx.Err() != nil {
		writeClientEventQueryError(c, 503)
		return
	}
	if expected != "" && expected != version {
		writeClientEventQueryError(c, 409)
		return
	}
	start := min((page-1)*size, total)
	end := min(start+size, total)
	var items any
	if kind == "clients" {
		items = result.Clients[start:end]
	} else {
		items = result.Usage[start:end]
	}
	config := service.CurrentClientEventsConfig()
	data := gin.H{"items": items, "total": total, "page": page, "page_size": size, "start_time": query.StartTime, "end_time": query.EndTime, "timezone": "UTC", "result_version": version, "provenance": "client_self_reported", "coverage": "retained_events", "data_complete": false, "intake_enabled": config.Enabled, "retention_days": config.RetentionDays}
	if kind == "clients" {
		data["activity_basis"], data["identity_basis"], data["groups_additive"] = "app_launch", "user_channel_client", false
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}
