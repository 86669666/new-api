package model

import (
	"math/big"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/chcol"
	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditOtherScanClickHouseJSON(t *testing.T) {
	const huge = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
	integer, ok := new(big.Int).SetString(huge, 10)
	require.True(t, ok)
	input := chcol.NewJSON()
	input.SetValueAtPath("op.action", chcol.NewDynamic("channel.update"))
	input.SetValueAtPath("op.params.id", chcol.NewDynamic(int64(9007199254740993)))
	input.SetValueAtPath("op.params.nested", chcol.NewDynamic(map[string]any{
		"huge": integer, "values": []any{uint64(18446744073709551615), int64(-9007199254740993), false, nil},
	}))
	input.SetValueAtPath("admin_info.admin_id", int64(7))
	input.SetValueAtPath("admin_info.admin_role", int64(100))
	input.SetValueAtPath("audit_info.method", "PUT")
	input.SetValueAtPath("audit_info.route", "/api/channel/")
	input.SetValueAtPath("audit_info.path", "/api/channel/")
	input.SetValueAtPath("audit_info.status", int64(200))
	input.SetValueAtPath("audit_info.success", false)
	input.SetValueAtPath("root_info.generation", chcol.NewDynamic(uint64(18446744073709551615)))
	input.SetValueAtPath("login_method", "password")
	input.SetValueAtPath("user_agent", "quoted \"agent\"")
	input.SetValueAtPath("future_field", "ignored")
	encoded, err := common.Marshal(input)
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		value any
	}{{"native", input}, {"string", string(encoded)}, {"bytes", encoded}} {
		t.Run(tc.name, func(t *testing.T) {
			var other AuditOther
			require.NoError(t, other.Scan(tc.value))
			require.NotNil(t, other.Op)
			assert.Equal(t, "channel.update", other.Op.Action)
			assert.Equal(t, common.RawMessage("9007199254740993"), other.Op.Params["id"])
			nested, ok := other.Op.Params["nested"].(common.RawMessage)
			require.True(t, ok)
			var fields map[string]common.RawMessage
			require.NoError(t, common.Unmarshal(nested, &fields))
			assert.Equal(t, huge, string(fields["huge"]))
			assert.Equal(t, "[18446744073709551615,-9007199254740993,false,null]", string(fields["values"]))
			assert.Equal(t, &AuditAdminInfo{AdminID: 7, AdminRole: 100}, other.AdminInfo)
			assert.Equal(t, &AuditRequestInfo{Method: "PUT", Route: "/api/channel/", Path: "/api/channel/", Status: 200, Success: false}, other.AuditInfo)
			assert.Equal(t, common.RawMessage("18446744073709551615"), other.RootInfo["generation"])
			assert.Equal(t, "password", other.LoginMethod)
			assert.Equal(t, "quoted \"agent\"", other.UserAgent)
			value, err := other.Value()
			require.NoError(t, err)
			text, ok := value.(string)
			require.True(t, ok, "database encoding must remain a string for PostgreSQL simple protocol")
			assert.Contains(t, text, `"huge":`+huge)
			assert.Contains(t, text, `"id":9007199254740993`)
			assert.NotContains(t, text, "future_field")
			// The API still receives a structured object, with privileged fields
			// separate for the existing role-based projection.
			api, err := common.Marshal(struct {
				Other AuditOther `json:"other"`
			}{other})
			require.NoError(t, err)
			assert.Contains(t, string(api), `"other":{"op":`)
			assert.Contains(t, string(api), `"admin_info":{"admin_id":7`)
		})
	}
}

func TestAuditOtherScanEmptyClearsPreviousRow(t *testing.T) {
	nulls := chcol.NewJSON()
	for _, path := range []string{"op", "admin_info", "audit_info", "root_info"} {
		nulls.SetValueAtPath(path, chcol.NewDynamic(nil))
	}
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"nil", nil}, {"empty_string", ""}, {"empty_bytes", []byte{}}, {"nil_bytes", []byte(nil)},
		{"null", "null"}, {"object", []byte("{}")}, {"native_empty", chcol.NewJSON()},
		{"native_zero", &chcol.JSON{}}, {"native_nil", (*chcol.JSON)(nil)}, {"native_null_fields", nulls},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := AuditOther{Op: &AuditOperation{Action: "old"}, AdminInfo: &AuditAdminInfo{AdminID: 3}, AuditInfo: &AuditRequestInfo{Status: 200}, RootInfo: AuditFields{"old": true}, LoginMethod: "password", UserAgent: "old"}
			require.NoError(t, other.Scan(tc.value))
			assert.Equal(t, AuditOther{}, other)
			value, err := other.Value()
			require.NoError(t, err)
			assert.Equal(t, "{}", value)
		})
	}
}

func TestAuditOtherScanFailurePreservesPreviousRow(t *testing.T) {
	invalidType := chcol.NewJSON()
	invalidType.SetValueAtPath("op.action", int64(123))
	invalidValue := chcol.NewJSON()
	invalidValue.SetValueAtPath("root_info.invalid", make(chan int))
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"unsupported_integer", 42}, {"unsupported_map", map[string]any{"op": "value"}},
		{"unsupported_native_value", *chcol.NewJSON()}, {"malformed_string", "{broken"},
		{"malformed_bytes", []byte("{broken")}, {"array", "[]"}, {"native_field_type", invalidType},
		{"native_marshal_error", invalidValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var other AuditOther
			require.NoError(t, other.Scan(`{"op":{"action":"original","params":{"id":9007199254740993}},"root_info":{"nested":{"id":18446744073709551615}}}`))
			before, err := other.Value()
			require.NoError(t, err)
			require.Error(t, other.Scan(tc.value))
			after, err := other.Value()
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
}
