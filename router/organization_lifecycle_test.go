package router

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/fxamacker/cbor/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// These tests consume the effective newapi-S3-lifecycle-g6-v1.1 HTTP contract.
// Domain records establish fixtures only; proofs always come from the public
// verification producers. No OrganizationAuthorization or signed JWT is forged.
type organizationLifecycleClient struct {
	*organizationHTTPFixture
	passwords map[string]string
	refresh   map[string]string
}

func newOrganizationLifecycleClient(t *testing.T) *organizationLifecycleClient {
	t.Helper()
	f := newOrganizationHTTPFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.AuthFlow{}, &model.TwoFA{}, &model.TwoFABackupCode{}, &model.PasskeyCredential{}, &model.UserOAuthBinding{}))
	enabled, encrypted := common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled
	secure, trusted := common.SessionCookieSecure, append([]string(nil), common.SessionCookieTrustedURLs...)
	common.SessionCookieSecure = true
	common.SessionCookieTrustedURLs = append(common.SessionCookieTrustedURLs, f.server.URL)
	settings := *system_setting.GetPasskeySettings()
	common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled = true, false
	*system_setting.GetPasskeySettings() = system_setting.PasskeySettings{Enabled: true, RPID: "example.com", Origins: "https://example.com", RPDisplayName: "new-api"}
	t.Cleanup(func() {
		common.PasswordLoginEnabled, common.PasswordLoginEncryptionEnabled = enabled, encrypted
		common.SessionCookieSecure = secure
		common.SessionCookieTrustedURLs = trusted
		*system_setting.GetPasskeySettings() = settings
	})
	c := &organizationLifecycleClient{organizationHTTPFixture: f, passwords: map[string]string{}, refresh: map[string]string{}}
	for _, actor := range []string{"owner", "admin", "member", "foreign", "root", "empty"} {
		password := "S3-local-fixture-" + actor + "-password"
		hashed, err := common.Password2Hash(password)
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users[actor].Id).Update("password", hashed).Error)
		c.passwords[actor] = password
		c.login(t, actor)
	}
	return c
}

func (c *organizationLifecycleClient) json(t *testing.T, method, path, actor string, body any, proof string) (int, http.Header, map[string]any) {
	t.Helper()
	raw := ""
	if body != nil {
		b, err := common.Marshal(body)
		require.NoError(t, err)
		raw = string(b)
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if proof != "" {
		h.Set("X-Security-Proof", proof)
	}
	return c.request(t, method, path, actor, raw, h)
}
func (c *organizationLifecycleClient) login(t *testing.T, actor string) {
	t.Helper()
	status, h, b := c.json(t, "POST", "/api/user/login", "", map[string]any{"username": c.users[actor].Username, "password": c.passwords[actor]}, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	c.installBundle(t, actor, b["data"], h)
}
func (c *organizationLifecycleClient) installBundle(t *testing.T, actor string, value any, h http.Header) {
	t.Helper()
	bundle, ok := value.(map[string]any)
	require.True(t, ok)
	token, ok := bundle["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, token)
	session, ok := bundle["session"].(map[string]any)
	require.True(t, ok)
	sid, ok := session["sid"].(string)
	require.True(t, ok)
	require.NotEmpty(t, sid)
	c.bearer[actor], c.sids[actor] = token, sid
	previousRefresh := c.refresh[actor]
	c.refresh[actor] = ""
	for _, cookie := range (&http.Response{Header: h}).Cookies() {
		if cookie.Name == service.RefreshCookieName {
			c.refresh[actor] = cookie.Value
		}
	}
	require.NotEmpty(t, c.refresh[actor], "new response must carry refresh cookie")
	require.True(t, previousRefresh != c.refresh[actor], "refresh must be newly issued")
	cookieSID, valid := service.RefreshTokenSID(c.refresh[actor])
	require.True(t, valid)
	assert.Equal(t, sid, cookieSID)
}
func (c *organizationLifecycleClient) revision(t *testing.T) string {
	t.Helper()
	var org model.Organization
	require.NoError(t, c.db.First(&org, c.orgA).Error)
	return strconv.FormatInt(org.Revision, 10)
}
func (c *organizationLifecycleClient) path() string {
	return fmt.Sprintf("/api/organizations/%d", c.orgA)
}
func (c *organizationLifecycleClient) operation(t *testing.T, actor, action string, body map[string]any, targets map[string]any) map[string]any {
	t.Helper()
	command := map[string]any{"organization_id": strconv.FormatInt(c.orgA, 10)}
	for k, v := range body {
		command[k] = v
	}
	for k, v := range targets {
		command[k] = v
	}
	path := c.path() + "/authorization-context"
	if action == "platform_disable" {
		path = fmt.Sprintf("/api/platform/organizations/%d/authorization-context", c.orgA)
	}
	status, h, b := c.json(t, "POST", path, actor, map[string]any{"action": action, "command": command}, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	assert.True(t, organizationPrivateNoStore(h.Values("Cache-Control")), "Cache-Control requires unqualified private and no-store")
	data, ok := b["data"].(map[string]any)
	require.True(t, ok)
	op, ok := data["operation"].(map[string]any)
	require.True(t, ok)
	context, ok := op["context"].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, 1, context["schema_version"])
	assert.Equal(t, command, context["command"])
	assert.NotContains(t, context, "command_hash")
	return op
}
func (c *organizationLifecycleClient) proof(t *testing.T, actor string, op map[string]any, method, code string) string {
	t.Helper()
	body := map[string]any{"scope": op["scope"], "context": op["context"], "method": method}
	if method == "password" {
		body["password"] = c.passwords[actor]
	} else {
		body["code"] = code
	}
	// Establish that this exact refresh request passes Origin/session guards
	// before testing revocation. The replacement refresh remains fixture-only.
	preStatus, preHeaders, preBody := c.request(t, "POST", "/api/user/auth/refresh", "", "", http.Header{"Cookie": {service.RefreshCookieName + "=" + c.refresh[actor]}, "Origin": {c.server.URL}, "X-Auth-Session": {c.sids[actor]}})
	require.Equal(t, 200, preStatus)
	require.Equal(t, true, preBody["success"])
	c.installBundle(t, actor, preBody["data"], preHeaders)
	oldToken, oldSID, oldRefresh := c.bearer[actor], c.sids[actor], c.refresh[actor]
	var old model.UserSession
	require.NoError(t, c.db.Where("sid = ?", oldSID).First(&old).Error)
	status, h, b := c.json(t, "POST", "/api/verify", actor, body, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	data, ok := b["data"].(map[string]any)
	require.True(t, ok)
	proof, ok := data["proof_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, proof)
	assert.Equal(t, method, data["method"])
	assert.Equal(t, op["scope"], data["scope"])
	c.installBundle(t, actor, data["auth_bundle"], h)
	assert.True(t, oldSID != c.sids[actor], "SID must rotate")
	assert.True(t, oldRefresh != c.refresh[actor], "refresh cookie must rotate")
	var rotated model.UserSession
	require.NoError(t, c.db.Where("sid = ?", c.sids[actor]).First(&rotated).Error)
	assert.Equal(t, old.ExpiresAt, rotated.ExpiresAt)
	assert.Equal(t, old.UserAuthVersion, rotated.UserAuthVersion)
	assert.EqualValues(t, 1, rotated.Version)
	status, _, _ = c.json(t, "GET", c.path()+"/self-state", oldToken, nil, "")
	assert.Equal(t, 401, status)
	status, _, b = c.request(t, "POST", "/api/user/auth/refresh", "", "", http.Header{"Cookie": {service.RefreshCookieName + "=" + oldRefresh}, "Origin": {c.server.URL}, "X-Auth-Session": {oldSID}})
	assert.Equal(t, 401, status)
	assert.Equal(t, false, b["success"])
	assert.Equal(t, "AUTH_SESSION_REVOKED", b["code"])
	var revoked model.UserSession
	require.NoError(t, c.db.Where("sid = ?", oldSID).First(&revoked).Error)
	assert.Equal(t, model.UserSessionStatusRevoked, revoked.Status)
	assert.Positive(t, revoked.RevokedAt)
	assert.Empty(t, revoked.PreviousRefreshHash)
	assert.Zero(t, revoked.PreviousValidUntil)
	return proof
}
func (c *organizationLifecycleClient) mutate(t *testing.T, actor, method, path, action string, body map[string]any, targets map[string]any, sensitive bool) map[string]any {
	t.Helper()
	proof := ""
	if sensitive {
		op := c.operation(t, actor, action, body, targets)
		proof = c.proof(t, actor, op, "password", "")
	}
	status, h, b := c.json(t, method, path, actor, body, proof)
	want := 200
	if action == "create" {
		want = 201
	}
	require.Equal(t, want, status)
	require.Equal(t, true, b["success"])
	assert.True(t, organizationPrivateNoStore(h.Values("Cache-Control")), "Cache-Control requires unqualified private and no-store")
	receipt, ok := b["data"].(map[string]any)
	require.True(t, ok)
	require.Len(t, receipt, 8)
	for _, key := range []string{"organization_id", "revision", "action", "event_id", "object_kind", "object_id", "generation", "status"} {
		require.Contains(t, receipt, key)
	}
	eventID, ok := receipt["event_id"].(string)
	require.True(t, ok)
	var event model.OrganizationEvent
	require.NoError(t, c.db.Where("id = ?", eventID).First(&event).Error)
	assert.Equal(t, strconv.FormatInt(event.OrganizationID, 10), receipt["organization_id"])
	assert.Equal(t, strconv.FormatInt(event.OrganizationRevision, 10), receipt["revision"])
	assert.Equal(t, action, receipt["action"])
	expectedEvent := map[string]string{
		"create": "organization.created", "rename": "organization.rename", "self_disable": "organization.self_disable", "platform_disable": "organization.platform_disable", "dissolve": "organization.dissolve",
		"change_role": "member.change_role", "remove": "member.remove", "leave": "member.leave", "invite": "invitation.issued", "reissue": "invitation.issued",
		"invitation_accept": "invitation.accepted", "invitation_decline": "invitation.declined", "invitation_revoke": "invitation.revoked", "transfer_initiate": "transfer.initiated", "transfer_accept": "transfer.accepted", "transfer_decline": "transfer.declined", "transfer_cancel": "transfer.cancelled",
	}[action]
	assert.Equal(t, expectedEvent, event.Action)
	assert.Equal(t, event.ObjectKind, receipt["object_kind"])
	assert.Equal(t, strconv.FormatInt(event.ObjectID, 10), receipt["object_id"])
	if event.ObjectKind == "organization" || event.ObjectKind == "member" {
		assert.Nil(t, receipt["generation"])
		assert.Nil(t, receipt["status"])
	} else {
		assert.Equal(t, strconv.FormatInt(event.ObjectGeneration, 10), receipt["generation"])
		assert.Equal(t, event.AfterState, receipt["status"])
	}
	return receipt
}

func TestOrganizationLifecycleWriteReceipts(t *testing.T) {
	for _, action := range []string{"create", "rename", "self_disable", "platform_disable", "dissolve", "change_role", "remove", "leave", "invite", "reissue", "invitation_accept", "invitation_decline", "invitation_revoke", "transfer_initiate", "transfer_accept", "transfer_decline", "transfer_cancel"} {
		t.Run(action, func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			body := map[string]any{"revision": c.revision(t)}
			method, path, actor, sensitive := "POST", c.path(), "owner", false
			targets := map[string]any{}
			switch action {
			case "create":
				path = "/api/organizations"
				body = map[string]any{"name": "组织 S3"}
			case "rename":
				method = "PATCH"
				path += "/name"
				body["name"] = " renamed "
			case "self_disable":
				path += "/self-state"
				body["disabled"] = true
				body["reason"] = "fixture"
				sensitive = true
			case "platform_disable":
				path = fmt.Sprintf("/api/platform/organizations/%d/state", c.orgA)
				actor = "root"
				body["disabled"] = true
				body["reason"] = "fixture"
				sensitive = true
			case "dissolve":
				path += "/dissolve"
				sensitive = true
			case "change_role":
				method = "PATCH"
				path += fmt.Sprintf("/members/%d/role", c.users["member"].Id)
				body["role"] = "admin"
				targets["target_user_id"] = strconv.Itoa(c.users["member"].Id)
				sensitive = true
			case "remove":
				method = "DELETE"
				path += fmt.Sprintf("/members/%d", c.users["admin"].Id)
				targets["target_user_id"] = strconv.Itoa(c.users["admin"].Id)
				sensitive = true
			case "leave":
				path += "/leave"
				actor = "member"
			case "invite":
				path += "/invitations"
				body["target_user_id"] = strconv.Itoa(c.users["foreign"].Id)
				body["role"] = "admin"
				sensitive = true
			case "reissue", "invitation_accept", "invitation_decline", "invitation_revoke":
				invitation := c.mutate(t, "owner", "POST", path+"/invitations", "invite", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["foreign"].Id), "role": "member"}, nil, false)
				body = map[string]any{"revision": c.revision(t), "generation": invitation["generation"]}
				path += "/invitations/" + invitation["object_id"].(string)
				if action == "reissue" {
					path += "/reissue"
					body["target_user_id"] = strconv.Itoa(c.users["foreign"].Id)
					body["role"] = "admin"
					targets["invitation_id"] = invitation["object_id"]
					sensitive = true
				} else {
					path += "/" + strings.TrimPrefix(action, "invitation_")
					if action != "invitation_revoke" {
						actor = "foreign"
					}
				}
			case "transfer_initiate":
				path += "/ownership-transfers"
				body["target_user_id"] = strconv.Itoa(c.users["member"].Id)
				body["previous_id"] = "0"
				body["previous_generation"] = "0"
				body["replace"] = false
				sensitive = true
			default:
				transfer := c.mutate(t, "owner", "POST", path+"/ownership-transfers", "transfer_initiate", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["member"].Id), "previous_id": "0", "previous_generation": "0", "replace": false}, nil, true)
				path += "/ownership-transfers/" + transfer["object_id"].(string) + "/" + strings.TrimPrefix(action, "transfer_")
				body = map[string]any{"revision": c.revision(t), "generation": transfer["generation"]}
				targets["transfer_id"] = transfer["object_id"]
				if action != "transfer_cancel" {
					actor = "member"
				}
				sensitive = action == "transfer_accept"
			}
			receipt := c.mutate(t, actor, method, path, action, body, targets, sensitive)
			if action != "create" {
				assert.Equal(t, strconv.FormatInt(c.orgA, 10), receipt["organization_id"])
			}
		})
	}
}

func TestOrganizationLifecycleStrictTransport(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	valid := fmt.Sprintf(`{"revision":%q,"name":"valid"}`, c.revision(t))
	for _, tc := range []struct {
		name, body string
		headers    http.Header
		status     int
		code       string
	}{
		{"duplicate", `{"revision":"1","name":"a","name":"b"}`, nil, 400, "ORG_REQUEST_INVALID"},
		{"unknown", `{"revision":"1","name":"a","extra":0}`, nil, 400, "ORG_REQUEST_INVALID"},
		{"null", `{"revision":"1","name":null}`, nil, 400, "ORG_REQUEST_INVALID"},
		{"trailing", valid + ` {}`, nil, 400, "ORG_REQUEST_INVALID"},
		{"array", `[]`, nil, 400, "ORG_REQUEST_INVALID"},
		{"numeric_id", `{"revision":9007199254740993,"name":"a"}`, nil, 400, "ORG_REQUEST_INVALID"},
		{"invalid_utf8", "{\"revision\":\"1\",\"name\":\"\xff\"}", nil, 400, "ORG_REQUEST_INVALID"},
		{"size", strings.Repeat(" ", 16385) + valid, nil, 413, "REQUEST_TOO_LARGE"},
		{"media", valid, http.Header{"Content-Type": {"text/plain"}}, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"origin", valid, http.Header{"Origin": {"https://untrusted.invalid"}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"null_origin", valid, http.Header{"Origin": {"null"}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"fetch_without_origin", valid, http.Header{"Sec-Fetch-Site": {"same-site"}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"idempotency", valid, http.Header{"Idempotency-Key": {"unsupported"}}, 400, "ORG_REQUEST_INVALID"},
		{"override", valid, http.Header{"X-HTTP-Method-Override": {"DELETE"}}, 400, "ORG_REQUEST_INVALID"},
		{"proof_forbidden", valid, http.Header{"X-Security-Proof": {"not-a-proof"}}, 400, "ORG_REQUEST_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Content-Type": {"application/json"}}
			for k, v := range tc.headers {
				h[k] = v
			}
			status, headers, b := c.request(t, "PATCH", c.path()+"/name", "owner", tc.body, h)
			organizationError(t, status, headers, b, tc.status, tc.code)
		})
	}
}

func TestOrganizationLifecycleVisibilityAndRevision(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	body := map[string]any{"revision": "1", "name": "not-visible"}
	for _, path := range []string{c.path() + "/name", "/api/organizations/9223372036854775806/name"} {
		status, h, b := c.json(t, "PATCH", path, "foreign", body, "")
		organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
	}
	status, h, b := c.json(t, "PATCH", c.path()+"/name", "owner", body, "")
	organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
	c.mutate(t, "owner", "POST", c.path()+"/self-state", "self_disable", map[string]any{"revision": c.revision(t), "disabled": true, "reason": "private reason"}, nil, true)
	status, _, b = c.json(t, "GET", c.path()+"/self-state", "member", nil, "")
	require.Equal(t, 200, status)
	data := b["data"].(map[string]any)
	assert.Equal(t, true, data["self_disabled"])
	assert.NotContains(t, data, "reason")
	assert.NotContains(t, data, "platform_disabled_reason")
	status, h, b = c.json(t, "PATCH", c.path()+"/name", "owner", map[string]any{"revision": c.revision(t), "name": "disabled"}, "")
	organizationError(t, status, h, b, 409, "ORG_DISABLED")
	c.mutate(t, "member", "POST", c.path()+"/leave", "leave", map[string]any{"revision": c.revision(t)}, nil, false)
	status, h, b = c.json(t, "GET", c.path()+"/self-state", "member", nil, "")
	organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
}

func TestOrganizationLifecycleHistory(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	invitation := c.mutate(t, "owner", "POST", c.path()+"/invitations", "invite", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["foreign"].Id), "role": "member"}, nil, false)
	slot := c.path() + "/invitations/" + invitation["object_id"].(string)
	history := slot + "/generations/" + invitation["generation"].(string)
	status, _, b := c.json(t, "GET", history, "foreign", nil, "")
	require.Equal(t, 200, status)
	pending := b["data"].(map[string]any)
	assert.Equal(t, c.revision(t), pending["organization_revision"])
	assert.NotNil(t, pending["organization_name"])
	c.mutate(t, "foreign", "POST", slot+"/decline", "invitation_decline", map[string]any{"revision": c.revision(t), "generation": invitation["generation"]}, nil, false)
	c.mutate(t, "owner", "POST", slot+"/reissue", "reissue", map[string]any{"revision": c.revision(t), "generation": invitation["generation"], "target_user_id": strconv.Itoa(c.users["foreign"].Id), "role": "member"}, nil, false)
	status, _, b = c.json(t, "GET", history, "foreign", nil, "")
	require.Equal(t, 200, status)
	terminal := b["data"].(map[string]any)
	assert.Equal(t, "declined", terminal["status"])
	assert.Nil(t, terminal["organization_revision"])
	assert.Nil(t, terminal["organization_name"])
	status, h, b := c.json(t, "GET", history, "empty", nil, "")
	organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
}

func TestOrganizationLifecycleProofBindingsAndExpiry(t *testing.T) {
	for _, scenario := range []string{"context", "signature", "other_session", "expiry"} {
		t.Run(scenario, func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			body := map[string]any{"revision": c.revision(t), "disabled": true, "reason": "bound"}
			op := c.operation(t, "owner", "self_disable", body, nil)
			proof := c.proof(t, "owner", op, "password", "")
			originalProof, originalBearer := proof, c.bearer["owner"]
			originalBody := map[string]any{"revision": body["revision"], "disabled": true, "reason": "bound"}
			var flows []model.AuthFlow
			require.NoError(t, c.db.Where("purpose = ? AND user_id = ? AND session_id = ?", model.AuthFlowPurposeSecurityProof, c.users["owner"].Id, c.sids["owner"]).Find(&flows).Error)
			require.Len(t, flows, 1)
			require.Nil(t, flows[0].ConsumedAt)
			want := "SECURITY_PROOF_CONTEXT_MISMATCH"
			switch scenario {
			case "context":
				body["reason"] = "changed"
			case "signature":
				parts := strings.Split(proof, ".")
				require.Len(t, parts, 3)
				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				require.NoError(t, err)
				sig[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(sig)
				proof = strings.Join(parts, ".")
				want = "SECURITY_PROOF_INVALID"
			case "other_session":
				c.login(t, "owner")
				want = "SECURITY_PROOF_INVALID"
			case "expiry":
				require.NoError(t, c.db.Model(&model.AuthFlow{}).Where("purpose = ? AND user_id = ? AND consumed_at IS NULL", model.AuthFlowPurposeSecurityProof, c.users["owner"].Id).Update("expires_at", time.Now().Add(-time.Second)).Error)
				want = "SECURITY_PROOF_EXPIRED"
			}
			status, h, b := c.json(t, "POST", c.path()+"/self-state", "owner", body, proof)
			organizationError(t, status, h, b, 403, want)
			var org model.Organization
			require.NoError(t, c.db.First(&org, c.orgA).Error)
			assert.Zero(t, org.SelfDisabledAt)
			var rejectedFlow model.AuthFlow
			require.NoError(t, c.db.First(&rejectedFlow, flows[0].Id).Error)
			assert.Nil(t, rejectedFlow.ConsumedAt, "pre-consumption rejection must leave exact proof unconsumed")
			if scenario != "expiry" {
				status, _, b = c.json(t, "POST", c.path()+"/self-state", originalBearer, originalBody, originalProof)
				require.Equal(t, 200, status)
				require.Equal(t, true, b["success"])
				var consumed model.AuthFlow
				require.NoError(t, c.db.First(&consumed, flows[0].Id).Error)
				assert.NotNil(t, consumed.ConsumedAt)
			}
		})
	}
}

func TestOrganizationLifecycleConsumedProofAndAtomicRollback(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	body := map[string]any{"revision": c.revision(t), "disabled": true, "reason": "rollback"}
	op := c.operation(t, "owner", "self_disable", body, nil)
	proof := c.proof(t, "owner", op, "password", "")
	var before model.Organization
	require.NoError(t, c.db.First(&before, c.orgA).Error)
	var eventCount int64
	require.NoError(t, c.db.Model(&model.OrganizationEvent{}).Where("organization_id = ?", c.orgA).Count(&eventCount).Error)
	callback := "s3_fail_primary_event"
	require.NoError(t, c.db.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Table == "organization_events" {
			tx.AddError(errors.New("isolated event insertion failure"))
		}
	}))
	t.Cleanup(func() { _ = c.db.Callback().Create().Remove(callback) })
	status, h, b := c.json(t, "POST", c.path()+"/self-state", "owner", body, proof)
	organizationError(t, status, h, b, 500, "ORG_INTERNAL_ERROR")
	require.NoError(t, c.db.Callback().Create().Remove(callback))
	var after model.Organization
	require.NoError(t, c.db.First(&after, c.orgA).Error)
	assert.Equal(t, before, after)
	var afterCount int64
	require.NoError(t, c.db.Model(&model.OrganizationEvent{}).Where("organization_id = ?", c.orgA).Count(&afterCount).Error)
	assert.Equal(t, eventCount, afterCount)
	// Same revision and unchanged command: this cannot be explained by stale revision.
	status, h, b = c.json(t, "POST", c.path()+"/self-state", "owner", body, proof)
	organizationError(t, status, h, b, 403, "SECURITY_PROOF_CONSUMED")
}

func TestOrganizationLifecycleAccountAttemptBudget(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	op := c.operation(t, "owner", "dissolve", map[string]any{"revision": c.revision(t)}, nil)
	other := c.operation(t, "owner", "self_disable", map[string]any{"revision": c.revision(t), "disabled": true, "reason": "budget"}, nil)
	// Independent sessions, shared account; wrong factors avoid rotating either SID.
	firstToken := c.bearer["owner"]
	c.login(t, "owner")
	secondToken := c.bearer["owner"]
	type result struct {
		status int
		retry  string
		code   any
	}
	results := make(chan result, 6)
	var workers sync.WaitGroup
	for i := range 6 {
		workers.Go(func() {
			operation := op
			token := firstToken
			if i%2 == 1 {
				operation = other
				token = secondToken
			}
			raw, err := common.Marshal(map[string]any{"scope": operation["scope"], "context": operation["context"], "method": "password", "password": "wrong-local-password"})
			if err != nil {
				results <- result{status: -1}
				return
			}
			req, err := http.NewRequest("POST", c.server.URL+"/api/verify", strings.NewReader(string(raw)))
			if err != nil {
				results <- result{status: -1}
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := c.client.Do(req)
			if err != nil {
				results <- result{status: -1}
				return
			}
			defer resp.Body.Close()
			var body map[string]any
			err = common.DecodeJson(resp.Body, &body)
			if err != nil {
				results <- result{status: -1}
				return
			}
			results <- result{resp.StatusCode, resp.Header.Get("Retry-After"), body["code"]}
		})
	}
	workers.Wait()
	close(results)
	denied, limited := 0, 0
	for r := range results {
		switch r.status {
		case 403:
			denied++
			assert.Equal(t, "SECURITY_VERIFICATION_FAILED", r.code)
		case 429:
			limited++
			assert.Equal(t, "SECURITY_VERIFICATION_RATE_LIMITED", r.code)
			retry, err := strconv.Atoi(r.retry)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, retry, 1)
			assert.LessOrEqual(t, retry, 300)
		default:
			t.Errorf("unexpected verification HTTP status %d", r.status)
		}
	}
	assert.Equal(t, 5, denied)
	assert.Equal(t, 1, limited)
	var attempts int64
	require.NoError(t, c.db.Model(&model.AuthFlow{}).Where("purpose = ? AND user_id = ?", "org_verify_attempt", c.users["owner"].Id).Count(&attempts).Error)
	assert.EqualValues(t, 5, attempts)
	// Move owned fixture timestamps rather than waiting five minutes.
	require.NoError(t, c.db.Model(&model.AuthFlow{}).Where("purpose = ? AND user_id = ?", "org_verify_attempt", c.users["owner"].Id).Updates(map[string]any{"created_at": time.Now().Add(-301 * time.Second), "expires_at": time.Now().Add(-time.Second)}).Error)
	c.proof(t, "owner", op, "password", "")
}

func TestOrganizationLifecycleTOTPReuseAcrossScopes(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	factor := &model.TwoFA{UserId: c.users["owner"].Id, Secret: "JBSWY3DPEHPK3PXP", IsEnabled: true}
	require.NoError(t, c.db.Create(factor).Error)
	body := map[string]any{"revision": c.revision(t), "disabled": true, "reason": "TOTP"}
	op := c.operation(t, "owner", "self_disable", body, nil)
	code, err := totp.GenerateCode(factor.Secret, time.Now())
	require.NoError(t, err)
	proof := c.proof(t, "owner", op, "2fa", code)
	other := c.operation(t, "owner", "dissolve", map[string]any{"revision": c.revision(t)}, nil)
	status, h, b := c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": other["scope"], "context": other["context"], "method": "2fa", "code": code}, "")
	organizationError(t, status, h, b, 403, "SECURITY_VERIFICATION_FAILED")
	status, h, b = c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": other["scope"], "context": other["context"], "method": "password", "password": c.passwords["owner"]}, "")
	organizationError(t, status, h, b, 403, "SECURITY_METHOD_UNAVAILABLE")
	status, _, b = c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": "2fa.disable", "method": "2fa", "code": code}, "")
	assert.Equal(t, 200, status)
	assert.Equal(t, "SECURITY_VERIFICATION_FAILED", b["code"])
	assert.Equal(t, false, b["success"])
	assert.NotContains(t, slices.Collect(maps.Keys(b)), "data")
	status, _, b = c.json(t, "POST", c.path()+"/self-state", "owner", body, proof)
	require.Equal(t, 200, status)
	assert.Equal(t, true, b["success"])
}

func TestOrganizationLifecycleSoftwarePasskey(t *testing.T) {
	for _, scenario := range []string{"valid", "uv_missing", "wrong_rp", "wrong_origin", "wrong_challenge", "clone", "counter_regression", "zero_counter", "backup", "nullable_user_handle", "case_alias_finish", "mixed_alias_finish", "flow_lookup_failure"} {
		t.Run(scenario, func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			id := sha256.Sum256(elliptic.Marshal(key.Curve, key.X, key.Y))
			publicKey, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
			require.NoError(t, err)
			require.NoError(t, c.db.Create(&model.PasskeyCredential{UserID: c.users["owner"].Id, CredentialID: base64.StdEncoding.EncodeToString(id[:]), PublicKey: base64.StdEncoding.EncodeToString(publicKey), UserPresent: true, UserVerified: true}).Error)
			if scenario == "counter_regression" {
				require.NoError(t, c.db.Model(&model.PasskeyCredential{}).Where("user_id = ?", c.users["owner"].Id).Update("sign_count", 5).Error)
			}
			if scenario == "backup" {
				require.NoError(t, c.db.Model(&model.PasskeyCredential{}).Where("user_id = ?", c.users["owner"].Id).Update("backup_eligible", true).Error)
			}
			body := map[string]any{"revision": c.revision(t), "disabled": true, "reason": "passkey"}
			op := c.operation(t, "owner", "self_disable", body, nil)
			status, _, b := c.json(t, "POST", "/api/user/passkey/verify/begin", "owner", map[string]any{"scope": op["scope"], "context": op["context"]}, "")
			require.Equal(t, 200, status)
			require.Equal(t, true, b["success"])
			data := b["data"].(map[string]any)
			options := data["options"].(map[string]any)["publicKey"].(map[string]any)
			assert.Equal(t, "required", options["userVerification"])
			origin, rp, challenge := "https://example.com", "example.com", options["challenge"]
			if scenario == "wrong_origin" {
				origin = "https://other.invalid"
			}
			if scenario == "wrong_rp" {
				rp = "other.invalid"
			}
			if scenario == "wrong_challenge" {
				challenge = base64.RawURLEncoding.EncodeToString([]byte("different-challenge"))
			}
			if scenario == "clone" {
				require.NoError(t, c.db.Model(&model.PasskeyCredential{}).Where("user_id = ?", c.users["owner"].Id).Update("clone_warning", true).Error)
			}
			clientData, err := common.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin})
			require.NoError(t, err)
			rpHash := sha256.Sum256([]byte(rp))
			authData := append([]byte{}, rpHash[:]...)
			flags := byte(5)
			if scenario == "uv_missing" {
				flags = 1
			}
			if scenario == "backup" {
				flags = 0x1d
			}
			authData = append(authData, flags)
			counter := uint32(1)
			if scenario == "zero_counter" {
				counter = 0
			}
			authData = binary.BigEndian.AppendUint32(authData, counter)
			clientHash := sha256.Sum256(clientData)
			signedHash := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
			signature, err := ecdsa.SignASN1(rand.Reader, key, signedHash[:])
			require.NoError(t, err)
			credentialID := base64.RawURLEncoding.EncodeToString(id[:])
			credential := map[string]any{"id": credentialID, "rawId": credentialID, "type": "public-key", "response": map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(clientData), "authenticatorData": base64.RawURLEncoding.EncodeToString(authData), "signature": base64.RawURLEncoding.EncodeToString(signature)}}
			if scenario == "nullable_user_handle" {
				credential["response"].(map[string]any)["userHandle"] = nil
			}
			finishBody := map[string]any{"flow_token": data["flow_token"], "credential": credential}
			if scenario == "case_alias_finish" {
				finishBody["FLOW_TOKEN"] = data["flow_token"]
				finishBody["Credential"] = credential
			}
			var ceremony model.AuthFlow
			if scenario == "mixed_alias_finish" || scenario == "flow_lookup_failure" {
				require.NoError(t, c.db.Where("purpose = ? AND user_id = ?", model.AuthFlowPurposePasskeyStepUp, c.users["owner"].Id).Order("id DESC").First(&ceremony).Error)
				require.Nil(t, ceremony.ConsumedAt)
			}
			if scenario == "mixed_alias_finish" {
				finishBody["FLOW_TOKEN"] = data["flow_token"]
				finishBody["flow_token"] = "unknown-owned-flow-token"
			}
			var lookupFailed atomic.Bool
			if scenario == "flow_lookup_failure" {
				require.NoError(t, c.db.Callback().Query().Before("gorm:query").Register("s3:first_flow_failure", func(tx *gorm.DB) {
					if tx.Statement.Table == "auth_flows" && lookupFailed.CompareAndSwap(false, true) {
						tx.AddError(errors.New("owned first flow lookup failure"))
					}
				}))
				t.Cleanup(func() { _ = c.db.Callback().Query().Remove("s3:first_flow_failure") })
			}
			oldSID := c.sids["owner"]
			status, h, b := c.json(t, "POST", "/api/user/passkey/verify/finish", "owner", finishBody, "")
			if scenario == "mixed_alias_finish" || scenario == "flow_lookup_failure" {
				if scenario == "flow_lookup_failure" {
					require.NoError(t, c.db.Callback().Query().Remove("s3:first_flow_failure"))
					assert.True(t, lookupFailed.Load())
				}
				assert.Equal(t, false, b["success"])
				assert.NotContains(t, slices.Collect(maps.Keys(b)), "data")
				assert.Empty(t, h.Values("Set-Cookie"))
				var after model.AuthFlow
				require.NoError(t, c.db.First(&after, ceremony.Id).Error)
				assert.Nil(t, after.ConsumedAt, "classification failure must not consume organization ceremony")
				var factor model.PasskeyCredential
				require.NoError(t, c.db.Where("user_id = ?", c.users["owner"].Id).First(&factor).Error)
				assert.Zero(t, factor.SignCount, "classification failure must not advance software authenticator counter")
				if scenario == "mixed_alias_finish" {
					assert.Equal(t, 400, status)
				} else {
					assert.Equal(t, 500, status)
				}
				return
			}
			if scenario == "case_alias_finish" {
				organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
				return
			}
			if scenario != "valid" && scenario != "zero_counter" && scenario != "backup" && scenario != "nullable_user_handle" {
				organizationError(t, status, h, b, 403, "SECURITY_VERIFICATION_FAILED")
				return
			}
			require.Equal(t, 200, status)
			require.Equal(t, true, b["success"])
			result := b["data"].(map[string]any)
			c.installBundle(t, "owner", result["auth_bundle"], h)
			assert.True(t, oldSID != c.sids["owner"], "SID must rotate")
			status, _, b = c.json(t, "POST", c.path()+"/self-state", "owner", body, result["proof_token"].(string))
			require.Equal(t, 200, status)
			assert.Equal(t, true, b["success"])
			var count int64
			require.NoError(t, c.db.Model(&model.AuthFlow{}).Where("purpose = ? AND user_id = ?", "org_verify_attempt", c.users["owner"].Id).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})
	}
}

func TestOrganizationLifecycleRouteAuthentication(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	for _, route := range []struct{ name, method, path string }{
		{"organization_create", "POST", "/api/organizations"},
		{"organization_rename", "PATCH", "/api/organizations/9007199254740993/name"},
		{"organization_self_disable", "POST", "/api/organizations/9007199254740993/self-state"},
		{"organization_platform_disable", "POST", "/api/platform/organizations/9007199254740993/state"},
		{"organization_dissolve", "POST", "/api/organizations/9007199254740993/dissolve"},
		{"organization_change_role", "PATCH", "/api/organizations/9007199254740993/members/1/role"},
		{"organization_remove", "DELETE", "/api/organizations/9007199254740993/members/1"},
		{"organization_leave", "POST", "/api/organizations/9007199254740993/leave"},
		{"organization_invite", "POST", "/api/organizations/9007199254740993/invitations"},
		{"organization_reissue", "POST", "/api/organizations/9007199254740993/invitations/1/reissue"},
		{"organization_invitation_accept", "POST", "/api/organizations/9007199254740993/invitations/1/accept"},
		{"organization_invitation_decline", "POST", "/api/organizations/9007199254740993/invitations/1/decline"},
		{"organization_invitation_revoke", "POST", "/api/organizations/9007199254740993/invitations/1/revoke"},
		{"organization_transfer_initiate", "POST", "/api/organizations/9007199254740993/ownership-transfers"},
		{"organization_transfer_accept", "POST", "/api/organizations/9007199254740993/ownership-transfers/1/accept"},
		{"organization_transfer_decline", "POST", "/api/organizations/9007199254740993/ownership-transfers/1/decline"},
		{"organization_transfer_cancel", "POST", "/api/organizations/9007199254740993/ownership-transfers/1/cancel"},
		{"organization_invitation_inbox", "GET", "/api/organization-invitations"},
		{"organization_transfer_inbox", "GET", "/api/organization-ownership-transfers"},
		{"organization_invitation_slots", "GET", "/api/organizations/9007199254740993/invitations"},
		{"organization_transfer_slot", "GET", "/api/organizations/9007199254740993/ownership-transfer"},
		{"organization_invitation_result", "GET", "/api/organizations/9007199254740993/invitations/1/generations/1"},
		{"organization_transfer_result", "GET", "/api/organizations/9007199254740993/ownership-transfers/1/generations/1"},
		{"organization_self_state", "GET", "/api/organizations/9007199254740993/self-state"},
		{"organization_platform_state", "GET", "/api/platform/organizations/9007199254740993/state"},
		{"organization_authorization_context", "POST", "/api/organizations/9007199254740993/authorization-context"},
		{"organization_authorization_context_platform", "POST", "/api/platform/organizations/9007199254740993/authorization-context"},
		{"existing_verification_methods_organization_branch", "GET", "/api/verify/methods?scope=organization.dissolve"},
		{"existing_verify_organization_branch", "POST", "/api/verify"},
		{"existing_passkey_begin_organization_branch", "POST", "/api/user/passkey/verify/begin"},
		{"existing_passkey_finish_organization_branch", "POST", "/api/user/passkey/verify/finish"},
	} {
		t.Run(route.name, func(t *testing.T) {
			body := any(map[string]any{})
			if route.method == "GET" {
				body = nil
			}
			status, h, b := c.json(t, route.method, route.path, "", body, "")
			require.Equal(t, 401, status)
			assert.Equal(t, false, b["success"])
			assert.True(t, organizationPrivateNoStore(h.Values("Cache-Control")), "Cache-Control requires unqualified private and no-store")
			assert.NotContains(t, slices.Collect(maps.Keys(b)), "data")
		})
	}
}

func TestOrganizationLifecycleReadRoutes(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	invitation := c.mutate(t, "owner", "POST", c.path()+"/invitations", "invite", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["foreign"].Id), "role": "member"}, nil, false)
	transfer := c.mutate(t, "owner", "POST", c.path()+"/ownership-transfers", "transfer_initiate", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["member"].Id), "previous_id": "0", "previous_generation": "0", "replace": false}, nil, true)
	for _, route := range []struct{ name, path, actor string }{
		{"invitation_inbox", "/api/organization-invitations", "foreign"},
		{"transfer_inbox", "/api/organization-ownership-transfers", "member"},
		{"invitation_slots", c.path() + "/invitations", "owner"},
		{"transfer_slot", c.path() + "/ownership-transfer", "owner"},
		{"invitation_result", c.path() + "/invitations/" + invitation["object_id"].(string) + "/generations/" + invitation["generation"].(string), "foreign"},
		{"transfer_result", c.path() + "/ownership-transfers/" + transfer["object_id"].(string) + "/generations/" + transfer["generation"].(string), "member"},
		{"self_state", c.path() + "/self-state", "member"},
		{"platform_state", fmt.Sprintf("/api/platform/organizations/%d/state", c.orgA), "root"},
		{"methods", "/api/verify/methods?scope=organization.dissolve", "owner"},
	} {
		t.Run(route.name, func(t *testing.T) {
			status, h, b := c.json(t, "GET", route.path, route.actor, nil, "")
			require.Equal(t, 200, status)
			require.Equal(t, true, b["success"])
			assert.True(t, organizationPrivateNoStore(h.Values("Cache-Control")), "Cache-Control requires unqualified private and no-store")
			require.Contains(t, b, "data")
			if route.name == "methods" {
				methods := b["data"].(map[string]any)
				entries, ok := methods["methods"].([]any)
				require.True(t, ok)
				found := false
				for _, entry := range entries {
					m, ok := entry.(map[string]any)
					require.True(t, ok)
					if m["method"] == "password" {
						found = true
						assert.Equal(t, true, m["available"])
					}
				}
				assert.True(t, found, "password method must be discoverable and available")
				assert.Empty(t, methods["oauth_providers"])
			}
			if strings.HasPrefix(route.name, "invitation_") || strings.HasPrefix(route.name, "transfer_") {
				view := b["data"].(map[string]any)
				if strings.HasSuffix(route.name, "inbox") || route.name == "invitation_slots" {
					assert.EqualValues(t, 20, view["limit"])
					assert.IsType(t, float64(0), view["limit"])
					assert.Nil(t, view["next_after_id"])
					items := view["items"].([]any)
					require.Len(t, items, 1)
					view = items[0].(map[string]any)
				}
				expected, target, kind := invitation, "foreign", "invitation"
				if strings.HasPrefix(route.name, "transfer_") {
					expected, target, kind = transfer, "member", "transfer"
				}
				assert.Equal(t, expected["object_id"], view["object_id"])
				assert.Equal(t, expected["generation"], view["generation"])
				assert.Equal(t, strconv.FormatInt(c.orgA, 10), view["organization_id"])
				assert.Equal(t, strconv.Itoa(c.users["owner"].Id), view["from_user_id"])
				assert.Equal(t, strconv.Itoa(c.users[target].Id), view["target_user_id"])
				assert.Equal(t, kind, view["kind"])
				assert.Equal(t, "pending", view["status"])
				assert.Equal(t, "organization-A", view["organization_name"])
				assert.Equal(t, c.revision(t), view["organization_revision"])
				assert.Nil(t, view["resolved_at"])
				if kind == "transfer" {
					assert.Nil(t, view["role"])
				} else {
					assert.Equal(t, "member", view["role"])
				}
			}
			if route.name == "self_state" || route.name == "platform_state" {
				view := b["data"].(map[string]any)
				assert.Equal(t, strconv.FormatInt(c.orgA, 10), view["organization_id"])
				assert.Equal(t, c.revision(t), view["revision"])
				assert.Equal(t, false, view["self_disabled"])
				assert.Equal(t, false, view["platform_disabled"])
				assert.Equal(t, false, view["dissolved"])
				assert.Equal(t, "organization-A", view["name"])
				if route.name == "self_state" {
					assert.Equal(t, "member", view["my_role"])
				} else {
					assert.NotContains(t, view, "my_role")
				}
			}
			status, h, b = c.json(t, "GET", route.path, route.actor, nil, "unexpected-proof")
			organizationError(t, status, h, b, 400, "ORG_REQUEST_INVALID")
		})
	}
}

func TestOrganizationLifecycleOTPLoginReuse(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	factor := &model.TwoFA{UserId: c.users["owner"].Id, Secret: "JBSWY3DPEHPK3PXP", IsEnabled: true}
	require.NoError(t, c.db.Create(factor).Error)
	status, _, b := c.json(t, "POST", "/api/user/login", "", map[string]any{"username": c.users["owner"].Username, "password": c.passwords["owner"]}, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	data := b["data"].(map[string]any)
	flow, ok := data["flow_token"].(string)
	require.True(t, ok)
	code, err := totp.GenerateCode(factor.Secret, time.Now())
	require.NoError(t, err)
	status, h, b := c.json(t, "POST", "/api/user/login/verify", "", map[string]any{"flow_token": flow, "method": "2fa", "code": code}, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	c.installBundle(t, "owner", b["data"], h)
	op := c.operation(t, "owner", "dissolve", map[string]any{"revision": c.revision(t)}, nil)
	status, h, b = c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": op["scope"], "context": op["context"], "method": "2fa", "code": code}, "")
	organizationError(t, status, h, b, 403, "SECURITY_VERIFICATION_FAILED")
}

func TestOrganizationLifecycleStrictNestedAndHeaders(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	c.mutate(t, "owner", "POST", c.path()+"/self-state", "self_disable", map[string]any{"revision": c.revision(t), "disabled": true, "reason": "prepare re-enable"}, nil, true)

	command := fmt.Sprintf(`{"organization_id":%q,"revision":%q,"disabled":false,"reason":""}`, strconv.FormatInt(c.orgA, 10), c.revision(t))
	valid := `{"action":"self_disable","command":` + command + `}`
	for _, tc := range []struct {
		name, body string
		headers    http.Header
	}{
		{"case_alias_action", strings.Replace(valid, `"action":"self_disable"`, `"action":"self_disable","Action":"self_disable"`, 1), nil},
		{"case_alias_command", strings.Replace(valid, `"command":`, `"Command":`, 1), nil},
		{"nested_duplicate", strings.Replace(valid, `"disabled":false`, `"disabled":false,"disabled":true`, 1), nil},
		{"escaped_duplicate", strings.Replace(valid, `"disabled":false`, `"disabled":false,"dis\u0061bled":true`, 1), nil},
		{"required_boolean", strings.Replace(valid, `"disabled":false,`, "", 1), nil},
		{"null_boolean", strings.Replace(valid, `"disabled":false`, `"disabled":null`, 1), nil},
		{"unknown_nested", strings.Replace(valid, `"disabled":false`, `"disabled":false,"extra":1`, 1), nil},
		{"duplicate_authorization", valid, http.Header{"Authorization": {"Bearer " + c.bearer["owner"], "Bearer " + c.bearer["owner"]}}},
		{"duplicate_proof", valid, http.Header{"X-Security-Proof": {"one", "two"}}},
		{"duplicate_origin", valid, http.Header{"Origin": {"https://example.com", "https://example.com"}}},
		{"duplicate_selector", valid, http.Header{"X-Organization-Id": {strconv.FormatInt(c.orgA, 10), strconv.FormatInt(c.orgA, 10)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Content-Type": {"application/json"}}
			for k, v := range tc.headers {
				h[k] = v
			}
			status, headers, b := c.request(t, "POST", c.path()+"/authorization-context", "owner", tc.body, h)
			assert.GreaterOrEqual(t, status, 400)
			assert.Less(t, status, 500)
			assert.Equal(t, false, b["success"])
			assert.NotContains(t, slices.Collect(maps.Keys(b)), "data")
			assert.True(t, organizationPrivateNoStore(headers.Values("Cache-Control")), "Cache-Control requires unqualified private and no-store")
		})
	}
	status, _, b := c.request(t, "POST", c.path()+"/authorization-context", "owner", valid, http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	actual := b["data"].(map[string]any)["operation"].(map[string]any)["context"].(map[string]any)["command"].(map[string]any)
	assert.Equal(t, false, actual["disabled"])
	assert.Equal(t, "", actual["reason"])
}

func TestOrganizationLifecycleFilteredPagination(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	hidden := c.mutate(t, "owner", "POST", c.path()+"/invitations", "invite", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["foreign"].Id), "role": "admin"}, nil, true)
	visible := c.mutate(t, "owner", "POST", c.path()+"/invitations", "invite", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["empty"].Id), "role": "member"}, nil, false)
	status, _, b := c.json(t, "GET", c.path()+"/invitations?limit=1&after_id=0", "admin", nil, "")
	require.Equal(t, 200, status)
	page := b["data"].(map[string]any)
	items := page["items"].([]any)
	require.Len(t, items, 1)
	assert.Equal(t, visible["object_id"], items[0].(map[string]any)["object_id"])
	assert.NotEqual(t, hidden["object_id"], items[0].(map[string]any)["object_id"])
	status, h, b := c.json(t, "GET", c.path()+"/invitations/"+hidden["object_id"].(string)+"/generations/1", "admin", nil, "")
	organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
}

func TestOrganizationLifecycleHistoricalTransferParticipants(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	first := c.mutate(t, "owner", "POST", c.path()+"/ownership-transfers", "transfer_initiate", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["member"].Id), "previous_id": "0", "previous_generation": "0", "replace": false}, nil, true)
	slot := c.path() + "/ownership-transfers/" + first["object_id"].(string)
	c.mutate(t, "member", "POST", slot+"/decline", "transfer_decline", map[string]any{"revision": c.revision(t), "generation": first["generation"]}, nil, false)
	second := c.mutate(t, "owner", "POST", c.path()+"/ownership-transfers", "transfer_initiate", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["revoked"].Id), "previous_id": first["object_id"], "previous_generation": first["generation"], "replace": false}, nil, true)
	c.mutate(t, "owner", "DELETE", c.path()+fmt.Sprintf("/members/%d", c.users["member"].Id), "remove", map[string]any{"revision": c.revision(t)}, nil, false)
	c.mutate(t, "owner", "PATCH", c.path()+"/name", "rename", map[string]any{"revision": c.revision(t), "name": "private-new-name"}, nil, false)
	status, _, b := c.json(t, "GET", slot+"/generations/"+first["generation"].(string), "member", nil, "")
	require.Equal(t, 200, status)
	view := b["data"].(map[string]any)
	assert.Equal(t, "declined", view["status"])
	assert.Nil(t, view["organization_name"])
	assert.Nil(t, view["organization_revision"])
	status, h, b := c.json(t, "GET", slot+"/generations/"+second["generation"].(string), "member", nil, "")
	organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
}

func TestOrganizationLifecycleEnrollmentOTPReuse(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	status, _, b := c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": "2fa.setup", "method": "password", "password": c.passwords["owner"]}, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	proof := b["data"].(map[string]any)["proof_token"].(string)
	status, _, b = c.json(t, "POST", "/api/user/2fa/setup", "owner", map[string]any{}, proof)
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	setup := b["data"].(map[string]any)
	code, err := totp.GenerateCode(setup["secret"].(string), time.Now())
	require.NoError(t, err)
	status, h, b := c.json(t, "POST", "/api/user/2fa/enable", "owner", map[string]any{"flow_token": setup["flow_token"], "code": code}, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	rotation := b["data"].(map[string]any)
	// Existing nonorganization enable advances auth/session version without
	// issuing a new refresh cookie; organization producers use installBundle.
	require.Equal(t, c.sids["owner"], rotation["session"].(map[string]any)["sid"])
	c.bearer["owner"] = rotation["access_token"].(string)
	op := c.operation(t, "owner", "dissolve", map[string]any{"revision": c.revision(t)}, nil)
	status, h, b = c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": op["scope"], "context": op["context"], "method": "2fa", "code": code}, "")
	organizationError(t, status, h, b, 403, "SECURITY_VERIFICATION_FAILED")
	status, _, b = c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": "2fa.disable", "method": "2fa", "code": code}, "")
	assert.NotEqual(t, true, b["success"])
	assert.Equal(t, 200, status)
	assert.Equal(t, "SECURITY_VERIFICATION_FAILED", b["code"])
	assert.NotContains(t, slices.Collect(maps.Keys(b)), "data")
}

func TestOrganizationLifecycleNoPasswordDowngrade(t *testing.T) {
	for _, state := range []string{"totp_locked", "passkey_enrolled", "passkey_disabled", "password_disabled"} {
		t.Run(state, func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			switch state {
			case "totp_locked":
				until := time.Now().Add(time.Hour)
				require.NoError(t, c.db.Create(&model.TwoFA{UserId: c.users["owner"].Id, Secret: "JBSWY3DPEHPK3PXP", IsEnabled: true, LockedUntil: &until}).Error)
			case "passkey_enrolled", "passkey_disabled":
				require.NoError(t, c.db.Create(&model.PasskeyCredential{UserID: c.users["owner"].Id, CredentialID: "fixture-credential", PublicKey: "fixture-public-key"}).Error)
				if state == "passkey_disabled" {
					system_setting.GetPasskeySettings().Enabled = false
				}
			case "password_disabled":
				common.PasswordLoginEnabled = false
			}
			statusMethods, _, methodsBody := c.json(t, "GET", "/api/verify/methods?scope=organization.dissolve", "owner", nil, "")
			require.Equal(t, 200, statusMethods)
			methods := methodsBody["data"].(map[string]any)["methods"].([]any)
			for _, entry := range methods {
				method := entry.(map[string]any)
				if method["method"] == "password" {
					assert.Equal(t, false, method["available"])
				}
			}
			op := c.operation(t, "owner", "dissolve", map[string]any{"revision": c.revision(t)}, nil)
			status, _, b := c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": op["scope"], "context": op["context"], "method": "password", "password": c.passwords["owner"]}, "")
			assert.Equal(t, 403, status)
			assert.Equal(t, false, b["success"])
			assert.NotContains(t, slices.Collect(maps.Keys(b)), "data")
		})
	}
}

// This child-process protocol carries synthetic fixture credentials only over
// anonymous pipes. No DSN/token/session secret is printed or saved to disk.
type organizationBudgetProcessInput struct {
	Kind, DSN, Port, SQLiteRoot, SessionSecret, Bearer string
	Operation                                          map[string]any
}
type organizationBudgetProcessResult struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Retry  int    `json:"retry"`
}

func TestOrganizationLifecycleBudgetWorker(t *testing.T) {
	if os.Getenv("NEWAPI_S3_BUDGET_CHILD") != "g6-A03-http-completion" {
		t.Skip("child entrypoint; invoked only by two-process parent")
	}
	input := os.NewFile(3, "owned-input")
	output := os.NewFile(4, "owned-result")
	start := os.NewFile(5, "owned-start")
	require.NotNil(t, input)
	require.NotNil(t, output)
	require.NotNil(t, start)
	defer input.Close()
	defer output.Close()
	defer start.Close()
	var config organizationBudgetProcessInput
	require.NoError(t, common.DecodeJson(io.LimitReader(input, 65536), &config))
	var dialector gorm.Dialector
	switch config.Kind {
	case "sqlite":
		root, err := filepath.EvalSymlinks(config.SQLiteRoot)
		require.NoError(t, err)
		path, err := filepath.EvalSymlinks(config.DSN)
		require.NoError(t, err)
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		require.False(t, strings.HasPrefix(rel, ".."))
		require.Equal(t, "organization.db", filepath.Base(path))
		dialector = sqlite.Open(path + "?_pragma=busy_timeout(10000)&_txlock=immediate")
	case "mysql", "postgres":
		require.NoError(t, organizationFixtureDSN(config.Kind, config.DSN, config.Port))
		require.Contains(t, config.DSN, "/newapi_s2_", "only parent-created dedicated database may be attached")
		if config.Kind == "mysql" {
			dialector = mysql.Open(config.DSN)
		} else {
			dialector = postgres.Open(config.DSN)
		}
	default:
		t.Fatal("unsupported explicitly owned child database")
	}
	db, err := gorm.Open(dialector, &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	conn, err := db.DB()
	require.NoError(t, err)
	defer conn.Close()
	model.DB, model.LOG_DB = db, db
	common.SetDatabaseTypes(common.DatabaseType(config.Kind), common.DatabaseType(config.Kind))
	common.RedisEnabled = false
	common.MemoryCacheEnabled = false
	common.IsMasterNode = false
	common.GlobalApiRateLimitEnable = false
	common.PasswordLoginEnabled = true
	common.PasswordLoginEncryptionEnabled = false
	common.SessionSecret = config.SessionSecret
	deny := &organizationLoopbackTransport{next: http.DefaultTransport}
	http.DefaultTransport = deny
	for _, client := range []*http.Client{service.GetHttpClient(), service.GetSSRFProtectedHTTPClient()} {
		if client != nil {
			client.Transport = deny
		}
	}
	t.Cleanup(func() { assert.Zero(t, deny.rejected.Load(), "child attempted forbidden outbound HTTP") })
	require.NoError(t, i18n.Init())
	require.NoError(t, authz.Init(db))
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard
	engine := gin.New()
	SetRouter(engine, WebAssets{IndexPage: []byte("isolated-worker")})
	server := httptest.NewServer(engine)
	defer server.Close()
	_, err = output.Write([]byte{1})
	require.NoError(t, err)
	signal := make([]byte, 1)
	_, err = io.ReadFull(start, signal)
	require.NoError(t, err)
	payload, err := common.Marshal(map[string]any{"scope": config.Operation["scope"], "context": config.Operation["context"], "method": "password", "password": "wrong-local-password"})
	require.NoError(t, err)
	// Each worker is an independent gateway process with a shared account store.
	results := make([]organizationBudgetProcessResult, 3)
	var group sync.WaitGroup
	for i := range 3 {
		group.Go(func() {
			req, err := http.NewRequest("POST", server.URL+"/api/verify", strings.NewReader(string(payload)))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+config.Bearer)
			req.Header.Set("Content-Type", "application/json")
			client := server.Client()
			client.Timeout = 15 * time.Second
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			var body struct {
				Code string `json:"code"`
			}
			if common.DecodeJson(resp.Body, &body) != nil {
				return
			}
			retry, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
			results[i] = organizationBudgetProcessResult{resp.StatusCode, body.Code, retry}
		})
	}
	group.Wait()
	raw, err := common.Marshal(results)
	require.NoError(t, err)
	_, err = output.Write(raw)
	require.NoError(t, err)
}

func TestOrganizationLifecycleTwoProcessBudget(t *testing.T) {
	if os.Getenv("NEWAPI_S3_TWO_PROCESS") != "g6-A03-http-completion" {
		t.Skip("requires explicit later isolated-matrix dispatch; skip is not acceptance")
	}
	c := newOrganizationLifecycleClient(t)
	op := c.operation(t, "owner", "dissolve", map[string]any{"revision": c.revision(t)}, nil)
	first := c.bearer["owner"]
	c.login(t, "owner")
	tokens := []string{first, c.bearer["owner"]}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	type worker struct {
		cmd           *exec.Cmd
		output, start *os.File
	}
	workers := make([]worker, 0, 2)
	for i := range 2 {
		inR, inW, err := os.Pipe()
		require.NoError(t, err)
		outR, outW, err := os.Pipe()
		require.NoError(t, err)
		startR, startW, err := os.Pipe()
		require.NoError(t, err)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOrganizationLifecycleBudgetWorker$", "-test.timeout=40s")
		cmd.Env = append(os.Environ(), "NEWAPI_S3_BUDGET_CHILD=g6-A03-http-completion")
		cmd.ExtraFiles = []*os.File{inR, outW, startR}
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		require.NoError(t, cmd.Start())
		inR.Close()
		outW.Close()
		startR.Close()
		t.Cleanup(func() {
			_ = inW.Close()
			_ = outR.Close()
			_ = startW.Close()
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		config := organizationBudgetProcessInput{Kind: c.mainKind, DSN: c.mainDSN, Port: os.Getenv("NEWAPI_S2_" + strings.ToUpper(c.mainKind) + "_PORT"), SQLiteRoot: filepath.Dir(c.mainDSN), SessionSecret: common.SessionSecret, Bearer: tokens[i], Operation: op}
		raw, err := common.Marshal(config)
		require.NoError(t, err)
		_, err = inW.Write(raw)
		require.NoError(t, err)
		require.NoError(t, inW.Close())
		workers = append(workers, worker{cmd, outR, startW})
	}
	for _, w := range workers {
		ready := make([]byte, 1)
		_, err := io.ReadFull(w.output, ready)
		require.NoError(t, err)
		require.Equal(t, byte(1), ready[0])
	}
	for _, w := range workers {
		_, err := w.start.Write([]byte{1})
		require.NoError(t, err)
		w.start.Close()
	}
	failed, limited := 0, 0
	for _, w := range workers {
		var results []organizationBudgetProcessResult
		require.NoError(t, common.DecodeJson(io.LimitReader(w.output, 65536), &results))
		require.NoError(t, w.cmd.Wait())
		require.Len(t, results, 3)
		for _, r := range results {
			switch r.Status {
			case 403:
				failed++
				assert.Equal(t, "SECURITY_VERIFICATION_FAILED", r.Code)
			case 429:
				limited++
				assert.Equal(t, "SECURITY_VERIFICATION_RATE_LIMITED", r.Code)
				assert.GreaterOrEqual(t, r.Retry, 1)
				assert.LessOrEqual(t, r.Retry, 300)
			default:
				t.Errorf("unexpected child HTTP status %d", r.Status)
			}
		}
	}
	assert.Equal(t, 5, failed)
	assert.Equal(t, 1, limited)
	var count int64
	require.NoError(t, c.db.Model(&model.AuthFlow{}).Where("purpose = ? AND user_id = ?", "org_verify_attempt", c.users["owner"].Id).Count(&count).Error)
	assert.EqualValues(t, 5, count)
}

func TestOrganizationLifecycleNonOrganizationOTPReuse(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	factor := &model.TwoFA{UserId: c.users["owner"].Id, Secret: "JBSWY3DPEHPK3PXP", IsEnabled: true}
	require.NoError(t, c.db.Create(factor).Error)
	code, err := totp.GenerateCode(factor.Secret, time.Now())
	require.NoError(t, err)
	status, _, b := c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": "2fa.disable", "method": "2fa", "code": code}, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	require.NotEmpty(t, b["data"].(map[string]any)["proof_token"])
	op := c.operation(t, "owner", "dissolve", map[string]any{"revision": c.revision(t)}, nil)
	status, h, b := c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": op["scope"], "context": op["context"], "method": "2fa", "code": code}, "")
	organizationError(t, status, h, b, 403, "SECURITY_VERIFICATION_FAILED")
}

func TestOrganizationLifecycleGeneratedConsumer(t *testing.T) {
	entry := os.Getenv("NEWAPI_S3_CONSUMER_ENTRY")
	if entry == "" {
		t.Skip("requires frozen generated consumer runtime binding; skip is not acceptance")
	}
	require.True(t, filepath.IsAbs(entry))
	require.Equal(t, "consumer_entry.cjs", filepath.Base(entry))
	node := os.Getenv("NEWAPI_S3_NODE")
	require.True(t, filepath.IsAbs(node))
	require.NotEmpty(t, node)
	c := newOrganizationLifecycleClient(t)
	common.SessionCookieTrustedURLs = append(common.SessionCookieTrustedURLs, "https://example.com")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := sha256.Sum256(elliptic.Marshal(key.Curve, key.X, key.Y))
	pub, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	require.NoError(t, err)
	require.NoError(t, c.db.Create(&model.PasskeyCredential{UserID: c.users["foreign"].Id, CredentialID: base64.StdEncoding.EncodeToString(id[:]), PublicKey: base64.StdEncoding.EncodeToString(pub), UserPresent: true, UserVerified: true}).Error)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	users := map[string]any{}
	for _, actor := range []string{"owner", "admin", "member", "foreign", "root", "empty"} {
		users[actor] = map[string]string{"id": strconv.Itoa(c.users[actor].Id), "username": c.users[actor].Username, "password": c.passwords[actor]}
	}
	input, err := common.Marshal(map[string]any{"baseURL": c.server.URL, "users": users, "passkey": map[string]string{"privateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "credentialID": base64.RawURLEncoding.EncodeToString(id[:]), "accessToken": c.bearer["foreign"], "sid": c.sids["foreign"]}})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, entry)
	cmd.Stdin = strings.NewReader(string(input))
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	output, err := cmd.Output()
	require.NoError(t, err, "generated consumer process must finish successfully: %s", diagnostic.String())
	var receipt struct {
		Operations []struct {
			OperationID string `json:"operation_id"`
			Success     bool   `json:"success"`
		} `json:"operation_results"`
		RouteCount     int    `json:"route_count"`
		FormalLogin    bool   `json:"formal_login"`
		Producer       bool   `json:"proof_producer"`
		Rotated        bool   `json:"rotated_session"`
		Consumer       bool   `json:"consumer"`
		OrganizationID string `json:"organization_id"`
		EventID        string `json:"event_id"`
	}
	require.NoError(t, common.Unmarshal(output, &receipt))
	assert.Equal(t, 31, receipt.RouteCount)
	require.Len(t, receipt.Operations, 31)
	seen := map[string]bool{}
	for _, operation := range receipt.Operations {
		require.True(t, operation.Success)
		require.False(t, seen[operation.OperationID])
		seen[operation.OperationID] = true
		t.Logf("generated operation PASS: %s", operation.OperationID)
	}
	assert.True(t, receipt.FormalLogin)
	assert.True(t, receipt.Producer)
	assert.True(t, receipt.Rotated)
	assert.True(t, receipt.Consumer)
	var event model.OrganizationEvent
	require.NoError(t, c.db.Where("id = ? AND organization_id = ?", receipt.EventID, receipt.OrganizationID).First(&event).Error)
	assert.Equal(t, "organization.dissolve", event.Action)
}

func TestOrganizationLifecycleDeadlineAfterLocks(t *testing.T) {
	for _, stage := range []int32{1, 2} {
		t.Run(fmt.Sprintf("stage_%d", stage), func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			body := map[string]any{"revision": c.revision(t), "disabled": true, "reason": "deadline"}
			op := c.operation(t, "owner", "self_disable", body, nil)
			proof := c.proof(t, "owner", op, "password", "")
			var flow model.AuthFlow
			require.NoError(t, c.db.Where("purpose = ? AND session_id = ?", model.AuthFlowPurposeSecurityProof, c.sids["owner"]).First(&flow).Error)
			deadline := time.Now().Add(3 * time.Second).Truncate(time.Second)
			require.NoError(t, c.db.Model(&flow).Update("expires_at", deadline).Error)
			reached, release := make(chan struct{}, 1), make(chan struct{})
			var once sync.Once
			var calls atomic.Int32
			callback := "s3:deadline_after_locks"
			require.NoError(t, c.db.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
				if _, ok := tx.Statement.Dest.(*model.UserVerificationState); ok && calls.Add(1) == stage {
					reached <- struct{}{}
					select {
					case <-release:
					case <-tx.Statement.Context.Done():
					}
				}
			}))
			t.Cleanup(func() { once.Do(func() { close(release) }); _ = c.db.Callback().Query().Remove(callback) })
			type response struct {
				status int
				h      http.Header
				b      map[string]any
			}
			done := make(chan response, 1)
			go func() {
				status, h, b := c.json(t, "POST", c.path()+"/self-state", "owner", body, proof)
				done <- response{status, h, b}
			}()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("expected locked verification-state barrier not reached")
			}
			timer := time.NewTimer(time.Until(deadline) + 20*time.Millisecond)
			defer timer.Stop()
			<-timer.C
			once.Do(func() { close(release) })
			var result response
			select {
			case result = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("bounded expiry request did not finish")
			}
			organizationError(t, result.status, result.h, result.b, 403, "SECURITY_PROOF_EXPIRED")
			var final model.AuthFlow
			require.NoError(t, c.db.First(&final, flow.Id).Error)
			if stage == 1 {
				assert.Nil(t, final.ConsumedAt)
			} else {
				assert.NotNil(t, final.ConsumedAt)
			}
			var org model.Organization
			require.NoError(t, c.db.First(&org, c.orgA).Error)
			assert.Zero(t, org.SelfDisabledAt)
			assert.Equal(t, body["revision"], strconv.FormatInt(org.Revision, 10))
		})
	}
}

// This wrapper is confined to the owned test DB. It actually commits a rotation
// and then reports uncertainty, rather than conflating an insert rollback with
// an unknown commit result.
type organizationUncertainPool struct {
	gorm.ConnPool
	fired *atomic.Bool
}

func (p *organizationUncertainPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	var pool gorm.ConnPool
	var err error
	if beginner, ok := p.ConnPool.(gorm.ConnPoolBeginner); ok {
		pool, err = beginner.BeginTx(ctx, opts)
	} else if beginner, ok := p.ConnPool.(gorm.TxBeginner); ok {
		pool, err = beginner.BeginTx(ctx, opts)
	} else {
		return nil, errors.New("test pool cannot begin")
	}
	if err != nil {
		return nil, err
	}
	return &organizationUncertainTx{ConnPool: pool, fired: p.fired}, nil
}

type organizationUncertainTx struct {
	gorm.ConnPool
	fired    *atomic.Bool
	rotation bool
}

func (t *organizationUncertainTx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if strings.Contains(strings.ToLower(q), "insert") && strings.Contains(q, "user_sessions") {
		t.rotation = true
	}
	return t.ConnPool.ExecContext(ctx, q, args...)
}
func (t *organizationUncertainTx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if strings.Contains(strings.ToLower(q), "insert") && strings.Contains(q, "user_sessions") {
		t.rotation = true
	}
	return t.ConnPool.QueryContext(ctx, q, args...)
}
func (t *organizationUncertainTx) Commit() error {
	err := t.ConnPool.(gorm.TxCommitter).Commit()
	if err == nil && t.rotation && t.fired.CompareAndSwap(false, true) {
		return errors.New("test committed rotation outcome uncertain")
	}
	return err
}
func (t *organizationUncertainTx) Rollback() error { return t.ConnPool.(gorm.TxCommitter).Rollback() }

func TestOrganizationLifecycleRotationFailures(t *testing.T) {
	for _, failure := range []string{"rotation_insert", "proof_insert", "unknown_commit", "confirm_read"} {
		t.Run(failure, func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			op := c.operation(t, "owner", "dissolve", map[string]any{"revision": c.revision(t)}, nil)
			oldSID := c.sids["owner"]
			var fired atomic.Bool
			var replacementSID atomic.Value
			if failure == "confirm_read" {
				var created atomic.Bool
				require.NoError(t, c.db.Callback().Create().After("gorm:create").Register("s3:track_confirmation", func(tx *gorm.DB) {
					if tx.Statement.Table == "user_sessions" && tx.Error == nil {
						created.Store(true)
						if session, ok := tx.Statement.Dest.(*model.UserSession); ok {
							replacementSID.Store(session.SID)
						}
					}
				}))
				require.NoError(t, c.db.Callback().Query().Before("gorm:query").Register("s3:fail_confirmation", func(tx *gorm.DB) {
					if !created.Load() || tx.Statement.Table != "user_sessions" {
						return
					}
					if _, count := tx.Statement.Dest.(*int64); count && fired.CompareAndSwap(false, true) {
						tx.AddError(errors.New("owned postcommit confirmation read failure"))
					}
				}))
				t.Cleanup(func() {
					_ = c.db.Callback().Create().Remove("s3:track_confirmation")
					_ = c.db.Callback().Query().Remove("s3:fail_confirmation")
				})
			} else if failure == "unknown_commit" {
				originalConfig, originalStatement := c.db.Config.ConnPool, c.db.Statement.ConnPool
				pool := &organizationUncertainPool{ConnPool: originalStatement, fired: &fired}
				c.db.Config.ConnPool = pool
				c.db.Statement.ConnPool = pool
				t.Cleanup(func() { c.db.Config.ConnPool = originalConfig; c.db.Statement.ConnPool = originalStatement })
			} else {
				callback := "s3:rotation_failure"
				require.NoError(t, c.db.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
					matches := failure == "rotation_insert" && tx.Statement.Table == "user_sessions"
					if flow, ok := tx.Statement.Dest.(*model.AuthFlow); ok && failure == "proof_insert" && flow.Purpose == model.AuthFlowPurposeSecurityProof {
						matches = true
					}
					if matches {
						fired.Store(true)
						tx.AddError(errors.New("owned rotation failure"))
					}
				}))
				t.Cleanup(func() { _ = c.db.Callback().Create().Remove(callback) })
			}
			status, h, b := c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": op["scope"], "context": op["context"], "method": "password", "password": c.passwords["owner"]}, "")
			assert.Equal(t, 500, status)
			assert.Equal(t, false, b["success"])
			assert.NotContains(t, slices.Collect(maps.Keys(b)), "data")
			assert.Empty(t, h.Values("Set-Cookie"))
			assert.True(t, fired.Load())
			var old model.UserSession
			require.NoError(t, c.db.Where("sid = ?", oldSID).First(&old).Error)
			expected := model.UserSessionStatusRevoked
			if failure == "rotation_insert" {
				expected = model.UserSessionStatusActive
			}
			assert.Equal(t, expected, old.Status)
			var proofs int64
			require.NoError(t, c.db.Model(&model.AuthFlow{}).Where("purpose = ? AND user_id = ?", model.AuthFlowPurposeSecurityProof, c.users["owner"].Id).Count(&proofs).Error)
			assert.Zero(t, proofs)
			if failure == "confirm_read" {
				sid, ok := replacementSID.Load().(string)
				require.True(t, ok, "replacement SID must be observed in committed insert")
				require.True(t, sid != "" && sid != oldSID)
				var replacement model.UserSession
				require.NoError(t, c.db.Where("sid = ?", sid).First(&replacement).Error)
				assert.Equal(t, model.UserSessionStatusRevoked, replacement.Status, "only the actual replacement SID is checked; unrelated fixture sessions are preserved")
			}
		})
	}
}

func TestOrganizationLifecycleDatabaseContextCancellation(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	entered := make(chan struct{}, 1)
	observed := make(chan bool, 1)
	release := make(chan struct{})
	var once sync.Once
	var hit atomic.Bool
	callback := "s3:context_observation"
	require.NoError(t, c.db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table != "organizations" || !hit.CompareAndSwap(false, true) {
			return
		}
		_, bounded := tx.Statement.Context.Deadline()
		entered <- struct{}{}
		select {
		case <-tx.Statement.Context.Done():
			observed <- bounded
		case <-release:
			observed <- false
		}
	}))
	t.Cleanup(func() { once.Do(func() { close(release) }); _ = c.db.Callback().Query().Remove(callback) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.server.URL+c.path()+"/self-state", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+c.bearer["owner"])
	done := make(chan struct{})
	go func() {
		resp, _ := c.client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("database query not observed")
	}
	cancel()
	select {
	case bounded := <-observed:
		assert.True(t, bounded, "DB call must retain bounded transaction/request deadline")
	case <-time.After(time.Second):
		t.Error("request cancellation did not propagate to DB context")
		once.Do(func() { close(release) })
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled HTTP client did not terminate")
	}
}

// organizationPrivateNoStore implements the effective gate's required directive set.
func organizationPrivateNoStore(values []string) bool {
	private, noStore := false, false
	for _, value := range values {
		start, quoted, escaped := 0, false, false
		// Commas inside quoted field-name lists do not separate directives.
		for i := 0; i <= len(value); i++ {
			if i < len(value) {
				if escaped {
					escaped = false
					continue
				}
				if quoted && value[i] == '\\' {
					escaped = true
					continue
				}
				if value[i] == '"' {
					quoted = !quoted
					continue
				}
				if value[i] != ',' || quoted {
					continue
				}
			}
			if quoted {
				return false
			}
			switch strings.ToLower(strings.Trim(value[start:i], " \t")) {
			case "private":
				private = true
			case "no-store":
				noStore = true
			}
			start = i + 1
		}
	}
	return private && noStore
}

func TestOrganizationLifecycleCacheControlContract(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   bool
	}{
		{"canonical", []string{"private, no-store"}, true},
		{"case_order_ows", []string{" NO-STORE , PRIVATE "}, true},
		{"multiple_headers", []string{"private", "no-store"}, true},
		{"conservative_extras", []string{"no-store, no-cache, must-revalidate, private, max-age=0"}, true},
		{"no_private", []string{"no-store, no-cache, max-age=0"}, false},
		{"no_store_missing", []string{"private, no-cache, max-age=0"}, false},
		{"qualified_private", []string{`private="Authorization", no-store`}, false},
		{"qualified_no_store", []string{`private, no-store="x"`}, false},
		{"quoted_directives_are_not_directives", []string{`private="x,private,no-store,x"`}, false},
		{"unclosed_quote", []string{`private, no-store, x="`}, false},
		{"quoted_list_with_required", []string{`no-cache="x,y", private, no-store`}, true},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, organizationPrivateNoStore(tc.values)) })
	}
}

// These failures are produced by the dedicated Redis server (WRONGTYPE), not
// by miniredis or a client error stub. Only this fixture user's exact keys change.
func TestOrganizationLifecycleRedisAuthorityFaults(t *testing.T) {
	if os.Getenv("NEWAPI_S2_CACHE_MODE") != "redis" {
		t.Skip("dedicated Redis mode required; matrix selects this root only for Redis")
	}
	for _, scenario := range []string{"fence_failure", "publication_failure", "late_fill"} {
		t.Run(scenario, func(t *testing.T) {
			c := newOrganizationLifecycleClient(t)
			uid := c.users["owner"].Id
			ctx := t.Context()
			cacheKey := fmt.Sprintf("user:%d", uid)
			fenceKey := fmt.Sprintf("auth:user:fence:%d", uid)
			versionKey := fmt.Sprintf("auth:user:version:%d", uid)
			t.Cleanup(func() { require.NoError(t, common.RDB.Del(context.Background(), cacheKey, fenceKey, versionKey).Err()) })
			before, err := model.GetUserCache(uid)
			require.NoError(t, err)
			version := before.AuthVersion
			switch scenario {
			case "fence_failure":
				require.NoError(t, common.RDB.Del(ctx, fenceKey).Err())
				require.NoError(t, common.RDB.LPush(ctx, fenceKey, "owned-wrong-type").Err())
				_, err := model.BumpUserAuthVersion(uid)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "WRONGTYPE")
				var current model.User
				require.NoError(t, c.db.First(&current, uid).Error)
				assert.Equal(t, version, current.AuthVersion, "fence failure must roll back restrictive mutation")
				require.NoError(t, common.RDB.Del(ctx, fenceKey).Err())
				status, _, body := c.json(t, "GET", c.path()+"/self-state", "owner", nil, "")
				assert.Equal(t, 200, status)
				assert.Equal(t, true, body["success"])
			case "publication_failure":
				require.NoError(t, common.RDB.Del(ctx, versionKey).Err())
				require.NoError(t, common.RDB.LPush(ctx, versionKey, "owned-wrong-type").Err())
				next, err := model.BumpUserAuthVersion(uid)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "WRONGTYPE")
				assert.Equal(t, version+1, next)
				var current model.User
				require.NoError(t, c.db.First(&current, uid).Error)
				assert.Equal(t, next, current.AuthVersion, "publication failure cannot undo an already committed authority change")
				status, h, body := c.json(t, "GET", c.path()+"/self-state", "owner", nil, "")
				organizationError(t, status, h, body, 401, "AUTH_SESSION_REVOKED")
				require.NoError(t, common.RDB.Del(ctx, versionKey).Err())
				require.NoError(t, model.PublishUserAuthCache(uid))
				fresh, err := model.GetUserCache(uid)
				require.NoError(t, err)
				assert.Equal(t, next, fresh.AuthVersion)
			case "late_fill":
				require.NoError(t, common.RDB.Del(ctx, cacheKey).Err())
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				var observed atomic.Bool
				callback := "s3:late_user_fill"
				require.NoError(t, c.db.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
					if tx.Statement.Table != "users" || !observed.CompareAndSwap(false, true) {
						return
					}
					close(entered)
					select {
					case <-release:
					case <-time.After(5 * time.Second):
						tx.AddError(errors.New("owned late-fill barrier deadline"))
					}
				}))
				t.Cleanup(func() { once.Do(func() { close(release) }); _ = c.db.Callback().Query().Remove(callback) })
				done := make(chan error, 1)
				go func() { _, err := model.GetUserCache(uid); done <- err }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("late-fill snapshot not observed")
				}
				next, err := model.BumpUserAuthVersion(uid)
				require.NoError(t, err)
				once.Do(func() { close(release) })
				select {
				case err := <-done:
					assert.ErrorIs(t, err, model.ErrUserAuthCachePending)
				case <-time.After(5 * time.Second):
					t.Fatal("late fill did not finish")
				}
				fresh, err := model.GetUserCache(uid)
				require.NoError(t, err)
				assert.Equal(t, next, fresh.AuthVersion)
				stored, err := common.RDB.HGet(ctx, cacheKey, "AuthVersion").Int64()
				require.NoError(t, err)
				assert.Equal(t, next, stored, "late snapshot must not overwrite committed authority")
				status, h, body := c.json(t, "GET", c.path()+"/self-state", "owner", nil, "")
				organizationError(t, status, h, body, 401, "AUTH_SESSION_REVOKED")
			}
		})
	}
}
