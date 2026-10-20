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
	"net/url"
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
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/pkg/jsplugin"
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
		{"empty_origin", valid, http.Header{"Origin": {""}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"origin_list", valid, http.Header{"Origin": {"https://example.com, https://example.com"}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"duplicate_origin", valid, http.Header{"Origin": {"https://example.com", "https://example.com"}}, 400, "ORG_REQUEST_INVALID"},
		{"invalid_referer", valid, http.Header{"Referer": {"not-an-absolute-url"}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"empty_referer", valid, http.Header{"Referer": {""}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"duplicate_referer", valid, http.Header{"Referer": {"https://example.com/a", "https://example.com/b"}}, 400, "ORG_REQUEST_INVALID"},
		{"fetch_without_origin", valid, http.Header{"Sec-Fetch-Site": {"same-site"}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"fetch_destination_without_origin", valid, http.Header{"Sec-Fetch-Dest": {"empty"}}, 403, "AUTH_ORIGIN_FORBIDDEN"},
		{"idempotency", valid, http.Header{"Idempotency-Key": {"unsupported"}}, 400, "ORG_REQUEST_INVALID"},
		{"override", valid, http.Header{"X-HTTP-Method-Override": {"DELETE"}}, 400, "ORG_REQUEST_INVALID"},
		{"proof_forbidden", valid, http.Header{"X-Security-Proof": {"not-a-proof"}}, 400, "ORG_REQUEST_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Content-Type": {"application/json"}, "Sec-Fetch-Mode": {"cors"}}
			for k, v := range tc.headers {
				h[k] = v
			}
			status, headers, b := c.request(t, "PATCH", c.path()+"/name", "owner", tc.body, h)
			organizationError(t, status, headers, b, tc.status, tc.code)
			if tc.code == "AUTH_ORIGIN_FORBIDDEN" {
				message := "request origin is not allowed"
				if tc.headers.Values("Origin") == nil && tc.headers.Values("Referer") == nil {
					message = "Fetch metadata is not allowed without an Origin or Referer header."
				}
				assert.Equal(t, message, b["message"])
				assert.Equal(t, message, b["message_key"])
			}
		})
	}
	status, _, body := c.request(t, "PATCH", c.path()+"/name", "owner", valid,
		http.Header{"Content-Type": {"application/json"}, "Origin": {c.server.URL}, "Sec-Fetch-Mode": {"cors"}, "Sec-Fetch-Site": {"same-origin"}})
	require.Equal(t, 200, status)
	assert.Equal(t, true, body["success"])
}

func TestOrganizationLifecycleNativeFetchOrigin(t *testing.T) {
	node := os.Getenv("NEWAPI_S3_NODE")
	if node == "" {
		t.Skip("requires Node fetch runtime; skip is not acceptance")
	}
	require.True(t, filepath.IsAbs(node))
	curl, err := exec.LookPath("curl")
	require.NoError(t, err)
	c := newOrganizationLifecycleClient(t)

	// Observe only non-secret source metadata while serving the production
	// router. The bearer comes from the fixture's real password-login endpoint.
	var metadataMu sync.Mutex
	var metadata []http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := http.Header{}
		for key, values := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "sec-fetch-") || strings.EqualFold(key, "Origin") || strings.EqualFold(key, "Referer") {
				headers[key] = slices.Clone(values)
			}
		}
		metadataMu.Lock()
		metadata = append(metadata, headers)
		metadataMu.Unlock()
		c.engine.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	input, err := common.Marshal(map[string]string{"baseURL": server.URL, "bearer": c.bearer["owner"], "curl": curl})
	require.NoError(t, err)
	// Credentials travel through anonymous stdin pipes, including curl's config.
	// Neither client sets, removes, nor overrides its default Fetch Metadata.
	const script = `
const { readFileSync } = require('node:fs');
const { execFileSync } = require('node:child_process');
const input = JSON.parse(readFileSync(0, 'utf8'));
const results = [];
(async () => {
  for (const client of ['node', 'curl']) {
    async function request(step, method, path, payload) {
      const headers = { Authorization: 'Bearer ' + input.bearer, 'Accept-Language': 'en' };
      if (payload) headers['Content-Type'] = 'application/json';
      let status, body, cacheControl, setCookie;
      if (client === 'node') {
        const response = await fetch(input.baseURL + path, {
          method, headers, body: payload && JSON.stringify(payload), signal: AbortSignal.timeout(10000)
        });
        status = response.status;
        body = await response.json();
        cacheControl = response.headers.get('cache-control');
        setCookie = response.headers.has('set-cookie');
      } else {
        let config = 'url = ' + JSON.stringify(input.baseURL + path) + '\nrequest = ' + JSON.stringify(method) + '\n';
        for (const [name, value] of Object.entries(headers)) config += 'header = ' + JSON.stringify(name + ': ' + value) + '\n';
        if (payload) config += 'data = ' + JSON.stringify(JSON.stringify(payload)) + '\n';
        const raw = execFileSync(input.curl, ['--disable', '--silent', '--show-error', '--noproxy', '*', '--max-time', '10', '--include', '--config', '-'], {
          input: config, encoding: 'utf8', timeout: 12000, maxBuffer: 1048576, stdio: ['pipe', 'pipe', 'pipe']
        });
        const split = raw.indexOf('\r\n\r\n');
        const head = raw.slice(0, split);
        status = Number(head.match(/^HTTP\/\S+ (\d+)/)[1]);
        body = JSON.parse(raw.slice(split + 4));
        cacheControl = head.match(/^cache-control:\s*(.*)$/im)?.[1].trim() || '';
        setCookie = /^set-cookie:/im.test(head);
      }
      const organizationID = body.data?.organization_id || body.data?.org_id || '';
      results.push({ name: client + '_' + step, status, success: body.success, code: body.code || '', organizationID,
        role: body.data?.my_role || '', cacheControl, setCookie });
      return organizationID;
    }
    const id = await request('create', 'POST', '/api/organizations', { name: 'native-' + client });
    if (/^[1-9]\d*$/.test(id)) await request('read', 'GET', '/api/organizations/' + id);
  }
  process.stdout.write(JSON.stringify({ nodeVersion: process.version, results }));
})().catch(() => { process.stderr.write('native client regression failed\n'); process.exitCode = 1; });
`
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", script)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	require.NoError(t, err, "native clients must complete without exposing credentials in diagnostics")
	var receipt struct {
		NodeVersion string `json:"nodeVersion"`
		Results     []struct {
			Name           string `json:"name"`
			Status         int    `json:"status"`
			Success        bool   `json:"success"`
			OrganizationID string `json:"organizationID"`
			Role           string `json:"role"`
			CacheControl   string `json:"cacheControl"`
			SetCookie      bool   `json:"setCookie"`
		} `json:"results"`
	}
	require.NoError(t, common.Unmarshal(output, &receipt))
	require.Len(t, receipt.Results, 4)
	for i, result := range receipt.Results {
		assert.Equal(t, []string{"node_create", "node_read", "curl_create", "curl_read"}[i], result.Name)
		assert.Equal(t, []int{201, 200, 201, 200}[i], result.Status)
		assert.True(t, result.Success)
		assert.Regexp(t, `^[1-9][0-9]*$`, result.OrganizationID)
		assert.Equal(t, "private, no-store", result.CacheControl)
		assert.False(t, result.SetCookie)
		if i%2 == 1 {
			assert.Equal(t, receipt.Results[i-1].OrganizationID, result.OrganizationID)
			assert.Equal(t, "owner", result.Role)
		}
	}
	metadataMu.Lock()
	observed := slices.Clone(metadata)
	metadataMu.Unlock()
	require.Len(t, observed, 4)
	assert.Equal(t, http.Header{"Sec-Fetch-Mode": {"cors"}}, observed[0])
	assert.Equal(t, http.Header{"Sec-Fetch-Mode": {"cors"}}, observed[1])
	assert.Empty(t, observed[2])
	assert.Empty(t, observed[3])
	t.Logf("Node %s default fetch and curl each created and read an organization with the same login session", receipt.NodeVersion)

	patSuffix, err := common.GenerateRandomCharsKey(43)
	require.NoError(t, err)
	pat := model.AccessTokenPrefix + patSuffix
	grant := &model.UserAccessToken{Name: "native-origin", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
	require.NoError(t, grant.SetScopes([]string{"*"}))
	require.NoError(t, model.CreateUserAccessToken(c.users["root"].Id, grant, service.AccessTokenMaxPerUser))
	legacy, err := common.GenerateRandomCharsKey(32)
	require.NoError(t, err)
	require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", c.users["root"].Id).Update("access_token", legacy).Error)
	revoked, err := model.RevokeUserSession(c.users["admin"].Id, c.sids["admin"], "native_origin_regression")
	require.NoError(t, err)
	require.True(t, revoked)
	for _, tc := range []struct {
		name, credential, code string
		status                 int
	}{
		{"missing", "", "AUTH_UNAUTHORIZED", 401},
		{"invalid", "not-a-session", "AUTH_UNAUTHORIZED", 401},
		{"revoked", c.bearer["admin"], "AUTH_SESSION_REVOKED", 401},
		{"relay", c.bearer["relay"], "AUTH_UNAUTHORIZED", 401},
		{"pat", pat, "AUTH_SESSION_REQUIRED", 403},
		{"legacy", legacy, "AUTH_SESSION_REQUIRED", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []string{"POST", "GET"} {
				path, body := "/api/organizations", `{"name":"must-not-create"}`
				if method == "GET" {
					path, body = c.path(), ""
				}
				status, headers, response := c.request(t, method, path, tc.credential, body, http.Header{"Content-Type": {"application/json"}, "Sec-Fetch-Mode": {"cors"}})
				organizationError(t, status, headers, response, tc.status, tc.code)
			}
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

func TestOrganizationLifecycleInvitationConflicts(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	path, initialRevision := c.path()+"/invitations", c.revision(t)
	target := strconv.Itoa(c.users["foreign"].Id)
	invitation := c.mutate(t, "owner", "POST", path, "invite", map[string]any{"revision": initialRevision, "target_user_id": target, "role": "member"}, nil, false)
	currentRevision := c.revision(t)
	assert.Equal(t, currentRevision, invitation["revision"])
	assert.Equal(t, "1", invitation["generation"])
	assert.Equal(t, "pending", invitation["status"])
	for _, tc := range []struct {
		name, actor, endpoint, revision, target, code, message string
		status                                                 int
	}{
		{"pending invitation", "owner", path, currentRevision, target, "ORG_INVITATION_EXISTS", "An invitation already exists for this user. Use reissue to send another invitation.", 409},
		{"existing member", "owner", path, currentRevision, strconv.Itoa(c.users["member"].Id), "ORG_ALREADY_MEMBER", "This user is already a member of the organization.", 409},
		{"stale revision before invitation", "owner", path, initialRevision, target, "ORG_STATE_CHANGED", "Organization state changed. Refresh the organization state before retrying.", 409},
		{"stale revision before member", "owner", path, initialRevision, strconv.Itoa(c.users["member"].Id), "ORG_STATE_CHANGED", "Organization state changed. Refresh the organization state before retrying.", 409},
		{"stale revision before missing target", "owner", path, initialRevision, "999999999", "ORG_STATE_CHANGED", "Organization state changed. Refresh the organization state before retrying.", 409},
		{"current revision missing target", "owner", path, currentRevision, "999999999", "ORG_NOT_FOUND", "", 404},
		{"member cannot inspect invitation", "member", path, currentRevision, target, "ORG_FORBIDDEN", "", 403},
		{"stale member cannot inspect revision", "member", path, initialRevision, target, "ORG_STATE_CHANGED", "", 409},
		{"stale root nonmember cannot inspect revision", "root", path, initialRevision, target, "ORG_NOT_FOUND", "", 404},
		{"stale nonmember cannot inspect revision", "empty", path, initialRevision, target, "ORG_NOT_FOUND", "", 404},
		{"member cannot inspect membership", "member", path, currentRevision, strconv.Itoa(c.users["admin"].Id), "ORG_FORBIDDEN", "", 403},
		{"nonmember cannot inspect invitation", "empty", path, currentRevision, target, "ORG_NOT_FOUND", "", 404},
		{"foreign cannot inspect membership", "foreign", path, currentRevision, strconv.Itoa(c.users["member"].Id), "ORG_NOT_FOUND", "", 404},
		{"other organization", "owner", fmt.Sprintf("/api/organizations/%d/invitations", c.orgB), "1", target, "ORG_NOT_FOUND", "", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, h, b := c.json(t, "POST", tc.endpoint, tc.actor, map[string]any{"revision": tc.revision, "target_user_id": tc.target, "role": "member"}, "")
			organizationError(t, status, h, b, tc.status, tc.code)
			assert.NotContains(t, b, "revision")
			if tc.code == "ORG_STATE_CHANGED" && tc.actor == "owner" {
				assert.Equal(t, map[string]any{"revision": currentRevision}, b["data"])
			} else {
				assert.NotContains(t, b, "data")
			}
			if tc.message != "" {
				assert.Equal(t, tc.message, b["message"])
			}
		})
	}
	for _, tc := range []struct{ target, revision, code string }{
		{target, currentRevision, "ORG_INVITATION_EXISTS"},
		{strconv.Itoa(c.users["member"].Id), currentRevision, "ORG_ALREADY_MEMBER"},
		{target, initialRevision, "ORG_STATE_CHANGED"},
	} {
		command := map[string]any{"organization_id": strconv.FormatInt(c.orgA, 10), "revision": tc.revision, "target_user_id": tc.target, "role": "admin"}
		status, h, b := c.json(t, "POST", c.path()+"/authorization-context", "owner", map[string]any{"action": "invite", "command": command}, "")
		organizationError(t, status, h, b, 409, tc.code)
		if tc.code == "ORG_STATE_CHANGED" {
			assert.Equal(t, map[string]any{"revision": currentRevision}, b["data"])
		} else {
			assert.NotContains(t, b, "data")
		}
	}
	for _, actor := range []string{"owner", "admin"} {
		for _, selector := range []string{"target_user_id", "username"} {
			t.Run("stale "+actor+" "+selector, func(t *testing.T) {
				value := "999999999"
				if selector == "username" {
					value = "missing-org-user"
				}
				status, h, b := c.json(t, "POST", path, actor, map[string]any{"revision": initialRevision, selector: value, "role": "member"}, "")
				organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
				assert.Equal(t, map[string]any{"revision": currentRevision}, b["data"])
			})
		}
	}
	for _, tc := range []struct{ selector, target string }{{"target_user_id", strconv.Itoa(c.users["owner"].Id)}, {"username", c.users["owner"].Username}} {
		t.Run("self invite "+tc.selector, func(t *testing.T) {
			status, h, b := c.json(t, "POST", path, "owner", map[string]any{"revision": currentRevision, tc.selector: tc.target, "role": "member"}, "")
			organizationError(t, status, h, b, 400, "ORG_SELF_INVITE")
			assert.Equal(t, "You cannot invite yourself to an organization.", b["message"])
		})
	}
	for _, actor := range []string{"owner", "admin"} {
		status, h, b := c.json(t, "POST", path+"/"+invitation["object_id"].(string)+"/reissue", actor,
			map[string]any{"revision": initialRevision, "generation": "999", "target_user_id": target, "role": "member"}, "")
		organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
		assert.Equal(t, map[string]any{"revision": currentRevision}, b["data"])
	}
	for _, endpoint := range []string{path, path + "/" + invitation["object_id"].(string) + "/reissue"} {
		body := map[string]any{"revision": initialRevision, "target_user_id": target, "role": "admin"}
		if strings.HasSuffix(endpoint, "/reissue") {
			body["generation"] = invitation["generation"]
		}
		status, h, b := c.json(t, "POST", endpoint, "admin", body, "")
		organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
		assert.NotContains(t, b, "data")
	}
	status, h, b := c.json(t, "PATCH", c.path()+"/name", "owner", map[string]any{"revision": initialRevision, "name": "must-not-rename"}, "")
	organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
	assert.NotContains(t, b, "data")
	// Concurrent repeats observe the same existing slot; neither may add an
	// invitation/event or advance the revision. Existing lock/CAS tests remain.
	raw, err := common.Marshal(map[string]any{"revision": currentRevision, "target_user_id": target, "role": "member"})
	require.NoError(t, err)
	type reply struct {
		status  int
		headers http.Header
		body    map[string]any
		err     error
	}
	replies := make(chan reply, 2)
	var requests sync.WaitGroup
	for range 2 {
		req, err := http.NewRequest("POST", c.server.URL+path, bytes.NewReader(raw))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+c.bearer["owner"])
		req.Header.Set("Content-Type", "application/json")
		requests.Go(func() {
			response, err := c.client.Do(req)
			if err != nil {
				replies <- reply{err: err}
				return
			}
			defer response.Body.Close()
			payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			body := map[string]any{}
			if err == nil {
				err = common.Unmarshal(payload, &body)
			}
			replies <- reply{response.StatusCode, response.Header, body, err}
		})
	}
	requests.Wait()
	close(replies)
	for result := range replies {
		require.NoError(t, result.err)
		organizationError(t, result.status, result.headers, result.body, 409, "ORG_INVITATION_EXISTS")
	}
	assert.Equal(t, currentRevision, c.revision(t))
	var count int64
	require.NoError(t, c.db.Model(&model.OrganizationInvitation{}).Where("organization_id = ?", c.orgA).Count(&count).Error)
	assert.EqualValues(t, 1, count)
	require.NoError(t, c.db.Model(&model.OrganizationEvent{}).Where("organization_id = ? AND action = ?", c.orgA, "invitation.issued").Count(&count).Error)
	assert.EqualValues(t, 1, count)

	slot := path + "/" + invitation["object_id"].(string)
	for _, state := range []string{"declined", "revoked", "expired", "accepted"} {
		t.Run("existing "+state+" slot", func(t *testing.T) {
			body := map[string]any{"revision": c.revision(t), "generation": invitation["generation"]}
			switch state {
			case "declined":
				c.mutate(t, "foreign", "POST", slot+"/decline", "invitation_decline", body, nil, false)
			case "revoked":
				c.mutate(t, "owner", "POST", slot+"/revoke", "invitation_revoke", body, nil, false)
			case "expired":
				require.NoError(t, c.db.Model(&model.OrganizationInvitation{}).Where("id = ?", invitation["object_id"]).Update("expires_at", time.Now().Unix()-1).Error)
				require.NoError(t, model.ExpireOrganizationInvitations(c.orgA))
			case "accepted":
				c.mutate(t, "foreign", "POST", slot+"/accept", "invitation_accept", body, nil, false)
				status, h, b := c.json(t, "POST", path, "owner", map[string]any{"revision": c.revision(t), "target_user_id": target, "role": "member"}, "")
				organizationError(t, status, h, b, 409, "ORG_ALREADY_MEMBER")
				c.mutate(t, "owner", "DELETE", fmt.Sprintf("%s/members/%s", c.path(), target), "remove", map[string]any{"revision": c.revision(t)}, map[string]any{"target_user_id": target}, false)
			}
			status, h, b := c.json(t, "POST", path, "owner", map[string]any{"revision": c.revision(t), "target_user_id": target, "role": "member"}, "")
			organizationError(t, status, h, b, 409, "ORG_INVITATION_EXISTS")
			assert.Equal(t, "An invitation already exists for this user. Use reissue to send another invitation.", b["message"])
			reissue := map[string]any{"revision": c.revision(t), "generation": "999", "target_user_id": target, "role": "member"}
			status, h, b = c.json(t, "POST", slot+"/reissue", "owner", reissue, "")
			organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
			assert.NotContains(t, b, "data")
			reissue["generation"] = invitation["generation"]
			next := c.mutate(t, "owner", "POST", slot+"/reissue", "reissue", reissue, nil, false)
			assert.Equal(t, invitation["object_id"], next["object_id"])
			generation, err := strconv.ParseInt(invitation["generation"].(string), 10, 64)
			require.NoError(t, err)
			assert.Equal(t, strconv.FormatInt(generation+1, 10), next["generation"])
			assert.Equal(t, "pending", next["status"])
			invitation = next
		})
	}
	t.Run("platform root joins as member", func(t *testing.T) {
		target := strconv.Itoa(c.users["root"].Id)
		invite := c.mutate(t, "owner", "POST", path, "invite", map[string]any{"revision": c.revision(t), "target_user_id": target, "role": "member"}, nil, false)
		c.mutate(t, "root", "POST", path+"/"+invite["object_id"].(string)+"/accept", "invitation_accept", map[string]any{"revision": c.revision(t), "generation": invite["generation"]}, nil, false)
		status, _, b := c.json(t, "GET", c.path(), "root", nil, "")
		require.Equal(t, 200, status)
		assert.Equal(t, "member", b["data"].(map[string]any)["my_role"])
		status, h, b := c.json(t, "POST", path, "root", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["empty"].Id), "role": "member"}, "")
		organizationError(t, status, h, b, 403, "ORG_FORBIDDEN")
		status, h, b = c.json(t, "POST", path, "root", map[string]any{"revision": initialRevision, "target_user_id": strconv.Itoa(c.users["empty"].Id), "role": "member"}, "")
		organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
		assert.NotContains(t, b, "data")
	})
	for _, state := range []string{"disabled", "revoked", "expired"} {
		t.Run("no revision after "+state, func(t *testing.T) {
			f := newOrganizationLifecycleClient(t)
			stale := f.revision(t)
			if state == "disabled" {
				f.mutate(t, "owner", "POST", f.path()+"/self-state", "self_disable", map[string]any{"revision": stale, "disabled": true, "reason": ""}, nil, true)
			} else if state == "revoked" {
				revoked, err := model.RevokeUserSession(f.users["owner"].Id, f.sids["owner"], "invitation_revision_test")
				require.NoError(t, err)
				require.True(t, revoked)
			} else {
				require.NoError(t, f.db.Model(&model.UserSession{}).Where("sid = ?", f.sids["owner"]).Update("expires_at", time.Now().Unix()-1).Error)
			}
			status, h, b := f.json(t, "POST", f.path()+"/invitations", "owner", map[string]any{"revision": stale, "target_user_id": strconv.Itoa(f.users["foreign"].Id), "role": "member"}, "")
			if state == "disabled" {
				organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
			} else {
				organizationError(t, status, h, b, 401, "AUTH_SESSION_REVOKED")
			}
			assert.NotContains(t, b, "data")
		})
	}
}

// The rollback hook runs only after the real transaction is rolled back. It
// makes selector changes and uncertain rollback outcomes deterministic, without
// changing production callbacks or relying on concurrent timing.
type organizationSelectorPool struct {
	gorm.ConnPool
	afterRollback func() error
	fired         atomic.Bool
}

func (p *organizationSelectorPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
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
	return &organizationSelectorTx{ConnPool: pool, owner: p}, nil
}

type organizationSelectorTx struct {
	gorm.ConnPool
	owner *organizationSelectorPool
}

func (tx *organizationSelectorTx) Commit() error { return tx.ConnPool.(gorm.TxCommitter).Commit() }
func (tx *organizationSelectorTx) Rollback() error {
	if err := tx.ConnPool.(gorm.TxCommitter).Rollback(); err != nil {
		return err
	}
	if tx.owner.fired.CompareAndSwap(false, true) {
		return tx.owner.afterRollback()
	}
	return nil
}

func TestOrganizationLifecycleInvitationIdentity(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	path := c.path() + "/invitations"
	longUsername, atUsername := strings.Repeat("名", 20), "target@example.test"
	for actor, username := range map[string]string{"foreign": longUsername, "empty": atUsername} {
		require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", c.users[actor].Id).Update("username", username).Error)
		c.users[actor].Username = username
	}
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"both selectors", map[string]any{"target_user_id": strconv.Itoa(c.users["empty"].Id), "username": atUsername}},
		{"no selector", map[string]any{}},
		{"null username", map[string]any{"username": nil}},
		{"nonstring username", map[string]any{"username": 42}},
		{"empty username", map[string]any{"username": ""}},
		{"over twenty codepoints", map[string]any{"username": strings.Repeat("名", 21)}},
		{"control character", map[string]any{"username": "target\n"}},
		{"email field", map[string]any{"email": atUsername}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := maps.Clone(tc.body)
			body["revision"], body["role"] = c.revision(t), "member"
			status, h, b := c.json(t, "POST", path, "owner", body, "")
			code := "ORG_REQUEST_INVALID"
			if tc.name == "email field" {
				code = "ORG_EMAIL_INVITE_UNSUPPORTED"
			}
			organizationError(t, status, h, b, 400, code)
		})
	}
	for _, username := range []string{"TARGET@example.test", "tárget@example.test", atUsername + " "} {
		status, h, b := c.json(t, "POST", path, "owner", map[string]any{"revision": c.revision(t), "username": username, "role": "member"}, "")
		organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
	}
	for _, tc := range []struct {
		actor, endpoint, revision, code string
		status                          int
	}{
		{"owner", path, "1", "ORG_STATE_CHANGED", 409},
		{"member", path, c.revision(t), "ORG_FORBIDDEN", 403},
		{"root", path, c.revision(t), "ORG_NOT_FOUND", 404},
		{"owner", fmt.Sprintf("/api/organizations/%d/invitations", c.orgB), "1", "ORG_NOT_FOUND", 404},
	} {
		for _, username := range []string{longUsername, "missing-user"} {
			status, h, b := c.json(t, "POST", tc.endpoint, tc.actor, map[string]any{"revision": tc.revision, "username": username, "role": "member"}, "")
			organizationError(t, status, h, b, tc.status, tc.code)
			assert.NotContains(t, b, "revision")
		}
	}
	// Legacy IDs and an exact username containing @ both use the public write
	// and acceptance routes; neither requires an email lookup or new proof shape.
	for _, tc := range []struct{ actor, field, value string }{
		{"root", "target_user_id", strconv.Itoa(c.users["root"].Id)},
		{"empty", "username", atUsername},
	} {
		invitation := c.mutate(t, "owner", "POST", path, "invite", map[string]any{"revision": c.revision(t), tc.field: tc.value, "role": "member"}, nil, false)
		c.mutate(t, tc.actor, "POST", path+"/"+invitation["object_id"].(string)+"/accept", "invitation_accept", map[string]any{"revision": c.revision(t), "generation": invitation["generation"]}, nil, false)
	}
	status, h, b := c.json(t, "POST", path, "owner", map[string]any{"revision": c.revision(t), "username": atUsername, "role": "member"}, "")
	organizationError(t, status, h, b, 409, "ORG_ALREADY_MEMBER")

	revision := c.revision(t)
	command := map[string]any{"organization_id": strconv.FormatInt(c.orgA, 10), "revision": revision, "username": longUsername, "role": "admin"}
	status, h, b = c.json(t, "POST", c.path()+"/authorization-context", "owner", map[string]any{"action": "invite", "command": command}, "")
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	assert.True(t, organizationPrivateNoStore(h.Values("Cache-Control")))
	op := b["data"].(map[string]any)["operation"].(map[string]any)
	idBody := map[string]any{"revision": revision, "target_user_id": strconv.Itoa(c.users["foreign"].Id), "role": "admin"}
	assert.Equal(t, c.operation(t, "owner", "invite", idBody, nil), op, "username preview must produce the original ID-only proof contract")
	malformedContext := maps.Clone(op["context"].(map[string]any))
	malformedContext["command"] = command
	var flowCount int64
	require.NoError(t, c.db.Model(&model.AuthFlow{}).Count(&flowCount).Error)
	status, h, b = c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": op["scope"], "context": malformedContext, "method": "password", "password": c.passwords["owner"]}, "")
	organizationError(t, status, h, b, 400, "SECURITY_CONTEXT_INVALID")
	var afterCount int64
	require.NoError(t, c.db.Model(&model.AuthFlow{}).Count(&afterCount).Error)
	assert.Equal(t, flowCount, afterCount, "raw username proof context must not create verification state")
	proof := c.proof(t, "owner", op, "password", "")
	var flow model.AuthFlow
	require.NoError(t, c.db.Where("purpose = ? AND user_id = ? AND session_id = ?", model.AuthFlowPurposeSecurityProof, c.users["owner"].Id, c.sids["owner"]).First(&flow).Error)
	require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", c.users["foreign"].Id).Update("username", "renamed-foreign").Error)
	c.users["foreign"].Username = "renamed-foreign"
	reused := model.User{Username: longUsername, Password: "fixture-not-login-password", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: fmt.Sprintf("identity-%d", c.users["foreign"].Id)}
	require.NoError(t, c.db.Create(&reused).Error)
	status, h, b = c.json(t, "POST", path, "owner", map[string]any{"revision": revision, "username": longUsername, "role": "admin"}, proof)
	organizationError(t, status, h, b, 403, "SECURITY_PROOF_CONTEXT_MISMATCH")
	require.NoError(t, c.db.First(&flow, flow.Id).Error)
	assert.Nil(t, flow.ConsumedAt)
	status, _, b = c.json(t, "POST", path, "owner", idBody, proof)
	require.Equal(t, 200, status)
	require.Equal(t, true, b["success"])
	invitation := b["data"].(map[string]any)
	var stored model.OrganizationInvitation
	require.NoError(t, c.db.First(&stored, invitation["object_id"]).Error)
	assert.Equal(t, c.users["foreign"].Id, stored.TargetUserID)
	c.mutate(t, "foreign", "POST", path+"/"+invitation["object_id"].(string)+"/accept", "invitation_accept", map[string]any{"revision": c.revision(t), "generation": invitation["generation"]}, nil, false)

	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprintf("selector rollback failure=%t", failure), func(t *testing.T) {
			require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", reused.Id).Update("username", longUsername).Error)
			revision := c.revision(t)
			var events, invitations int64
			require.NoError(t, c.db.Model(&model.OrganizationEvent{}).Count(&events).Error)
			require.NoError(t, c.db.Model(&model.OrganizationInvitation{}).Count(&invitations).Error)
			originalPool, originalStatementPool := c.db.ConnPool, c.db.Statement.ConnPool
			pool := &organizationSelectorPool{ConnPool: originalPool, afterRollback: func() error {
				if failure {
					return errors.New("test rollback outcome uncertain")
				}
				return c.db.Model(&model.User{}).Where("id = ?", reused.Id).Update("username", "changed-after-resolve").Error
			}}
			c.db.ConnPool, c.db.Statement.ConnPool = pool, pool
			t.Cleanup(func() { c.db.ConnPool, c.db.Statement.ConnPool = originalPool, originalStatementPool })
			status, h, b := c.json(t, "POST", path, "owner", map[string]any{"revision": revision, "username": longUsername, "role": "member"}, "")
			if failure {
				organizationError(t, status, h, b, 500, "ORG_INTERNAL_ERROR")
			} else {
				organizationError(t, status, h, b, 409, "ORG_STATE_CHANGED")
			}
			assert.True(t, pool.fired.Load())
			assert.Equal(t, revision, c.revision(t))
			require.NoError(t, c.db.Model(&model.OrganizationEvent{}).Count(&afterCount).Error)
			assert.Equal(t, events, afterCount)
			require.NoError(t, c.db.Model(&model.OrganizationInvitation{}).Count(&afterCount).Error)
			assert.Equal(t, invitations, afterCount)
		})
	}

	// Unavailable users stay in the member page with the same IDs and cursors.
	require.NoError(t, c.db.Delete(&model.User{}, c.users["member"].Id).Error)
	require.NoError(t, c.db.Unscoped().Delete(&model.User{}, c.users["admin"].Id).Error)
	want := map[string]string{}
	for _, actor := range []string{"owner", "admin", "member", "revoked", "root", "empty", "foreign"} {
		username := c.users[actor].Username
		if actor == "admin" || actor == "member" {
			username = ""
		}
		want[strconv.Itoa(c.users[actor].Id)] = username
	}
	seen, cursor := map[string]string{}, ""
	for range 4 {
		endpoint := c.path() + "/members?limit=2" + cursor
		status, _, b := c.json(t, "GET", endpoint, "owner", nil, "")
		require.Equal(t, 200, status)
		page := b["data"].(map[string]any)
		for _, item := range page["items"].([]any) {
			member := item.(map[string]any)
			require.Len(t, member, 6)
			id := member["user_id"].(string)
			assert.NotContains(t, seen, id)
			seen[id] = member["username"].(string)
		}
		if page["next_after_id"] == nil {
			break
		}
		cursor = "&after_id=" + page["next_after_id"].(string)
	}
	assert.Equal(t, want, seen)
	c.mutate(t, "owner", "DELETE", c.path()+"/members/"+strconv.Itoa(c.users["root"].Id), "remove", map[string]any{"revision": c.revision(t)}, map[string]any{"target_user_id": strconv.Itoa(c.users["root"].Id)}, false)
	status, h, b = c.json(t, "GET", c.path()+"/members", "root", nil, "")
	organizationError(t, status, h, b, 404, "ORG_NOT_FOUND")
}

// This fixture writes owned rows through the real task writer. It deliberately
// does not submit organization work, invoke a provider or exercise billing.
func TestOrganizationInvitationPresentation(t *testing.T) {
	c := newOrganizationLifecycleClient(t)
	path := c.path() + "/invitations"
	username := "target@example.test"
	require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", c.users["foreign"].Id).Update("username", username).Error)
	c.users["foreign"].Username = username
	first := c.mutate(t, "owner", "POST", path, "invite", map[string]any{"revision": c.revision(t), "username": username, "role": "member"}, nil, false)
	second := c.mutate(t, "admin", "POST", path, "invite", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["empty"].Id), "role": "member"}, nil, false)
	adminBody := map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["root"].Id), "role": "admin"}
	operation := c.operation(t, "owner", "invite", adminBody, nil)
	context := operation["context"].(map[string]any)
	assert.NotContains(t, context["command"], "from_username")
	assert.NotContains(t, context["command"], "target_username")
	assert.NotContains(t, context["snapshot"], "from_username")
	assert.NotContains(t, context["snapshot"], "target_username")
	c.mutate(t, "owner", "POST", path, "invite", adminBody, nil, true)
	firstID, secondID := first["object_id"].(string), second["object_id"].(string)
	firstResult := path + "/" + firstID + "/generations/1"

	t.Run("authorized pages and single generation", func(t *testing.T) {
		for _, tc := range []struct{ endpoint, from, target, objectID string }{
			{path + "?limit=1", "owner", "foreign", firstID},
			{path + "?limit=1&after_id=" + firstID, "admin", "empty", secondID},
		} {
			status, headers, body := c.json(t, "GET", tc.endpoint, "owner", nil, "")
			require.Equal(t, 200, status)
			assert.True(t, organizationPrivateNoStore(headers.Values("Cache-Control")))
			page := body["data"].(map[string]any)
			items := page["items"].([]any)
			require.Len(t, items, 1)
			item := items[0].(map[string]any)
			assert.Len(t, item, 15)
			assert.Equal(t, tc.objectID, item["object_id"])
			assert.Equal(t, tc.objectID, page["next_after_id"])
			assert.Equal(t, strconv.Itoa(c.users[tc.from].Id), item["from_user_id"])
			assert.Equal(t, c.users[tc.from].Username, item["from_username"])
			assert.Equal(t, c.users[tc.target].Username, item["target_username"])
		}
		status, _, body := c.json(t, "GET", firstResult, "foreign", nil, "")
		require.Equal(t, 200, status)
		assert.Equal(t, c.users["owner"].Username, body["data"].(map[string]any)["from_username"])
		assert.Equal(t, username, body["data"].(map[string]any)["target_username"])
		status, _, body = c.json(t, "GET", "/api/organization-invitations", "foreign", nil, "")
		require.Equal(t, 200, status)
		items := body["data"].(map[string]any)["items"].([]any)
		require.Len(t, items, 1)
		assert.Equal(t, c.users["owner"].Username, items[0].(map[string]any)["from_username"])
		status, _, body = c.json(t, "GET", path, "admin", nil, "")
		require.Equal(t, 200, status)
		items = body["data"].(map[string]any)["items"].([]any)
		require.Len(t, items, 2, "administrators see member invitations only")
		for _, tc := range []struct {
			actor, endpoint, code string
			status                int
		}{
			{"member", path, "ORG_FORBIDDEN", 403}, {"root", path, "ORG_NOT_FOUND", 404},
			{"empty", firstResult, "ORG_NOT_FOUND", 404},
			{"owner", fmt.Sprintf("/api/organizations/%d/invitations", c.orgB), "ORG_NOT_FOUND", 404},
		} {
			status, headers, body := c.json(t, "GET", tc.endpoint, tc.actor, nil, "")
			organizationError(t, status, headers, body, tc.status, tc.code)
		}
	})

	t.Run("generation identity and current name snapshot", func(t *testing.T) {
		c.mutate(t, "admin", "POST", path+"/"+firstID+"/reissue", "reissue", map[string]any{"revision": c.revision(t), "generation": "1", "target_user_id": strconv.Itoa(c.users["foreign"].Id), "role": "member"}, nil, false)
		for actor, name := range map[string]string{"owner": "renamed-owner", "admin": "renamed-admin", "foreign": "renamed-target"} {
			require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", c.users[actor].Id).Update("username", name).Error)
			c.users[actor].Username = name
		}
		for _, tc := range []struct{ generation, actor string }{{"1", "owner"}, {"2", "admin"}} {
			status, _, body := c.json(t, "GET", path+"/"+firstID+"/generations/"+tc.generation, "owner", nil, "")
			require.Equal(t, 200, status)
			item := body["data"].(map[string]any)
			assert.Equal(t, strconv.Itoa(c.users[tc.actor].Id), item["from_user_id"])
			assert.Equal(t, c.users[tc.actor].Username, item["from_username"])
			assert.Equal(t, strconv.Itoa(c.users["foreign"].Id), item["target_user_id"])
			assert.Equal(t, "renamed-target", item["target_username"])
		}
	})

	t.Run("transfer projection and proof stay unchanged", func(t *testing.T) {
		c.mutate(t, "owner", "POST", c.path()+"/ownership-transfers", "transfer_initiate", map[string]any{"revision": c.revision(t), "target_user_id": strconv.Itoa(c.users["member"].Id), "previous_id": "0", "previous_generation": "0", "replace": false}, nil, true)
		status, _, body := c.json(t, "GET", c.path()+"/ownership-transfer", "owner", nil, "")
		require.Equal(t, 200, status)
		assert.Len(t, body["data"], 13)
		assert.NotContains(t, body["data"], "from_username")
		assert.NotContains(t, body["data"], "target_username")
		malformed := maps.Clone(context)
		command := maps.Clone(context["command"].(map[string]any))
		delete(command, "target_user_id")
		command["email"] = "not-searched@example.test"
		malformed["command"] = command
		var before, after int64
		require.NoError(t, c.db.Model(&model.AuthFlow{}).Count(&before).Error)
		status, headers, body := c.json(t, "POST", "/api/verify", "owner", map[string]any{"scope": operation["scope"], "context": malformed, "method": "password", "password": c.passwords["owner"]}, "")
		organizationError(t, status, headers, body, 400, "SECURITY_CONTEXT_INVALID")
		require.NoError(t, c.db.Model(&model.AuthFlow{}).Count(&after).Error)
		assert.Equal(t, before, after)
	})

	t.Run("missing names retain invitation and cursor", func(t *testing.T) {
		require.NoError(t, c.db.Delete(&model.User{}, c.users["admin"].Id).Error)
		require.NoError(t, c.db.Delete(&model.User{}, c.users["foreign"].Id).Error)
		require.NoError(t, c.db.Unscoped().Delete(&model.User{}, c.users["empty"].Id).Error)
		for _, tc := range []struct{ after, id string }{{"0", firstID}, {firstID, secondID}} {
			status, _, body := c.json(t, "GET", path+"?limit=1&after_id="+tc.after, "owner", nil, "")
			require.Equal(t, 200, status)
			page := body["data"].(map[string]any)
			items := page["items"].([]any)
			require.Len(t, items, 1)
			item := items[0].(map[string]any)
			assert.Equal(t, tc.id, item["object_id"])
			assert.Equal(t, tc.id, page["next_after_id"])
			assert.Equal(t, "", item["from_username"])
			assert.Equal(t, "", item["target_username"])
		}
	})

	t.Run("email unsupported retains strict input rejection", func(t *testing.T) {
		revision := c.revision(t)
		for _, tc := range []struct{ name, body, code string }{
			{"email only", `{"revision":%q,"email":"nobody@example.test","role":"member"}`, "ORG_EMAIL_INVITE_UNSUPPORTED"},
			{"empty email", `{"revision":%q,"email":"","role":"member"}`, "ORG_REQUEST_INVALID"},
			{"null email", `{"revision":%q,"email":null,"role":"member"}`, "ORG_REQUEST_INVALID"},
			{"numeric email", `{"revision":%q,"email":123,"role":"member"}`, "ORG_REQUEST_INVALID"},
			{"two selectors", `{"revision":%q,"email":"nobody@example.test","username":"someone","role":"member"}`, "ORG_REQUEST_INVALID"},
			{"ID and email", `{"revision":%q,"email":"nobody@example.test","target_user_id":"1","role":"member"}`, "ORG_REQUEST_INVALID"},
			{"unknown field", `{"revision":%q,"email":"nobody@example.test","role":"member","extra":true}`, "ORG_REQUEST_INVALID"},
			{"duplicate email", `{"revision":%q,"email":"one@example.test","email":"two@example.test","role":"member"}`, "ORG_REQUEST_INVALID"},
			{"empty role", `{"revision":%q,"email":"nobody@example.test","role":""}`, "ORG_REQUEST_INVALID"},
			{"invalid revision", `{"revision":%q,"email":"nobody@example.test","role":"member"}`, "ORG_REQUEST_INVALID"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				value := revision
				if tc.name == "invalid revision" {
					value = "0"
				}
				status, headers, body := c.request(t, "POST", path, "owner", fmt.Sprintf(tc.body, value), http.Header{"Content-Type": {"application/json"}})
				organizationError(t, status, headers, body, 400, tc.code)
				if tc.code == "ORG_EMAIL_INVITE_UNSUPPORTED" {
					assert.Equal(t, "Email invitations are not supported. Use a user ID or username.", body["message"])
				}
			})
		}
		command := map[string]any{"organization_id": strconv.FormatInt(c.orgA, 10), "revision": revision, "email": "nobody@example.test", "role": "admin"}
		status, headers, body := c.json(t, "POST", c.path()+"/authorization-context", "owner", map[string]any{"action": "invite", "command": command}, "")
		organizationError(t, status, headers, body, 400, "ORG_EMAIL_INVITE_UNSUPPORTED")
		for _, orgID := range []string{"0", strconv.FormatInt(c.orgB, 10)} {
			command["organization_id"] = orgID
			status, headers, body = c.json(t, "POST", c.path()+"/authorization-context", "owner", map[string]any{"action": "invite", "command": command}, "")
			organizationError(t, status, headers, body, 400, "ORG_REQUEST_INVALID")
		}
		status, headers, body = c.json(t, "POST", path+"/"+firstID+"/reissue", "owner", map[string]any{"revision": revision, "generation": "2", "email": "nobody@example.test", "role": "member"}, "")
		organizationError(t, status, headers, body, 400, "ORG_REQUEST_INVALID")
	})
}

func newOrganizationTaskReadClient(t *testing.T, upstream string) (*organizationLifecycleClient, map[string]*model.Task) {
	t.Helper()
	c := newOrganizationLifecycleClient(t)
	require.NoError(t, c.db.AutoMigrate(&model.Channel{}))
	originalFetch := *system_setting.GetFetchSetting()
	originalSecret := common.CryptoSecret
	common.CryptoSecret = common.SessionSecret
	t.Cleanup(func() {
		*system_setting.GetFetchSetting() = originalFetch
		common.CryptoSecret = originalSecret
	})
	address, err := url.Parse(upstream)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", address.Hostname())
	*system_setting.GetFetchSetting() = system_setting.FetchSetting{EnableSSRFProtection: true, AllowPrivateIp: true,
		IpFilterMode: true, IpList: []string{"127.0.0.1/32"}, AllowedPorts: []string{address.Port()}}
	plugin := routerPluginSource("orgreadfixture", "1.0.0", `[{method:"GET",path:"/orgreadfixture/jobs/:task_id",type:"query",render:"native"}]`) + `
export function listArtifacts(task) {
 return [{key:"video",type:"video",mimeType:"video/mp4"}];
}
export function buildContentRequest(ctx) {
 if (ctx.data.lookup) utils.fetch({url:ctx.baseUrl+"/lookup"});
 return {url:ctx.data.url,method:ctx.clientRequest.method,headers:{"X-Fixture-Key":ctx.apiKey}};
}
`
	_, err = jsplugin.DefaultRegistry.Register(plugin, jsplugin.Options{Key: "orgreadfixture", Version: "1.0.0"})
	require.NoError(t, err)
	channel := model.Channel{Name: "owned-organization-artifacts", Type: constant.ChannelTypeTaskPlugin,
		Key: "fixture-provider-key", Status: common.ChannelStatusEnabled, BaseURL: &upstream}
	require.NoError(t, c.db.Create(&channel).Error)
	rows := map[string]*model.Task{}
	for _, seed := range []struct {
		name, actor string
		org         int64
	}{
		{"personal", "owner", 0}, {"owner", "owner", c.orgA}, {"member", "member", c.orgA},
		{"admin", "admin", c.orgA}, {"other_org", "member", c.orgB}, {"same_org_duplicate", "owner", c.orgA},
		{"personal_duplicate", "owner", 0}, {"pending", "member", c.orgA}, {"failed", "member", c.orgA},
		{"legacy_video", "member", c.orgA}, {"legacy_audio", "member", c.orgA}, {"discarded", "member", c.orgA},
	} {
		task := &model.Task{TaskID: "org-read-" + seed.name, UserId: c.users[seed.actor].Id, OrganizationID: seed.org,
			Platform: "orgreadfixture", ChannelId: channel.Id, Action: constant.TaskActionTextToVideo,
			Status: model.TaskStatusSuccess, Progress: "100%", SubmitTime: 1, FinishTime: 2,
			PrivateData: model.TaskPrivateData{Execution: &model.TaskExecutionSnapshot{TaskPlugin: &model.TaskPluginSnapshot{Key: "orgreadfixture", Version: "1.0.0", APIVersion: 1}}}}
		if slices.Contains([]string{"owner", "member", "other_org", "same_org_duplicate", "personal_duplicate"}, seed.name) {
			task.TaskID = "shared-public-task-id"
		}
		task.SetData(map[string]any{"url": upstream + "/media?artifact-secret=org-private-canary"})
		switch seed.name {
		case "owner":
			task.ID = 9007199254740993 // Wire row IDs must remain exact above JavaScript's integer range.
		case "pending":
			task.Status, task.Progress, task.FinishTime = model.TaskStatusInProgress, "20%", 0
		case "failed":
			task.Status = model.TaskStatusFailure
			task.FailReason = "https://raw-error.invalid/private?raw-error-canary"
			task.PrivateData.ResultURL = "https://raw-result.invalid/private?raw-result-canary"
		case "personal", "legacy_video":
			task.Platform, task.PrivateData = "document", model.TaskPrivateData{}
			task.FailReason = "data:video/mp4;base64,YWJj"
		case "legacy_audio":
			task.Platform, task.PrivateData = constant.TaskPlatformSuno, model.TaskPrivateData{}
			task.SetData([]any{map[string]any{"audio_url": "https://audio.invalid/private?audio-secret-canary"}})
		case "discarded":
			task.PrivateData.ResultDiscarded = true
		}
		require.NoError(t, task.InsertWithContext(t.Context()))
		rows[seed.name] = task
	}
	return c, rows
}

func readOrganizationTaskContent(t *testing.T, c *organizationLifecycleClient, method, path, actor string, headers http.Header) (int, http.Header, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, c.server.URL+path, nil)
	require.NoError(t, err)
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = http.Header{}
	}
	if actor != "" {
		request.Header.Set("Authorization", "Bearer "+c.bearer[actor])
	}
	response, err := c.client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	require.NoError(t, err)
	return response.StatusCode, response.Header, body
}

func TestOrganizationTaskReadLifecycle(t *testing.T) {
	t.Run("isolation_permissions_and_artifacts", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "fixture-provider-key", r.Header.Get("X-Fixture-Key"))
			assert.Empty(t, r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("ETag", `"fixture-etag"`)
			w.Header().Set("Set-Cookie", "provider-secret-canary")
			w.Header().Set("Location", "https://redirect.invalid/private?location-secret-canary")
			w.Header().Set("WWW-Authenticate", "provider-secret-canary")
			if r.Header.Get("If-None-Match") != "" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			if r.Header.Get("Range") == "bytes=900-" {
				w.Header().Set("Content-Range", "bytes */14")
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			if r.Header.Get("Range") == "bytes=0-3" {
				w.Header().Set("Content-Range", "bytes 0-3/14")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte("arti"))
				return
			}
			w.Header().Set("Content-Length", "14")
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte("artifact-bytes"))
			}
		}))
		t.Cleanup(upstream.Close)
		c, rows := newOrganizationTaskReadClient(t, upstream.URL)
		base := c.path() + "/tasks/"
		for _, actor := range []string{"owner", "admin", "member"} {
			status, _, response := c.json(t, "GET", "/api/task/self?org_id="+strconv.FormatInt(c.orgA, 10), actor, nil, "")
			require.Equal(t, 200, status)
			encoded, err := common.Marshal(response)
			require.NoError(t, err)
			for _, secret := range []string{"raw-error-canary", "raw-result-canary", "org-private-canary", "audio-secret-canary", "fixture-provider-key"} {
				assert.NotContains(t, string(encoded), secret)
			}
			seen := map[string]bool{}
			for _, value := range response["data"].(map[string]any)["items"].([]any) {
				item := value.(map[string]any)
				id, ok := item["task_row_id"].(string)
				require.True(t, ok)
				seen[id] = true
				assert.Empty(t, item["result_url"])
				assert.Empty(t, item["fail_reason"])
			}
			assert.Contains(t, seen, strconv.FormatInt(rows["member"].ID, 10))
			assert.NotContains(t, seen, strconv.FormatInt(rows["other_org"].ID, 10))
			assert.Equal(t, actor != "member", seen[strconv.FormatInt(rows["owner"].ID, 10)])
		}
		for _, tc := range []struct {
			actor, row string
			org        int64
			status     int
		}{
			{"owner", "member", c.orgA, 200}, {"admin", "member", c.orgA, 200}, {"member", "member", c.orgA, 200},
			{"member", "owner", c.orgA, 404}, {"owner", "same_org_duplicate", c.orgA, 200},
			{"member", "other_org", c.orgB, 200}, {"member", "other_org", c.orgA, 404},
			{"owner", "member", c.orgB, 404}, {"owner", "personal_duplicate", c.orgA, 404},
			{"foreign", "member", c.orgA, 404}, {"root", "member", c.orgA, 404}, {"owner", "discarded", c.orgA, 404},
		} {
			endpoint := fmt.Sprintf("/api/organizations/%d/tasks/%d", tc.org, rows[tc.row].ID)
			status, headers, response := c.json(t, "GET", endpoint, tc.actor, nil, "")
			if tc.status == 200 {
				require.Equal(t, 200, status)
				data := response["data"].(map[string]any)
				assert.Equal(t, strconv.FormatInt(rows[tc.row].ID, 10), data["task_row_id"])
				assert.Equal(t, rows[tc.row].TaskID, data["task_id"])
				require.Len(t, data, 10)
			} else {
				organizationError(t, status, headers, response, tc.status, "ORG_NOT_FOUND")
			}
		}
		rowPath := base + strconv.FormatInt(rows["member"].ID, 10)
		for _, suffix := range []string{"?access=old-capability", "?user_id=1", "?org_id=1&org_id=1"} {
			status, _, _ := c.json(t, "GET", rowPath+suffix, "member", nil, "")
			assert.Equal(t, 400, status)
		}
		for _, id := range []string{"0", "01", "-1", "9223372036854775808", "shared-public-task-id"} {
			status, _, _ := c.json(t, "GET", base+id, "member", nil, "")
			assert.Equal(t, 400, status)
		}
		for _, name := range []string{"member", "legacy_video"} {
			status, headers, response := c.json(t, "GET", base+strconv.FormatInt(rows[name].ID, 10)+"/artifacts", "member", nil, "")
			require.Equal(t, 200, status)
			assert.True(t, organizationPrivateNoStore(headers.Values("Cache-Control")))
			data := response["data"].(map[string]any)
			artifacts := data["artifacts"].([]any)
			require.Len(t, artifacts, 1)
			content := artifacts[0].(map[string]any)["content_url"].(string)
			assert.Equal(t, base+strconv.FormatInt(rows[name].ID, 10)+"/artifacts/video/content", content)
			assert.NotContains(t, content, "access=")
			for _, method := range []string{"GET", "HEAD"} {
				status, headers, body := readOrganizationTaskContent(t, c, method, content, "member", nil)
				require.Equal(t, 200, status)
				assert.Equal(t, "private, no-store", headers.Get("Cache-Control"))
				assert.Empty(t, headers.Get("Location"))
				assert.Empty(t, headers.Get("Set-Cookie"))
				assert.Empty(t, headers.Get("WWW-Authenticate"))
				assert.Empty(t, headers.Get("Content-Encoding"))
				if method == "HEAD" {
					assert.Empty(t, body)
				} else if name == "legacy_video" {
					assert.Equal(t, "abc", string(body))
				} else {
					assert.Equal(t, "artifact-bytes", string(body))
				}
			}
		}
		for _, name := range []string{"pending", "legacy_audio"} {
			status, _, response := c.json(t, "GET", base+strconv.FormatInt(rows[name].ID, 10)+"/artifacts", "member", nil, "")
			require.Equal(t, 200, status)
			assert.Empty(t, response["data"].(map[string]any)["artifacts"])
		}
		content := rowPath + "/artifacts/video/content"
		for _, tc := range []struct {
			headers http.Header
			status  int
			body    string
		}{
			{http.Header{"Range": {"bytes=0-3"}}, 206, "arti"},
			{http.Header{"If-None-Match": {`"fixture-etag"`}}, 304, ""},
			{http.Header{"Range": {"bytes=900-"}}, 416, ""},
		} {
			status, headers, body := readOrganizationTaskContent(t, c, "GET", content, "member", tc.headers)
			assert.Equal(t, tc.status, status)
			assert.Equal(t, tc.body, string(body))
			assert.True(t, organizationPrivateNoStore(headers.Values("Cache-Control")))
		}
		patSuffix, err := common.GenerateRandomCharsKey(43)
		require.NoError(t, err)
		pat := model.AccessTokenPrefix + patSuffix
		grant := &model.UserAccessToken{Name: "organization-task-read", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
		require.NoError(t, grant.SetScopes([]string{"*"}))
		require.NoError(t, model.CreateUserAccessToken(c.users["root"].Id, grant, service.AccessTokenMaxPerUser))
		legacy, err := common.GenerateRandomCharsKey(32)
		require.NoError(t, err)
		require.NoError(t, c.db.Model(&model.User{}).Where("id = ?", c.users["root"].Id).Update("access_token", legacy).Error)
		for _, tc := range []struct {
			credential, code string
			status           int
		}{{pat, "AUTH_SESSION_REQUIRED", 403}, {legacy, "AUTH_SESSION_REQUIRED", 403}, {c.bearer["relay"], "AUTH_UNAUTHORIZED", 401}, {"", "AUTH_UNAUTHORIZED", 401}} {
			status, headers, response := c.json(t, "GET", rowPath+"/artifacts", tc.credential, nil, "")
			organizationError(t, status, headers, response, tc.status, tc.code)
		}
		status, _, _ := c.request(t, "GET", rowPath, "", "", http.Header{"Cookie": {service.RefreshCookieName + "=" + c.refresh["member"]}})
		assert.Equal(t, 401, status)
		revoked, err := model.RevokeUserSession(c.users["admin"].Id, c.sids["admin"], "organization_task_read")
		require.NoError(t, err)
		require.True(t, revoked)
		status, headers, response := c.json(t, "GET", "/api/organizations/999999/tasks/1", "admin", nil, "")
		organizationError(t, status, headers, response, 401, "AUTH_SESSION_REVOKED")
		access, err := service.IssueTaskArtifactAccess(rows["member"].TaskID, "video")
		require.NoError(t, err)
		status, _, _ = readOrganizationTaskContent(t, c, "GET", "/v1/tasks/"+rows["member"].TaskID+"/artifacts/video/content?access="+url.QueryEscape(access), "", nil)
		assert.Equal(t, 404, status, "an old public-ID capability cannot select an organization row")
	})

	for _, change := range []string{"remove", "self_disable", "platform_disable"} {
		t.Run("completed_after_"+change, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("artifact-bytes")) }))
			t.Cleanup(upstream.Close)
			c, rows := newOrganizationTaskReadClient(t, upstream.URL)
			base := c.path() + "/tasks/" + strconv.FormatInt(rows["pending"].ID, 10)
			status, _, response := c.json(t, "GET", base, "member", nil, "")
			require.Equal(t, 200, status)
			assert.Equal(t, string(model.TaskStatusInProgress), response["data"].(map[string]any)["status"])
			status, _, response = c.json(t, "GET", base+"/artifacts", "member", nil, "")
			require.Equal(t, 200, status)
			assert.Empty(t, response["data"].(map[string]any)["artifacts"])
			oldURL := c.path() + "/tasks/" + strconv.FormatInt(rows["member"].ID, 10) + "/artifacts/video/content"
			status, _, _ = readOrganizationTaskContent(t, c, "GET", oldURL, "member", nil)
			require.Equal(t, 200, status)
			_, err := model.GetUserCache(c.users["member"].Id)
			require.NoError(t, err)
			_, err = model.GetUserSessionCached(c.sids["member"])
			require.NoError(t, err)
			if change == "remove" {
				c.mutate(t, "owner", "DELETE", c.path()+"/members/"+strconv.Itoa(c.users["member"].Id), "remove", map[string]any{"revision": c.revision(t)}, map[string]any{"target_user_id": strconv.Itoa(c.users["member"].Id)}, false)
			} else {
				actor, endpoint := "owner", c.path()+"/self-state"
				if change == "platform_disable" {
					actor, endpoint = "root", fmt.Sprintf("/api/platform/organizations/%d/state", c.orgA)
				}
				c.mutate(t, actor, "POST", endpoint, change, map[string]any{"revision": c.revision(t), "disabled": true, "reason": "task read revocation"}, nil, true)
			}
			rows["pending"].Status, rows["pending"].Progress, rows["pending"].FinishTime = model.TaskStatusSuccess, "100%", 2
			updated, err := rows["pending"].UpdateWithStatus(model.TaskStatusInProgress)
			require.NoError(t, err)
			require.True(t, updated)
			for _, endpoint := range []string{"/api/task/self?org_id=" + strconv.FormatInt(c.orgA, 10), base, base + "/artifacts"} {
				status, headers, response := c.json(t, "GET", endpoint, "member", nil, "")
				organizationError(t, status, headers, response, 404, "ORG_NOT_FOUND")
			}
			for _, method := range []string{"GET", "HEAD"} {
				status, headers, body := readOrganizationTaskContent(t, c, method, oldURL, "member", nil)
				assert.Equal(t, 404, status)
				assert.NotContains(t, string(body), "artifact-bytes")
				assert.True(t, organizationPrivateNoStore(headers.Values("Cache-Control")))
			}
			if change == "remove" {
				status, _, _ := c.json(t, "GET", base, "owner", nil, "")
				assert.Equal(t, 200, status, "departed submitter's task remains with the organization")
			}
			personalAccess, err := service.IssueTaskArtifactAccess(rows["personal"].TaskID, "video")
			require.NoError(t, err)
			status, _, body := readOrganizationTaskContent(t, c, "GET", "/v1/tasks/"+rows["personal"].TaskID+"/artifacts/video/content?access="+url.QueryEscape(personalAccess), "", nil)
			assert.Equal(t, 200, status)
			assert.Equal(t, "abc", string(body))
			status, _, response = c.json(t, "GET", "/api/task/self", "owner", nil, "")
			require.Equal(t, 200, status)
			for _, item := range response["data"].(map[string]any)["items"].([]any) {
				assert.NotContains(t, item.(map[string]any), "task_row_id", "personal projection remains unchanged")
			}
		})
	}

	for _, outcome := range []string{"plugin", "GET", "HEAD", "304", "416", "disconnect", "upstream_error"} {
		t.Run("revoked_before_publication_"+outcome, func(t *testing.T) {
			reached, release := make(chan struct{}), make(chan struct{})
			var once, reachedOnce sync.Once
			var mediaRequests atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/media" {
					mediaRequests.Add(1)
				}
				reachedOnce.Do(func() { close(reached) })
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				if outcome == "disconnect" {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = connection.Close()
					}
					return
				}
				w.Header().Set("Content-Type", "video/mp4")
				w.Header().Set("Location", "https://provider.invalid/private?upstream-secret-canary")
				status := 200
				if outcome == "304" {
					status = 304
				} else if outcome == "416" {
					status = 416
				} else if outcome == "upstream_error" {
					status = 502
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte("never-deliver-artifact-canary"))
			}))
			t.Cleanup(upstream.Close)
			c, rows := newOrganizationTaskReadClient(t, upstream.URL)
			t.Cleanup(func() { once.Do(func() { close(release) }) })
			if outcome == "plugin" {
				rows["member"].SetData(map[string]any{"url": upstream.URL + "/media", "lookup": true})
				updated, err := rows["member"].UpdateWithStatus(model.TaskStatusSuccess)
				require.NoError(t, err)
				require.True(t, updated)
			}
			method := "GET"
			if outcome == "HEAD" {
				method = "HEAD"
			}
			type result struct {
				status int
				header http.Header
				body   []byte
				err    error
			}
			request, err := http.NewRequest(method, c.server.URL+c.path()+"/tasks/"+strconv.FormatInt(rows["member"].ID, 10)+"/artifacts/video/content", nil)
			require.NoError(t, err)
			request.Header.Set("Authorization", "Bearer "+c.bearer["member"])
			done := make(chan result, 1)
			go func() {
				response, err := c.client.Do(request)
				if err != nil {
					done <- result{err: err}
					return
				}
				defer response.Body.Close()
				body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				done <- result{response.StatusCode, response.Header, body, err}
			}()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("authenticated content request did not reach its upstream barrier")
			}
			c.mutate(t, "owner", "DELETE", c.path()+"/members/"+strconv.Itoa(c.users["member"].Id), "remove", map[string]any{"revision": c.revision(t)}, map[string]any{"target_user_id": strconv.Itoa(c.users["member"].Id)}, false)
			once.Do(func() { close(release) })
			select {
			case response := <-done:
				require.NoError(t, response.err)
				assert.Equal(t, 404, response.status)
				assert.NotContains(t, string(response.body), "never-deliver-artifact-canary")
				assert.NotContains(t, string(response.body), "upstream-secret-canary")
				assert.Empty(t, response.header.Get("Location"))
				assert.True(t, organizationPrivateNoStore(response.header.Values("Cache-Control")))
				if method != "HEAD" {
					var body map[string]any
					require.NoError(t, common.Unmarshal(response.body, &body))
					assert.Equal(t, "ORG_NOT_FOUND", body["code"])
				}
			case <-time.After(5 * time.Second):
				t.Fatal("revoked content request did not finish after its barrier")
			}
			if outcome == "plugin" {
				assert.Zero(t, mediaRequests.Load(), "revoked plugin lookup must stop before media fetch")
			}
		})
	}

	t.Run("content_timeout_boundary", func(t *testing.T) {
		// Observe the actual boundary context without waiting thirty seconds.
		engine := gin.New()
		engine.Use(middleware.OrganizationSelectionBoundary())
		for _, route := range []struct{ method, path string }{
			{"GET", "/api/organizations/:org_id/tasks/:task_row_id"},
			{"GET", "/api/organizations/:org_id/tasks/:task_row_id/artifacts"},
			{"GET", "/api/organizations/:org_id/tasks/:task_row_id/artifacts/:artifact_key/content"},
			{"HEAD", "/api/organizations/:org_id/tasks/:task_row_id/artifacts/:artifact_key/content"},
		} {
			engine.Handle(route.method, route.path, func(c *gin.Context) {
				_, bounded := c.Request.Context().Deadline()
				c.Header("X-Test-Context-Bounded", strconv.FormatBool(bounded))
				c.Status(204)
			})
		}
		server := httptest.NewServer(engine)
		t.Cleanup(server.Close)
		for _, tc := range []struct{ method, suffix, bounded string }{
			{"GET", "", "true"}, {"GET", "/artifacts", "true"},
			{"GET", "/artifacts/video/content", "false"}, {"HEAD", "/artifacts/video/content", "false"},
		} {
			request, err := http.NewRequest(tc.method, server.URL+"/api/organizations/1/tasks/1"+tc.suffix, nil)
			require.NoError(t, err)
			response, err := server.Client().Do(request)
			require.NoError(t, err)
			response.Body.Close()
			assert.Equal(t, 204, response.StatusCode)
			assert.Equal(t, tc.bounded, response.Header.Get("X-Test-Context-Bounded"))
		}
	})
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
