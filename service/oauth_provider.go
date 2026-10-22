package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"gorm.io/gorm"
)

var (
	ErrOAuthProviderConfiguration = errors.New("Invalid OAuth provider bridge configuration.")
	ErrOAuthProviderRequest       = errors.New("invalid_request")
	ErrOAuthProviderDenied        = errors.New("access_denied")
	ErrOAuthProviderReplay        = errors.New("invalid_grant")
	ErrOAuthRevocationClient      = errors.New("invalid_client")
	currentOAuthProvider          atomic.Pointer[OAuthProviderBridge]
)

type OAuthProviderConfig struct {
	Enabled           bool
	RevocationEnabled bool
	AdminBaseURL      string
	AuthorizationURL  string
}

type OAuthProviderBridge struct {
	resource  *OAuthUserInfoResource
	admin     string
	authorize string
	policy    string
	revoke    string
	public    *OAuthPublic
}

type OAuthProviderPreview struct {
	PreviewToken   string   `json:"preview_token"`
	ExpiresAt      int64    `json:"expires_at"`
	Phase          string   `json:"phase"`
	ClientID       string   `json:"client_id"`
	ClientName     string   `json:"client_name"`
	Username       string   `json:"username"`
	RequestedScope []string `json:"requested_scopes"`
	AllowedScope   []string `json:"allowed_scopes"`
	Audience       string   `json:"audience"`
}

type OAuthProviderDecision struct {
	Challenge      string   `json:"challenge"`
	PreviewToken   string   `json:"preview_token"`
	Decision       string   `json:"decision"`
	SelectedScopes []string `json:"selected_scopes,omitempty"`
}

type OAuthProviderRedirect struct {
	RedirectTo string `json:"redirect_to"`
}

type oauthProviderBinding struct {
	Identity      AuthIdentity `json:"identity"`
	Phase         string       `json:"phase"`
	PolicyHash    string       `json:"policy_hash"`
	ChallengeHash string       `json:"challenge_hash"`
	RequestHash   string       `json:"request_hash"`
}

// Only security-relevant fields and plain client display text are decoded.
// Unknown optional Hydra metadata, including null values, is deliberately ignored.
type oauthProviderChallenge struct {
	Challenge        string               `json:"challenge"`
	ConsentRequestID *string              `json:"consent_request_id"`
	LoginSessionID   *string              `json:"login_session_id"`
	Subject          *string              `json:"subject"`
	Skip             *bool                `json:"skip"`
	RequestURL       *string              `json:"request_url"`
	Scopes           *[]string            `json:"requested_scope"`
	Audience         *[]string            `json:"requested_access_token_audience"`
	Client           *oauthProviderClient `json:"client"`
}

type oauthProviderClient struct {
	ID          string    `json:"client_id"`
	SubjectType string    `json:"subject_type"`
	Name        *string   `json:"client_name"`
	Method      *string   `json:"token_endpoint_auth_method"`
	Scope       *string   `json:"scope"`
	Audience    *[]string `json:"audience"`
	Redirects   []string  `json:"redirect_uris"`
	Grants      []string  `json:"grant_types"`
	Responses   []string  `json:"response_types"`
	SkipConsent bool      `json:"skip_consent"`
}

type oauthProviderRequest struct {
	binding          oauthProviderBinding
	clientID         string
	clientName       string
	requested        []string
	allowed          []string
	query            url.Values
	consentRequestID string
	loginSessionID   string
}

func InitOAuthProviderBridge() error {
	enabled := os.Getenv("OAUTH_PROVIDER_BRIDGE_ENABLED")
	revocation := os.Getenv("OAUTH_PROVIDER_REVOCATION_ENABLED")
	if enabled != "" && enabled != "false" && enabled != "true" || revocation != "" && revocation != "false" && revocation != "true" {
		return ErrOAuthProviderConfiguration
	}
	bridge, err := NewOAuthProviderBridge(OAuthProviderConfig{
		Enabled: enabled == "true", RevocationEnabled: revocation == "true", AdminBaseURL: os.Getenv("OAUTH_PROVIDER_ADMIN_BASE_URL"),
		AuthorizationURL: os.Getenv("OAUTH_PROVIDER_AUTHORIZATION_URL"),
	}, CurrentOAuthUserInfoResource())
	if err != nil {
		return ErrOAuthProviderConfiguration
	}
	public := os.Getenv("OAUTH_PROVIDER_PUBLIC_ENABLED")
	if public != "" && public != "false" && public != "true" {
		return ErrOAuthProviderConfiguration
	}
	if _, err := NewOAuthPublic(OAuthPublicConfig{Enabled: public == "true", BaseURL: os.Getenv("OAUTH_PROVIDER_PUBLIC_BASE_URL")}, bridge); err != nil {
		return err
	}
	currentOAuthProvider.Store(bridge)
	return nil
}

func CurrentOAuthProviderBridge() *OAuthProviderBridge { return currentOAuthProvider.Load() }

func NewOAuthProviderBridge(config OAuthProviderConfig, resource *OAuthUserInfoResource) (*OAuthProviderBridge, error) {
	if config.RevocationEnabled && (!config.Enabled || resource == nil) {
		return nil, ErrOAuthProviderConfiguration
	}
	if !config.Enabled {
		return nil, nil
	}
	if resource == nil {
		return nil, ErrOAuthProviderConfiguration
	}
	admin, err := url.Parse(config.AdminBaseURL)
	if err != nil || admin.Scheme != "https" || admin.Hostname() == "" || admin.User != nil || admin.RawQuery != "" || admin.ForceQuery || admin.Fragment != "" || admin.Opaque != "" || admin.RawPath != "" || (admin.Path != "" && admin.Path != "/") {
		return nil, ErrOAuthProviderConfiguration
	}
	admin.Path = ""
	base := admin.String()
	if config.AdminBaseURL != base && config.AdminBaseURL != base+"/" || resource.endpoint != base+"/admin/oauth2/introspect" {
		return nil, ErrOAuthProviderConfiguration
	}
	authorize, err := url.Parse(config.AuthorizationURL)
	issuer, issuerErr := url.Parse(resource.issuer)
	if err != nil || issuerErr != nil || authorize.Scheme != "https" || authorize.Host != issuer.Host || authorize.User != nil || authorize.RawQuery != "" || authorize.ForceQuery || authorize.Fragment != "" || authorize.RawPath != "" || authorize.Opaque != "" || authorize.Path != strings.TrimSuffix(issuer.Path, "/")+"/oauth2/auth" || authorize.String() != config.AuthorizationURL {
		return nil, ErrOAuthProviderConfiguration
	}
	policy, err := common.Marshal(struct {
		Admin, Authorization, Issuer, Audience string
		Clients                                []string
	}{base, config.AuthorizationURL, resource.issuer, resource.audience, resource.clients})
	if err != nil {
		return nil, ErrOAuthProviderConfiguration
	}
	bridge := &OAuthProviderBridge{resource: resource, admin: base, authorize: config.AuthorizationURL, policy: fmt.Sprintf("%x", sha256.Sum256(policy))}
	if config.RevocationEnabled {
		bridge.revoke = strings.TrimSuffix(config.AuthorizationURL, "/auth") + "/revoke"
	}
	return bridge, nil
}

func (b *OAuthProviderBridge) RevocationEnabled() bool { return b != nil && b.revoke != "" }

// RevokeToken forwards only to the fixed issuer. Its RFC-style 200 is not proof
// of invalidation: the pinned issuer can mask wrong-client and storage errors.
func (b *OAuthProviderBridge) RevokeToken(ctx context.Context, token, clientID string) error {
	if !b.RevocationEnabled() {
		return ErrOAuthResourceUnavailable
	}
	if !slices.Contains(b.resource.clients, clientID) {
		return ErrOAuthProviderRequest
	}
	body := url.Values{"token": {token}, "client_id": {clientID}}.Encode()
	endpoint := b.revoke
	if b.public != nil {
		endpoint = b.public.base + "/oauth2/revoke"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	// Do not replay a sent credential-bearing body on a reused connection.
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := b.resource.client.Do(req)
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(data) > 4096 {
		return ErrOAuthResourceUnavailable
	}
	if response.StatusCode == http.StatusOK {
		if b.public != nil {
			return b.public.verifyRevocation(ctx, token)
		}
		return nil
	}
	if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized {
		fields, err := common.DecodeRawJSONObject(data)
		var code string
		if err == nil && common.Unmarshal(fields["error"], &code) == nil && code == "invalid_client" {
			return ErrOAuthRevocationClient
		}
	}
	return ErrOAuthResourceUnavailable
}

func (b *OAuthProviderBridge) Preview(ctx context.Context, actor AuthIdentity, phase, challenge string) (*OAuthProviderPreview, error) {
	if phase != "login" && phase != "consent" || !validOAuthHydraCapability(challenge) {
		return nil, ErrOAuthProviderRequest
	}
	if _, _, err := currentOAuthProviderActor(ctx, actor); err != nil {
		return nil, err
	}
	request, err := b.readRequest(ctx, actor, phase, challenge)
	if err != nil {
		return nil, err
	}
	user, session, err := currentOAuthProviderActor(ctx, actor)
	if err != nil {
		return nil, err
	}
	expires := min(time.Now().Add(5*time.Minute).Unix(), session.ExpiresAt)
	payload, err := common.Marshal(request.binding)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	token, _, err := model.CreateAuthFlowWithContext(ctx, model.AuthFlowCreate{
		Purpose: model.AuthFlowPurposeOAuthProviderPreview, Provider: "hydra", Intent: phase,
		UserId: actor.UserID, SessionId: actor.SessionID, Payload: string(payload), ExpiresAt: time.Unix(expires, 0),
	})
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	if _, _, err := currentOAuthProviderActor(ctx, actor); err != nil {
		return nil, err
	}
	return &OAuthProviderPreview{PreviewToken: token, ExpiresAt: expires, Phase: phase, ClientID: request.clientID,
		ClientName: request.clientName, Username: user.Username, RequestedScope: request.requested,
		AllowedScope: request.allowed, Audience: b.resource.audience}, nil
}

func (b *OAuthProviderBridge) Decide(ctx context.Context, actor AuthIdentity, phase string, input OAuthProviderDecision) (*OAuthProviderRedirect, error) {
	if phase != "login" && phase != "consent" || !validOAuthHydraCapability(input.Challenge) || len(input.PreviewToken) != 43 {
		return nil, ErrOAuthProviderRequest
	}
	if _, _, err := currentOAuthProviderActor(ctx, actor); err != nil {
		return nil, err
	}
	request, err := b.readRequest(ctx, actor, phase, input.Challenge)
	if err != nil {
		return nil, err
	}
	var body any
	var prepared *model.OAuthGrant
	suffix := "accept"
	if input.Decision == "deny" {
		if len(input.SelectedScopes) != 0 {
			return nil, ErrOAuthProviderRequest
		}
		suffix, body = "reject", map[string]any{"error": "access_denied"}
	} else if phase == "login" && input.Decision == "continue" && len(input.SelectedScopes) == 0 {
		body = map[string]any{"subject": strconv.Itoa(actor.UserID), "remember": false}
	} else if phase == "consent" && input.Decision == "approve" {
		selected := input.SelectedScopes
		limit := 2
		if b.public != nil {
			limit = 4
		}
		if len(selected) == 0 || len(selected) > limit || !slices.Contains(selected, "profile") || b.public != nil && slices.Contains(request.requested, "openid") && !slices.Contains(selected, "openid") {
			return nil, ErrOAuthProviderDenied
		}
		for i, scope := range selected {
			if !slices.Contains(request.allowed, scope) || slices.Contains(selected[:i], scope) {
				return nil, ErrOAuthProviderDenied
			}
		}
		body = map[string]any{"remember": false, "grant_scope": selected, "grant_access_token_audience": []string{b.resource.audience},
			"session": map[string]any{"access_token": map[string]string{"newapi_auth_version": strconv.FormatInt(actor.UserAuthVersion, 10)}}}
		if b.public != nil {
			grant := make([]byte, 32)
			if _, err := rand.Read(grant); err != nil {
				return nil, ErrOAuthResourceUnavailable
			}
			scopes := slices.Clone(selected)
			slices.Sort(scopes)
			encoded, err := common.Marshal(scopes)
			if err != nil {
				return nil, ErrOAuthResourceUnavailable
			}
			prepared = &model.OAuthGrant{GrantID: base64.RawURLEncoding.EncodeToString(grant), Issuer: b.resource.issuer,
				ClientID: request.clientID, Subject: strconv.Itoa(actor.UserID), UserID: actor.UserID,
				ConsentRequestID: request.consentRequestID, HydraLoginSessionID: request.loginSessionID,
				OriginSID: actor.SessionID, SessionVersion: actor.SessionVersion, UserAuthVersion: actor.UserAuthVersion,
				Scopes: string(encoded), PolicyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(b.policy)))}
		}
	} else {
		return nil, ErrOAuthProviderRequest
	}
	_, err = model.ConsumeAuthFlowWithActionWithContext(ctx, input.PreviewToken, model.AuthFlowMatch{
		Purpose: model.AuthFlowPurposeOAuthProviderPreview, Provider: "hydra", Intent: phase, UserId: actor.UserID, SessionId: actor.SessionID,
	}, func(tx *gorm.DB, flow *model.AuthFlow) error {
		var binding oauthProviderBinding
		if common.UnmarshalStrictObject([]byte(flow.Payload), &binding) != nil || binding != request.binding {
			return ErrOAuthProviderDenied
		}
		if err := model.ValidateAuthSessionWithTx(tx, actor); err != nil {
			return oauthGrantError(err)
		}
		// No HTTP runs while this transaction holds the flow/user/session locks.
		// Existing cleanup retains this consumed claim for at least 24h. Real
		// activation requires verified effective Hydra challenge TTL<=30m,
		// including old outstanding requests; this is not permanent retention.
		if err := model.ClaimExternalAuthAssertionWithTx(tx, model.AuthFlowPurposeOAuthProviderAttempt,
			b.resource.issuer+"\n"+phase+"\n"+input.Challenge, flow.ExpiresAt); err != nil {
			return err
		}
		if prepared != nil {
			return oauthGrantError(model.CreateOAuthGrantWithTx(tx, prepared))
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrOAuthInvalidToken) || errors.Is(err, ErrOAuthProviderDenied) {
			return nil, err
		}
		if errors.Is(err, model.ErrAuthFlowInvalid) || errors.Is(err, model.ErrAuthFlowExpired) || errors.Is(err, model.ErrAuthFlowConsumed) {
			return nil, ErrOAuthProviderReplay
		}
		return nil, ErrOAuthResourceUnavailable
	}
	if prepared != nil {
		body.(map[string]any)["session"] = map[string]any{"access_token": map[string]string{
			"newapi_auth_version": strconv.FormatInt(prepared.UserAuthVersion, 10), "newapi_grant_id": prepared.GrantID,
			"newapi_grant_expires_at": strconv.FormatInt(prepared.ExpiresAt, 10)}}
	}
	// Local consumption and the cross-preview claim have committed before PUT.
	if _, _, err := currentOAuthProviderActor(ctx, actor); err != nil {
		return nil, err
	}
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := b.adminCall(ctx, http.MethodPut, phase, suffix, input.Challenge, body, &result); err != nil {
		return nil, err
	}
	if !b.validResume(result.RedirectTo, phase, request.query) {
		return nil, ErrOAuthResourceUnavailable
	}
	if prepared != nil {
		if err := model.ApproveOAuthGrant(ctx, prepared); err != nil {
			return nil, oauthGrantError(err)
		}
	} else if _, _, err := currentOAuthProviderActor(ctx, actor); err != nil {
		return nil, err
	}
	return &OAuthProviderRedirect{RedirectTo: result.RedirectTo}, nil
}

func currentOAuthProviderActor(ctx context.Context, actor AuthIdentity) (*model.User, *model.UserSession, error) {
	if actor.UserID <= 0 || actor.UserAuthVersion <= 0 || actor.SessionVersion <= 0 || actor.SessionID == "" || strings.HasPrefix(actor.SessionID, "pat:") || strings.HasPrefix(actor.SessionID, "legacy") {
		return nil, nil, ErrOAuthInvalidToken
	}
	user, err := model.GetOAuthUserInfoByID(ctx, actor.UserID)
	if err != nil {
		return nil, nil, oauthGrantError(err)
	}
	session, err := model.GetUserSessionBySIDWithContext(ctx, actor.SessionID)
	if err != nil {
		return nil, nil, oauthGrantError(err)
	}
	if user.Status != common.UserStatusEnabled || user.AuthVersion != actor.UserAuthVersion || session.UserID != actor.UserID || session.Version != actor.SessionVersion || session.UserAuthVersion != actor.UserAuthVersion || session.Status != model.UserSessionStatusActive || session.RevokedAt != 0 || session.ExpiresAt <= time.Now().Unix() {
		return nil, nil, ErrOAuthInvalidToken
	}
	return user, session, nil
}

func (b *OAuthProviderBridge) readRequest(ctx context.Context, actor AuthIdentity, phase, challenge string) (*oauthProviderRequest, error) {
	if b == nil {
		return nil, ErrOAuthResourceUnavailable
	}
	var value oauthProviderChallenge
	if err := b.adminCall(ctx, http.MethodGet, phase, "", challenge, nil, &value); err != nil {
		return nil, err
	}
	client := value.Client
	if value.Challenge != challenge || value.Subject == nil || value.Skip == nil || *value.Skip || value.RequestURL == nil || value.Scopes == nil || value.Audience == nil || client == nil || client.Method == nil || *client.Method != "none" || client.Scope == nil || client.Audience == nil || client.SkipConsent || !slices.Contains(b.resource.clients, client.ID) || !slices.Contains(client.Grants, "authorization_code") || !slices.Contains(client.Responses, "code") {
		return nil, ErrOAuthProviderDenied
	}
	if phase == "consent" && *value.Subject != strconv.Itoa(actor.UserID) || phase == "login" && *value.Subject != "" && *value.Subject != strconv.Itoa(actor.UserID) {
		return nil, ErrOAuthProviderDenied
	}
	if b.public != nil && phase == "consent" {
		for _, id := range []*string{value.ConsentRequestID, value.LoginSessionID} {
			if id == nil || len(*id) == 0 || len(*id) > 256 {
				return nil, ErrOAuthProviderDenied
			}
			for _, c := range *id {
				if c < 0x21 || c > 0x7e {
					return nil, ErrOAuthProviderDenied
				}
			}
		}
	}
	original, err := url.Parse(*value.RequestURL)
	if err != nil || original.User != nil || original.Fragment != "" || original.Opaque != "" {
		return nil, ErrOAuthProviderDenied
	}
	base := *original
	base.RawQuery, base.ForceQuery = "", false
	if base.String() != b.authorize {
		return nil, ErrOAuthProviderDenied
	}
	q, err := url.ParseQuery(original.RawQuery)
	if err != nil {
		return nil, ErrOAuthProviderDenied
	}
	for key, values := range q {
		if !slices.Contains([]string{"client_id", "response_type", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "response_mode", "prompt", "audience", "nonce"}, key) || len(values) == 0 || key != "audience" && len(values) != 1 {
			return nil, ErrOAuthProviderDenied
		}
	}
	pkce, err := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	if err != nil || len(pkce) != 32 || base64.RawURLEncoding.EncodeToString(pkce) != q.Get("code_challenge") || q.Get("code_challenge_method") != "S256" || q.Get("client_id") != client.ID || q.Get("response_type") != "code" || !validOAuthProviderCapability(q.Get("state")) || q.Get("response_mode") != "" && q.Get("response_mode") != "query" || q.Get("prompt") != "" && q.Get("prompt") != "consent" {
		return nil, ErrOAuthProviderDenied
	}
	redirect := q.Get("redirect_uri")
	if !slices.ContainsFunc(client.Redirects, func(registered string) bool { return validOAuthProviderRedirect(redirect, registered) }) {
		return nil, ErrOAuthProviderDenied
	}
	requested, err := oauthProviderScopeSet(q.Get("scope"))
	registered, regErr := oauthProviderScopeSet(*client.Scope)
	if err != nil || regErr != nil || !sameOAuthProviderSet(requested, *value.Scopes) || !slices.Contains(*value.Audience, b.resource.audience) || !slices.Contains(*client.Audience, b.resource.audience) {
		return nil, ErrOAuthProviderDenied
	}
	if audience, exists := q["audience"]; exists && !sameOAuthProviderSet(audience, *value.Audience) {
		return nil, ErrOAuthProviderDenied
	}
	allowed := []string{}
	supported := []string{"profile", "email"}
	if b.public != nil {
		supported = oauthPublicScopes
		for _, scope := range requested {
			if !slices.Contains(supported, scope) || !slices.Contains(registered, scope) {
				return nil, ErrOAuthProviderDenied
			}
		}
		if slices.Contains(requested, "offline_access") && !slices.Contains(requested, "openid") || q.Has("nonce") && !validOAuthProviderCapability(q.Get("nonce")) {
			return nil, ErrOAuthProviderDenied
		}
	}
	for _, scope := range supported {
		if slices.Contains(requested, scope) && slices.Contains(registered, scope) {
			allowed = append(allowed, scope)
		}
	}
	if !slices.Contains(allowed, "profile") {
		return nil, ErrOAuthProviderDenied
	}
	encoded, err := common.Marshal(value)
	if err != nil {
		return nil, ErrOAuthResourceUnavailable
	}
	name := client.ID
	if client.Name != nil {
		name = *client.Name
	}
	request := &oauthProviderRequest{
		binding: oauthProviderBinding{Identity: actor, Phase: phase, PolicyHash: b.policy,
			ChallengeHash: fmt.Sprintf("%x", sha256.Sum256([]byte(challenge))), RequestHash: fmt.Sprintf("%x", sha256.Sum256(encoded))},
		clientID: client.ID, clientName: name, requested: requested, allowed: allowed, query: q,
	}
	if b.public != nil && phase == "consent" {
		request.consentRequestID, request.loginSessionID = *value.ConsentRequestID, *value.LoginSessionID
	}
	return request, nil
}

func (b *OAuthProviderBridge) adminCall(ctx context.Context, method, phase, action, challenge string, body, result any) error {
	endpoint := b.admin + "/admin/oauth2/auth/requests/" + phase
	if action != "" {
		endpoint += "/" + action
	}
	endpoint += "?" + url.Values{phase + "_challenge": {challenge}}.Encode()
	var reader io.Reader
	if body != nil {
		data, err := common.Marshal(body)
		if err != nil {
			return ErrOAuthResourceUnavailable
		}
		reader = strings.NewReader(string(data))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	req.GetBody = nil
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.resource.client.Do(req)
	if err != nil {
		return ErrOAuthResourceUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
		return ErrOAuthProviderReplay
	}
	if resp.StatusCode != http.StatusOK {
		return ErrOAuthResourceUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 || common.Unmarshal(data, result) != nil {
		return ErrOAuthResourceUnavailable
	}
	return nil
}

func (b *OAuthProviderBridge) validResume(raw, phase string, original url.Values) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	base := *u
	base.RawQuery, base.ForceQuery = "", false
	if base.String() != b.authorize {
		return false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	verifier := phase + "_verifier"
	if len(q[verifier]) != 1 || !validOAuthHydraCapability(q.Get(verifier)) || len(q) != len(original)+1 {
		return false
	}
	for key, values := range original {
		if !slices.Equal(q[key], values) {
			return false
		}
	}
	return true
}

func validOAuthProviderCapability(value string) bool {
	if value == "" || len(value) > 2048 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}

func oauthProviderScopeSet(value string) ([]string, error) {
	result := []string{}
	if value == "" {
		return result, nil
	}
	for scope := range strings.SplitSeq(value, " ") {
		if scope == "" || slices.Contains(result, scope) {
			return nil, ErrOAuthProviderDenied
		}
		for _, c := range scope {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return nil, ErrOAuthProviderDenied
			}
		}
		result = append(result, scope)
	}
	return result, nil
}

func sameOAuthProviderSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y) && len(slices.Compact(x)) == len(x)
}

func validOAuthProviderRedirect(raw, registered string) bool {
	u, err := url.Parse(raw)
	v, regErr := url.Parse(registered)
	if err != nil || regErr != nil || u.User != nil || v.User != nil || u.Fragment != "" || v.Fragment != "" || u.Opaque != "" || v.Opaque != "" {
		return false
	}
	if u.Scheme == "https" && u.Hostname() != "" {
		return raw == registered
	}
	if u.Scheme == "cherrystudio" {
		return raw == registered && u.Host == "oauth" && u.Path == "/callback"
	}
	if u.Scheme != "http" || v.Scheme != "http" || u.Hostname() != v.Hostname() || u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	u.Host = v.Host
	// Replace only the numeric loopback port. Keep exact registered path/query.
	return u.String() == registered && net.ParseIP(v.Hostname()) != nil
}
