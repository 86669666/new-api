package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
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
	ErrOAuthResourceConfiguration = errors.New("Invalid OAuth userinfo configuration.")
	ErrOAuthInvalidToken          = errors.New("invalid_token")
	ErrOAuthInsufficientScope     = errors.New("insufficient_scope")
	ErrOAuthResourceUnavailable   = errors.New("temporarily_unavailable")
	currentOAuthUserInfo          atomic.Pointer[OAuthUserInfoResource]
)

// OAuthUserInfoConfig is startup-only resource-server configuration. It does not
// enable an authorization server, login flow, consent or token issuance.
type OAuthUserInfoConfig struct {
	Enabled          bool
	IntrospectionURL string
	Issuer           string
	Audience         string
	ClientIDs        []string
}

type OAuthUserInfoResource struct {
	endpoint       string
	issuer         string
	audience       string
	clients        []string
	client         *http.Client
	grantsRequired bool
}

// OAuthResourceIdentity is deliberately separate from AuthIdentity. It cannot
// become a dashboard session, PAT authorization or security-proof principal.
type OAuthResourceIdentity struct {
	userID         int
	authVersion    int64
	issuer         string
	clientID       string
	expiresAt      int64
	notBefore      int64
	email          bool
	scopes         []string
	grantID        string
	grantExpiresAt int64
}

// OAuthUserInfoAccess keeps the bearer private and request-local. Neither the
// credential nor the internal binding fields are serializable profile data.
type OAuthUserInfoAccess struct {
	resource   *OAuthUserInfoResource
	credential string
	identity   OAuthResourceIdentity
}

type OAuthUserInfo struct {
	ID          int     `json:"id"`
	Sub         string  `json:"sub,omitempty"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	Group       string  `json:"group"`
	Email       *string `json:"email,omitempty"`
}

func InitOAuthUserInfoResource() error {
	enabled := os.Getenv("OAUTH_USERINFO_ENABLED")
	if enabled != "" && enabled != "false" && enabled != "true" {
		return ErrOAuthResourceConfiguration
	}
	resource, err := NewOAuthUserInfoResource(OAuthUserInfoConfig{
		Enabled: enabled == "true", IntrospectionURL: os.Getenv("OAUTH_USERINFO_INTROSPECTION_URL"),
		Issuer: os.Getenv("OAUTH_USERINFO_ISSUER"), Audience: os.Getenv("OAUTH_USERINFO_AUDIENCE"),
		ClientIDs: strings.Split(os.Getenv("OAUTH_USERINFO_CLIENT_IDS"), ","),
	}, nil)
	if err != nil {
		return ErrOAuthResourceConfiguration
	}
	currentOAuthUserInfo.Store(resource)
	return nil
}

func CurrentOAuthUserInfoResource() *OAuthUserInfoResource {
	return currentOAuthUserInfo.Load()
}

// roots optionally supplies trusted certificate authorities, including an
// isolated test issuer's CA. Certificate and hostname verification stay enabled;
// there is no plaintext or InsecureSkipVerify configuration path.
func NewOAuthUserInfoResource(config OAuthUserInfoConfig, roots *x509.CertPool) (*OAuthUserInfoResource, error) {
	if !config.Enabled {
		return nil, nil
	}
	for _, raw := range []string{config.IntrospectionURL, config.Issuer} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || raw != strings.TrimSpace(raw) {
			return nil, ErrOAuthResourceConfiguration
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return nil, ErrOAuthResourceConfiguration
			}
		}
	}
	if config.Audience == "" || len(config.ClientIDs) == 0 {
		return nil, ErrOAuthResourceConfiguration
	}
	for _, c := range config.Audience {
		if c < 0x21 || c > 0x7e {
			return nil, ErrOAuthResourceConfiguration
		}
	}
	clients := slices.Clone(config.ClientIDs)
	for i, client := range clients {
		if client == "" || len(client) > 256 || client != strings.TrimSpace(client) || slices.Contains(clients[:i], client) {
			return nil, ErrOAuthResourceConfiguration
		}
		for _, c := range client {
			if c < 0x21 || c > 0x7e {
				return nil, ErrOAuthResourceConfiguration
			}
		}
	}
	if roots != nil {
		roots = roots.Clone()
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 4,
	}
	return &OAuthUserInfoResource{
		endpoint: config.IntrospectionURL, issuer: config.Issuer, audience: config.Audience, clients: clients,
		client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

func (r *OAuthUserInfoResource) CloseIdleConnections() {
	if r != nil {
		r.client.CloseIdleConnections()
	}
}

func (r *OAuthUserInfoResource) Authorize(ctx context.Context, credential string) (*OAuthUserInfoAccess, error) {
	identity, _, err := r.readCurrentIdentity(ctx, credential)
	if err != nil {
		return nil, err
	}
	return &OAuthUserInfoAccess{resource: r, credential: credential, identity: identity}, nil
}

// Read performs the final uncached issuer and local-state checks. The returned
// profile is the final current projection; no network request follows it.
func (a *OAuthUserInfoAccess) Read(ctx context.Context) (*OAuthUserInfo, error) {
	if a == nil || a.resource == nil || a.credential == "" {
		return nil, ErrOAuthInvalidToken
	}
	identity, user, err := a.resource.readCurrentIdentity(ctx, a.credential)
	if err != nil {
		return nil, err
	}
	if identity.userID != a.identity.userID || identity.authVersion != a.identity.authVersion || identity.issuer != a.identity.issuer || identity.clientID != a.identity.clientID || (a.identity.email && !identity.email) || identity.grantID != a.identity.grantID || identity.grantExpiresAt != a.identity.grantExpiresAt {
		return nil, ErrOAuthInvalidToken
	}
	profile := &OAuthUserInfo{ID: user.Id, Username: user.Username, DisplayName: user.DisplayName, Group: user.Group}
	if a.resource.grantsRequired {
		profile.Sub = strconv.Itoa(user.Id)
	}
	if identity.email {
		profile.Email = &user.Email
	}
	return profile, nil
}

func (r *OAuthUserInfoResource) readCurrentIdentity(ctx context.Context, credential string) (OAuthResourceIdentity, *model.User, error) {
	identity, err := r.introspect(ctx, credential)
	if err != nil {
		return identity, nil, err
	}
	user, err := model.GetOAuthUserInfoByID(ctx, identity.userID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return identity, nil, ErrOAuthInvalidToken
	}
	if err != nil {
		return identity, nil, ErrOAuthResourceUnavailable
	}
	// Re-evaluate time after any database wait, not just at introspection.
	now := time.Now().Unix()
	if user.Status != common.UserStatusEnabled || user.AuthVersion != identity.authVersion || identity.expiresAt <= now || identity.notBefore > now || r.grantsRequired && identity.grantExpiresAt <= now {
		return identity, nil, ErrOAuthInvalidToken
	}
	return identity, user, nil
}

func (r *OAuthUserInfoResource) introspect(ctx context.Context, credential string) (OAuthResourceIdentity, error) {
	return r.introspectPurpose(ctx, credential, "access_token")
}

func (r *OAuthUserInfoResource) introspectPurpose(ctx context.Context, credential, purpose string) (OAuthResourceIdentity, error) {
	var identity OAuthResourceIdentity
	if r == nil || credential == "" {
		return identity, ErrOAuthInvalidToken
	}
	// Hydra's optional form scope would collapse insufficient_scope into inactive.
	// Submit only token and enforce delegated scopes locally after typed validation.
	body := url.Values{"token": {credential}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, strings.NewReader(body))
	if err != nil {
		return identity, ErrOAuthResourceUnavailable
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return identity, ErrOAuthResourceUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return identity, ErrOAuthResourceUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 || common.ValidateStrictJSONObject(data) != nil {
		return identity, ErrOAuthResourceUnavailable
	}
	var fields map[string]common.RawMessage
	if common.Unmarshal(data, &fields) != nil {
		return identity, ErrOAuthResourceUnavailable
	}
	var active bool
	var use, tokenType, issuer, subject, clientID, scope string
	var audience []string
	var expires, notBefore int64
	var extra map[string]common.RawMessage
	var version string
	if common.Unmarshal(fields["active"], &active) != nil || !active ||
		common.Unmarshal(fields["token_use"], &use) != nil || use != purpose ||
		common.Unmarshal(fields["token_type"], &tokenType) != nil || tokenType != "Bearer" ||
		common.Unmarshal(fields["iss"], &issuer) != nil || issuer != r.issuer ||
		common.Unmarshal(fields["aud"], &audience) != nil || !slices.Contains(audience, r.audience) ||
		common.Unmarshal(fields["client_id"], &clientID) != nil || !slices.Contains(r.clients, clientID) ||
		common.Unmarshal(fields["sub"], &subject) != nil ||
		common.Unmarshal(fields["exp"], &expires) != nil ||
		common.Unmarshal(fields["scope"], &scope) != nil ||
		common.Unmarshal(fields["ext"], &extra) != nil || common.Unmarshal(extra["newapi_auth_version"], &version) != nil {
		return identity, ErrOAuthInvalidToken
	}
	id, err := strconv.ParseInt(subject, 10, strconv.IntSize)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != subject {
		return identity, ErrOAuthInvalidToken
	}
	authVersion, err := strconv.ParseInt(version, 10, 64)
	if err != nil || authVersion <= 0 || strconv.FormatInt(authVersion, 10) != version {
		return identity, ErrOAuthInvalidToken
	}
	if value, exists := fields["nbf"]; exists && common.Unmarshal(value, &notBefore) != nil {
		return identity, ErrOAuthInvalidToken
	}
	now := time.Now().Unix()
	if expires <= now || notBefore < 0 || notBefore > now {
		return identity, ErrOAuthInvalidToken
	}
	scopes := map[string]bool{}
	if scope != "" {
		for item := range strings.SplitSeq(scope, " ") {
			if item == "" || scopes[item] {
				return identity, ErrOAuthInvalidToken
			}
			for _, c := range item {
				if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
					return identity, ErrOAuthInvalidToken
				}
			}
			scopes[item] = true
		}
	}
	if !scopes["profile"] {
		return identity, ErrOAuthInsufficientScope
	}
	var grantID, grantExpiry string
	var grantExpires int64
	if r.grantsRequired {
		if common.Unmarshal(extra["newapi_grant_id"], &grantID) != nil || len(grantID) != 43 || !validOAuthHydraCapability(grantID) || common.Unmarshal(extra["newapi_grant_expires_at"], &grantExpiry) != nil {
			return identity, ErrOAuthInvalidToken
		}
		grantBytes, err := base64.RawURLEncoding.DecodeString(grantID)
		if err != nil || len(grantBytes) != 32 || base64.RawURLEncoding.EncodeToString(grantBytes) != grantID {
			return identity, ErrOAuthInvalidToken
		}
		var valid bool
		grantExpires, valid = oauthGrantExpiry(grantExpiry)
		if !valid || grantExpires <= now || grantExpires > now+7*24*60*60 {
			return identity, ErrOAuthInvalidToken
		}
	}
	return OAuthResourceIdentity{userID: int(id), authVersion: authVersion, issuer: issuer, clientID: clientID, expiresAt: expires, notBefore: notBefore, email: scopes["email"], scopes: strings.Split(scope, " "), grantID: grantID, grantExpiresAt: grantExpires}, nil
}
