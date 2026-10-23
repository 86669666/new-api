package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

var errOAuthTextTransport = errors.New("OAuth derived text send unavailable")

// OAuthDerivedTextSelectedRequest is constructed only by the trusted selected
// request producer. It is not an HTTP binding or permission to spend. Credentials
// stay in memory; callers must not log this value or persist its body.
type OAuthDerivedTextSelectedRequest struct {
	URL    string `json:"-"`
	Body   []byte `json:"-"`
	APIKey string `json:"-"`
}

// DoOAuthDerivedTextOnce claims and sends at most once. Claim remains CLOSED.
// This operation neither settles nor refunds. The consumer owns response.Body
// and must validate bounded raw usage and durably settle before publishing.
func DoOAuthDerivedTextOnce(ctx context.Context, ref string, facts model.OAuthTextFacts, reserve int, selected OAuthDerivedTextSelectedRequest) (*http.Response, error) {
	op, err := newOAuthTextSendOperation(ref, facts, reserve, selected)
	if err != nil {
		return nil, err
	}
	return op.do(ctx)
}

// Dependencies are per operation, private, and never populated from HTTP input.
// Tests may supply a claim, clock and local CA without opening production Claim.
type oauthTextSendOperation struct {
	ref      string
	facts    model.OAuthTextFacts
	reserve  int
	endpoint string
	host     string
	body     []byte
	apiKey   string
	used     atomic.Bool
	claim    func(context.Context, string, model.OAuthTextFacts, int) (*model.OAuthTextSendPermit, error)
	now      func() time.Time
	roots    *x509.CertPool
	dial     func(context.Context, string, string) (net.Conn, error)
	timeout  time.Duration
}

func newOAuthTextSendOperation(ref string, facts model.OAuthTextFacts, reserve int, selected OAuthDerivedTextSelectedRequest) (*oauthTextSendOperation, error) {
	body := bytes.Clone(selected.Body)
	u, err := url.Parse(selected.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Host == "" || u.Path != "/v1/chat/completions" || strings.ContainsAny(selected.URL, "?#%\\") {
		return nil, errOAuthTextTransport
	}
	host := u.Hostname()
	authority := host
	if ip := net.ParseIP(host); ip != nil {
		authority = ip.String()
		if strings.Contains(authority, ":") {
			authority = "[" + authority + "]"
		}
	} else {
		for label := range strings.SplitSeq(host, ".") {
			if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return nil, errOAuthTextTransport
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, errOAuthTextTransport
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || n == 443 {
			return nil, errOAuthTextTransport
		}
		authority += ":" + port
	}
	if selected.URL != "https://"+authority+"/v1/chat/completions" || len(body) == 0 || selected.APIKey == "" {
		return nil, errOAuthTextTransport
	}
	for _, c := range selected.APIKey {
		if c < 33 || c > 126 {
			return nil, errOAuthTextTransport
		}
	}
	route, err := common.Marshal([]any{http.MethodPost, selected.URL, facts.ChannelID, facts.Model})
	if err != nil {
		return nil, errOAuthTextTransport
	}
	routeHash, bodyHash := sha256.Sum256(route), sha256.Sum256(body)
	if facts.RouteHash != hex.EncodeToString(routeHash[:]) || facts.BodyHash != hex.EncodeToString(bodyHash[:]) {
		return nil, errOAuthTextTransport
	}
	return &oauthTextSendOperation{ref: ref, facts: facts, reserve: reserve, endpoint: selected.URL, host: host, body: body, apiKey: selected.APIKey, claim: ClaimOAuthDerivedText, now: time.Now, timeout: time.Minute, dial: (&net.Dialer{}).DialContext}, nil
}

func (op *oauthTextSendOperation) do(ctx context.Context) (*http.Response, error) {
	if ctx == nil || !op.used.CompareAndSwap(false, true) {
		return nil, errOAuthTextTransport
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	permit, err := op.claim(ctx, op.ref, op.facts, op.reserve)
	if err != nil {
		return nil, err
	}
	if permit == nil || permit.Ref != op.ref {
		return nil, errOAuthTextTransport
	}
	deadline := permit.Deadline // Immutable copy; never retain a caller's permit.
	if op.now().Unix() >= deadline {
		return nil, errOAuthTextTransport
	}
	ctx, cancel := context.WithTimeout(ctx, op.timeout)
	transport := &http.Transport{DisableCompression: true, ResponseHeaderTimeout: op.timeout, MaxResponseHeaderBytes: 1 << 20}
	applyHTTP1Force(transport)
	transport.DisableKeepAlives = true
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	// A fresh transport can dial only once, even if a future stdlib adds a retry.
	var dialed atomic.Bool
	transport.DialTLSContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		if !dialed.CompareAndSwap(false, true) || op.now().Unix() >= deadline {
			return nil, errOAuthTextTransport
		}
		// Transport detaches its dialing context from request cancellation. Bound
		// the actual dial/handshake by our operation context instead.
		conn, err := op.dial(ctx, network, addr)
		if err != nil {
			return nil, errOAuthTextTransport
		}
		ioDeadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(ioDeadline); err != nil {
			conn.Close()
			return nil, errOAuthTextTransport
		}
		secure := tls.Client(conn, &tls.Config{ServerName: op.host, RootCAs: op.roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
		if err := secure.HandshakeContext(ctx); err != nil {
			secure.Close()
			return nil, errOAuthTextTransport
		}
		if protocol := secure.ConnectionState().NegotiatedProtocol; protocol != "" && protocol != "http/1.1" {
			secure.Close()
			return nil, errOAuthTextTransport
		}
		return &oauthTextFirstWriteConn{Conn: secure, ctx: ctx, now: op.now, deadline: deadline}, nil
	}
	// NopCloser deliberately hides bytes.Reader from NewRequest's replay setup.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, op.endpoint, io.NopCloser(bytes.NewReader(op.body)))
	if err != nil {
		cancel()
		return nil, errOAuthTextTransport
	}
	req.ContentLength = int64(len(op.body))
	req.GetBody = nil
	req.Close = true
	req.Header.Set("Authorization", "Bearer "+op.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		transport.CloseIdleConnections()
		return nil, errOAuthTextTransport // No URL, credential or upstream text.
	}
	if resp.ProtoMajor != 1 || resp.ProtoMinor != 1 {
		resp.Body.Close()
		cancel()
		return nil, errOAuthTextTransport
	}
	resp.Body = &oauthTextResponseBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// This wraps the established TLS connection, not its encrypted socket: the
// permission check runs before the first HTTP application byte is handed to TLS.
type oauthTextFirstWriteConn struct {
	net.Conn
	ctx      context.Context
	now      func() time.Time
	deadline int64
	mu       sync.Mutex
	started  bool
}

func (c *oauthTextFirstWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		if c.ctx.Err() != nil || c.now().Unix() >= c.deadline {
			c.Conn.Close()
			return 0, errOAuthTextTransport
		}
		c.started = true
	}
	return c.Conn.Write(p)
}

type oauthTextResponseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *oauthTextResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.Close()
	}
	return n, err
}

func (b *oauthTextResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
