package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
)

const (
	TaskMediaCookieName = "__Secure-new_api_task_media"
	TaskMediaTicketTTL  = 5 * time.Minute
	taskMediaTicketUse  = "task-media-cookie-v1"
)

var ErrTaskMediaTicketInvalid = errors.New("task media ticket is invalid")

// TaskMediaTicket is an opaque, short-lived capability for one native video
// response. The cookie carries no reusable dashboard credential.
type TaskMediaTicket struct {
	UserID          int    `json:"user_id"`
	SessionID       string `json:"session_id"`
	UserAuthVersion int64  `json:"user_auth_version"`
	SessionVersion  int64  `json:"session_version"`
	RowID           int64  `json:"row_id"`
	ArtifactKey     string `json:"artifact_key"`
	ResultDigest    string `json:"result_digest"`
	IssuedAt        int64  `json:"issued_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

func taskMediaTicketKey() []byte {
	mac := hmac.New(sha256.New, []byte(common.CryptoSecret))
	_, _ = mac.Write([]byte(taskMediaTicketUse))
	return mac.Sum(nil)
}

func newTaskMediaAEAD() (cipher.AEAD, error) {
	if common.CryptoSecret == "" {
		return nil, ErrTaskMediaTicketInvalid
	}
	block, err := aes.NewCipher(taskMediaTicketKey())
	if err != nil {
		return nil, ErrTaskMediaTicketInvalid
	}
	return cipher.NewGCM(block)
}

func IssueTaskMediaTicket(identity AuthIdentity, rowID int64, artifactKey, resultDigest string) (string, TaskMediaTicket, error) {
	artifactKey = strings.TrimSpace(artifactKey)
	resultDigest = strings.TrimSpace(resultDigest)
	if identity.UserID <= 0 || identity.SessionID == "" || identity.UserAuthVersion <= 0 || identity.SessionVersion <= 0 || rowID <= 0 || artifactKey != "video" || resultDigest == "" {
		return "", TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	now := time.Now()
	ticket := TaskMediaTicket{
		UserID: identity.UserID, SessionID: identity.SessionID,
		UserAuthVersion: identity.UserAuthVersion, SessionVersion: identity.SessionVersion,
		RowID: rowID, ArtifactKey: artifactKey, ResultDigest: resultDigest,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(TaskMediaTicketTTL).Unix(),
	}
	payload, err := common.Marshal(ticket)
	if err != nil {
		return "", TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	aead, err := newTaskMediaAEAD()
	if err != nil {
		return "", TaskMediaTicket{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	sealed := aead.Seal(nil, nonce, payload, []byte(taskMediaTicketUse))
	encoded := base64.RawURLEncoding.EncodeToString(append(nonce, sealed...))
	return encoded, ticket, nil
}

func ParseTaskMediaTicket(raw string) (TaskMediaTicket, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 4096 {
		return TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	aead, err := newTaskMediaAEAD()
	if err != nil || len(data) <= aead.NonceSize() {
		return TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	plaintext, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(taskMediaTicketUse))
	if err != nil {
		return TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	var ticket TaskMediaTicket
	if err := common.Unmarshal(plaintext, &ticket); err != nil || !ticket.ValidAt(time.Now()) {
		return TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	if ticket.UserID <= 0 || ticket.SessionID == "" || ticket.UserAuthVersion <= 0 || ticket.SessionVersion <= 0 || ticket.RowID <= 0 || ticket.ArtifactKey != "video" || ticket.ResultDigest == "" {
		return TaskMediaTicket{}, ErrTaskMediaTicketInvalid
	}
	return ticket, nil
}

func (ticket TaskMediaTicket) ValidAt(now time.Time) bool {
	return ticket.IssuedAt > 0 && ticket.ExpiresAt >= ticket.IssuedAt && ticket.ExpiresAt > now.Unix() && ticket.IssuedAt <= now.Add(5*time.Second).Unix()
}

func (ticket TaskMediaTicket) Matches(identity AuthIdentity, rowID int64, artifactKey, resultDigest string) bool {
	return ticket.ValidAt(time.Now()) && ticket.UserID == identity.UserID && ticket.SessionID == identity.SessionID && ticket.UserAuthVersion == identity.UserAuthVersion && ticket.SessionVersion == identity.SessionVersion && ticket.RowID == rowID && ticket.ArtifactKey == strings.TrimSpace(artifactKey) && ticket.ResultDigest == strings.TrimSpace(resultDigest)
}
