package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

type tokenUsageCredential struct {
	key string
}

const tokenUsageCredentialContextKey = "token_usage_credential"

// TokenUsageCredentialBoundary opts only the new usage endpoints into a single
// Bearer credential. Generated relay keys have no hyphens; disallowing them after
// the optional sk- prefix prevents legacy TokenAuthReadOnly channel-suffix parsing
// from shortening the credential. The unchanged complete key reaches its lookup.
func TokenUsageCredentialBoundary() gin.HandlerFunc {
	return func(c *gin.Context) {
		var authorization string
		count := 0
		for name, values := range c.Request.Header {
			if !strings.EqualFold(name, "Authorization") {
				continue
			}
			count += max(1, len(values))
			if len(values) == 1 {
				authorization = values[0]
			}
		}
		scheme, credential, separated := strings.Cut(authorization, " ")
		key := strings.TrimPrefix(credential, "sk-")
		valid := count == 1 && separated && strings.EqualFold(scheme, "Bearer") && key != "" && len(key) <= 128
		for _, b := range []byte(key) {
			if b <= ' ' || b >= 127 || b == '-' || b == ',' {
				valid = false
				break
			}
		}
		if !valid {
			common.ApiErrorStatus(c, http.StatusUnauthorized, errors.New(i18n.T(c, i18n.MsgTokenInvalid)), gin.H{"code": "TOKEN_USAGE_AUTH_INVALID"})
			c.Abort()
			return
		}
		// Normalize the case-insensitive scheme, never the credential bytes.
		c.Request.Header.Set("Authorization", "Bearer "+credential)
		c.Set(tokenUsageCredentialContextKey, tokenUsageCredential{key: key})
		c.Next()
	}
}

// GetTokenUsageToken also checks exact credential bytes, including on stores
// whose key collation is case-insensitive or whose cached identity is mismatched.
func GetTokenUsageToken(c *gin.Context) (model.Token, bool) {
	value, _ := c.Get(tokenUsageCredentialContextKey)
	credential, present := value.(tokenUsageCredential)
	token, _, authenticated := GetReadOnlyToken(c)
	if !present || !authenticated || credential.key != token.Key {
		return model.Token{}, false
	}
	return token, true
}
