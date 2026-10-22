package service

import (
	"errors"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/shopspring/decimal"
)

// walletQuotaShortfall is host-only provenance, carried by the error rather than
// request context so a subsequent subscription fallback cannot inherit it.
// Every generic/native serializer sees only the safe message through Error().
type walletQuotaShortfall struct {
	userID, tokenID int
	key             string
	quota           *int
	original, safe  string
}

func (e *walletQuotaShortfall) Error() string { return e.safe }
func (e *walletQuotaShortfall) Unwrap() error { return ErrInsufficientWalletQuota }

func newWalletQuotaError(info *relaycommon.RelayInfo, lang string, quota *int, original string) *types.NewAPIError {
	cause := &walletQuotaShortfall{safe: i18n.Translate(lang, i18n.MsgQuotaUserInsufficientPrivate), original: original}
	if info != nil && !info.IsPlayground {
		cause.userID, cause.tokenID, cause.key = info.UserId, info.TokenId, info.TokenKey
	}
	if quota != nil {
		observed := *quota
		cause.quota = &observed
	}
	return types.NewErrorWithStatusCode(cause, types.ErrorCodeInsufficientUserQuota, http.StatusForbidden, types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
}

// WalletQuotaErrorPresentation makes one fresh primary-DB authorization decision
// for both message and optional display. Call before NewAPIError.SetMessage loses
// its cause, and only at a final, uncommitted OpenAI-compatible HTTP output.
func WalletQuotaErrorPresentation(apiErr *types.NewAPIError) (message, remaining string) {
	if apiErr == nil {
		return "", ""
	}
	message = apiErr.Error()
	var cause *walletQuotaShortfall
	if apiErr.StatusCode != http.StatusForbidden || apiErr.GetErrorCode() != types.ErrorCodeInsufficientUserQuota || apiErr.GetErrorType() != types.ErrorTypeNewAPIError || !errors.As(apiErr, &cause) || cause.quota == nil || cause.key == "" {
		return message, ""
	}
	token, err := model.GetTokenByIds(cause.tokenID, cause.userID)
	if err != nil || token == nil || token.Key != cause.key || token.Status != common.TokenStatusEnabled || token.ExpiredTime != -1 && token.ExpiredTime < time.Now().Unix() || !token.UnlimitedQuota && token.RemainQuota <= 0 || !token.AllowUserQuotaQuery {
		return message, ""
	}
	return cause.original, formatWalletQuotaRemaining(*cause.quota)
}

// formatWalletQuotaRemaining follows the console's formatQuota en-US profile.
// Intl rounds the shortest decimal representation of a Number; toFixed (token
// abbreviations) instead rounds the exact binary value. Neither changes quota.
func formatWalletQuotaRemaining(quota int) string {
	return formatWalletQuotaSnapshot(quota, common.QuotaPerUnit, *operation_setting.GetGeneralSetting(), operation_setting.USDExchangeRate)
}

// formatWalletQuotaSnapshot uses only captured configuration, so a resource can
// finish all external authorization waits before formatting its returned quota.
func formatWalletQuotaSnapshot(quota int, unit float64, cfg operation_setting.GeneralSetting, usdToCNY float64) string {
	const maxSafe = 9007199254740991
	if int64(quota) > maxSafe || int64(quota) < -maxSafe {
		return ""
	}
	value := float64(quota)
	if cfg.QuotaDisplayType == operation_setting.QuotaDisplayTypeTokens {
		if math.Abs(value) < 1000 {
			return strconv.Itoa(quota)
		}
		exact := new(big.Rat).SetFloat64(math.Abs(value / 1000))
		exact.Mul(exact, big.NewRat(10, 1))
		integer, remainder := new(big.Int), new(big.Int)
		integer.QuoRem(exact.Num(), exact.Denom(), remainder)
		if remainder.Lsh(remainder, 1).Cmp(exact.Denom()) >= 0 {
			integer.Add(integer, big.NewInt(1))
		}
		digits := integer.String()
		if len(digits) < 2 {
			digits = "0" + digits
		}
		text := strings.TrimSuffix(strings.TrimSuffix(digits[:len(digits)-1]+"."+digits[len(digits)-1:], "0"), ".")
		if value < 0 {
			text = "-" + text
		}
		return text + "k"
	}
	rate, symbol := 1.0, "$"
	custom := false
	switch cfg.QuotaDisplayType {
	case operation_setting.QuotaDisplayTypeUSD:
	case operation_setting.QuotaDisplayTypeCNY:
		rate, symbol = usdToCNY, "¥"
	case operation_setting.QuotaDisplayTypeCustom:
		custom = true
		rate = cfg.CustomCurrencyExchangeRate
		symbol = cfg.CustomCurrencySymbol
		if !utf8.ValidString(symbol) {
			return ""
		}
		for _, r := range symbol {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return ""
			}
		}
		symbol = strings.TrimSpace(symbol)
		if symbol == "" {
			symbol = "¤"
		}
	default:
		return ""
	}
	if unit <= 0 || rate <= 0 || math.IsNaN(unit) || math.IsInf(unit, 0) || math.IsNaN(rate) || math.IsInf(rate, 0) {
		return ""
	}
	value = value / unit * rate
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return ""
	}
	digits := int32(2)
	if math.Abs(value) < 1 {
		digits = 4
	}
	if value != 0 && math.Abs(value) < math.Pow10(-int(digits)) {
		value = math.Copysign(math.Pow10(-int(digits)), value)
	}
	text := decimal.NewFromFloat(math.Abs(value)).Round(digits).String()
	whole, fraction, hasFraction := strings.Cut(text, ".")
	var grouped strings.Builder
	for i, c := range whole {
		if i > 0 && (len(whole)-i)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(c)
	}
	if hasFraction {
		grouped.WriteByte('.')
		grouped.WriteString(fraction)
	}
	number := grouped.String()
	if custom {
		if math.Signbit(value) {
			number = "-" + number
		}
		return symbol + " " + number
	}
	if math.Signbit(value) {
		return "-" + symbol + number
	}
	return symbol + number
}
