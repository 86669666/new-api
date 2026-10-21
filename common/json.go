package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"unicode/utf8"

	kitutil "github.com/QuantumNous/new-api/relaykit/relayconvert/kitutil"
	"github.com/gin-gonic/gin/binding"
)

type RawMessage = json.RawMessage

// hostJSONCodec is the single place where the host chooses its JSON engine.
// Swap the implementation here (for example to sonic.ConfigStd) and every
// common.* and kitutil.* JSON helper, including relaykit DTO (un)marshalling,
// follows. Injected from init() rather than main() so tests run on the same
// engine as production: common is imported by virtually every root package
// and test binary, while main() never executes under `go test`.
type hostJSONCodec struct{}

func (hostJSONCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (hostJSONCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (hostJSONCodec) Decode(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

func (hostJSONCodec) Valid(data []byte) bool {
	return json.Valid(data)
}

func init() {
	kitutil.SetCodec(hostJSONCodec{})
}

func Unmarshal(data []byte, v any) error {
	return kitutil.Unmarshal(data, v)
}

func UnmarshalJsonStr(data string, v any) error {
	return kitutil.UnmarshalJsonStr(data, v)
}

func DecodeJson(reader io.Reader, v any) error {
	return kitutil.DecodeJson(reader, v)
}

// DecodeRawJSONObject preserves exact keys and nullable unknown values. Only
// the decoded object's keys are checked; callers decide which children to read.
func DecodeRawJSONObject(data []byte) (map[string]RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8 JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("JSON object required")
	}
	fields := map[string]RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("JSON object key required")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate JSON key")
		}
		var value RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return fields, nil
}

// DecodeJsonWithValidation decodes JSON and applies Gin's configured binding-tag
// validator, including binding:"required" and any registered custom validators.
func DecodeJsonWithValidation(reader io.Reader, v any) error {
	if err := DecodeJson(reader, v); err != nil {
		return err
	}
	if binding.Validator == nil {
		return nil
	}
	return binding.Validator.ValidateStruct(v)
}

func Marshal(v any) ([]byte, error) {
	return kitutil.Marshal(v)
}

func IndentJson(data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	if err := json.Indent(&buffer, data, "", "  "); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func GetJsonType(data RawMessage) string {
	return kitutil.GetJsonType(data)
}

// JsonRawMessageToString returns JSON strings as their decoded value and other JSON values as raw text.
func JsonRawMessageToString(data RawMessage) string {
	return kitutil.JsonRawMessageToString(data)
}

// ValidateStrictJSONObject rejects ambiguous JSON before decoding typed fields.
// Null is forbidden throughout the security envelope. The WebAuthn finish
// variant permits only the protocol-defined nullable response.userHandle.
func ValidateStrictJSONObject(data []byte) error {
	return validateStrictJSONObject(data, false)
}

// ValidateWebAuthnFinishJSONObject retains strict syntax and envelope validation
// while allowing the nullable userHandle emitted by WebAuthn serializers.
func ValidateWebAuthnFinishJSONObject(data []byte) error {
	return validateStrictJSONObject(data, true)
}

func validateStrictJSONObject(data []byte, webAuthnFinish bool) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8 JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("JSON object required")
	}
	if err := strictJSONContainer(d, '{', nil, webAuthnFinish); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func strictJSONContainer(d *json.Decoder, kind json.Delim, path []string, webAuthnFinish bool) error {
	if len(path) > 64 {
		return errors.New("JSON nesting too deep")
	}
	seen := map[string]bool{}
	for d.More() {
		key := ""
		if kind == '{' {
			token, err := d.Token()
			if err != nil {
				return err
			}
			var ok bool
			key, ok = token.(string)
			if !ok || seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if token == nil {
			if webAuthnFinish && kind == '{' && len(path) == 2 && path[0] == "credential" && path[1] == "response" && key == "userHandle" {
				continue
			}
			return errors.New("null JSON field")
		}
		if delim, ok := token.(json.Delim); ok {
			if delim != '{' && delim != '[' {
				return errors.New("invalid JSON delimiter")
			}
			if err := strictJSONContainer(d, delim, append(path, key), webAuthnFinish); err != nil {
				return err
			}
		}
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	expected := json.Delim('}')
	if kind == '[' {
		expected = ']'
	}
	if token != expected {
		return errors.New("invalid JSON close")
	}
	return nil
}
func UnmarshalStrictObject(data []byte, v any) error {
	if err := ValidateStrictJSONObject(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// UnmarshalWebAuthnFinishObject does not constrain protocol extension keys;
// callers validate the exact finish envelope and the WebAuthn library verifies
// the credential. Only response.userHandle may be null.
func UnmarshalWebAuthnFinishObject(data []byte, v any) error {
	if err := ValidateWebAuthnFinishJSONObject(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// ValidateJSONObjectFields rejects case aliases as unknown wire fields before
// encoding/json's case-insensitive struct matching can merge them.
func ValidateJSONObjectFields(data []byte, required, optional []string) error {
	var fields map[string]RawMessage
	if err := Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return errors.New("missing JSON field")
		}
	}
	for name := range fields {
		if !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return errors.New("unknown JSON field")
		}
	}
	return nil
}
