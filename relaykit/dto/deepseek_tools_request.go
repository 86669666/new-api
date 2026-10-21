package dto

import (
	"encoding/json"
	"net/http"

	"github.com/QuantumNous/new-api/relaykit/types"
)

// DeepSeekToolsRequest carries a server-owned subject; native Search has no
// model selector. RawBody preserves optional false and unknown extensions.
type DeepSeekToolsRequest struct {
	Model   string          `json:"-"`
	RawBody json.RawMessage `json:"-"`
}

func (r *DeepSeekToolsRequest) GetTokenCountMeta() *types.TokenCountMeta {
	return &types.TokenCountMeta{CombineText: string(r.RawBody), TokenType: types.TokenTypeTokenizer}
}
func (*DeepSeekToolsRequest) IsStream(*http.Request) bool { return false }
func (r *DeepSeekToolsRequest) SetModelName(string)       {} // Mapping cannot change the fixed subject.
