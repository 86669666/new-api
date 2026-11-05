package deepseek

import (
	"testing"

	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepSeekToolsSearchRequestURL(t *testing.T) {
	for _, baseURL := range []string{"https://provider.example", "https://provider.example/"} {
		t.Run(baseURL, func(t *testing.T) {
			info := &relaycommon.RelayInfo{
				RelayMode:   relayconstant.RelayModeToolsSearch,
				ChannelMeta: &relaycommon.ChannelMeta{ChannelBaseUrl: baseURL},
			}
			actual, err := (&Adaptor{}).GetRequestURL(info)
			require.NoError(t, err)
			assert.Equal(t, "https://provider.example/v1/tools/search", actual)
		})
	}
}
