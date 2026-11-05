package vertex

import (
	"testing"

	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildGoogleModelURLUsesTheLocationHost(t *testing.T) {
	tests := []struct {
		region string
		want   string
	}{
		{"global", "https://aiplatform.googleapis.com/v1/projects/my-project/locations/global/publishers/google/models/gemini-4-argon:generateContent"},
		{"us-central1", "https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-4-argon:generateContent"},
		{"us", "https://aiplatform.us.rep.googleapis.com/v1/projects/my-project/locations/us/publishers/google/models/gemini-4-argon:generateContent"},
		{"eu", "https://aiplatform.eu.rep.googleapis.com/v1/projects/my-project/locations/eu/publishers/google/models/gemini-4-argon:generateContent"},
	}
	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			got := BuildGoogleModelURL("", DefaultAPIVersion, "my-project", tt.region, "gemini-4-argon", "generateContent")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGoogleModelURLVersionTransitions(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		version string
		want    string
	}{
		{"v1 to beta", "https://proxy.example/custom/v1", "v1beta1", "https://proxy.example/custom/v1beta1"},
		{"beta to v1", "https://proxy.example/custom/v1beta1", "v1", "https://proxy.example/custom/v1"},
		{"beta to default", "https://proxy.example/custom/v1beta1", "", "https://proxy.example/custom/v1"},
		{"matching v1", "https://proxy.example/custom/v1", "v1", "https://proxy.example/custom/v1"},
		{"matching beta", "https://proxy.example/custom/v1beta1", "v1beta1", "https://proxy.example/custom/v1beta1"},
		{"default on v1", "https://proxy.example/custom/v1", "", "https://proxy.example/custom/v1"},
		{"trailing slash", " https://proxy.example/custom/v1/ ", "v1beta1", "https://proxy.example/custom/v1beta1"},
		{"unversioned prefix", "https://proxy.example/custom", "v1beta1", "https://proxy.example/custom/v1beta1"},
		{"interior version prefix", "https://proxy.example/v1/custom", "v1beta1", "https://proxy.example/v1/custom/v1beta1"},
		{"unrecognized suffix", "https://proxy.example/custom/v2", "v1", "https://proxy.example/custom/v2/v1"},
	}
	credentials := []struct {
		name      string
		keyType   dto.VertexKeyType
		key       string
		projectID string
		path      string
		query     string
	}{
		{"API key express", dto.VertexKeyTypeAPIKey, "test-key", "", "", "?key=test-key"},
		{"API key project", dto.VertexKeyTypeAPIKey, "test-key", "my-project", "/projects/my-project/locations/us-central1", "?key=test-key"},
		{"service account", "", `{"project_id":"my-project"}`, "", "/projects/my-project/locations/us-central1", ""},
	}
	for _, tt := range tests {
		for _, credential := range credentials {
			t.Run(tt.name+"/"+credential.name, func(t *testing.T) {
				info := &relaycommon.RelayInfo{
					OriginModelName: "gemini-4-argon",
					ChannelMeta: &relaycommon.ChannelMeta{
						ChannelBaseUrl: tt.baseURL,
						ApiVersion:     `{"default":"us-central1"}`,
						ApiKey:         credential.key,
						ChannelOtherSettings: dto.ChannelOtherSettings{
							VertexKeyType:    credential.keyType,
							VertexProjectID:  credential.projectID,
							VertexAPIVersion: tt.version,
						},
					},
				}
				adaptor := &Adaptor{RequestMode: RequestModeGemini}
				got, err := adaptor.getRequestUrl(info, "gemini-4-argon", "generateContent")
				require.NoError(t, err)
				assert.Equal(t, tt.want+credential.path+"/publishers/google/models/gemini-4-argon:generateContent"+credential.query, got)
			})
		}
	}
}

func TestNonGoogleModelURLsIgnoreGoogleAPIVersion(t *testing.T) {
	tests := []struct {
		name    string
		mode    int
		version string
		model   string
		action  string
		want    string
	}{
		{"Claude", RequestModeClaude, "v1beta1", "claude-sonnet-4@20250514", "rawPredict", "v1/projects/my-project/locations/global/publishers/anthropic/models/claude-sonnet-4@20250514:rawPredict"},
		{"open source", RequestModeOpenSource, "v1", "llama-4", "", "v1beta1/projects/my-project/locations/global/endpoints/openapi/chat/completions"},
	}
	for _, tt := range tests {
		for _, baseURL := range []string{"", "https://proxy.example/custom", "https://proxy.example/custom/" + tt.version} {
			t.Run(tt.name+"/"+baseURL, func(t *testing.T) {
				info := &relaycommon.RelayInfo{
					OriginModelName: tt.model,
					ChannelMeta: &relaycommon.ChannelMeta{
						ChannelBaseUrl:       baseURL,
						ApiVersion:           `{"default":"global"}`,
						ApiKey:               `{"project_id":"my-project"}`,
						ChannelOtherSettings: dto.ChannelOtherSettings{VertexAPIVersion: tt.version},
					},
				}
				adaptor := &Adaptor{RequestMode: tt.mode}
				got, err := adaptor.getRequestUrl(info, tt.model, tt.action)
				require.NoError(t, err)
				prefix := "https://proxy.example/custom/"
				if baseURL == "" {
					prefix = "https://aiplatform.googleapis.com/"
				}
				assert.Equal(t, prefix+tt.want, got)
			})
		}
	}
}
