package condaccess

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConditionalAccessIdPRejectsMissingDependencies(t *testing.T) {
	err := RegisterIdP(nil, nil, nil, nil, nil)
	require.Error(t, err)
}

func TestConditionalAccessEndpointURLRequiresCanonicalHTTPS(t *testing.T) {
	got, err := endpointURL("https://fleet.example", conditionalAccessIdPSSOPath)
	require.NoError(t, err)
	require.Equal(t, "https://fleet.example/api/fleet/conditional_access/idp/sso", got.String())

	for _, raw := range []string{
		"http://fleet.example",
		"https://user:pass@fleet.example",
		"https://fleet.example?query=1",
		"https://fleet.example#fragment",
		"not-a-url",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := endpointURL(raw, conditionalAccessIdPSSOPath)
			require.Error(t, err)
		})
	}
}
