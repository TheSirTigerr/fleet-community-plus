package condaccess

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConditionalAccessIdPRejectsMissingDependencies(t *testing.T) {
	err := RegisterIdP(nil, nil, nil, nil, nil)
	require.Error(t, err)
}
