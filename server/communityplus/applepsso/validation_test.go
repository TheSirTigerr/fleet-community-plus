package applepsso

import (
	"testing"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

func TestClaimsFromUpstreamIDTokenRequiresSubject(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"email": "user@example.com"})
	raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = claimsFromUpstreamIDToken(raw)
	require.ErrorContains(t, err, "missing sub")
}
