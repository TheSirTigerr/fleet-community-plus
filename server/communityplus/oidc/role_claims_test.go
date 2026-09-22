package oidc

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func jwtClaimsPart(t *testing.T, claims map[string]any) string {
	t.Helper()
	data, err := json.Marshal(claims)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestRoleAttributesFromJWTPart(t *testing.T) {
	attrs, err := roleAttributesFromJWTPart(jwtClaimsPart(t, map[string]any{
		"sub":                          "user-123",
		"groups":                       []string{"engineering"},
		"FLEET_JIT_USER_ROLE_GLOBAL":   "admin",
		"FLEET_JIT_USER_ROLE_FLEET_12": []string{"observer", "maintainer"},
		"FLEET_JIT_USER_ROLE_FLEET_13": nil,
	}))
	require.NoError(t, err)
	require.Equal(t, []Attribute{
		{Name: "FLEET_JIT_USER_ROLE_FLEET_12", Values: []string{"observer", "maintainer"}},
		{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Values: []string{"admin"}},
	}, attrs)
}

func TestRoleAttributesFromJWTPartKeepsEmptyValueForFleetParserCoercion(t *testing.T) {
	attrs, err := roleAttributesFromJWTPart(jwtClaimsPart(t, map[string]any{
		"FLEET_JIT_USER_ROLE_GLOBAL": "",
	}))
	require.NoError(t, err)
	require.Equal(t, []Attribute{{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Values: []string{""}}}, attrs)
}

func TestRoleAttributesFromJWTPartRejectsInvalidClaimType(t *testing.T) {
	_, err := roleAttributesFromJWTPart(jwtClaimsPart(t, map[string]any{
		"FLEET_JIT_USER_ROLE_GLOBAL": true,
	}))
	require.EqualError(t, err, `OIDC role claim "FLEET_JIT_USER_ROLE_GLOBAL" must be a string or array of strings`)
}
