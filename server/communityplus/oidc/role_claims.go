package oidc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	roleClaimGlobal      = "FLEET_JIT_USER_ROLE_GLOBAL"
	roleClaimFleetPrefix = "FLEET_JIT_USER_ROLE_FLEET_"
	roleClaimTeamPrefix  = "FLEET_JIT_USER_ROLE_TEAM_"
)

// Attribute is a protocol-neutral verified IdP attribute. The login adapter
// translates these values to Fleet's existing SSO attribute contract after the
// ID token signature and standard OIDC claims have been verified.
type Attribute struct {
	Name   string
	Values []string
}

func roleAttributesFromJWTPart(part string) ([]Attribute, error) {
	var claims map[string]json.RawMessage
	if err := decodeJWTPart(part, &claims); err != nil {
		return nil, fmt.Errorf("decode OIDC role claims: %w", err)
	}

	names := make([]string, 0)
	for name := range claims {
		if name == roleClaimGlobal || strings.HasPrefix(name, roleClaimFleetPrefix) || strings.HasPrefix(name, roleClaimTeamPrefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	attrs := make([]Attribute, 0, len(names))
	for _, name := range names {
		raw := claims[name]
		if string(raw) == "null" {
			continue
		}
		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			attrs = append(attrs, Attribute{Name: name, Values: []string{single}})
			continue
		}
		var many []string
		if err := json.Unmarshal(raw, &many); err == nil {
			attrs = append(attrs, Attribute{Name: name, Values: append([]string(nil), many...)})
			continue
		}
		return nil, fmt.Errorf("OIDC role claim %q must be a string or array of strings", name)
	}
	return attrs, nil
}
