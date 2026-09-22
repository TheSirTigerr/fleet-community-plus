package communityplus

import (
	"context"
	"fmt"
	"strings"

	communityoidc "github.com/fleetdm/fleet/v4/server/communityplus/oidc"
)

const (
	maxOIDCIssuerURLLength    = 2048
	maxOIDCClientIDLength     = 512
	maxOIDCClientSecretLength = 8192
	maxOIDCIDPNameLength      = 255
	maxOIDCScopes             = 32
	maxOIDCScopeLength        = 255
)

// OIDCSettings is the durable Community+ OpenID Connect configuration.
// ClientSecret is intentionally omitted from JSON responses and is only
// accepted through the write-only update field exposed by the settings API.
type OIDCSettings struct {
	Enabled      bool     `json:"enabled"`
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"`
	Scopes       []string `json:"scopes"`
	IDPName      string   `json:"idp_name"`
}

func DefaultOIDCSettings() OIDCSettings {
	return OIDCSettings{Scopes: []string{"openid", "email"}}
}

// Normalize canonicalizes user-controlled settings before validation/storage.
func (s *OIDCSettings) Normalize() {
	if s == nil {
		return
	}
	s.IssuerURL = strings.TrimRight(strings.TrimSpace(s.IssuerURL), "/")
	s.ClientID = strings.TrimSpace(s.ClientID)
	s.IDPName = strings.TrimSpace(s.IDPName)

	seen := make(map[string]struct{}, len(s.Scopes)+2)
	normalized := make([]string, 0, len(s.Scopes)+2)
	for _, scope := range append([]string{"openid", "email"}, s.Scopes...) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	s.Scopes = normalized
}

func (s OIDCSettings) Validate() error {
	if len(s.IssuerURL) > maxOIDCIssuerURLLength {
		return fmt.Errorf("communityplus: OIDC issuer_url exceeds %d characters", maxOIDCIssuerURLLength)
	}
	if len(s.ClientID) > maxOIDCClientIDLength {
		return fmt.Errorf("communityplus: OIDC client_id exceeds %d characters", maxOIDCClientIDLength)
	}
	if len(s.ClientSecret) > maxOIDCClientSecretLength {
		return fmt.Errorf("communityplus: OIDC client_secret exceeds %d characters", maxOIDCClientSecretLength)
	}
	if len(s.IDPName) > maxOIDCIDPNameLength {
		return fmt.Errorf("communityplus: OIDC idp_name exceeds %d characters", maxOIDCIDPNameLength)
	}
	if len(s.Scopes) > maxOIDCScopes {
		return fmt.Errorf("communityplus: OIDC scopes must contain at most %d entries", maxOIDCScopes)
	}
	for _, scope := range s.Scopes {
		if scope == "" || len(scope) > maxOIDCScopeLength || strings.ContainsAny(scope, " \t\r\n") {
			return fmt.Errorf("communityplus: invalid OIDC scope %q", scope)
		}
	}

	if s.IssuerURL != "" {
		clientID := s.ClientID
		if clientID == "" {
			clientID = "validation-placeholder"
		}
		if err := communityoidc.ValidateSettings(communityoidc.Settings{IssuerURL: s.IssuerURL, ClientID: clientID}); err != nil {
			return fmt.Errorf("communityplus: invalid OIDC settings: %w", err)
		}
	}
	if s.Enabled {
		if s.IssuerURL == "" || s.ClientID == "" {
			return fmt.Errorf("communityplus: OIDC issuer_url and client_id are required when enabled")
		}
		if err := communityoidc.ValidateSettings(communityoidc.Settings{IssuerURL: s.IssuerURL, ClientID: s.ClientID}); err != nil {
			return fmt.Errorf("communityplus: invalid OIDC settings: %w", err)
		}
	}
	return nil
}

// OIDCSettingsView is safe to expose over authenticated administrative APIs.
type OIDCSettingsView struct {
	Enabled                bool     `json:"enabled"`
	IssuerURL              string   `json:"issuer_url"`
	ClientID               string   `json:"client_id"`
	ClientSecretConfigured bool     `json:"client_secret_configured"`
	Scopes                 []string `json:"scopes"`
	IDPName                string   `json:"idp_name"`
}

func (s OIDCSettings) View() OIDCSettingsView {
	return OIDCSettingsView{
		Enabled:                s.Enabled,
		IssuerURL:              s.IssuerURL,
		ClientID:               s.ClientID,
		ClientSecretConfigured: s.ClientSecret != "",
		Scopes:                 append([]string(nil), s.Scopes...),
		IDPName:                s.IDPName,
	}
}

type OIDCSettingsStore interface {
	GetOIDCSettings(context.Context) (OIDCSettings, error)
	UpsertOIDCSettings(context.Context, OIDCSettings) error
}
