package communityplus

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// GetOIDCSettings loads the singleton Community+ OIDC configuration.
func (s *SQLStore) GetOIDCSettings(ctx context.Context) (OIDCSettings, error) {
	settings := DefaultOIDCSettings()
	var scopes []byte
	err := s.db.QueryRowContext(ctx, `
SELECT enabled, enable_jit_provisioning, issuer_url, client_id, client_secret, scopes, idp_name
FROM communityplus_oidc_settings
WHERE id = 1`).Scan(
		&settings.Enabled,
		&settings.EnableJITProvisioning,
		&settings.IssuerURL,
		&settings.ClientID,
		&settings.ClientSecret,
		&scopes,
		&settings.IDPName,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return OIDCSettings{}, fmt.Errorf("communityplus: get OIDC settings: %w", err)
	}
	if err := json.Unmarshal(scopes, &settings.Scopes); err != nil {
		return OIDCSettings{}, fmt.Errorf("communityplus: decode OIDC scopes: %w", err)
	}
	settings.Normalize()
	if err := settings.Validate(); err != nil {
		return OIDCSettings{}, fmt.Errorf("communityplus: validate stored OIDC settings: %w", err)
	}
	return settings, nil
}

// UpsertOIDCSettings persists the singleton Community+ OIDC configuration.
func (s *SQLStore) UpsertOIDCSettings(ctx context.Context, settings OIDCSettings) error {
	settings.Normalize()
	if err := settings.Validate(); err != nil {
		return err
	}
	scopes, err := json.Marshal(settings.Scopes)
	if err != nil {
		return fmt.Errorf("communityplus: encode OIDC scopes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO communityplus_oidc_settings
    (id, enabled, enable_jit_provisioning, issuer_url, client_id, client_secret, scopes, idp_name)
VALUES (1, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    enabled = VALUES(enabled),
    enable_jit_provisioning = VALUES(enable_jit_provisioning),
    issuer_url = VALUES(issuer_url),
    client_id = VALUES(client_id),
    client_secret = VALUES(client_secret),
    scopes = VALUES(scopes),
    idp_name = VALUES(idp_name)`,
		settings.Enabled,
		settings.EnableJITProvisioning,
		settings.IssuerURL,
		settings.ClientID,
		settings.ClientSecret,
		scopes,
		settings.IDPName,
	)
	if err != nil {
		return fmt.Errorf("communityplus: upsert OIDC settings: %w", err)
	}
	return nil
}
