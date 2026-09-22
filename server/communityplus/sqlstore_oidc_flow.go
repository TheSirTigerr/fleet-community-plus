package communityplus

import (
	"context"
	"fmt"
)

func (s *SQLStore) SaveOIDCFlow(ctx context.Context, flow OIDCFlow) error {
	if err := flow.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO communityplus_oidc_flows
    (state_hash, nonce, code_verifier, redirect_url, expires_at)
VALUES (?, ?, ?, ?, ?)`,
		oidcStateHash(flow.State), flow.Nonce, flow.CodeVerifier, flow.RedirectURL, flow.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("communityplus: save OIDC flow: %w", err)
	}
	return nil
}

func (s *SQLStore) ConsumeOIDCFlow(ctx context.Context, state string) (OIDCFlow, error) {
	if state == "" {
		return OIDCFlow{}, ErrOIDCFlowInvalid
	}
	stateHash := oidcStateHash(state)
	result, err := s.db.ExecContext(ctx, `
UPDATE communityplus_oidc_flows
SET consumed_at = NOW(6)
WHERE state_hash = ?
  AND consumed_at IS NULL
  AND expires_at > NOW(6)`, stateHash)
	if err != nil {
		return OIDCFlow{}, fmt.Errorf("communityplus: consume OIDC flow: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return OIDCFlow{}, fmt.Errorf("communityplus: inspect OIDC flow consume result: %w", err)
	}
	if affected != 1 {
		return OIDCFlow{}, ErrOIDCFlowInvalid
	}

	flow := OIDCFlow{State: state}
	err = s.db.QueryRowContext(ctx, `
SELECT nonce, code_verifier, redirect_url, expires_at
FROM communityplus_oidc_flows
WHERE state_hash = ?`, stateHash).Scan(
		&flow.Nonce, &flow.CodeVerifier, &flow.RedirectURL, &flow.ExpiresAt,
	)
	if err != nil {
		return OIDCFlow{}, fmt.Errorf("communityplus: load consumed OIDC flow: %w", err)
	}
	if err := flow.Validate(); err != nil {
		return OIDCFlow{}, fmt.Errorf("communityplus: validate consumed OIDC flow: %w", err)
	}
	return flow, nil
}
