package communityplus

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *SQLStore) QueueAutomationDeployment(ctx context.Context, deploymentID string, hostID uint) error {
	if deploymentID == "" {
		return fmt.Errorf("communityplus: deployment id is required")
	}
	if hostID == 0 {
		return fmt.Errorf("communityplus: host id must be greater than zero")
	}

	var (
		fleetID  uint
		provider CatalogProvider
		platform string
		hostTeam sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `
SELECT d.fleet_id, e.provider, h.platform, h.team_id
FROM communityplus_catalog_deployments d
JOIN communityplus_catalog_entries e ON e.id = d.catalog_entry_id
JOIN hosts h ON h.id = ?
WHERE d.id = ?`, hostID, deploymentID).Scan(&fleetID, &provider, &platform, &hostTeam)
	if err != nil {
		return fmt.Errorf("communityplus: resolve automation deployment target: %w", err)
	}
	if !hostTeam.Valid || uint(hostTeam.Int64) != fleetID {
		return fmt.Errorf("%w: automation deployment host is outside the Fleet", ErrScopeConflict)
	}

	wantProvider := CatalogProvider("")
	switch platform {
	case "windows":
		wantProvider = CatalogProviderWinget
	case "darwin":
		wantProvider = CatalogProviderHomebrew
	default:
		return fmt.Errorf("communityplus: automation deployment does not support host platform %q", platform)
	}
	if provider != wantProvider {
		return fmt.Errorf("communityplus: automation deployment provider %q does not match host platform %q", provider, platform)
	}

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO communityplus_automation_deployment_requests (deployment_id, host_id, requested_at)
VALUES (?, ?, NOW(6))
ON DUPLICATE KEY UPDATE requested_at = VALUES(requested_at)`, deploymentID, hostID); err != nil {
		return fmt.Errorf("communityplus: queue automation deployment request: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM communityplus_deployment_results WHERE deployment_id = ? AND host_id = ?`,
		deploymentID, hostID,
	); err != nil {
		return fmt.Errorf("communityplus: reset automation deployment result: %w", err)
	}
	return nil
}

func (s *SQLStore) IsAutomationDeploymentRequested(ctx context.Context, deploymentID string, hostID uint) (bool, error) {
	if deploymentID == "" || hostID == 0 {
		return false, nil
	}
	var requested bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM communityplus_automation_deployment_requests WHERE deployment_id = ? AND host_id = ?)`,
		deploymentID, hostID,
	).Scan(&requested); err != nil {
		return false, fmt.Errorf("communityplus: check automation deployment request: %w", err)
	}
	return requested, nil
}
