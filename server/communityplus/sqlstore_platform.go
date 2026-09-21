package communityplus

import (
	"context"
	"fmt"
)

// PendingDeploymentIDsForProvider returns only automatic deployments whose
// reviewed catalog entry belongs to the endpoint's package provider. This keeps
// WinGet work off macOS hosts and Homebrew work off Windows hosts.
func (s *SQLStore) PendingDeploymentIDsForProvider(ctx context.Context, hostID, fleetID uint, provider CatalogProvider) ([]string, error) {
	if !supportedCatalogProvider(provider) {
		return nil, fmt.Errorf("communityplus: unsupported catalog provider %q", provider)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT d.id
FROM communityplus_catalog_deployments d
JOIN communityplus_catalog_entries e ON e.id = d.catalog_entry_id
LEFT JOIN communityplus_deployment_results r ON r.deployment_id = d.id AND r.host_id = ?
WHERE d.fleet_id = ? AND d.automatic_install = 1 AND e.provider = ?
  AND (r.deployment_id IS NULL OR (r.exit_code <> 0 AND r.attempt_count < 3 AND r.updated_at <= DATE_SUB(NOW(6), INTERVAL 5 MINUTE)))
ORDER BY d.created_at, d.id`, hostID, fleetID, provider)
	if err != nil {
		return nil, fmt.Errorf("communityplus: list pending provider deployments: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("communityplus: scan pending provider deployment: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate pending provider deployments: %w", err)
	}
	return ids, nil
}
