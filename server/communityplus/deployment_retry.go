package communityplus

import (
	"context"
	"fmt"
)

// DeploymentRetryStore resets one failed host result so the regular pending
// deployment reconciliation can pick it up immediately. Successful installs
// are deliberately not retried through this path.
type DeploymentRetryStore interface {
	RetryDeployment(context.Context, string, uint) error
}

func (s *SQLStore) RetryDeployment(ctx context.Context, deploymentID string, hostID uint) error {
	if deploymentID == "" {
		return fmt.Errorf("communityplus: deployment id is required")
	}
	if hostID == 0 {
		return fmt.Errorf("communityplus: host id must be greater than zero")
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE communityplus_deployment_results
SET attempt_count = 0,
    updated_at = DATE_SUB(NOW(6), INTERVAL 6 MINUTE)
WHERE deployment_id = ? AND host_id = ? AND exit_code <> 0`, deploymentID, hostID)
	if err != nil {
		return fmt.Errorf("communityplus: retry deployment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("communityplus: inspect retry result: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("communityplus: failed deployment result not found")
	}
	return nil
}
