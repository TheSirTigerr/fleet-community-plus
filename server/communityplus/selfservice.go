package communityplus

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// SelfServiceItem is one Community+ deployment exposed to a device user.
// TitleID is a stable numeric alias used by Fleet Desktop's existing software routes.
type SelfServiceItem struct {
	TitleID           uint
	DeploymentID      string
	CatalogEntryID    string
	Name              string
	PackageIdentifier string
	Version           string
	Provider          CatalogProvider
	InstallerType     string
	Status            *fleet.SoftwareInstallerStatus
}

func (s *SQLStore) syncSelfServiceDeployment(ctx context.Context, deployment Deployment) error {
	if deployment.SelfService {
		if _, err := s.db.ExecContext(ctx,
			`INSERT IGNORE INTO communityplus_self_service_deployments (deployment_id) VALUES (?)`,
			deployment.ID,
		); err != nil {
			return fmt.Errorf("communityplus: register self-service deployment: %w", err)
		}
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM communityplus_self_service_deployments WHERE deployment_id = ?`,
		deployment.ID,
	); err != nil {
		return fmt.Errorf("communityplus: unregister self-service deployment: %w", err)
	}
	return nil
}

func (s *SQLStore) ListSelfServiceItemsForHost(
	ctx context.Context,
	hostID, fleetID uint,
	provider CatalogProvider,
	matchQuery string,
) ([]SelfServiceItem, error) {
	if hostID == 0 || fleetID == 0 {
		return nil, fmt.Errorf("communityplus: host and Fleet ids are required")
	}
	if !supportedCatalogProvider(provider) {
		return nil, fmt.Errorf("communityplus: unsupported catalog provider %q", provider)
	}

	needle := "%" + strings.TrimSpace(matchQuery) + "%"
	rows, err := s.db.QueryContext(ctx, `
SELECT ss.id, d.id, e.id, e.name, e.package_identifier, e.version, e.provider, e.installer_type,
       r.exit_code, q.requested_at
FROM communityplus_self_service_deployments ss
JOIN communityplus_catalog_deployments d ON d.id = ss.deployment_id
JOIN communityplus_catalog_entries e ON e.id = d.catalog_entry_id
LEFT JOIN communityplus_deployment_results r ON r.deployment_id = d.id AND r.host_id = ?
LEFT JOIN communityplus_self_service_requests q ON q.deployment_id = d.id AND q.host_id = ?
WHERE d.fleet_id = ? AND d.self_service = 1 AND e.provider = ?
  AND (e.name LIKE ? OR e.package_identifier LIKE ?)
ORDER BY e.name, d.id`, hostID, hostID, fleetID, provider, needle, needle)
	if err != nil {
		return nil, fmt.Errorf("communityplus: list self-service software: %w", err)
	}
	defer rows.Close()

	var items []SelfServiceItem
	for rows.Next() {
		var item SelfServiceItem
		var exitCode sql.NullInt64
		var requestedAt sql.NullTime
		if err := rows.Scan(
			&item.TitleID, &item.DeploymentID, &item.CatalogEntryID, &item.Name,
			&item.PackageIdentifier, &item.Version, &item.Provider, &item.InstallerType,
			&exitCode, &requestedAt,
		); err != nil {
			return nil, fmt.Errorf("communityplus: scan self-service software: %w", err)
		}
		switch {
		case exitCode.Valid && exitCode.Int64 == 0:
			status := fleet.SoftwareInstalled
			item.Status = &status
		case exitCode.Valid:
			status := fleet.SoftwareInstallFailed
			item.Status = &status
		case requestedAt.Valid:
			status := fleet.SoftwareInstallPending
			item.Status = &status
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate self-service software: %w", err)
	}
	return items, nil
}

func (s *SQLStore) RequestSelfServiceDeployment(
	ctx context.Context,
	hostID, fleetID, titleID uint,
	provider CatalogProvider,
) (string, error) {
	if hostID == 0 || fleetID == 0 || titleID == 0 {
		return "", fmt.Errorf("communityplus: host, Fleet and software title ids are required")
	}
	if !supportedCatalogProvider(provider) {
		return "", fmt.Errorf("communityplus: unsupported catalog provider %q", provider)
	}

	var deploymentID string
	err := s.db.QueryRowContext(ctx, `
SELECT d.id
FROM communityplus_self_service_deployments ss
JOIN communityplus_catalog_deployments d ON d.id = ss.deployment_id
JOIN communityplus_catalog_entries e ON e.id = d.catalog_entry_id
WHERE ss.id = ? AND d.fleet_id = ? AND d.self_service = 1 AND e.provider = ?`,
		titleID, fleetID, provider,
	).Scan(&deploymentID)
	if err != nil {
		return "", fmt.Errorf("communityplus: resolve self-service deployment: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO communityplus_self_service_requests (deployment_id, host_id, requested_at)
VALUES (?, ?, NOW(6))
ON DUPLICATE KEY UPDATE requested_at = VALUES(requested_at)`, deploymentID, hostID); err != nil {
		return "", fmt.Errorf("communityplus: queue self-service deployment: %w", err)
	}

	// A new user request is allowed to reinstall software. Clearing the previous
	// terminal result makes the normal Orbit reconciliation queue it again.
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM communityplus_deployment_results WHERE deployment_id = ? AND host_id = ?`,
		deploymentID, hostID,
	); err != nil {
		return "", fmt.Errorf("communityplus: reset self-service deployment result: %w", err)
	}
	return deploymentID, nil
}

func (s *SQLStore) IsSelfServiceRequested(ctx context.Context, deploymentID string, hostID uint) (bool, error) {
	if deploymentID == "" || hostID == 0 {
		return false, nil
	}
	var requested bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM communityplus_self_service_requests WHERE deployment_id = ? AND host_id = ?)`,
		deploymentID, hostID,
	).Scan(&requested); err != nil {
		return false, fmt.Errorf("communityplus: check self-service request: %w", err)
	}
	return requested, nil
}

// ListSelfServiceForHost exposes the Community+ self-service catalog for a host.
// configured is false when Community+ self-service is unavailable for the host platform.
func ListSelfServiceForHost(ctx context.Context, host *fleet.Host, matchQuery string) (items []SelfServiceItem, configured bool, err error) {
	provider, ok := providerForHost(host)
	if OrbitDelivery == nil || !ok || host == nil || host.TeamID == nil {
		return nil, false, nil
	}
	items, err = OrbitDelivery.ListSelfServiceItemsForHost(ctx, host.ID, *host.TeamID, provider, matchQuery)
	return items, true, err
}

// RequestSelfServiceForHost queues one Community+ self-service deployment using
// the stable numeric title ID presented by Fleet Desktop.
func RequestSelfServiceForHost(ctx context.Context, host *fleet.Host, titleID uint) (handled bool, err error) {
	provider, ok := providerForHost(host)
	if OrbitDelivery == nil || !ok || host == nil || host.TeamID == nil {
		return false, nil
	}
	_, err = OrbitDelivery.RequestSelfServiceDeployment(ctx, host.ID, *host.TeamID, titleID, provider)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return true, nil
}

// RequestAllSelfServiceForHost queues every matching Community+ self-service
// deployment. It deliberately does not emulate Fleet's category IDs.
func RequestAllSelfServiceForHost(ctx context.Context, host *fleet.Host, matchQuery string) (handled bool, err error) {
	items, configured, err := ListSelfServiceForHost(ctx, host, matchQuery)
	if err != nil || !configured {
		return configured, err
	}
	provider, _ := providerForHost(host)
	for _, item := range items {
		if _, err := OrbitDelivery.RequestSelfServiceDeployment(ctx, host.ID, *host.TeamID, item.TitleID, provider); err != nil {
			return true, err
		}
	}
	return true, nil
}

func HasSelfServiceForHost(ctx context.Context, host *fleet.Host) (available, configured bool, err error) {
	items, configured, err := ListSelfServiceForHost(ctx, host, "")
	if err != nil || !configured {
		return false, configured, err
	}
	return len(items) > 0, true, nil
}
