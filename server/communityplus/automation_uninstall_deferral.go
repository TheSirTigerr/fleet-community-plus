package communityplus

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/google/uuid"
)

type DeferredSoftwareUninstallAutomation struct {
	RuleID      string
	HostID      uint
	FleetID     uint
	InstallerID uint
	RequestedAt time.Time
}

func (s *SQLStore) QueueDeferredSoftwareUninstallAutomation(ctx context.Context, req DeferredSoftwareUninstallAutomation) error {
	if req.RuleID == "" || req.HostID == 0 || req.FleetID == 0 || req.InstallerID == 0 {
		return fmt.Errorf("communityplus: deferred software uninstall requires rule, host, Fleet and installer ids")
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO communityplus_automation_uninstall_requests
	(rule_id, host_id, fleet_id, installer_id, requested_at)
VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
	fleet_id = VALUES(fleet_id),
	installer_id = VALUES(installer_id),
	requested_at = VALUES(requested_at)`,
		req.RuleID, req.HostID, req.FleetID, req.InstallerID, req.RequestedAt,
	)
	if err != nil {
		return fmt.Errorf("communityplus: defer software uninstall automation: %w", err)
	}
	return nil
}

func (s *SQLStore) ListDeferredSoftwareUninstallAutomationsForHost(ctx context.Context, hostID uint) ([]DeferredSoftwareUninstallAutomation, error) {
	if hostID == 0 {
		return nil, fmt.Errorf("communityplus: deferred software uninstall host id is required")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT rule_id, host_id, fleet_id, installer_id, requested_at
FROM communityplus_automation_uninstall_requests
WHERE host_id = ?
ORDER BY requested_at, rule_id`, hostID)
	if err != nil {
		return nil, fmt.Errorf("communityplus: list deferred software uninstalls: %w", err)
	}
	defer rows.Close()

	var result []DeferredSoftwareUninstallAutomation
	for rows.Next() {
		var req DeferredSoftwareUninstallAutomation
		if err := rows.Scan(&req.RuleID, &req.HostID, &req.FleetID, &req.InstallerID, &req.RequestedAt); err != nil {
			return nil, fmt.Errorf("communityplus: scan deferred software uninstall: %w", err)
		}
		result = append(result, req)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate deferred software uninstalls: %w", err)
	}
	return result, nil
}

func (s *SQLStore) DeleteDeferredSoftwareUninstallAutomation(ctx context.Context, ruleID string, hostID uint) error {
	if ruleID == "" || hostID == 0 {
		return fmt.Errorf("communityplus: deferred software uninstall rule and host ids are required")
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM communityplus_automation_uninstall_requests WHERE rule_id = ? AND host_id = ?`,
		ruleID, hostID,
	); err != nil {
		return fmt.Errorf("communityplus: delete deferred software uninstall: %w", err)
	}
	return nil
}

func (s *SQLStore) IsSoftwareUninstallPending(ctx context.Context, hostID, installerID uint) (bool, error) {
	if hostID == 0 || installerID == 0 {
		return false, nil
	}
	var pending bool
	if err := s.db.QueryRowContext(ctx, `
SELECT (
	EXISTS(
		SELECT 1
		FROM upcoming_activities ua
		JOIN software_install_upcoming_activities siua ON siua.upcoming_activity_id = ua.id
		WHERE ua.host_id = ? AND ua.activity_type = 'software_uninstall'
		  AND siua.software_installer_id = ?
	)
	OR EXISTS(
		SELECT 1
		FROM host_software_installs
		WHERE host_id = ? AND software_installer_id = ?
		  AND status = 'pending_uninstall' AND canceled = 0
	)
)`, hostID, installerID, hostID, installerID).Scan(&pending); err != nil {
		return false, fmt.Errorf("communityplus: check pending software uninstall: %w", err)
	}
	return pending, nil
}

type fleetInitiatedSoftwareUninstallStore interface {
	InsertFleetInitiatedSoftwareUninstallRequest(context.Context, string, uint, uint) error
}

// ReleasePendingSoftwareUninstallAutomations promotes deferred uninstall actions
// into Fleet's native software-uninstall queue once the maintenance window opens.
func ReleasePendingSoftwareUninstallAutomations(ctx context.Context, host *fleet.Host, ds fleet.Datastore) error {
	if OrbitDelivery == nil || host == nil || host.TeamID == nil || ds == nil {
		return nil
	}
	queue, ok := ds.(fleetInitiatedSoftwareUninstallStore)
	if !ok {
		return fmt.Errorf("communityplus: datastore does not support fleet-initiated software uninstall")
	}

	requests, err := OrbitDelivery.ListDeferredSoftwareUninstallAutomationsForHost(ctx, host.ID)
	if err != nil {
		return err
	}
	if len(requests) == 0 {
		return nil
	}
	allowed, err := OrbitDelivery.AutomaticDeploymentsAllowed(ctx, *host.TeamID, time.Now())
	if err != nil {
		return err
	}
	if !allowed {
		return nil
	}
	if host.OrbitNodeKey == nil || strings.TrimSpace(*host.OrbitNodeKey) == "" {
		return nil
	}

	for _, req := range requests {
		if req.FleetID != *host.TeamID {
			return fmt.Errorf("%w: deferred software uninstall Fleet does not match host", ErrScopeConflict)
		}
		pending, err := OrbitDelivery.IsSoftwareUninstallPending(ctx, host.ID, req.InstallerID)
		if err != nil {
			return err
		}
		if pending {
			if err := OrbitDelivery.DeleteDeferredSoftwareUninstallAutomation(ctx, req.RuleID, host.ID); err != nil {
				return err
			}
			continue
		}

		metadata, err := ds.GetSoftwareInstallerMetadataByID(ctx, req.InstallerID)
		if err != nil {
			return fmt.Errorf("communityplus: load deferred uninstall installer: %w", err)
		}
		if metadata == nil || metadata.TitleID == nil || !sameAutomationTeam(host.TeamID, metadata.TeamID) {
			return fmt.Errorf("%w: deferred uninstall installer no longer belongs to host Fleet", ErrScopeConflict)
		}
		if want, got := metadata.Platform, fleet.PlatformFromHost(host.Platform); want != got {
			return fmt.Errorf("communityplus: deferred uninstall installer platform %q does not match host platform %q", want, got)
		}
		installer, err := ds.GetSoftwareInstallerMetadataByTeamTitleAndInstallerID(
			ctx, host.TeamID, *metadata.TitleID, req.InstallerID, true,
		)
		if err != nil {
			return fmt.Errorf("communityplus: load deferred uninstall script: %w", err)
		}
		if installer == nil || strings.TrimSpace(installer.UninstallScript) == "" || installer.UninstallScriptContentID == 0 {
			return fmt.Errorf("communityplus: software installer %d has no uninstall script", req.InstallerID)
		}
		if err := fleet.ValidateHostScriptContents(installer.UninstallScript, true); err != nil {
			return fmt.Errorf("communityplus: validate deferred uninstall script: %w", err)
		}

		last, err := ds.GetHostLastInstallData(ctx, host.ID, req.InstallerID)
		if err != nil {
			return fmt.Errorf("communityplus: load last software state before deferred uninstall: %w", err)
		}
		if last != nil && (last.Status == nil || *last.Status == fleet.SoftwareUninstallPending) {
			if err := OrbitDelivery.DeleteDeferredSoftwareUninstallAutomation(ctx, req.RuleID, host.ID); err != nil {
				return err
			}
			continue
		}

		if err := queue.InsertFleetInitiatedSoftwareUninstallRequest(ctx, uuid.NewString(), host.ID, req.InstallerID); err != nil {
			return fmt.Errorf("communityplus: release deferred software uninstall: %w", err)
		}
		if err := OrbitDelivery.DeleteDeferredSoftwareUninstallAutomation(ctx, req.RuleID, host.ID); err != nil {
			return err
		}
	}
	return nil
}
