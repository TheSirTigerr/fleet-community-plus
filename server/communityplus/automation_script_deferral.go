package communityplus

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type DeferredScriptAutomation struct {
	RuleID      string
	HostID      uint
	FleetID     uint
	ScriptID    uint
	PolicyID    uint
	RequestedAt time.Time
}

type automationScriptDeferralStore interface {
	AutomaticDeploymentsAllowed(context.Context, uint, time.Time) (bool, error)
	QueueDeferredScriptAutomation(context.Context, DeferredScriptAutomation) error
}

func (s *SQLStore) QueueDeferredScriptAutomation(ctx context.Context, req DeferredScriptAutomation) error {
	if req.RuleID == "" || req.HostID == 0 || req.FleetID == 0 || req.ScriptID == 0 {
		return fmt.Errorf("communityplus: deferred script automation requires rule, host, Fleet and script ids")
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now().UTC()
	}
	var policyID any
	if req.PolicyID != 0 {
		policyID = req.PolicyID
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO communityplus_automation_script_requests
	(rule_id, host_id, fleet_id, script_id, policy_id, requested_at)
VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
	fleet_id = VALUES(fleet_id),
	script_id = VALUES(script_id),
	policy_id = VALUES(policy_id),
	requested_at = VALUES(requested_at)`,
		req.RuleID, req.HostID, req.FleetID, req.ScriptID, policyID, req.RequestedAt,
	)
	if err != nil {
		return fmt.Errorf("communityplus: defer script automation: %w", err)
	}
	return nil
}

func (s *SQLStore) ListDeferredScriptAutomationsForHost(ctx context.Context, hostID uint) ([]DeferredScriptAutomation, error) {
	if hostID == 0 {
		return nil, fmt.Errorf("communityplus: deferred script host id is required")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT rule_id, host_id, fleet_id, script_id, policy_id, requested_at
FROM communityplus_automation_script_requests
WHERE host_id = ?
ORDER BY requested_at, rule_id`, hostID)
	if err != nil {
		return nil, fmt.Errorf("communityplus: list deferred script automations: %w", err)
	}
	defer rows.Close()

	var result []DeferredScriptAutomation
	for rows.Next() {
		var req DeferredScriptAutomation
		var policyID sql.NullInt64
		if err := rows.Scan(&req.RuleID, &req.HostID, &req.FleetID, &req.ScriptID, &policyID, &req.RequestedAt); err != nil {
			return nil, fmt.Errorf("communityplus: scan deferred script automation: %w", err)
		}
		if policyID.Valid && policyID.Int64 > 0 {
			req.PolicyID = uint(policyID.Int64)
		}
		result = append(result, req)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate deferred script automations: %w", err)
	}
	return result, nil
}

func (s *SQLStore) DeleteDeferredScriptAutomation(ctx context.Context, ruleID string, hostID uint) error {
	if ruleID == "" || hostID == 0 {
		return fmt.Errorf("communityplus: deferred script rule and host ids are required")
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM communityplus_automation_script_requests WHERE rule_id = ? AND host_id = ?`,
		ruleID, hostID,
	); err != nil {
		return fmt.Errorf("communityplus: delete deferred script automation: %w", err)
	}
	return nil
}

// ReleasePendingScriptAutomations promotes deferred policy-script actions into
// Fleet's normal script queue once the host's Fleet maintenance window is open.
func ReleasePendingScriptAutomations(ctx context.Context, host *fleet.Host, ds fleet.Datastore) error {
	if OrbitDelivery == nil || host == nil || host.TeamID == nil || ds == nil {
		return nil
	}
	requests, err := OrbitDelivery.ListDeferredScriptAutomationsForHost(ctx, host.ID)
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

	cfg, err := ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("communityplus: load app config for deferred scripts: %w", err)
	}
	if cfg == nil || cfg.ServerSettings.ScriptsDisabled {
		return nil
	}
	if host.OrbitNodeKey == nil || strings.TrimSpace(*host.OrbitNodeKey) == "" {
		return nil
	}
	if host.ScriptsEnabled != nil && !*host.ScriptsEnabled {
		return nil
	}

	for _, req := range requests {
		if req.FleetID != *host.TeamID {
			return fmt.Errorf("%w: deferred script Fleet does not match host", ErrScopeConflict)
		}
		script, err := ds.Script(ctx, req.ScriptID)
		if err != nil {
			return fmt.Errorf("communityplus: load deferred script: %w", err)
		}
		var scriptFleetID uint
		if script.TeamID != nil {
			scriptFleetID = *script.TeamID
		}
		if scriptFleetID != req.FleetID {
			return fmt.Errorf("%w: deferred script no longer belongs to host Fleet", ErrScopeConflict)
		}

		hostPlatform := fleet.PlatformFromHost(host.Platform)
		extension := strings.ToLower(filepath.Ext(script.Name))
		if (hostPlatform == "windows" && extension == ".sh") ||
			(hostPlatform != "windows" && extension == ".ps1") {
			return fmt.Errorf("communityplus: deferred script %q is incompatible with host platform %q", script.Name, hostPlatform)
		}

		pending, err := ds.IsExecutionPendingForHost(ctx, host.ID, script.ID)
		if err != nil {
			return fmt.Errorf("communityplus: check deferred script pending state: %w", err)
		}
		if pending {
			if err := OrbitDelivery.DeleteDeferredScriptAutomation(ctx, req.RuleID, host.ID); err != nil {
				return err
			}
			continue
		}

		pendingScripts, err := ds.ListPendingHostScriptExecutions(ctx, host.ID, false)
		if err != nil {
			return fmt.Errorf("communityplus: list pending scripts before deferred release: %w", err)
		}
		if len(pendingScripts) >= maxAutomationPendingScripts {
			return nil
		}

		contents, err := ds.GetScriptContents(ctx, script.ID)
		if err != nil {
			return fmt.Errorf("communityplus: load deferred script contents: %w", err)
		}
		if err := fleet.ValidateHostScriptContents(string(contents), true); err != nil {
			return fmt.Errorf("communityplus: validate deferred script contents: %w", err)
		}

		request := &fleet.HostScriptRequestPayload{
			HostID:          host.ID,
			ScriptID:        &script.ID,
			ScriptContents:  string(contents),
			ScriptContentID: script.ScriptContentID,
			TeamID:          req.FleetID,
		}
		if req.PolicyID != 0 {
			policyID := req.PolicyID
			request.PolicyID = &policyID
		}
		if _, err := ds.NewHostScriptExecutionRequest(ctx, request); err != nil {
			return fmt.Errorf("communityplus: release deferred script automation: %w", err)
		}
		if err := OrbitDelivery.DeleteDeferredScriptAutomation(ctx, req.RuleID, host.ID); err != nil {
			return err
		}
	}
	return nil
}
