package communityplus

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// SQLExecutor is the subset of database/sql used by SQLStore. Both *sql.DB
// and *sql.Tx implement it, which lets callers make persistence transactional.
type SQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// SQLStore persists Community+ foundation data in Fleet's MySQL database.
type SQLStore struct {
	db SQLExecutor
}

// AutomationStore is the persistence contract used by the Community+ API.
type AutomationStore interface {
	UpsertAutomationRule(context.Context, AutomationRule) error
	DeleteAutomationRule(context.Context, string) error
	ListAutomationRules(context.Context) ([]AutomationRule, error)
}

// AuditStore is the read/write persistence contract used by the Community+ API.
type AuditStore interface {
	AuditSink
	ListAuditEvents(context.Context, AuditFilter) ([]AuditEvent, error)
}

// AuditFilter limits audit results. FleetID nil means all scopes.
type AuditFilter struct {
	FleetID *uint
	Limit   int
}

func NewSQLStore(db SQLExecutor) (*SQLStore, error) {
	if db == nil {
		return nil, fmt.Errorf("communityplus: SQL executor is required")
	}
	return &SQLStore{db: db}, nil
}

// RecordAuditEvent implements AuditSink.
func (s *SQLStore) RecordAuditEvent(ctx context.Context, event AuditEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("communityplus: encode audit metadata: %w", err)
	}
	var fleetID any
	if event.Scope.Kind == ScopeFleet {
		fleetID = event.Scope.FleetID
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO communityplus_audit_events
    (id, occurred_at, actor_id, action, resource, resource_id, scope_kind, fleet_id, metadata)
VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?)`,
		event.ID, event.OccurredAt, event.ActorID, event.Action, event.Resource,
		event.ResourceID, event.Scope.Kind, fleetID, metadata,
	)
	if err != nil {
		return fmt.Errorf("communityplus: record audit event: %w", err)
	}
	return nil
}

// ListAuditEvents returns newest events first. Limits are bounded to keep the
// administrative endpoint from accidentally issuing an unbounded query.
func (s *SQLStore) ListAuditEvents(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	query := `
SELECT id, occurred_at, actor_id, action, resource, COALESCE(resource_id, ''),
       scope_kind, fleet_id, metadata
FROM communityplus_audit_events`
	args := make([]any, 0, 2)
	if filter.FleetID != nil {
		if *filter.FleetID == 0 {
			return nil, fmt.Errorf("communityplus: audit fleet_id must be greater than zero")
		}
		query += ` WHERE fleet_id = ?`
		args = append(args, *filter.FleetID)
	}
	query += ` ORDER BY occurred_at DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("communityplus: list audit events: %w", err)
	}
	defer rows.Close()

	events := make([]AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		var fleetID sql.NullInt64
		var metadata []byte
		if err := rows.Scan(
			&event.ID, &event.OccurredAt, &event.ActorID, &event.Action, &event.Resource,
			&event.ResourceID, &event.Scope.Kind, &fleetID, &metadata,
		); err != nil {
			return nil, fmt.Errorf("communityplus: scan audit event: %w", err)
		}
		if fleetID.Valid {
			if fleetID.Int64 <= 0 {
				return nil, fmt.Errorf("communityplus: invalid stored audit fleet_id %d", fleetID.Int64)
			}
			event.Scope.FleetID = uint(fleetID.Int64)
		}
		if len(metadata) > 0 && string(metadata) != "null" {
			if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
				return nil, fmt.Errorf("communityplus: decode audit metadata for %q: %w", event.ID, err)
			}
		}
		if err := event.Validate(); err != nil {
			return nil, fmt.Errorf("communityplus: validate stored audit event %q: %w", event.ID, err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate audit events: %w", err)
	}
	return events, nil
}

// UpsertAutomationRule creates or replaces a durable automation rule.
func (s *SQLStore) UpsertAutomationRule(ctx context.Context, rule AutomationRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	conditions, err := json.Marshal(rule.Conditions)
	if err != nil {
		return fmt.Errorf("communityplus: encode automation conditions: %w", err)
	}
	config, err := json.Marshal(rule.Config)
	if err != nil {
		return fmt.Errorf("communityplus: encode automation config: %w", err)
	}
	var fleetID any
	if rule.Scope.Kind == ScopeFleet {
		fleetID = rule.Scope.FleetID
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO communityplus_automation_rules
    (id, name, scope_kind, fleet_id, trigger_name, action_name, enabled, conditions, config)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    name = VALUES(name), scope_kind = VALUES(scope_kind), fleet_id = VALUES(fleet_id),
    trigger_name = VALUES(trigger_name), action_name = VALUES(action_name),
    enabled = VALUES(enabled), conditions = VALUES(conditions), config = VALUES(config)`,
		rule.ID, rule.Name, rule.Scope.Kind, fleetID, rule.Trigger, rule.Action,
		rule.Enabled, conditions, config,
	)
	if err != nil {
		return fmt.Errorf("communityplus: upsert automation rule: %w", err)
	}
	return nil
}

func (s *SQLStore) DeleteAutomationRule(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("communityplus: automation rule id is required")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM communityplus_automation_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("communityplus: delete automation rule: %w", err)
	}
	return nil
}

// ListAutomationRules returns all rules in stable ID order for deterministic startup.
func (s *SQLStore) ListAutomationRules(ctx context.Context) ([]AutomationRule, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, scope_kind, fleet_id, trigger_name, action_name, enabled, conditions, config
FROM communityplus_automation_rules
ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("communityplus: list automation rules: %w", err)
	}
	defer rows.Close()

	var rules []AutomationRule
	for rows.Next() {
		var rule AutomationRule
		var fleetID sql.NullInt64
		var conditions, config []byte
		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Scope.Kind, &fleetID, &rule.Trigger,
			&rule.Action, &rule.Enabled, &conditions, &config,
		); err != nil {
			return nil, fmt.Errorf("communityplus: scan automation rule: %w", err)
		}
		if fleetID.Valid {
			if fleetID.Int64 <= 0 {
				return nil, fmt.Errorf("communityplus: invalid stored fleet_id %d", fleetID.Int64)
			}
			rule.Scope.FleetID = uint(fleetID.Int64)
		}
		if err := json.Unmarshal(conditions, &rule.Conditions); err != nil {
			return nil, fmt.Errorf("communityplus: decode automation conditions for %q: %w", rule.ID, err)
		}
		if err := json.Unmarshal(config, &rule.Config); err != nil {
			return nil, fmt.Errorf("communityplus: decode automation config for %q: %w", rule.ID, err)
		}
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("communityplus: validate stored automation rule %q: %w", rule.ID, err)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate automation rules: %w", err)
	}
	return rules, nil
}

// RestoreAutomationRules loads durable rules into an engine during startup.
func RestoreAutomationRules(ctx context.Context, store interface {
	ListAutomationRules(context.Context) ([]AutomationRule, error)
}, engine *AutomationEngine) error {
	if store == nil || engine == nil {
		return fmt.Errorf("communityplus: automation store and engine are required")
	}
	rules, err := store.ListAutomationRules(ctx)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := engine.UpsertRule(rule); err != nil {
			return fmt.Errorf("communityplus: restore automation rule %q: %w", rule.ID, err)
		}
	}
	return nil
}

// UpsertCatalogEntry persists one reviewed, immutable package version.
func (s *SQLStore) UpsertCatalogEntry(ctx context.Context, entry CatalogEntry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO communityplus_catalog_entries
  (id, provider, package_identifier, name, version, installer_type, installer_url, installer_sha256, product_code, source_url, source_sha256, imported_at, imported_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  name = VALUES(name), installer_type = VALUES(installer_type), installer_url = VALUES(installer_url), installer_sha256 = VALUES(installer_sha256), product_code = VALUES(product_code), source_url = VALUES(source_url), source_sha256 = VALUES(source_sha256), imported_at = VALUES(imported_at), imported_by = VALUES(imported_by)`,
		entry.ID, entry.Provider, entry.PackageIdentifier, entry.Name, entry.Version, entry.InstallerType, entry.InstallerURL, entry.InstallerSHA256, entry.ProductCode, entry.SourceURL, entry.SourceSHA256, entry.ImportedAt, entry.ImportedBy)
	if err != nil {
		return fmt.Errorf("communityplus: upsert catalog entry: %w", err)
	}
	return nil
}

func (s *SQLStore) SearchCatalogEntries(ctx context.Context, provider CatalogProvider, query string, limit int) ([]CatalogEntry, error) {
	needle := "%" + query + "%"
	rows, err := s.db.QueryContext(ctx, `
SELECT id, provider, package_identifier, name, version, installer_type, installer_url, installer_sha256, COALESCE(product_code, ''), source_url, source_sha256, imported_at, imported_by
FROM communityplus_catalog_entries
WHERE provider = ? AND (name LIKE ? OR package_identifier LIKE ?)
ORDER BY name, package_identifier LIMIT ?`, provider, needle, needle, limit)
	if err != nil {
		return nil, fmt.Errorf("communityplus: search catalog entries: %w", err)
	}
	defer rows.Close()
	entries := []CatalogEntry{}
	for rows.Next() {
		var e CatalogEntry
		if err := rows.Scan(&e.ID, &e.Provider, &e.PackageIdentifier, &e.Name, &e.Version, &e.InstallerType, &e.InstallerURL, &e.InstallerSHA256, &e.ProductCode, &e.SourceURL, &e.SourceSHA256, &e.ImportedAt, &e.ImportedBy); err != nil {
			return nil, fmt.Errorf("communityplus: scan catalog entry: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate catalog entries: %w", err)
	}
	return entries, nil
}

func (s *SQLStore) GetCatalogEntry(ctx context.Context, id string) (CatalogEntry, error) {
	var e CatalogEntry
	err := s.db.QueryRowContext(ctx, `SELECT id, provider, package_identifier, name, version, installer_type, installer_url, installer_sha256, COALESCE(product_code, ''), source_url, source_sha256, imported_at, imported_by FROM communityplus_catalog_entries WHERE id = ?`, id).Scan(&e.ID, &e.Provider, &e.PackageIdentifier, &e.Name, &e.Version, &e.InstallerType, &e.InstallerURL, &e.InstallerSHA256, &e.ProductCode, &e.SourceURL, &e.SourceSHA256, &e.ImportedAt, &e.ImportedBy)
	if err != nil {
		return CatalogEntry{}, fmt.Errorf("communityplus: get catalog entry: %w", err)
	}
	return e, nil
}

func (s *SQLStore) UpsertDeployment(ctx context.Context, deployment Deployment) error {
	if err := deployment.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO communityplus_catalog_deployments (id, catalog_entry_id, fleet_id, self_service, automatic_install, patch, created_at, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE catalog_entry_id = VALUES(catalog_entry_id), fleet_id = VALUES(fleet_id), self_service = VALUES(self_service), automatic_install = VALUES(automatic_install), patch = VALUES(patch), created_at = VALUES(created_at), created_by = VALUES(created_by)`, deployment.ID, deployment.CatalogEntryID, deployment.Scope.FleetID, deployment.SelfService, deployment.Automatic, deployment.Patch, deployment.CreatedAt, deployment.CreatedBy)
	if err != nil {
		return fmt.Errorf("communityplus: upsert catalog deployment: %w", err)
	}
	return nil
}

func (s *SQLStore) ListDeployments(ctx context.Context, scope Scope) ([]Deployment, error) {
	if err := scope.Validate(); err != nil || scope.Kind != ScopeFleet {
		return nil, fmt.Errorf("communityplus: a Fleet scope is required")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, catalog_entry_id, self_service, automatic_install, patch, created_at, created_by FROM communityplus_catalog_deployments WHERE fleet_id = ? ORDER BY created_at DESC, id DESC`, scope.FleetID)
	if err != nil {
		return nil, fmt.Errorf("communityplus: list catalog deployments: %w", err)
	}
	defer rows.Close()
	result := []Deployment{}
	for rows.Next() {
		var d Deployment
		d.Scope = scope
		if err := rows.Scan(&d.ID, &d.CatalogEntryID, &d.SelfService, &d.Automatic, &d.Patch, &d.CreatedAt, &d.CreatedBy); err != nil {
			return nil, fmt.Errorf("communityplus: scan catalog deployment: %w", err)
		}
		result = append(result, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate catalog deployments: %w", err)
	}
	return result, nil
}

func (s *SQLStore) GetDeployment(ctx context.Context, id string) (Deployment, error) {
	var d Deployment; var fleetID uint
	err := s.db.QueryRowContext(ctx, `SELECT id, catalog_entry_id, fleet_id, self_service, automatic_install, patch, created_at, created_by FROM communityplus_catalog_deployments WHERE id = ?`, id).Scan(&d.ID, &d.CatalogEntryID, &fleetID, &d.SelfService, &d.Automatic, &d.Patch, &d.CreatedAt, &d.CreatedBy)
	if err != nil { return Deployment{}, fmt.Errorf("communityplus: get deployment: %w", err) }
	d.Scope = Scope{Kind: ScopeFleet, FleetID: fleetID}; return d, nil
}
func (s *SQLStore) PendingDeploymentIDs(ctx context.Context, hostID, fleetID uint) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id FROM communityplus_catalog_deployments d LEFT JOIN communityplus_deployment_results r ON r.deployment_id = d.id AND r.host_id = ? WHERE d.fleet_id = ? AND d.automatic_install = 1 AND (r.deployment_id IS NULL OR (r.exit_code <> 0 AND r.attempt_count < 3 AND r.updated_at <= DATE_SUB(NOW(6), INTERVAL 5 MINUTE))) ORDER BY d.created_at, d.id`, hostID, fleetID)
	if err != nil { return nil, fmt.Errorf("communityplus: list pending deployments: %w", err) }; defer rows.Close(); var ids []string
	for rows.Next() { var id string; if err := rows.Scan(&id); err != nil { return nil, err }; ids = append(ids, id) }; return ids, rows.Err()
}
func (s *SQLStore) RecordDeploymentResult(ctx context.Context, hostID uint, result fleet.CommunityPlusDeploymentResult) error {
	if result.DeploymentID == "" { return fmt.Errorf("communityplus: deployment id is required") }
	_, err := s.db.ExecContext(ctx, `INSERT INTO communityplus_deployment_results (deployment_id, host_id, exit_code, output, attempt_count, updated_at) VALUES (?, ?, ?, ?, ?, NOW(6)) ON DUPLICATE KEY UPDATE exit_code = VALUES(exit_code), output = VALUES(output), attempt_count = IF(VALUES(exit_code) = 0, 0, attempt_count + 1), updated_at = VALUES(updated_at)`, result.DeploymentID, hostID, result.ExitCode, result.Output, func() int { if result.ExitCode != 0 { return 1 }; return 0 }()); return err
}

func (s *SQLStore) ListDeploymentResults(ctx context.Context, deploymentID string) ([]DeploymentResult, error) { rows, err := s.db.QueryContext(ctx, `SELECT r.deployment_id, r.host_id, h.hostname, r.exit_code, r.output, r.updated_at FROM communityplus_deployment_results r JOIN hosts h ON h.id = r.host_id WHERE r.deployment_id = ? ORDER BY r.updated_at DESC, r.host_id`, deploymentID); if err != nil { return nil, fmt.Errorf("communityplus: list deployment results: %w", err) }; defer rows.Close(); var results []DeploymentResult; for rows.Next() { var result DeploymentResult; if err := rows.Scan(&result.DeploymentID, &result.HostID, &result.Hostname, &result.ExitCode, &result.Output, &result.UpdatedAt); err != nil { return nil, fmt.Errorf("communityplus: scan deployment result: %w", err) }; results = append(results, result) }; return results, rows.Err() }
