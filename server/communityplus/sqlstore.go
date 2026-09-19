package communityplus

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// SQLExecutor is the subset of database/sql used by SQLStore. Both *sql.DB
// and *sql.Tx implement it, which lets callers make persistence transactional.
type SQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// SQLStore persists Community+ foundation data in Fleet's MySQL database.
type SQLStore struct {
	db SQLExecutor
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
