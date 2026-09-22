package communityplus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLStoreRecordsAuditEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("new sqlmock: %v", err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatalf("new SQL store: %v", err)
	}

	occurredAt := time.Date(2026, time.September, 19, 19, 0, 0, 0, time.UTC)
	mock.ExpectExec("INSERT INTO communityplus_audit_events").
		WithArgs(
			"audit-1", occurredAt, "user-1", "script.execute", ResourceScripts,
			"script-7", ScopeFleet, uint(9), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.RecordAuditEvent(context.Background(), AuditEvent{
		ID:         "audit-1",
		OccurredAt: occurredAt,
		ActorID:    "user-1",
		Action:     "script.execute",
		Resource:   ResourceScripts,
		ResourceID: "script-7",
		Scope:      FleetScope(9),
		Metadata:   map[string]string{"source": "policy"},
	})
	if err != nil {
		t.Fatalf("record audit event: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreUpsertsAndListsAutomationRules(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("new sqlmock: %v", err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatalf("new SQL store: %v", err)
	}

	rule := AutomationRule{
		ID:         "encrypt-repair",
		Name:       "Repair disk encryption",
		Scope:      FleetScope(12),
		Trigger:    TriggerPolicyFailed,
		Action:     AutomationRunScript,
		Enabled:    true,
		Conditions: map[string]string{"policy": "disk-encryption"},
		Config:     map[string]string{"script_id": "42"},
	}
	mock.ExpectExec("INSERT INTO communityplus_automation_rules").
		WithArgs(
			rule.ID, rule.Name, ScopeFleet, uint(12), rule.Trigger, rule.Action,
			true, sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT scope_kind, fleet_id FROM communityplus_automation_rules").
		WithArgs(rule.ID).
		WillReturnRows(sqlmock.NewRows([]string{"scope_kind", "fleet_id"}).AddRow(ScopeFleet, 12))
	if err := store.UpsertAutomationRule(context.Background(), rule); err != nil {
		t.Fatalf("upsert automation rule: %v", err)
	}

	columns := []string{
		"id", "name", "scope_kind", "fleet_id", "trigger_name",
		"action_name", "enabled", "conditions", "config",
	}
	mock.ExpectQuery("SELECT id, name, scope_kind, fleet_id").
		WillReturnRows(sqlmock.NewRows(columns).AddRow(
			rule.ID, rule.Name, ScopeFleet, 12, rule.Trigger, rule.Action, true,
			[]byte(`{"policy":"disk-encryption"}`), []byte(`{"script_id":"42"}`),
		))
	rules, err := store.ListAutomationRules(context.Background())
	if err != nil {
		t.Fatalf("list automation rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(rules))
	}
	if got := rules[0]; got.ID != rule.ID || got.Scope != rule.Scope || got.Config["script_id"] != "42" {
		t.Fatalf("unexpected restored rule: %#v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreListsFleetAuditEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("new sqlmock: %v", err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatalf("new SQL store: %v", err)
	}

	columns := []string{
		"id", "occurred_at", "actor_id", "action", "resource", "resource_id",
		"scope_kind", "fleet_id", "metadata",
	}
	occurredAt := time.Date(2026, time.September, 19, 20, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT id, occurred_at, actor_id").
		WithArgs(uint(7), 25).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(
			"audit-7", occurredAt, "user-7", "automation_rule.upsert",
			ResourceAutomations, "rule-7", ScopeFleet, 7, []byte(`{"source":"api"}`),
		))
	fleetID := uint(7)
	events, err := store.ListAuditEvents(context.Background(), AuditFilter{FleetID: &fleetID, Limit: 25})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 || events[0].Scope != FleetScope(7) || events[0].Metadata["source"] != "api" {
		t.Fatalf("unexpected audit events: %#v", events)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

type staticRuleStore struct {
	rules []AutomationRule
	err   error
}

func (s staticRuleStore) ListAutomationRules(context.Context) ([]AutomationRule, error) {
	return s.rules, s.err
}

func TestRestoreAutomationRules(t *testing.T) {
	executor := &recordingExecutor{}
	engine, err := NewAutomationEngine(executor)
	if err != nil {
		t.Fatalf("new automation engine: %v", err)
	}
	rule := AutomationRule{
		ID: "startup-rule", Name: "Startup rule", Scope: GlobalScope(),
		Trigger: TriggerDeviceEnrolled, Action: AutomationNotify, Enabled: true,
	}
	if err := RestoreAutomationRules(context.Background(), staticRuleStore{rules: []AutomationRule{rule}}, engine); err != nil {
		t.Fatalf("restore automation rules: %v", err)
	}
	executed, err := engine.Dispatch(context.Background(), AutomationEvent{
		Trigger: TriggerDeviceEnrolled,
		Scope:   FleetScope(1),
	})
	if err != nil {
		t.Fatalf("dispatch restored rule: %v", err)
	}
	if len(executed) != 1 || executed[0] != rule.ID {
		t.Fatalf("unexpected executed rules: %#v", executed)
	}
}

func TestSQLStoreRejectsAutomationRuleScopeChange(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	rule := AutomationRule{
		ID: "shared-id", Name: "Fleet 12 rule", Scope: FleetScope(12),
		Trigger: TriggerPolicyFailed, Action: AutomationNotify, Enabled: true,
	}
	mock.ExpectExec("name = IF\\(scope_kind = VALUES\\(scope_kind\\) AND fleet_id <=> VALUES\\(fleet_id\\)").
		WithArgs(rule.ID, rule.Name, ScopeFleet, uint(12), rule.Trigger, rule.Action, true, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT scope_kind, fleet_id FROM communityplus_automation_rules").
		WithArgs(rule.ID).
		WillReturnRows(sqlmock.NewRows([]string{"scope_kind", "fleet_id"}).AddRow(ScopeFleet, 13))
	err = store.UpsertAutomationRule(context.Background(), rule)
	if !errors.Is(err, ErrScopeConflict) {
		t.Fatalf("expected ErrScopeConflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreRejectsDeploymentScopeChange(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	deployment := Deployment{
		ID: "shared-deployment", CatalogEntryID: "entry-1", Scope: FleetScope(7),
		Automatic: true, CreatedAt: time.Now().UTC(), CreatedBy: "user-7",
	}
	mock.ExpectExec("catalog_entry_id = IF\\(fleet_id = VALUES\\(fleet_id\\)").
		WithArgs(deployment.ID, deployment.CatalogEntryID, uint(7), false, true, false, deployment.CreatedAt, deployment.CreatedBy).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT fleet_id FROM communityplus_catalog_deployments").
		WithArgs(deployment.ID).
		WillReturnRows(sqlmock.NewRows([]string{"fleet_id"}).AddRow(8))
	err = store.UpsertDeployment(context.Background(), deployment)
	if !errors.Is(err, ErrScopeConflict) {
		t.Fatalf("expected ErrScopeConflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
