package communityplus

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLStoreDeferredScriptAutomationLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	requestedAt := time.Date(2026, time.October, 7, 0, 30, 0, 0, time.UTC)
	req := DeferredScriptAutomation{
		RuleID: "repair-rule", HostID: 42, FleetID: 7, ScriptID: 9,
		PolicyID: 10, RequestedAt: requestedAt,
	}

	mock.ExpectExec("INSERT INTO communityplus_automation_script_requests").
		WithArgs(req.RuleID, req.HostID, req.FleetID, req.ScriptID, req.PolicyID, requestedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.QueueDeferredScriptAutomation(context.Background(), req); err != nil {
		t.Fatalf("queue deferred script: %v", err)
	}

	mock.ExpectQuery("SELECT rule_id, host_id, fleet_id, script_id, policy_id, requested_at").
		WithArgs(uint(42)).
		WillReturnRows(sqlmock.NewRows([]string{
			"rule_id", "host_id", "fleet_id", "script_id", "policy_id", "requested_at",
		}).AddRow(req.RuleID, req.HostID, req.FleetID, req.ScriptID, req.PolicyID, requestedAt))

	requests, err := store.ListDeferredScriptAutomationsForHost(context.Background(), 42)
	if err != nil {
		t.Fatalf("list deferred scripts: %v", err)
	}
	if len(requests) != 1 || requests[0] != req {
		t.Fatalf("unexpected deferred requests: %#v", requests)
	}

	mock.ExpectExec("DELETE FROM communityplus_automation_script_requests").
		WithArgs(req.RuleID, req.HostID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.DeleteDeferredScriptAutomation(context.Background(), req.RuleID, req.HostID); err != nil {
		t.Fatalf("delete deferred script: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreDeferredScriptAutomationAllowsMissingPolicy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	req := DeferredScriptAutomation{
		RuleID: "manual-trigger", HostID: 42, FleetID: 7, ScriptID: 9,
		RequestedAt: time.Date(2026, time.October, 7, 0, 30, 0, 0, time.UTC),
	}
	mock.ExpectExec("INSERT INTO communityplus_automation_script_requests").
		WithArgs(req.RuleID, req.HostID, req.FleetID, req.ScriptID, nil, req.RequestedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.QueueDeferredScriptAutomation(context.Background(), req); err != nil {
		t.Fatalf("queue deferred script without policy: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
