package communityplus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLStoreListsAuditEventsWithFiltersAndCursor(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("new sqlmock: %v", err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatalf("new SQL store: %v", err)
	}

	from := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	until := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	before := time.Date(2026, 9, 22, 9, 30, 0, 0, time.UTC)
	fleetID := uint(7)
	filter := AuditFilter{
		FleetID: &fleetID, ActorID: "user-7", Action: "automation_rule.upsert",
		Resource: ResourceAutomations, ResourceID: "rule-7", From: &from, Until: &until,
		Before: &AuditCursor{Before: before, BeforeID: "event-z"}, Limit: 25,
	}

	columns := []string{"id", "occurred_at", "actor_id", "action", "resource", "resource_id", "scope_kind", "fleet_id", "metadata"}
	occurredAt := before.Add(-time.Minute)
	mock.ExpectQuery(`WHERE fleet_id = \? AND actor_id = \? AND action = \? AND resource = \? AND resource_id = \? AND occurred_at >= \? AND occurred_at <= \? AND \(occurred_at < \? OR \(occurred_at = \? AND id < \?\)\) ORDER BY occurred_at DESC, id DESC LIMIT \?`).
		WithArgs(uint(7), "user-7", "automation_rule.upsert", ResourceAutomations, "rule-7", from, until, before, before, "event-z", 25).
		WillReturnRows(sqlmock.NewRows(columns).AddRow("event-a", occurredAt, "user-7", "automation_rule.upsert", ResourceAutomations, "rule-7", ScopeFleet, 7, []byte(`{"source":"api"}`)))

	events, err := store.ListAuditEvents(context.Background(), filter)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 || events[0].ID != "event-a" || events[0].Metadata["source"] != "api" {
		t.Fatalf("unexpected events: %#v", events)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

type capturingAuditStore struct {
	filter AuditFilter
	events []AuditEvent
}

func (s *capturingAuditStore) RecordAuditEvent(context.Context, AuditEvent) error { return nil }

func (s *capturingAuditStore) ListAuditEvents(_ context.Context, filter AuditFilter) ([]AuditEvent, error) {
	s.filter = filter
	return append([]AuditEvent(nil), s.events...), nil
}

func TestHTTPAPIAuditFiltersAndNextCursor(t *testing.T) {
	engine, err := NewAutomationEngine(&recordingExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	foundation := newMemoryFoundationStore()
	at := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	audit := &capturingAuditStore{events: []AuditEvent{
		{ID: "event-1", OccurredAt: at, ActorID: "user-42", Action: "automation_rule.upsert", Resource: ResourceAutomations, Scope: FleetScope(7)},
		{ID: "event-2", OccurredAt: at.Add(-time.Second), ActorID: "user-42", Action: "automation_rule.upsert", Resource: ResourceAutomations, Scope: FleetScope(7)},
	}}
	api, err := NewHTTPAPI(NewRegistry(), engine, foundation, audit, roleAccessController{actor: "admin", roles: []Role{GlobalAdminRole()}})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/latest/fleet/communityplus/audit?fleet_id=7&actor_id=user-42&action=automation_rule.upsert&resource=automations&limit=2&before=2026-09-22T10:00:00Z&before_id=event-z", nil)
	res := httptest.NewRecorder()
	api.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("audit status=%d body=%s", res.Code, res.Body.String())
	}
	if audit.filter.FleetID == nil || *audit.filter.FleetID != 7 || audit.filter.ActorID != "user-42" || audit.filter.Action != "automation_rule.upsert" || audit.filter.Resource != ResourceAutomations || audit.filter.Before == nil || audit.filter.Before.BeforeID != "event-z" {
		t.Fatalf("unexpected parsed filter: %#v", audit.filter)
	}
	body := res.Body.String()
	if !containsAll(body, `"next_cursor"`, `"before_id":"event-2"`) {
		t.Fatalf("missing next cursor: %s", body)
	}
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !contains(value, needle) {
			return false
		}
	}
	return true
}

func contains(value, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
