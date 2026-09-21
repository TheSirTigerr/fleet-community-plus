package communityplus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type roleAccessController struct {
	actor string
	roles []Role
}

func (a roleAccessController) Authorize(_ context.Context, request Request) (string, error) {
	for _, role := range a.roles {
		if (Authorizer{}).Allowed(role, request) {
			return a.actor, nil
		}
	}
	return "", ErrForbidden
}

type memoryFoundationStore struct {
	mu     sync.Mutex
	rules  map[string]AutomationRule
	events []AuditEvent
}

func newMemoryFoundationStore() *memoryFoundationStore {
	return &memoryFoundationStore{rules: make(map[string]AutomationRule)}
}

func (s *memoryFoundationStore) UpsertAutomationRule(_ context.Context, rule AutomationRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[rule.ID] = rule
	return nil
}

func (s *memoryFoundationStore) DeleteAutomationRule(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rules, id)
	return nil
}

func (s *memoryFoundationStore) ListAutomationRules(context.Context) ([]AutomationRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rules := make([]AutomationRule, 0, len(s.rules))
	for _, rule := range s.rules {
		rules = append(rules, rule)
	}
	return rules, nil
}

func (s *memoryFoundationStore) RecordAuditEvent(_ context.Context, event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *memoryFoundationStore) ListAuditEvents(_ context.Context, filter AuditFilter) ([]AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]AuditEvent, 0, len(s.events))
	for i := len(s.events) - 1; i >= 0; i-- {
		event := s.events[i]
		if filter.FleetID != nil && (event.Scope.Kind != ScopeFleet || event.Scope.FleetID != *filter.FleetID) {
			continue
		}
		events = append(events, event)
		if len(events) == filter.Limit {
			break
		}
	}
	return events, nil
}

func newTestHTTPAPI(t *testing.T, access AccessController) (*HTTPAPI, *AutomationEngine, *memoryFoundationStore) {
	t.Helper()
	engine, err := NewAutomationEngine(&recordingExecutor{})
	if err != nil {
		t.Fatalf("new automation engine: %v", err)
	}
	store := newMemoryFoundationStore()
	api, err := NewHTTPAPI(NewRegistry(), engine, store, store, access)
	if err != nil {
		t.Fatalf("new HTTP API: %v", err)
	}
	return api, engine, store
}

func TestHTTPAPIAutomationRuleLifecycle(t *testing.T) {
	role, err := FleetAdminRole(7)
	if err != nil {
		t.Fatal(err)
	}
	api, engine, store := newTestHTTPAPI(t, roleAccessController{actor: "user-42", roles: []Role{role}})
	body := []byte(`{
        "name":"Repair encryption",
        "scope":{"kind":"fleet","fleet_id":7},
        "trigger":"policy_failed",
        "action":"run_script",
        "enabled":true,
        "conditions":{"policy":"disk-encryption"},
        "config":{"script_id":"12"}
    }`)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/communityplus/automation-rules/encryption", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("put rule status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(engine.Rules()) != 1 || len(store.rules) != 1 {
		t.Fatalf("rule was not stored and activated")
	}
	if len(store.events) != 1 || store.events[0].ActorID != "user-42" || store.events[0].Action != "automation_rule.upsert" {
		t.Fatalf("unexpected audit events: %#v", store.events)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/fleet/communityplus/automation-rules", nil)
	recorder = httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"id":"encryption"`)) {
		t.Fatalf("list rules status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/fleet/communityplus/automation-rules/encryption", nil)
	recorder = httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("delete rule status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(engine.Rules()) != 0 || len(store.rules) != 0 || len(store.events) != 2 {
		t.Fatalf("rule deletion was not persisted and audited")
	}
}

func TestHTTPAPIFleetIsolation(t *testing.T) {
	role, err := FleetAdminRole(7)
	if err != nil {
		t.Fatal(err)
	}
	api, engine, _ := newTestHTTPAPI(t, roleAccessController{actor: "fleet-7-admin", roles: []Role{role}})
	if err := engine.UpsertRule(AutomationRule{
		ID: "fleet-7", Name: "Fleet 7", Scope: FleetScope(7),
		Trigger: TriggerPolicyFailed, Action: AutomationNotify, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := engine.UpsertRule(AutomationRule{
		ID: "fleet-8", Name: "Fleet 8", Scope: FleetScope(8),
		Trigger: TriggerPolicyFailed, Action: AutomationNotify, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/latest/fleet/communityplus/automation-rules", nil)
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"id":"fleet-7"`)) || bytes.Contains(recorder.Body.Bytes(), []byte(`"id":"fleet-8"`)) {
		t.Fatalf("cross-fleet rule leaked: %s", recorder.Body.String())
	}

	body := []byte(`{"name":"Fleet 8","scope":{"kind":"fleet","fleet_id":8},"trigger":"policy_failed","action":"notify","enabled":true}`)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/fleet/communityplus/automation-rules/denied", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHTTPAPIAuditScopeAndValidation(t *testing.T) {
	admin := GlobalAdminRole()
	api, _, store := newTestHTTPAPI(t, roleAccessController{actor: "admin", roles: []Role{admin}})
	store.events = []AuditEvent{
		{ID: "one", ActorID: "a", Action: "read", Resource: ResourceAudit, Scope: FleetScope(1)},
		{ID: "two", ActorID: "b", Action: "read", Resource: ResourceAudit, Scope: FleetScope(2)},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/2022-04/fleet/communityplus/audit?fleet_id=2&limit=10", nil)
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || bytes.Contains(recorder.Body.Bytes(), []byte(`"id":"one"`)) || !bytes.Contains(recorder.Body.Bytes(), []byte(`"id":"two"`)) {
		t.Fatalf("unexpected scoped audit response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/fleet/communityplus/audit?limit=1001", nil)
	recorder = httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHTTPAPICapabilitiesRequireGlobalAccess(t *testing.T) {
	role, err := ObserverRole(3)
	if err != nil {
		t.Fatal(err)
	}
	api, _, _ := newTestHTTPAPI(t, roleAccessController{actor: "observer", roles: []Role{role}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/communityplus/capabilities", nil)
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestDecodeJSONRejectsUnknownAndTrailingData(t *testing.T) {
	for _, body := range []string{
		`{"unknown":true}`,
		`{} {}`,
	} {
		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(body))
		recorder := httptest.NewRecorder()
		var target AutomationRule
		if err := decodeJSONBody(recorder, req, &target); err == nil {
			t.Fatalf("expected body %q to fail", body)
		}
	}
}

func TestWriteAPIErrorStatus(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{ErrUnauthenticated, http.StatusUnauthorized},
		{ErrForbidden, http.StatusForbidden},
		{errors.New("invalid value"), http.StatusBadRequest},
		{errors.New("database unavailable"), http.StatusInternalServerError},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		writeAPIError(recorder, test.err)
		if recorder.Code != test.want {
			t.Fatalf("error %q status=%d want=%d", test.err, recorder.Code, test.want)
		}
		var response map[string]string
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
}

func TestHTTPAPICatalogSearchAndFleetDeployment(t *testing.T) {
	admin := GlobalAdminRole()
	engine, err := NewAutomationEngine(&recordingExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	foundation := newMemoryFoundationStore()
	catalog := &memoryCatalogStore{entries: []CatalogEntry{validCatalogEntry()}}
	api, err := NewHTTPAPI(NewRegistry(), engine, foundation, foundation, roleAccessController{actor: "admin", roles: []Role{admin}}, catalog)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/latest/fleet/communityplus/catalog/winget?query=power", nil)
	res := httptest.NewRecorder()
	api.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !bytes.Contains(res.Body.Bytes(), []byte("Microsoft.PowerToys")) {
		t.Fatalf("catalog search failed: status=%d body=%s", res.Code, res.Body.String())
	}

	body := []byte(`{"id":"team-seven-powertoys","catalog_entry_id":"entry-1","scope":{"kind":"fleet","fleet_id":7},"automatic":true,"patch":true}`)
	req = httptest.NewRequest(http.MethodPost, "/api/latest/fleet/communityplus/catalog/deployments", bytes.NewReader(body))
	res = httptest.NewRecorder()
	api.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusCreated || len(catalog.deployments) != 1 || catalog.deployments[0].CreatedBy != "admin" {
		t.Fatalf("catalog deployment failed: status=%d body=%s deployments=%#v", res.Code, res.Body.String(), catalog.deployments)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/latest/fleet/communityplus/catalog/deployments?fleet_id=7", nil)
	res = httptest.NewRecorder()
	api.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !bytes.Contains(res.Body.Bytes(), []byte("team-seven-powertoys")) {
		t.Fatalf("deployment listing failed: status=%d body=%s", res.Code, res.Body.String())
	}
}
