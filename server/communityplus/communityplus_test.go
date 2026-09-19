package communityplus

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRegistry(t *testing.T) {
	registry := NewRegistry()
	if status, ok := registry.Status(FeatureRBAC); !ok || status != StatusPlanned {
		t.Fatalf("expected RBAC planned, got status=%q ok=%v", status, ok)
	}
	if registry.Enabled(FeatureRBAC) {
		t.Fatal("planned feature must not be enabled")
	}
	if err := registry.SetStatus(FeatureRBAC, StatusExperimental); err != nil {
		t.Fatalf("set experimental: %v", err)
	}
	if !registry.Enabled(FeatureRBAC) {
		t.Fatal("experimental feature should be enabled")
	}
	if err := registry.SetStatus(Feature("not-real"), StatusAvailable); err == nil {
		t.Fatal("expected unknown feature to be rejected")
	}
	if err := registry.SetStatus(FeatureRBAC, FeatureStatus("broken")); err == nil {
		t.Fatal("expected invalid feature status to be rejected")
	}
}

func TestScopeContains(t *testing.T) {
	global := GlobalScope()
	fleetOne := FleetScope(1)
	fleetTwo := FleetScope(2)

	if !global.Contains(fleetOne) || !global.Contains(global) {
		t.Fatal("global scope should contain global and fleet targets")
	}
	if !fleetOne.Contains(fleetOne) {
		t.Fatal("fleet scope should contain itself")
	}
	if fleetOne.Contains(fleetTwo) || fleetOne.Contains(global) {
		t.Fatal("fleet scope must not cross fleet or elevate to global")
	}
	if FleetScope(0).Contains(fleetOne) {
		t.Fatal("invalid zero fleet scope must never contain a target")
	}
}

func TestAuthorizerEnforcesFleetIsolation(t *testing.T) {
	role, err := FleetAdminRole(10)
	if err != nil {
		t.Fatalf("fleet admin role: %v", err)
	}
	authorizer := Authorizer{}

	if !authorizer.Allowed(role, Request{Resource: ResourceScripts, Action: ActionExecute, Scope: FleetScope(10)}) {
		t.Fatal("fleet admin should execute scripts in its fleet")
	}
	if authorizer.Allowed(role, Request{Resource: ResourceScripts, Action: ActionExecute, Scope: FleetScope(11)}) {
		t.Fatal("fleet admin must not execute scripts in another fleet")
	}
	if authorizer.Allowed(role, Request{Resource: ResourceUsers, Action: ActionAdmin, Scope: GlobalScope()}) {
		t.Fatal("fleet admin must not administer global users")
	}
}

func TestObserverIsReadOnly(t *testing.T) {
	role, err := ObserverRole(7)
	if err != nil {
		t.Fatalf("observer role: %v", err)
	}
	authorizer := Authorizer{}
	if !authorizer.Allowed(role, Request{Resource: ResourceHosts, Action: ActionRead, Scope: FleetScope(7)}) {
		t.Fatal("observer should read hosts")
	}
	if authorizer.Allowed(role, Request{Resource: ResourceHosts, Action: ActionWrite, Scope: FleetScope(7)}) {
		t.Fatal("observer must not write hosts")
	}
}

func TestAuditRecorder(t *testing.T) {
	sink := &MemoryAuditSink{}
	recorder, err := NewAuditRecorder(sink)
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	fixed := time.Date(2026, time.September, 19, 18, 45, 0, 0, time.UTC)
	recorder.now = func() time.Time { return fixed }

	event := AuditEvent{
		ActorID:  "user-42",
		Action:   "script.execute",
		Resource: ResourceScripts,
		Scope:    FleetScope(3),
		Metadata: map[string]string{"script": "repair"},
	}
	if err := recorder.Record(context.Background(), event); err != nil {
		t.Fatalf("record audit: %v", err)
	}
	stored := sink.Events()
	if len(stored) != 1 {
		t.Fatalf("expected one event, got %d", len(stored))
	}
	if stored[0].ID == "" || !stored[0].OccurredAt.Equal(fixed) {
		t.Fatalf("event was not stamped correctly: %#v", stored[0])
	}

	event.Metadata["script"] = "mutated"
	if got := sink.Events()[0].Metadata["script"]; got != "repair" {
		t.Fatalf("audit metadata was not copied, got %q", got)
	}
}

type recordingExecutor struct {
	rules []string
	err   error
}

func (e *recordingExecutor) ExecuteAutomation(_ context.Context, rule AutomationRule, _ AutomationEvent) error {
	e.rules = append(e.rules, rule.ID)
	return e.err
}

func TestAutomationEngineDispatchesMatchingScopedRules(t *testing.T) {
	executor := &recordingExecutor{}
	engine, err := NewAutomationEngine(executor)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	rules := []AutomationRule{
		{ID: "global", Name: "global notify", Scope: GlobalScope(), Trigger: TriggerPolicyFailed, Action: AutomationNotify, Enabled: true},
		{ID: "fleet-1", Name: "repair fleet 1", Scope: FleetScope(1), Trigger: TriggerPolicyFailed, Action: AutomationRunScript, Enabled: true, Conditions: map[string]string{"policy": "disk-encryption"}},
		{ID: "fleet-2", Name: "repair fleet 2", Scope: FleetScope(2), Trigger: TriggerPolicyFailed, Action: AutomationRunScript, Enabled: true},
		{ID: "disabled", Name: "disabled", Scope: FleetScope(1), Trigger: TriggerPolicyFailed, Action: AutomationNotify, Enabled: false},
	}
	for _, rule := range rules {
		if err := engine.UpsertRule(rule); err != nil {
			t.Fatalf("upsert %s: %v", rule.ID, err)
		}
	}

	executed, err := engine.Dispatch(context.Background(), AutomationEvent{
		Trigger: TriggerPolicyFailed,
		Scope:   FleetScope(1),
		HostID:  99,
		Data:    map[string]string{"policy": "disk-encryption"},
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(executed) != 2 || executed[0] != "fleet-1" || executed[1] != "global" {
		t.Fatalf("unexpected executed rules: %#v", executed)
	}
	if len(executor.rules) != 2 {
		t.Fatalf("expected two executor calls, got %d", len(executor.rules))
	}
}

func TestAutomationEngineStopsOnExecutorError(t *testing.T) {
	executor := &recordingExecutor{err: errors.New("boom")}
	engine, err := NewAutomationEngine(executor)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if err := engine.UpsertRule(AutomationRule{
		ID: "rule", Name: "rule", Scope: GlobalScope(), Trigger: TriggerPatchDue, Action: AutomationInstallSoftware, Enabled: true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := engine.Dispatch(context.Background(), AutomationEvent{Trigger: TriggerPatchDue, Scope: FleetScope(1)}); err == nil {
		t.Fatal("expected executor error")
	}
}
