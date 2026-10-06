package communityplus

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type recordingAutomationExecutor struct {
	rules  []AutomationRule
	events []AutomationEvent
}

func (e *recordingAutomationExecutor) ExecuteAutomation(_ context.Context, rule AutomationRule, event AutomationEvent) error {
	e.rules = append(e.rules, rule)
	e.events = append(e.events, event)
	return nil
}

func TestDispatchPolicyTransitions(t *testing.T) {
	executor := &recordingAutomationExecutor{}
	engine, err := NewAutomationEngine(executor)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.UpsertRule(AutomationRule{
		ID: "install-on-failure", Name: "Install on failure", Scope: FleetScope(7),
		Trigger: TriggerPolicyFailed, Action: AutomationInstallSoftware, Enabled: true,
		Conditions: map[string]string{"policy_id": "10"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := engine.UpsertRule(AutomationRule{
		ID: "notify-on-pass", Name: "Notify on pass", Scope: FleetScope(7),
		Trigger: TriggerPolicyPassed, Action: AutomationNotify, Enabled: true,
		Conditions: map[string]string{"policy_id": "11"},
	}); err != nil {
		t.Fatal(err)
	}

	setRuntimeAutomationEngine(engine)
	t.Cleanup(func() { setRuntimeAutomationEngine(nil) })

	teamID := uint(7)
	host := &fleet.Host{ID: 42, TeamID: &teamID}
	executed, err := DispatchPolicyTransitions(context.Background(), host, []uint{10, 12}, []uint{11})
	if err != nil {
		t.Fatalf("dispatch policy transitions: %v", err)
	}
	if len(executed) != 2 {
		t.Fatalf("executed rules = %#v, want two matches", executed)
	}
	if len(executor.events) != 2 {
		t.Fatalf("events = %#v, want two matching events", executor.events)
	}
	if executor.events[0].Trigger != TriggerPolicyFailed || executor.events[0].Data["policy_id"] != "10" {
		t.Fatalf("unexpected failure event: %#v", executor.events[0])
	}
	if executor.events[1].Trigger != TriggerPolicyPassed || executor.events[1].Data["policy_id"] != "11" {
		t.Fatalf("unexpected passing event: %#v", executor.events[1])
	}
	for _, event := range executor.events {
		if event.Scope != FleetScope(7) || event.HostID != 42 {
			t.Fatalf("unexpected event scope/host: %#v", event)
		}
	}
}

func TestDispatchPolicyTransitionsWithoutRuntimeEngineIsNoOp(t *testing.T) {
	setRuntimeAutomationEngine(nil)
	host := &fleet.Host{ID: 42}
	executed, err := DispatchPolicyTransitions(context.Background(), host, []uint{1}, nil)
	if err != nil {
		t.Fatalf("dispatch without engine: %v", err)
	}
	if len(executed) != 0 {
		t.Fatalf("unexpected executions: %#v", executed)
	}
}
