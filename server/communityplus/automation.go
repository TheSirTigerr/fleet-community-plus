package communityplus

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Trigger identifies an event that may start an automation rule.
type Trigger string

const (
	TriggerPolicyFailed          Trigger = "policy_failed"
	TriggerPolicyPassed          Trigger = "policy_passed"
	TriggerVulnerabilityDetected Trigger = "vulnerability_detected"
	TriggerDeviceEnrolled        Trigger = "device_enrolled"
	TriggerPatchDue              Trigger = "patch_due"
	TriggerSoftwareMissing       Trigger = "software_missing"
)

// AutomationAction identifies an operation performed by a matching rule.
type AutomationAction string

const (
	AutomationRunScript       AutomationAction = "run_script"
	AutomationInstallSoftware AutomationAction = "install_software"
	AutomationLockDevice      AutomationAction = "lock_device"
	AutomationNotify          AutomationAction = "notify"
	AutomationAssignFleet     AutomationAction = "assign_fleet"
)

// AutomationRule is a clean-room orchestration primitive shared by policy
// remediation, software deployment and patch management.
type AutomationRule struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Scope      Scope             `json:"scope"`
	Trigger    Trigger           `json:"trigger"`
	Action     AutomationAction  `json:"action"`
	Enabled    bool              `json:"enabled"`
	Conditions map[string]string `json:"conditions,omitempty"`
	Config     map[string]string `json:"config,omitempty"`
}

func (r AutomationRule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("communityplus: automation rule id is required")
	}
	if r.Name == "" {
		return fmt.Errorf("communityplus: automation rule name is required")
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	switch r.Trigger {
	case TriggerPolicyFailed, TriggerPolicyPassed, TriggerVulnerabilityDetected, TriggerDeviceEnrolled, TriggerPatchDue, TriggerSoftwareMissing:
	default:
		return fmt.Errorf("communityplus: invalid automation trigger %q", r.Trigger)
	}
	switch r.Action {
	case AutomationRunScript, AutomationInstallSoftware, AutomationLockDevice, AutomationNotify, AutomationAssignFleet:
	default:
		return fmt.Errorf("communityplus: invalid automation action %q", r.Action)
	}
	return nil
}

// AutomationEvent is emitted by a Fleet adapter into the automation engine.
type AutomationEvent struct {
	Trigger Trigger           `json:"trigger"`
	Scope   Scope             `json:"scope"`
	HostID  uint              `json:"host_id,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
}

func (e AutomationEvent) Validate() error {
	if err := e.Scope.Validate(); err != nil {
		return err
	}
	switch e.Trigger {
	case TriggerPolicyFailed, TriggerPolicyPassed, TriggerVulnerabilityDetected, TriggerDeviceEnrolled, TriggerPatchDue, TriggerSoftwareMissing:
		return nil
	default:
		return fmt.Errorf("communityplus: invalid automation event trigger %q", e.Trigger)
	}
}

// AutomationExecutor performs a rule action after authorization/scoping has
// been resolved by the engine.
type AutomationExecutor interface {
	ExecuteAutomation(context.Context, AutomationRule, AutomationEvent) error
}

// AutomationEngine stores validated rules and dispatches matching events.
type AutomationEngine struct {
	mu       sync.RWMutex
	rules    map[string]AutomationRule
	executor AutomationExecutor
}

func NewAutomationEngine(executor AutomationExecutor) (*AutomationEngine, error) {
	if executor == nil {
		return nil, fmt.Errorf("communityplus: automation executor is required")
	}
	return &AutomationEngine{rules: make(map[string]AutomationRule), executor: executor}, nil
}

func (e *AutomationEngine) UpsertRule(rule AutomationRule) error {
	if e == nil {
		return fmt.Errorf("communityplus: automation engine is not configured")
	}
	if err := rule.Validate(); err != nil {
		return err
	}
	rule.Conditions = cloneStringMap(rule.Conditions)
	rule.Config = cloneStringMap(rule.Config)

	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules[rule.ID] = rule
	return nil
}

func (e *AutomationEngine) DeleteRule(id string) bool {
	if e == nil || id == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.rules[id]; !ok {
		return false
	}
	delete(e.rules, id)
	return true
}

func (e *AutomationEngine) Rules() []AutomationRule {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]AutomationRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rule.Conditions = cloneStringMap(rule.Conditions)
		rule.Config = cloneStringMap(rule.Config)
		result = append(result, rule)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// Dispatch executes all enabled rules whose trigger, scope and conditions match.
// A fleet-scoped event can be handled by global rules or rules for that same
// Fleet; a Fleet rule can never receive another Fleet's event.
func (e *AutomationEngine) Dispatch(ctx context.Context, event AutomationEvent) ([]string, error) {
	if e == nil || e.executor == nil {
		return nil, fmt.Errorf("communityplus: automation engine is not configured")
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}

	e.mu.RLock()
	candidates := make([]AutomationRule, 0, len(e.rules))
	for _, rule := range e.rules {
		if !rule.Enabled || rule.Trigger != event.Trigger || !rule.Scope.Contains(event.Scope) || !conditionsMatch(rule.Conditions, event.Data) {
			continue
		}
		candidates = append(candidates, rule)
	}
	e.mu.RUnlock()

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	executed := make([]string, 0, len(candidates))
	for _, rule := range candidates {
		if err := e.executor.ExecuteAutomation(ctx, rule, event); err != nil {
			return executed, fmt.Errorf("communityplus: execute automation %q: %w", rule.ID, err)
		}
		executed = append(executed, rule.ID)
	}
	return executed, nil
}

func conditionsMatch(conditions, data map[string]string) bool {
	for key, expected := range conditions {
		if actual, ok := data[key]; !ok || actual != expected {
			return false
		}
	}
	return true
}
