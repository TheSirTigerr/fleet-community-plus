package communityplus

import (
	"context"
	"strconv"
	"sync"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

var runtimeAutomationState struct {
	sync.RWMutex
	engine *AutomationEngine
}

func setRuntimeAutomationEngine(engine *AutomationEngine) {
	runtimeAutomationState.Lock()
	runtimeAutomationState.engine = engine
	runtimeAutomationState.Unlock()
}

func runtimeAutomationEngine() *AutomationEngine {
	runtimeAutomationState.RLock()
	engine := runtimeAutomationState.engine
	runtimeAutomationState.RUnlock()
	return engine
}

func automationScopeForHost(host *fleet.Host) Scope {
	if host != nil && host.TeamID != nil && *host.TeamID != 0 {
		return FleetScope(*host.TeamID)
	}
	return GlobalScope()
}

// DispatchPolicyResults feeds real policy membership results into the Community+
// automation engine. Newly failing policies dispatch all matching rules once.
// Policies that remain failed dispatch only rules explicitly marked continuous.
// If Community+ routes have not been initialized, this is a no-op so core
// osquery ingestion remains independent of the extension.
func DispatchPolicyResults(
	ctx context.Context,
	host *fleet.Host,
	failing []uint,
	newFailing []uint,
	newPassing []uint,
) ([]string, error) {
	engine := runtimeAutomationEngine()
	if engine == nil || host == nil {
		return nil, nil
	}

	scope := automationScopeForHost(host)
	executed := make([]string, 0)
	dispatch := func(trigger Trigger, policyID uint, transition string, continuousOnly bool) error {
		rules, err := engine.Dispatch(ctx, AutomationEvent{
			Trigger:        trigger,
			Scope:          scope,
			HostID:         host.ID,
			ContinuousOnly: continuousOnly,
			Data: map[string]string{
				"policy_id":  strconv.FormatUint(uint64(policyID), 10),
				"transition": transition,
			},
		})
		if err != nil {
			return err
		}
		executed = append(executed, rules...)
		return nil
	}

	newFailingSet := make(map[uint]struct{}, len(newFailing))
	for _, policyID := range newFailing {
		newFailingSet[policyID] = struct{}{}
		if err := dispatch(TriggerPolicyFailed, policyID, "new_failed", false); err != nil {
			return executed, err
		}
	}
	for _, policyID := range failing {
		if _, newlyFailed := newFailingSet[policyID]; newlyFailed {
			continue
		}
		if err := dispatch(TriggerPolicyFailed, policyID, "still_failed", true); err != nil {
			return executed, err
		}
	}
	for _, policyID := range newPassing {
		if err := dispatch(TriggerPolicyPassed, policyID, "passed", false); err != nil {
			return executed, err
		}
	}
	return executed, nil
}

// DispatchPolicyTransitions preserves the transition-only integration surface.
func DispatchPolicyTransitions(
	ctx context.Context,
	host *fleet.Host,
	newFailing []uint,
	newPassing []uint,
) ([]string, error) {
	return DispatchPolicyResults(ctx, host, newFailing, newFailing, newPassing)
}
