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

// DispatchPolicyTransitions feeds real policy membership transitions into the
// Community+ automation engine. If Community+ routes have not been initialized,
// this is a no-op so core osquery ingestion remains independent of the extension.
func DispatchPolicyTransitions(
	ctx context.Context,
	host *fleet.Host,
	newFailing []uint,
	newPassing []uint,
) ([]string, error) {
	engine := runtimeAutomationEngine()
	if engine == nil || host == nil {
		return nil, nil
	}

	scope := automationScopeForHost(host)
	executed := make([]string, 0)
	dispatch := func(trigger Trigger, policyID uint) error {
		rules, err := engine.Dispatch(ctx, AutomationEvent{
			Trigger: trigger,
			Scope:   scope,
			HostID:  host.ID,
			Data: map[string]string{
				"policy_id": strconv.FormatUint(uint64(policyID), 10),
			},
		})
		if err != nil {
			return err
		}
		executed = append(executed, rules...)
		return nil
	}

	for _, policyID := range newFailing {
		if err := dispatch(TriggerPolicyFailed, policyID); err != nil {
			return executed, err
		}
	}
	for _, policyID := range newPassing {
		if err := dispatch(TriggerPolicyPassed, policyID); err != nil {
			return executed, err
		}
	}
	return executed, nil
}
