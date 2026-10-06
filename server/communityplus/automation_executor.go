package communityplus

import (
	"context"
	"fmt"
	"strings"
)

type automationDeploymentStore interface {
	GetDeployment(context.Context, string) (Deployment, error)
	QueueAutomationDeployment(context.Context, string, uint) error
}

type productionAutomationExecutor struct {
	deployments automationDeploymentStore
}

func newProductionAutomationExecutor(store automationDeploymentStore) (*productionAutomationExecutor, error) {
	if store == nil {
		return nil, fmt.Errorf("communityplus: automation deployment store is required")
	}
	return &productionAutomationExecutor{deployments: store}, nil
}

func (e *productionAutomationExecutor) ExecuteAutomation(ctx context.Context, rule AutomationRule, event AutomationEvent) error {
	switch rule.Action {
	case AutomationInstallSoftware:
		return e.installSoftware(ctx, rule, event)
	default:
		return fmt.Errorf("automation action %q is not implemented by the production executor", rule.Action)
	}
}

func (e *productionAutomationExecutor) installSoftware(ctx context.Context, rule AutomationRule, event AutomationEvent) error {
	if event.HostID == 0 {
		return fmt.Errorf("install_software automation requires host_id")
	}
	deploymentID := strings.TrimSpace(rule.Config["deployment_id"])
	if deploymentID == "" {
		return fmt.Errorf("install_software automation requires config.deployment_id")
	}

	deployment, err := e.deployments.GetDeployment(ctx, deploymentID)
	if err != nil {
		return fmt.Errorf("load automation deployment: %w", err)
	}
	if deployment.Scope != event.Scope {
		return fmt.Errorf("%w: automation deployment %q does not match event scope", ErrScopeConflict, deploymentID)
	}
	if err := e.deployments.QueueAutomationDeployment(ctx, deploymentID, event.HostID); err != nil {
		return fmt.Errorf("queue automation deployment: %w", err)
	}
	return nil
}

var _ AutomationExecutor = (*productionAutomationExecutor)(nil)
