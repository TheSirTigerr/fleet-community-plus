package communityplus

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type automationDeploymentStore interface {
	GetDeployment(context.Context, string) (Deployment, error)
	QueueAutomationDeployment(context.Context, string, uint) error
}

type automationScriptStore interface {
	AppConfig(context.Context) (*fleet.AppConfig, error)
	Host(context.Context, uint) (*fleet.Host, error)
	Script(context.Context, uint) (*fleet.Script, error)
	GetScriptContents(context.Context, uint) ([]byte, error)
	IsExecutionPendingForHost(context.Context, uint, uint) (bool, error)
	ListPendingHostScriptExecutions(context.Context, uint, bool) ([]*fleet.HostScriptResult, error)
	NewHostScriptExecutionRequest(context.Context, *fleet.HostScriptRequestPayload) (*fleet.HostScriptResult, error)
}

type productionAutomationExecutor struct {
	deployments automationDeploymentStore
	scripts     automationScriptStore
}

func newProductionAutomationExecutor(store automationDeploymentStore, scriptStores ...automationScriptStore) (*productionAutomationExecutor, error) {
	if store == nil {
		return nil, fmt.Errorf("communityplus: automation deployment store is required")
	}
	if len(scriptStores) > 1 {
		return nil, fmt.Errorf("communityplus: only one automation script store may be configured")
	}
	executor := &productionAutomationExecutor{deployments: store}
	if len(scriptStores) == 1 {
		executor.scripts = scriptStores[0]
	}
	return executor, nil
}

func (e *productionAutomationExecutor) ExecuteAutomation(ctx context.Context, rule AutomationRule, event AutomationEvent) error {
	switch rule.Action {
	case AutomationInstallSoftware:
		return e.installSoftware(ctx, rule, event)
	case AutomationRunScript:
		return e.runScript(ctx, rule, event)
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

const maxAutomationPendingScripts = 1000

func (e *productionAutomationExecutor) runScript(ctx context.Context, rule AutomationRule, event AutomationEvent) error {
	if e.scripts == nil {
		return fmt.Errorf("run_script automation is not configured")
	}
	if event.HostID == 0 {
		return fmt.Errorf("run_script automation requires host_id")
	}

	rawScriptID := strings.TrimSpace(rule.Config["script_id"])
	scriptID64, err := strconv.ParseUint(rawScriptID, 10, 0)
	if err != nil || scriptID64 == 0 {
		return fmt.Errorf("run_script automation requires a valid config.script_id")
	}
	scriptID := uint(scriptID64)

	cfg, err := e.scripts.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("load app config for script automation: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("script automation app config is nil")
	}
	if cfg.ServerSettings.ScriptsDisabled {
		return fmt.Errorf("script automation is disabled by server settings")
	}

	host, err := e.scripts.Host(ctx, event.HostID)
	if err != nil {
		return fmt.Errorf("load automation script host: %w", err)
	}
	if automationScopeForHost(host) != event.Scope {
		return fmt.Errorf("%w: automation script host does not match event scope", ErrScopeConflict)
	}
	if host.OrbitNodeKey == nil || strings.TrimSpace(*host.OrbitNodeKey) == "" {
		return fmt.Errorf("script automation requires fleetd on the target host")
	}
	if host.ScriptsEnabled != nil && !*host.ScriptsEnabled {
		return fmt.Errorf("script execution is disabled on the target host")
	}

	script, err := e.scripts.Script(ctx, scriptID)
	if err != nil {
		return fmt.Errorf("load automation script: %w", err)
	}
	var hostFleetID uint
	if host.TeamID != nil {
		hostFleetID = *host.TeamID
	}
	var scriptFleetID uint
	if script.TeamID != nil {
		scriptFleetID = *script.TeamID
	}
	if hostFleetID != scriptFleetID {
		return fmt.Errorf("%w: automation script does not belong to the host Fleet", ErrScopeConflict)
	}

	hostPlatform := fleet.PlatformFromHost(host.Platform)
	extension := strings.ToLower(filepath.Ext(script.Name))
	if (hostPlatform == "windows" && extension == ".sh") ||
		(hostPlatform != "windows" && extension == ".ps1") {
		return fmt.Errorf("automation script %q is incompatible with host platform %q", script.Name, hostPlatform)
	}

	pending, err := e.scripts.IsExecutionPendingForHost(ctx, event.HostID, scriptID)
	if err != nil {
		return fmt.Errorf("check pending automation script: %w", err)
	}
	if pending {
		return nil
	}

	pendingScripts, err := e.scripts.ListPendingHostScriptExecutions(ctx, event.HostID, false)
	if err != nil {
		return fmt.Errorf("list pending automation scripts: %w", err)
	}
	if len(pendingScripts) >= maxAutomationPendingScripts {
		return fmt.Errorf("target host already has %d pending scripts", len(pendingScripts))
	}

	contents, err := e.scripts.GetScriptContents(ctx, scriptID)
	if err != nil {
		return fmt.Errorf("load automation script contents: %w", err)
	}
	if err := fleet.ValidateHostScriptContents(string(contents), true); err != nil {
		return fmt.Errorf("validate automation script contents: %w", err)
	}

	request := &fleet.HostScriptRequestPayload{
		HostID:          event.HostID,
		ScriptID:        &scriptID,
		ScriptContents:  string(contents),
		ScriptContentID: script.ScriptContentID,
		TeamID:          hostFleetID,
	}
	if rawPolicyID := strings.TrimSpace(event.Data["policy_id"]); rawPolicyID != "" {
		policyID64, err := strconv.ParseUint(rawPolicyID, 10, 0)
		if err != nil || policyID64 == 0 {
			return fmt.Errorf("invalid policy_id in automation event")
		}
		policyID := uint(policyID64)
		request.PolicyID = &policyID
	}

	if _, err := e.scripts.NewHostScriptExecutionRequest(ctx, request); err != nil {
		return fmt.Errorf("queue automation script: %w", err)
	}
	return nil
}
