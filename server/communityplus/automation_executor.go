package communityplus

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/google/uuid"
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

type automationUninstallStore interface {
	Host(context.Context, uint) (*fleet.Host, error)
	GetSoftwareInstallerMetadataByID(context.Context, uint) (*fleet.SoftwareInstaller, error)
	GetSoftwareInstallerMetadataByTeamTitleAndInstallerID(context.Context, *uint, uint, uint, bool) (*fleet.SoftwareInstaller, error)
	GetHostLastInstallData(context.Context, uint, uint) (*fleet.HostLastInstallData, error)
	InsertFleetInitiatedSoftwareUninstallRequest(context.Context, string, uint, uint) error
}

type automationUninstallDeferralStore interface {
	AutomaticDeploymentsAllowed(context.Context, uint, time.Time) (bool, error)
	IsSoftwareUninstallPending(context.Context, uint, uint) (bool, error)
	QueueDeferredSoftwareUninstallAutomation(context.Context, DeferredSoftwareUninstallAutomation) error
}

type productionAutomationExecutor struct {
	deployments        automationDeploymentStore
	scripts            automationScriptStore
	deferrals          automationScriptDeferralStore
	uninstalls         automationUninstallStore
	uninstallDeferrals automationUninstallDeferralStore
}

func newProductionAutomationExecutor(store automationDeploymentStore, scriptStores ...automationScriptStore) (*productionAutomationExecutor, error) {
	if store == nil {
		return nil, fmt.Errorf("communityplus: automation deployment store is required")
	}
	if len(scriptStores) > 1 {
		return nil, fmt.Errorf("communityplus: only one automation script store may be configured")
	}
	executor := &productionAutomationExecutor{deployments: store}
	if deferrals, ok := store.(automationScriptDeferralStore); ok {
		executor.deferrals = deferrals
	}
	if uninstallDeferrals, ok := store.(automationUninstallDeferralStore); ok {
		executor.uninstallDeferrals = uninstallDeferrals
	}
	if len(scriptStores) == 1 {
		executor.scripts = scriptStores[0]
		if uninstalls, ok := scriptStores[0].(automationUninstallStore); ok {
			executor.uninstalls = uninstalls
		}
	}
	return executor, nil
}

func (e *productionAutomationExecutor) ExecuteAutomation(ctx context.Context, rule AutomationRule, event AutomationEvent) error {
	switch rule.Action {
	case AutomationInstallSoftware:
		return e.installSoftware(ctx, rule, event)
	case AutomationUninstallSoftware:
		return e.uninstallSoftware(ctx, rule, event)
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

	policyID, err := automationEventPolicyID(event)
	if err != nil {
		return err
	}
	if event.Scope.Kind == ScopeFleet && e.deferrals != nil {
		allowed, err := e.deferrals.AutomaticDeploymentsAllowed(ctx, event.Scope.FleetID, time.Now())
		if err != nil {
			return fmt.Errorf("check maintenance window for script automation: %w", err)
		}
		if !allowed {
			if err := e.deferrals.QueueDeferredScriptAutomation(ctx, DeferredScriptAutomation{
				RuleID: rule.ID, HostID: event.HostID, FleetID: event.Scope.FleetID,
				ScriptID: scriptID, PolicyID: policyID, RequestedAt: time.Now().UTC(),
			}); err != nil {
				return err
			}
			return nil
		}
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
	if policyID != 0 {
		request.PolicyID = &policyID
	}

	if _, err := e.scripts.NewHostScriptExecutionRequest(ctx, request); err != nil {
		return fmt.Errorf("queue automation script: %w", err)
	}
	return nil
}

func automationEventPolicyID(event AutomationEvent) (uint, error) {
	rawPolicyID := strings.TrimSpace(event.Data["policy_id"])
	if rawPolicyID == "" {
		return 0, nil
	}
	policyID64, err := strconv.ParseUint(rawPolicyID, 10, 0)
	if err != nil || policyID64 == 0 {
		return 0, fmt.Errorf("invalid policy_id in automation event")
	}
	return uint(policyID64), nil
}

func sameAutomationTeam(a, b *uint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (e *productionAutomationExecutor) uninstallSoftware(ctx context.Context, rule AutomationRule, event AutomationEvent) error {
	if e.uninstalls == nil || e.uninstallDeferrals == nil {
		return fmt.Errorf("uninstall_software automation is not configured")
	}
	if event.HostID == 0 {
		return fmt.Errorf("uninstall_software automation requires host_id")
	}
	rawInstallerID := strings.TrimSpace(rule.Config["installer_id"])
	installerID64, err := strconv.ParseUint(rawInstallerID, 10, 0)
	if err != nil || installerID64 == 0 {
		return fmt.Errorf("uninstall_software automation requires a valid config.installer_id")
	}
	installerID := uint(installerID64)

	host, err := e.uninstalls.Host(ctx, event.HostID)
	if err != nil {
		return fmt.Errorf("load automation uninstall host: %w", err)
	}
	if automationScopeForHost(host) != event.Scope {
		return fmt.Errorf("%w: automation uninstall host does not match event scope", ErrScopeConflict)
	}
	if host.OrbitNodeKey == nil || strings.TrimSpace(*host.OrbitNodeKey) == "" {
		return fmt.Errorf("software uninstall automation requires fleetd on the target host")
	}

	metadata, err := e.uninstalls.GetSoftwareInstallerMetadataByID(ctx, installerID)
	if err != nil {
		return fmt.Errorf("load automation uninstall installer: %w", err)
	}
	if metadata == nil || metadata.TitleID == nil {
		return fmt.Errorf("automation uninstall installer %d has no software title", installerID)
	}
	if !sameAutomationTeam(host.TeamID, metadata.TeamID) {
		return fmt.Errorf("%w: automation uninstall installer does not belong to the host Fleet", ErrScopeConflict)
	}
	if want, got := metadata.Platform, fleet.PlatformFromHost(host.Platform); want != got {
		return fmt.Errorf("automation uninstall installer platform %q does not match host platform %q", want, got)
	}

	installer, err := e.uninstalls.GetSoftwareInstallerMetadataByTeamTitleAndInstallerID(
		ctx, host.TeamID, *metadata.TitleID, installerID, true,
	)
	if err != nil {
		return fmt.Errorf("load automation uninstall script: %w", err)
	}
	if installer == nil || strings.TrimSpace(installer.UninstallScript) == "" || installer.UninstallScriptContentID == 0 {
		return fmt.Errorf("software installer %d has no uninstall script", installerID)
	}
	if err := fleet.ValidateHostScriptContents(installer.UninstallScript, true); err != nil {
		return fmt.Errorf("validate automation uninstall script: %w", err)
	}

	pending, err := e.uninstallDeferrals.IsSoftwareUninstallPending(ctx, event.HostID, installerID)
	if err != nil {
		return fmt.Errorf("check pending automation uninstall: %w", err)
	}
	if pending {
		return nil
	}
	last, err := e.uninstalls.GetHostLastInstallData(ctx, event.HostID, installerID)
	if err != nil {
		return fmt.Errorf("load last software state before automation uninstall: %w", err)
	}
	if last != nil {
		if last.Status == nil || *last.Status == fleet.SoftwareUninstallPending {
			return nil
		}
	}

	if event.Scope.Kind == ScopeFleet {
		allowed, err := e.uninstallDeferrals.AutomaticDeploymentsAllowed(ctx, event.Scope.FleetID, time.Now())
		if err != nil {
			return fmt.Errorf("check maintenance window for uninstall automation: %w", err)
		}
		if !allowed {
			if err := e.uninstallDeferrals.QueueDeferredSoftwareUninstallAutomation(ctx, DeferredSoftwareUninstallAutomation{
				RuleID: rule.ID, HostID: event.HostID, FleetID: event.Scope.FleetID,
				InstallerID: installerID, RequestedAt: time.Now().UTC(),
			}); err != nil {
				return err
			}
			return nil
		}
	}

	executionID := uuid.NewString()
	if err := e.uninstalls.InsertFleetInitiatedSoftwareUninstallRequest(ctx, executionID, event.HostID, installerID); err != nil {
		return fmt.Errorf("queue automation software uninstall: %w", err)
	}
	return nil
}
