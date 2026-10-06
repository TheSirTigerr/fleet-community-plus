package communityplus

import (
	"context"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type memoryAutomationDeploymentStore struct {
	deployment Deployment
	queuedID   string
	queuedHost uint
}

func (s *memoryAutomationDeploymentStore) GetDeployment(context.Context, string) (Deployment, error) {
	return s.deployment, nil
}

func (s *memoryAutomationDeploymentStore) QueueAutomationDeployment(_ context.Context, deploymentID string, hostID uint) error {
	s.queuedID = deploymentID
	s.queuedHost = hostID
	return nil
}

func TestProductionAutomationExecutorQueuesSoftwareDeployment(t *testing.T) {
	store := &memoryAutomationDeploymentStore{deployment: Deployment{
		ID: "deployment-1", CatalogEntryID: "entry-1", Scope: FleetScope(7),
		Automatic: false, CreatedAt: time.Now().UTC(), CreatedBy: "admin",
	}}
	executor, err := newProductionAutomationExecutor(store)
	if err != nil {
		t.Fatal(err)
	}

	err = executor.ExecuteAutomation(context.Background(), AutomationRule{
		ID: "rule-1", Name: "Install package", Scope: FleetScope(7),
		Trigger: TriggerPolicyFailed, Action: AutomationInstallSoftware, Enabled: true,
		Config: map[string]string{"deployment_id": "deployment-1"},
	}, AutomationEvent{Trigger: TriggerPolicyFailed, Scope: FleetScope(7), HostID: 42})
	if err != nil {
		t.Fatalf("execute automation: %v", err)
	}
	if store.queuedID != "deployment-1" || store.queuedHost != 42 {
		t.Fatalf("unexpected queued deployment: %q host=%d", store.queuedID, store.queuedHost)
	}
}

func TestProductionAutomationExecutorRejectsCrossFleetDeployment(t *testing.T) {
	store := &memoryAutomationDeploymentStore{deployment: Deployment{
		ID: "deployment-1", CatalogEntryID: "entry-1", Scope: FleetScope(8),
		Automatic: false, CreatedAt: time.Now().UTC(), CreatedBy: "admin",
	}}
	executor, err := newProductionAutomationExecutor(store)
	if err != nil {
		t.Fatal(err)
	}
	err = executor.ExecuteAutomation(context.Background(), AutomationRule{
		ID: "rule-1", Name: "Install package", Scope: GlobalScope(),
		Trigger: TriggerPolicyFailed, Action: AutomationInstallSoftware, Enabled: true,
		Config: map[string]string{"deployment_id": "deployment-1"},
	}, AutomationEvent{Trigger: TriggerPolicyFailed, Scope: FleetScope(7), HostID: 42})
	if err == nil {
		t.Fatal("expected cross-Fleet deployment to be rejected")
	}
}


type memoryAutomationScriptStore struct {
	config  *fleet.AppConfig
	host    *fleet.Host
	script  *fleet.Script
	content []byte
	pending bool
	request *fleet.HostScriptRequestPayload
}

func (s *memoryAutomationScriptStore) AppConfig(context.Context) (*fleet.AppConfig, error) {
	return s.config, nil
}

func (s *memoryAutomationScriptStore) Host(context.Context, uint) (*fleet.Host, error) {
	return s.host, nil
}

func (s *memoryAutomationScriptStore) Script(context.Context, uint) (*fleet.Script, error) {
	return s.script, nil
}

func (s *memoryAutomationScriptStore) GetScriptContents(context.Context, uint) ([]byte, error) {
	return s.content, nil
}

func (s *memoryAutomationScriptStore) IsExecutionPendingForHost(context.Context, uint, uint) (bool, error) {
	return s.pending, nil
}

func (s *memoryAutomationScriptStore) ListPendingHostScriptExecutions(context.Context, uint, bool) ([]*fleet.HostScriptResult, error) {
	return nil, nil
}

func (s *memoryAutomationScriptStore) NewHostScriptExecutionRequest(_ context.Context, request *fleet.HostScriptRequestPayload) (*fleet.HostScriptResult, error) {
	copy := *request
	s.request = &copy
	return &fleet.HostScriptResult{HostID: request.HostID}, nil
}

func TestProductionAutomationExecutorQueuesPolicyScript(t *testing.T) {
	teamID := uint(7)
	orbitKey := "orbit-key"
	scriptsEnabled := true
	scriptStore := &memoryAutomationScriptStore{
		config: &fleet.AppConfig{},
		host: &fleet.Host{
			ID: 42, TeamID: &teamID, Platform: "windows",
			OrbitNodeKey: &orbitKey, ScriptsEnabled: &scriptsEnabled,
		},
		script: &fleet.Script{
			ID: 9, TeamID: &teamID, Name: "repair.ps1", ScriptContentID: 12,
		},
		content: []byte("Write-Output 'repair'"),
	}
	deploymentStore := &memoryAutomationDeploymentStore{}
	executor, err := newProductionAutomationExecutor(deploymentStore, scriptStore)
	if err != nil {
		t.Fatal(err)
	}

	err = executor.ExecuteAutomation(context.Background(), AutomationRule{
		ID: "script-rule", Name: "Repair", Scope: FleetScope(7),
		Trigger: TriggerPolicyFailed, Action: AutomationRunScript, Enabled: true,
		Config: map[string]string{"script_id": "9"},
	}, AutomationEvent{
		Trigger: TriggerPolicyFailed, Scope: FleetScope(7), HostID: 42,
		Data: map[string]string{"policy_id": "10"},
	})
	if err != nil {
		t.Fatalf("execute script automation: %v", err)
	}
	if scriptStore.request == nil {
		t.Fatal("script was not queued")
	}
	if scriptStore.request.HostID != 42 || scriptStore.request.ScriptID == nil || *scriptStore.request.ScriptID != 9 {
		t.Fatalf("unexpected script request: %#v", scriptStore.request)
	}
	if scriptStore.request.PolicyID == nil || *scriptStore.request.PolicyID != 10 {
		t.Fatalf("policy id not propagated: %#v", scriptStore.request)
	}
	if scriptStore.request.TeamID != 7 || scriptStore.request.ScriptContentID != 12 {
		t.Fatalf("unexpected script scope/content: %#v", scriptStore.request)
	}
}

func TestProductionAutomationExecutorDeduplicatesPendingScript(t *testing.T) {
	teamID := uint(7)
	orbitKey := "orbit-key"
	scriptStore := &memoryAutomationScriptStore{
		config:  &fleet.AppConfig{},
		host:    &fleet.Host{ID: 42, TeamID: &teamID, Platform: "windows", OrbitNodeKey: &orbitKey},
		script:  &fleet.Script{ID: 9, TeamID: &teamID, Name: "repair.ps1", ScriptContentID: 12},
		content: []byte("Write-Output 'repair'"),
		pending: true,
	}
	executor, err := newProductionAutomationExecutor(&memoryAutomationDeploymentStore{}, scriptStore)
	if err != nil {
		t.Fatal(err)
	}
	err = executor.ExecuteAutomation(context.Background(), AutomationRule{
		ID: "script-rule", Name: "Repair", Scope: FleetScope(7),
		Trigger: TriggerPolicyFailed, Action: AutomationRunScript, Enabled: true,
		Config: map[string]string{"script_id": "9"},
	}, AutomationEvent{Trigger: TriggerPolicyFailed, Scope: FleetScope(7), HostID: 42})
	if err != nil {
		t.Fatalf("pending script should be idempotent: %v", err)
	}
	if scriptStore.request != nil {
		t.Fatal("pending script was queued again")
	}
}

func TestProductionAutomationExecutorRejectsCrossFleetScript(t *testing.T) {
	hostTeamID := uint(7)
	scriptTeamID := uint(8)
	orbitKey := "orbit-key"
	scriptStore := &memoryAutomationScriptStore{
		config:  &fleet.AppConfig{},
		host:    &fleet.Host{ID: 42, TeamID: &hostTeamID, Platform: "windows", OrbitNodeKey: &orbitKey},
		script:  &fleet.Script{ID: 9, TeamID: &scriptTeamID, Name: "repair.ps1"},
		content: []byte("Write-Output 'repair'"),
	}
	executor, err := newProductionAutomationExecutor(&memoryAutomationDeploymentStore{}, scriptStore)
	if err != nil {
		t.Fatal(err)
	}
	err = executor.ExecuteAutomation(context.Background(), AutomationRule{
		ID: "script-rule", Name: "Repair", Scope: FleetScope(7),
		Trigger: TriggerPolicyFailed, Action: AutomationRunScript, Enabled: true,
		Config: map[string]string{"script_id": "9"},
	}, AutomationEvent{Trigger: TriggerPolicyFailed, Scope: FleetScope(7), HostID: 42})
	if err == nil {
		t.Fatal("expected cross-Fleet script to be rejected")
	}
}
