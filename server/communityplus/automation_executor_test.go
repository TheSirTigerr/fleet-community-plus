package communityplus

import (
	"context"
	"testing"
	"time"
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
