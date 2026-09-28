package hostnaming

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
)

type activityRecorder struct {
	activities []fleet.ActivityDetails
}

func (r *activityRecorder) NewActivity(_ context.Context, _ *fleet.User, activity fleet.ActivityDetails) error {
	r.activities = append(r.activities, activity)
	return nil
}

func TestApplyQueuesHostNameEnforcementAndRecordsActivity(t *testing.T) {
	ds := &mock.DataStore{}
	var queuedTeamID *uint
	ds.BulkUpsertHostDeviceNameEnforcementFunc = func(_ context.Context, teamID *uint) error {
		queuedTeamID = teamID
		return nil
	}
	ds.DeleteHostDeviceNameEnforcementForTeamFunc = func(context.Context, *uint) error {
		t.Fatal("delete enforcement must not run when a template is configured")
		return nil
	}
	recorder := &activityRecorder{}
	svc, err := New(ds, recorder)
	if err != nil {
		t.Fatalf("new host naming service: %v", err)
	}
	team := &fleet.Team{ID: 7, Name: "Workstations"}
	const template = "$FLEET_VAR_HOST_HARDWARE_SERIAL"

	if err := svc.Apply(context.Background(), team, template); err != nil {
		t.Fatalf("apply host naming template: %v", err)
	}
	if queuedTeamID == nil || *queuedTeamID != team.ID {
		t.Fatalf("expected fleet ID %d to be queued, got %v", team.ID, queuedTeamID)
	}
	if len(recorder.activities) != 1 {
		t.Fatalf("expected one activity, got %d", len(recorder.activities))
	}
	activity, ok := recorder.activities[0].(fleet.ActivityTypeEditedHostNameTemplate)
	if !ok {
		t.Fatalf("unexpected activity type %T", recorder.activities[0])
	}
	if activity.FleetID == nil || *activity.FleetID != team.ID || activity.FleetName == nil || *activity.FleetName != team.Name {
		t.Fatalf("unexpected activity fleet scope: %+v", activity)
	}
	if activity.HostNameTemplate == nil || *activity.HostNameTemplate != template {
		t.Fatalf("unexpected activity template: %+v", activity.HostNameTemplate)
	}
}

func TestApplyClearsHostNameEnforcement(t *testing.T) {
	ds := &mock.DataStore{}
	var deleted bool
	ds.DeleteHostDeviceNameEnforcementForTeamFunc = func(_ context.Context, teamID *uint) error {
		if teamID != nil {
			t.Fatalf("expected global/no-fleet scope, got %v", teamID)
		}
		deleted = true
		return nil
	}
	ds.BulkUpsertHostDeviceNameEnforcementFunc = func(context.Context, *uint) error {
		t.Fatal("queue enforcement must not run when clearing a template")
		return nil
	}
	recorder := &activityRecorder{}
	svc, err := New(ds, recorder)
	if err != nil {
		t.Fatalf("new host naming service: %v", err)
	}

	if err := svc.Apply(context.Background(), nil, ""); err != nil {
		t.Fatalf("clear host naming template: %v", err)
	}
	if !deleted {
		t.Fatal("expected enforcement rows to be deleted")
	}
	if len(recorder.activities) != 1 {
		t.Fatalf("expected one activity, got %d", len(recorder.activities))
	}
	activity := recorder.activities[0].(fleet.ActivityTypeEditedHostNameTemplate)
	if activity.FleetID != nil || activity.FleetName != nil || activity.HostNameTemplate != nil {
		t.Fatalf("expected cleared global activity, got %+v", activity)
	}
}

func TestUpdateTeamPersistsAndReconcilesChangedTemplate(t *testing.T) {
	ds := &mock.DataStore{}
	var saved *fleet.Team
	ds.SaveTeamFunc = func(_ context.Context, team *fleet.Team) (*fleet.Team, error) {
		saved = team
		return team, nil
	}
	var queued bool
	ds.BulkUpsertHostDeviceNameEnforcementFunc = func(context.Context, *uint) error {
		queued = true
		return nil
	}
	ds.DeleteHostDeviceNameEnforcementForTeamFunc = func(context.Context, *uint) error { return nil }
	recorder := &activityRecorder{}
	svc, err := New(ds, recorder)
	if err != nil {
		t.Fatalf("new host naming service: %v", err)
	}
	team := &fleet.Team{ID: 9, Name: "Laptops"}
	const template = "LT-$FLEET_VAR_HOST_HARDWARE_SERIAL"

	if err := svc.UpdateTeam(context.Background(), team, template); err != nil {
		t.Fatalf("update fleet host naming template: %v", err)
	}
	if saved != team || team.Config.MDM.HostNameTemplate != template {
		t.Fatalf("template was not persisted on the fleet: %+v", team.Config.MDM.HostNameTemplate)
	}
	if !queued || len(recorder.activities) != 1 {
		t.Fatalf("expected reconciliation and activity, queued=%v activities=%d", queued, len(recorder.activities))
	}
}

func TestUpdateTeamNoOpsWhenTemplateIsUnchanged(t *testing.T) {
	ds := &mock.DataStore{}
	ds.SaveTeamFunc = func(context.Context, *fleet.Team) (*fleet.Team, error) {
		t.Fatal("unchanged template must not save the fleet")
		return nil, nil
	}
	recorder := &activityRecorder{}
	svc, err := New(ds, recorder)
	if err != nil {
		t.Fatalf("new host naming service: %v", err)
	}
	team := &fleet.Team{ID: 3, Name: "Servers"}
	team.Config.MDM.HostNameTemplate = "SRV-$FLEET_VAR_HOST_HARDWARE_SERIAL"

	if err := svc.UpdateTeam(context.Background(), team, team.Config.MDM.HostNameTemplate); err != nil {
		t.Fatalf("unchanged fleet host naming template: %v", err)
	}
	if ds.BulkUpsertHostDeviceNameEnforcementFuncInvoked || ds.DeleteHostDeviceNameEnforcementForTeamFuncInvoked || len(recorder.activities) != 0 {
		t.Fatal("unchanged template must not reconcile or record an activity")
	}
}
