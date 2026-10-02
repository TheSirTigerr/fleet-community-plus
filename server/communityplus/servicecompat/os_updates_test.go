package servicecompat

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm"
	storemock "github.com/fleetdm/fleet/v4/server/mock"
	servicemock "github.com/fleetdm/fleet/v4/server/mock/service"
)

func TestOSUpdatesWrapperUpdatesWindowsFleet(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	team := &fleet.Team{ID: 21, Name: "Windows"}
	ds.TeamWithExtrasFunc = func(context.Context, uint) (*fleet.Team, error) {
		return team, nil
	}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{MDM: fleet.MDM{WindowsEnabledAndConfigured: true}}, nil
	}
	ds.HasWindowsUpdateConfigProfileConfiguredFunc = func(context.Context, uint) (bool, error) {
		return false, nil
	}
	ds.SaveTeamFunc = func(_ context.Context, value *fleet.Team) (*fleet.Team, error) {
		return value, nil
	}
	var profile *fleet.MDMWindowsConfigProfile
	ds.SetOrUpdateMDMWindowsConfigProfileFunc = func(_ context.Context, value fleet.MDMWindowsConfigProfile) error {
		profile = &value
		return nil
	}
	var activity fleet.ActivityDetails
	base.NewActivityFunc = func(_ context.Context, _ *fleet.User, value fleet.ActivityDetails) error {
		activity = value
		return nil
	}
	base.ModifyTeamFunc = func(context.Context, uint, fleet.TeamPayload) (*fleet.Team, error) {
		t.Fatal("OS-update-only payload must not fall through to base ModifyTeam")
		return nil, nil
	}

	svc, err := wrapOSUpdates(base, []any{fleet.Datastore(ds)})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.ModifyTeam(recoveryLockAdminContext(), team.ID, fleet.TeamPayload{
		MDM: &fleet.TeamPayloadMDM{WindowsUpdates: &fleet.WindowsUpdates{
			DeadlineDays:    optjson.SetInt(5),
			GracePeriodDays: optjson.SetInt(2),
		}},
	})
	if err != nil {
		t.Fatalf("modify Windows OS updates: %v", err)
	}
	if updated == nil || updated.Config.MDM.WindowsUpdates.DeadlineDays.Value != 5 {
		t.Fatalf("unexpected saved Windows settings: %#v", updated)
	}
	if profile == nil || profile.Name != mdm.FleetWindowsOSUpdatesProfileName {
		t.Fatalf("expected Fleet Windows update profile, got %#v", profile)
	}
	if _, ok := activity.(fleet.ActivityTypeEditedWindowsUpdates); !ok {
		t.Fatalf("unexpected activity type %T", activity)
	}
}

func TestOSUpdatesWrapperDisablesMacOSFleetUpdates(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	team := &fleet.Team{ID: 22, Name: "Macs"}
	team.Config.MDM.MacOSUpdates = fleet.AppleOSUpdateSettings{
		MinimumVersion: optjson.SetString("15.0"),
		Deadline:       optjson.SetString("2026-12-01"),
	}
	ds.TeamWithExtrasFunc = func(context.Context, uint) (*fleet.Team, error) {
		return team, nil
	}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{MDM: fleet.MDM{EnabledAndConfigured: true}}, nil
	}
	ds.SaveTeamFunc = func(_ context.Context, value *fleet.Team) (*fleet.Team, error) {
		return value, nil
	}
	var deleted string
	ds.DeleteMDMAppleDeclarationByNameFunc = func(_ context.Context, _ *uint, name string) error {
		deleted = name
		return nil
	}
	base.NewActivityFunc = func(context.Context, *fleet.User, fleet.ActivityDetails) error {
		return nil
	}
	base.ModifyTeamFunc = func(context.Context, uint, fleet.TeamPayload) (*fleet.Team, error) {
		t.Fatal("OS-update-only payload must not fall through to base ModifyTeam")
		return nil, nil
	}

	svc, err := wrapOSUpdates(base, []any{fleet.Datastore(ds)})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.ModifyTeam(recoveryLockAdminContext(), team.ID, fleet.TeamPayload{
		MDM: &fleet.TeamPayloadMDM{MacOSUpdates: &fleet.AppleOSUpdateSettings{
			MinimumVersion: optjson.SetString(""),
			Deadline:       optjson.SetString(""),
		}},
	})
	if err != nil {
		t.Fatalf("disable macOS OS updates: %v", err)
	}
	if updated == nil || updated.Config.MDM.MacOSUpdates.MinimumVersion.Value != "" {
		t.Fatalf("expected macOS update setting disabled, got %#v", updated)
	}
	if deleted != mdm.FleetMacOSUpdatesProfileName {
		t.Fatalf("unexpected declaration deleted: %q", deleted)
	}
}

func TestOSUpdatesWrapperDelegatesMixedFleetPayload(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	called := false
	base.ModifyTeamFunc = func(_ context.Context, _ uint, payload fleet.TeamPayload) (*fleet.Team, error) {
		called = true
		if payload.Name == nil {
			t.Fatal("expected mixed payload to be delegated")
		}
		return &fleet.Team{ID: 23}, nil
	}
	svc, err := wrapOSUpdates(base, []any{fleet.Datastore(ds)})
	if err != nil {
		t.Fatal(err)
	}
	name := "renamed"
	if _, err := svc.ModifyTeam(context.Background(), 23, fleet.TeamPayload{
		Name: &name,
		MDM: &fleet.TeamPayloadMDM{WindowsUpdates: &fleet.WindowsUpdates{
			DeadlineDays: optjson.SetInt(5),
		}},
	}); err != nil {
		t.Fatalf("delegated mixed payload: %v", err)
	}
	if !called {
		t.Fatal("expected base ModifyTeam to be called")
	}
}
