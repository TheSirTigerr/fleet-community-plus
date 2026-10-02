package servicecompat

import (
	"context"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	storemock "github.com/fleetdm/fleet/v4/server/mock"
	servicemock "github.com/fleetdm/fleet/v4/server/mock/service"
)

func recoveryLockAdminContext() context.Context {
	role := fleet.RoleAdmin
	return viewer.NewContext(context.Background(), viewer.Viewer{User: &fleet.User{ID: 1, GlobalRole: &role}})
}

func TestTeamSettingsWrapperUpdatesRecoveryLockOnlyPayload(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	team := &fleet.Team{ID: 7, Name: "Laptops"}
	ds.TeamWithExtrasFunc = func(context.Context, uint) (*fleet.Team, error) {
		return team, nil
	}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{MDM: fleet.MDM{EnabledAndConfigured: true}}, nil
	}
	ds.SaveTeamFunc = func(_ context.Context, value *fleet.Team) (*fleet.Team, error) {
		return value, nil
	}
	var activity fleet.ActivityDetails
	base.NewActivityFunc = func(_ context.Context, _ *fleet.User, value fleet.ActivityDetails) error {
		activity = value
		return nil
	}
	base.ModifyTeamFunc = func(context.Context, uint, fleet.TeamPayload) (*fleet.Team, error) {
		t.Fatal("recovery-lock-only payload must not fall through to base ModifyTeam")
		return nil, nil
	}

	svc := wrapTeamSettings(base, []any{fleet.Datastore(ds)})
	updated, err := svc.ModifyTeam(recoveryLockAdminContext(), team.ID, fleet.TeamPayload{
		MDM: &fleet.TeamPayloadMDM{EnableRecoveryLockPassword: optjson.SetBool(true)},
	})
	if err != nil {
		t.Fatalf("modify fleet Recovery Lock setting: %v", err)
	}
	if updated == nil || !updated.Config.MDM.EnableRecoveryLockPassword {
		t.Fatalf("expected Recovery Lock enabled, got %#v", updated)
	}
	if _, ok := activity.(fleet.ActivityTypeEnabledRecoveryLockPasswords); !ok {
		t.Fatalf("unexpected activity type %T", activity)
	}
}

func TestTeamSettingsWrapperRejectsRecoveryLockWhenAppleMDMOff(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	ds.TeamWithExtrasFunc = func(context.Context, uint) (*fleet.Team, error) {
		return &fleet.Team{ID: 8, Name: "Macs"}, nil
	}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{}, nil
	}
	base.ModifyTeamFunc = func(context.Context, uint, fleet.TeamPayload) (*fleet.Team, error) {
		t.Fatal("recovery-lock-only payload must not fall through to base ModifyTeam")
		return nil, nil
	}

	svc := wrapTeamSettings(base, []any{fleet.Datastore(ds)})
	_, err := svc.ModifyTeam(recoveryLockAdminContext(), 8, fleet.TeamPayload{
		MDM: &fleet.TeamPayloadMDM{EnableRecoveryLockPassword: optjson.SetBool(true)},
	})
	if err == nil {
		t.Fatal("expected MDM-disabled Recovery Lock update to fail")
	}
}

func TestTeamSettingsWrapperDelegatesMixedPayload(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	delegated := errors.New("delegated")
	base.ModifyTeamFunc = func(_ context.Context, _ uint, payload fleet.TeamPayload) (*fleet.Team, error) {
		if payload.Name == nil || *payload.Name != "renamed" {
			t.Fatalf("unexpected delegated payload: %#v", payload)
		}
		return nil, delegated
	}

	svc := wrapTeamSettings(base, []any{fleet.Datastore(ds)})
	name := "renamed"
	_, err := svc.ModifyTeam(context.Background(), 9, fleet.TeamPayload{
		Name: &name,
		MDM:  &fleet.TeamPayloadMDM{EnableRecoveryLockPassword: optjson.SetBool(true)},
	})
	if !errors.Is(err, delegated) {
		t.Fatalf("expected delegation, got %v", err)
	}
}
