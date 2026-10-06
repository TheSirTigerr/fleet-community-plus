package servicecompat

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	storemock "github.com/fleetdm/fleet/v4/server/mock"
	servicemock "github.com/fleetdm/fleet/v4/server/mock/service"
)

func agentControlsAdminContext() context.Context {
	role := fleet.RoleAdmin
	return viewer.NewContext(context.Background(), viewer.Viewer{User: &fleet.User{ID: 1, GlobalRole: &role}})
}

func TestAgentControlsWrapperUpdatesFleetChannels(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	team := &fleet.Team{ID: 7, Name: "Canary"}
	ds.TeamWithExtrasFunc = func(context.Context, uint) (*fleet.Team, error) {
		return team, nil
	}
	saved := false
	ds.SaveTeamFunc = func(_ context.Context, value *fleet.Team) (*fleet.Team, error) {
		saved = true
		return value, nil
	}
	var activity fleet.ActivityDetails
	base.NewActivityFunc = func(_ context.Context, _ *fleet.User, value fleet.ActivityDetails) error {
		activity = value
		return nil
	}
	base.ModifyTeamAgentOptionsFunc = func(context.Context, uint, json.RawMessage, fleet.ApplySpecOptions) (*fleet.Team, error) {
		t.Fatal("Community+ Fleet agent options must not fall through to Premium stub")
		return nil, nil
	}

	svc := wrapAgentControls(base, []any{fleet.Datastore(ds)})
	raw := json.RawMessage(`{"update_channels":{"orbit":"stable","osqueryd":"stable","desktop":"stable"}}`)
	updated, err := svc.ModifyTeamAgentOptions(agentControlsAdminContext(), team.ID, raw, fleet.ApplySpecOptions{})
	if err != nil {
		t.Fatalf("modify Fleet agent options: %v", err)
	}
	if !saved || updated.Config.AgentOptions == nil || string(*updated.Config.AgentOptions) != string(raw) {
		t.Fatalf("agent options were not persisted: %#v", updated)
	}
	got, ok := activity.(fleet.ActivityTypeEditedAgentOptions)
	if !ok || got.TeamID == nil || *got.TeamID != 7 || got.Global {
		t.Fatalf("unexpected agent-options activity: %#v", activity)
	}
}

func TestAgentControlsWrapperDryRunDoesNotSave(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	team := &fleet.Team{ID: 8, Name: "Pilot"}
	ds.TeamWithExtrasFunc = func(context.Context, uint) (*fleet.Team, error) {
		return team, nil
	}
	ds.SaveTeamFunc = func(context.Context, *fleet.Team) (*fleet.Team, error) {
		t.Fatal("dry-run must not save Fleet agent options")
		return nil, nil
	}

	svc := wrapAgentControls(base, []any{fleet.Datastore(ds)})
	raw := json.RawMessage(`{"update_channels":{"orbit":"edge"}}`)
	updated, err := svc.ModifyTeamAgentOptions(agentControlsAdminContext(), team.ID, raw, fleet.ApplySpecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run Fleet agent options: %v", err)
	}
	if updated.Config.AgentOptions == nil || string(*updated.Config.AgentOptions) != string(raw) {
		t.Fatalf("dry-run did not apply options in response: %#v", updated)
	}
}

func TestAgentControlsWrapperRejectsOtherPremiumOptions(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	ds.TeamWithExtrasFunc = func(context.Context, uint) (*fleet.Team, error) {
		return &fleet.Team{ID: 9, Name: "Restricted"}, nil
	}

	svc := wrapAgentControls(base, []any{fleet.Datastore(ds)})
	raw := json.RawMessage(`{
		"extensions":{"example":{"platform":"windows","channel":"stable","labels":["restricted"]}},
		"update_channels":{"orbit":"stable"}
	}`)
	if _, err := svc.ModifyTeamAgentOptions(agentControlsAdminContext(), 9, raw, fleet.ApplySpecOptions{}); err == nil {
		t.Fatal("expected non-update-channel Premium agent option to remain gated")
	}
}
