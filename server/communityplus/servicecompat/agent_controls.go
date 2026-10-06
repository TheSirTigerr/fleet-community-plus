package servicecompat

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/communityplus"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type agentControlsWrapper struct {
	fleet.Service
	ds         fleet.Datastore
	authorizer *authz.Authorizer
}

func wrapAgentControls(base fleet.Service, options []any) fleet.Service {
	if base == nil {
		return nil
	}
	var ds fleet.Datastore
	for _, option := range options {
		if value, ok := option.(fleet.Datastore); ok {
			ds = value
			break
		}
	}
	if ds == nil {
		return base
	}
	return &agentControlsWrapper{Service: base, ds: ds, authorizer: authz.Must()}
}

func (s *agentControlsWrapper) ModifyTeamAgentOptions(
	ctx context.Context,
	id uint,
	raw json.RawMessage,
	applyOpts fleet.ApplySpecOptions,
) (*fleet.Team, error) {
	team, err := s.ds.TeamWithExtras(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.authorizer.Authorize(ctx, team, fleet.ActionWrite); err != nil {
		return nil, err
	}

	if err := communityplus.ValidateAgentOptions(ctx, s.ds, raw, false, id); err != nil && !applyOpts.Force {
		err = fleet.SuggestAgentOptionsCorrection(err)
		return nil, fleet.NewUserMessageError(err, http.StatusBadRequest)
	}

	rawCopy := append(json.RawMessage(nil), raw...)
	team.Config.AgentOptions = &rawCopy
	if applyOpts.DryRun {
		return team, nil
	}

	saved, err := s.ds.SaveTeam(ctx, team)
	if err != nil {
		return nil, err
	}
	if saved != nil {
		team = saved
	}

	teamID := team.ID
	teamName := team.Name
	if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), fleet.ActivityTypeEditedAgentOptions{
		Global: false, TeamID: &teamID, TeamName: &teamName,
	}); err != nil {
		return nil, err
	}
	return team, nil
}
