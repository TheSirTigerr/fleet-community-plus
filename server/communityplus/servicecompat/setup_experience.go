package servicecompat

import (
	"context"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/communityplus/setupexperience"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type setupExperienceWrapper struct {
	fleet.Service
	setup *setupexperience.Service
}

func wrapSetupExperience(base fleet.Service, options []any) (fleet.Service, error) {
	if base == nil {
		return nil, nil
	}
	var ds fleet.Datastore
	for _, option := range options {
		if value, ok := option.(fleet.Datastore); ok {
			ds = value
			break
		}
	}
	if ds == nil {
		return base, nil
	}
	setup, err := setupexperience.New(ds, authz.Must())
	if err != nil {
		return nil, err
	}
	return &setupExperienceWrapper{Service: base, setup: setup}, nil
}

func (s *setupExperienceWrapper) UpdateMDMAppleSetup(ctx context.Context, payload fleet.MDMAppleSetupPayload) error {
	return s.setup.UpdateAppleSetup(ctx, payload)
}


func (s *setupExperienceWrapper) SetSetupExperienceSoftware(ctx context.Context, platform string, teamID uint, titleIDs []uint) error {
	teamName, err := s.setup.SetSoftware(ctx, platform, teamID, titleIDs)
	if err != nil {
		return err
	}
	return s.Service.NewActivity(ctx, authz.UserFromContext(ctx), fleet.ActivityEditedSetupExperienceSoftware{
		Platform: platform,
		TeamID:   teamID,
		TeamName: teamName,
	})
}

func (s *setupExperienceWrapper) ListSetupExperienceSoftware(
	ctx context.Context,
	platform string,
	teamID uint,
	opts fleet.ListOptions,
) ([]fleet.SoftwareTitleListResult, int, *fleet.PaginationMetadata, error) {
	return s.setup.ListSoftware(ctx, platform, teamID, opts)
}
