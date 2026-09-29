package servicecompat

import (
	"context"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// configurationProfilesWrapper fills the remaining device-scoped profile
// read path that Fleet Community keeps behind the Premium service. Profile
// CRUD itself stays in the core service; Community+ only removes the fleet
// scope license gates there.
type configurationProfilesWrapper struct {
	fleet.Service
}

func wrapConfigurationProfiles(base fleet.Service) fleet.Service {
	if base == nil {
		return nil
	}
	return &configurationProfilesWrapper{Service: base}
}

func (s *configurationProfilesWrapper) MDMListHostConfigurationProfiles(ctx context.Context, hostID uint) ([]*fleet.MDMAppleConfigProfile, error) {
	host, err := s.Service.GetHost(ctx, hostID, fleet.HostDetailOptions{})
	if err != nil {
		return nil, err
	}

	var teamID uint
	if host.TeamID != nil {
		teamID = *host.TeamID
	}
	return s.Service.ListMDMAppleConfigProfiles(ctx, teamID)
}
