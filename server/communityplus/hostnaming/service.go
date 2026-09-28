// Package hostnaming implements Community+ host naming template reconciliation.
package hostnaming

import (
	"context"
	"errors"
	"fmt"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type activityWriter interface {
	NewActivity(context.Context, *fleet.User, fleet.ActivityDetails) error
}

// Service reconciles device-name enforcement state and records host-name
// template changes for global and fleet scopes.
type Service struct {
	ds         fleet.Datastore
	activities activityWriter
}

func New(ds fleet.Datastore, activities activityWriter) (*Service, error) {
	if ds == nil {
		return nil, errors.New("host naming datastore is nil")
	}
	if activities == nil {
		return nil, errors.New("host naming activity service is nil")
	}
	return &Service{ds: ds, activities: activities}, nil
}

// UpdateTeam persists a fleet-scoped host naming template and reconciles all
// existing hosts in that fleet. Validation of the template itself is performed
// by the calling core service before reaching this callback.
func (s *Service) UpdateTeam(ctx context.Context, team *fleet.Team, nameTemplate string) error {
	if team == nil {
		return &fleet.BadRequestError{Message: "fleet is required for host naming template update"}
	}
	if team.Config.MDM.HostNameTemplate == nameTemplate {
		return nil
	}

	team.Config.MDM.HostNameTemplate = nameTemplate
	if _, err := s.ds.SaveTeam(ctx, team); err != nil {
		return fmt.Errorf("save fleet host naming template: %w", err)
	}
	return s.Apply(ctx, team, nameTemplate)
}

// Apply reconciles the per-host enforcement queue after a host naming template
// change and emits the standard edited_host_name_template activity.
func (s *Service) Apply(ctx context.Context, team *fleet.Team, nameTemplate string) error {
	var fleetID *uint
	var fleetName *string
	if team != nil {
		fleetID = &team.ID
		fleetName = &team.Name
	}

	if nameTemplate == "" {
		if err := s.ds.DeleteHostDeviceNameEnforcementForTeam(ctx, fleetID); err != nil {
			return fmt.Errorf("delete host name enforcement for fleet: %w", err)
		}
	} else {
		if err := s.ds.BulkUpsertHostDeviceNameEnforcement(ctx, fleetID); err != nil {
			return fmt.Errorf("queue host name enforcement for fleet: %w", err)
		}
	}

	var template *string
	if nameTemplate != "" {
		template = &nameTemplate
	}
	if err := s.activities.NewActivity(ctx, authz.UserFromContext(ctx), fleet.ActivityTypeEditedHostNameTemplate{
		FleetID:          fleetID,
		FleetName:        fleetName,
		HostNameTemplate: template,
	}); err != nil {
		return fmt.Errorf("record host naming template activity: %w", err)
	}
	return nil
}
