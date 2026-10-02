package servicecompat

import (
	"context"
	"fmt"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type teamSettingsWrapper struct {
	fleet.Service
	ds         fleet.Datastore
	authorizer *authz.Authorizer
}

func wrapTeamSettings(base fleet.Service, options []any) fleet.Service {
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
	return &teamSettingsWrapper{Service: base, ds: ds, authorizer: authz.Must()}
}

func (s *teamSettingsWrapper) ModifyTeam(ctx context.Context, id uint, payload fleet.TeamPayload) (*fleet.Team, error) {
	if !recoveryLockOnlyTeamPayload(payload) {
		return s.Service.ModifyTeam(ctx, id, payload)
	}

	team, err := s.ds.TeamWithExtras(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.authorizer.Authorize(ctx, team, fleet.ActionWrite); err != nil {
		return nil, err
	}

	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return nil, err
	}
	if !appConfig.MDM.EnabledAndConfigured {
		return nil, fleet.NewInvalidArgumentError(
			"mdm.enable_recovery_lock_password",
			"Couldn't update enable_recovery_lock_password because MDM features aren't turned on in Fleet.",
		)
	}

	enabled := payload.MDM.EnableRecoveryLockPassword.Value
	if team.Config.MDM.EnableRecoveryLockPassword == enabled {
		return team, nil
	}
	team.Config.MDM.EnableRecoveryLockPassword = enabled

	saved, err := s.ds.SaveTeam(ctx, team)
	if err != nil {
		return nil, fmt.Errorf("save fleet recovery lock settings: %w", err)
	}
	if saved != nil {
		team = saved
	}

	var activity fleet.ActivityDetails
	if enabled {
		activity = fleet.ActivityTypeEnabledRecoveryLockPasswords{TeamID: &team.ID, TeamName: &team.Name}
	} else {
		activity = fleet.ActivityTypeDisabledRecoveryLockPasswords{TeamID: &team.ID, TeamName: &team.Name}
	}
	if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), activity); err != nil {
		return nil, fmt.Errorf("record fleet recovery lock activity: %w", err)
	}
	return team, nil
}

func recoveryLockOnlyTeamPayload(payload fleet.TeamPayload) bool {
	if payload.MDM == nil || !payload.MDM.EnableRecoveryLockPassword.Valid {
		return false
	}
	if payload.Name != nil || payload.Description != nil || payload.Secrets != nil || payload.WebhookSettings != nil ||
		payload.Integrations != nil || payload.HostExpirySettings != nil || payload.Features != nil {
		return false
	}

	mdm := payload.MDM
	return !mdm.EnableDiskEncryption.Valid &&
		!mdm.RequireBitLockerPIN.Valid &&
		mdm.MacOSUpdates == nil &&
		mdm.IOSUpdates == nil &&
		mdm.IPadOSUpdates == nil &&
		mdm.WindowsUpdates == nil &&
		mdm.MacOSSetup == nil &&
		!mdm.HostNameTemplate.Set &&
		mdm.MacOSSettings == nil &&
		mdm.WindowsSettings == nil &&
		mdm.LinuxSettings == nil
}
