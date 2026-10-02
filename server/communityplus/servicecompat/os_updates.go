package servicecompat

import (
	"context"
	"fmt"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/communityplus/osupdates"
	"github.com/fleetdm/fleet/v4/server/fleet"
	apple_mdm "github.com/fleetdm/fleet/v4/server/mdm/apple"
)

type osUpdatesWrapper struct {
	fleet.Service
	ds         fleet.Datastore
	authorizer *authz.Authorizer
	updates    *osupdates.Service
}

func wrapOSUpdates(base fleet.Service, options []any) (fleet.Service, error) {
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
	updates, err := osupdates.New(ds)
	if err != nil {
		return nil, err
	}
	return &osUpdatesWrapper{
		Service:    base,
		ds:         ds,
		authorizer: authz.Must(),
		updates:    updates,
	}, nil
}

func (s *osUpdatesWrapper) ModifyTeam(ctx context.Context, id uint, payload fleet.TeamPayload) (*fleet.Team, error) {
	if !osUpdatesOnlyTeamPayload(payload) || id == 0 {
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

	type appleChange struct {
		device  fleet.AppleDevice
		current *fleet.AppleOSUpdateSettings
		next    *fleet.AppleOSUpdateSettings
		field   string
	}
	appleChanges := []appleChange{
		{fleet.MacOS, &team.Config.MDM.MacOSUpdates, payload.MDM.MacOSUpdates, "macos_updates"},
		{fleet.IOS, &team.Config.MDM.IOSUpdates, payload.MDM.IOSUpdates, "ios_updates"},
		{fleet.IPadOS, &team.Config.MDM.IPadOSUpdates, payload.MDM.IPadOSUpdates, "ipados_updates"},
	}

	changedApple := make([]appleChange, 0, len(appleChanges))
	for _, change := range appleChanges {
		if change.next == nil {
			continue
		}
		if err := change.next.Validate(); err != nil {
			return nil, fleet.NewInvalidArgumentError(change.field, err.Error())
		}
		if !appleOSSettingsTouched(change.next) {
			continue
		}
		if !appConfig.MDM.EnabledAndConfigured {
			return nil, fleet.NewInvalidArgumentError(
				"mdm."+change.field,
				"Couldn't update Apple OS updates because Apple MDM isn't turned on in Fleet.",
			)
		}
		if change.next.Configured() {
			hasCustom, err := s.ds.HasAppleUpdateConfigProfileConfigured(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("check for custom Apple OS update declaration: %w", err)
			}
			if hasCustom {
				return nil, &fleet.BadRequestError{Message: fleet.CouldNotUpdateAppleOSSettingsWithCustomProfileErrorMessage}
			}
		}
		old := *change.current
		*change.current = *change.next
		if versions, err := apple_mdm.ValidateMDMSettingsAppleSupportedOSVersion(team.Config.MDM, false); err != nil {
			*change.current = old
			return nil, fleet.NewInvalidArgumentError("mdm", err.Error())
		} else if msg, ok := versions[appleDeviceKey(change.device)]; ok {
			*change.current = old
			return nil, fleet.NewInvalidArgumentError(change.field+".minimum_version", msg)
		}
		if !appleOSSettingsEqual(old, *change.current) {
			changedApple = append(changedApple, change)
		}
	}

	windowsChanged := false
	if next := payload.MDM.WindowsUpdates; next != nil {
		if err := next.Validate(); err != nil {
			return nil, fleet.NewInvalidArgumentError("windows_updates", err.Error())
		}
		if windowsOSSettingsTouched(next) {
			if !appConfig.MDM.WindowsEnabledAndConfigured {
				return nil, fleet.NewInvalidArgumentError(
					"mdm.windows_updates",
					"Couldn't update Windows OS updates because Windows MDM isn't turned on in Fleet.",
				)
			}
			if next.Configured() {
				hasCustom, err := s.ds.HasWindowsUpdateConfigProfileConfigured(ctx, id)
				if err != nil {
					return nil, fmt.Errorf("check for custom Windows OS update profile: %w", err)
				}
				if hasCustom {
					return nil, &fleet.BadRequestError{Message: fleet.CouldNotUpdateWindowsOSSettingsWithCustomProfileErrorMessage}
				}
			}
			windowsChanged = !team.Config.MDM.WindowsUpdates.Equal(*next)
			team.Config.MDM.WindowsUpdates = *next
		}
	}

	if len(changedApple) == 0 && !windowsChanged {
		return team, nil
	}
	saved, err := s.ds.SaveTeam(ctx, team)
	if err != nil {
		return nil, err
	}
	if saved != nil {
		team = saved
	}

	for _, change := range changedApple {
		var settings fleet.AppleOSUpdateSettings
		switch change.device {
		case fleet.MacOS:
			settings = team.Config.MDM.MacOSUpdates
		case fleet.IOS:
			settings = team.Config.MDM.IOSUpdates
		case fleet.IPadOS:
			settings = team.Config.MDM.IPadOSUpdates
		}
		if err := s.updates.AppleEdited(ctx, &team.ID, change.device, settings); err != nil {
			return nil, err
		}
		if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), appleUpdateActivity(team, change.device, settings)); err != nil {
			return nil, fmt.Errorf("record Apple OS update activity: %w", err)
		}
	}

	if windowsChanged {
		settings := team.Config.MDM.WindowsUpdates
		if settings.DeadlineDays.Valid {
			if err := s.updates.WindowsEnable(ctx, &team.ID, settings); err != nil {
				return nil, err
			}
		} else if err := s.updates.WindowsDisable(ctx, &team.ID); err != nil {
			return nil, err
		}
		var deadline, grace *int
		if settings.DeadlineDays.Valid {
			deadline = &settings.DeadlineDays.Value
		}
		if settings.GracePeriodDays.Valid {
			grace = &settings.GracePeriodDays.Value
		}
		if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), fleet.ActivityTypeEditedWindowsUpdates{
			TeamID:          &team.ID,
			TeamName:        &team.Name,
			DeadlineDays:    deadline,
			GracePeriodDays: grace,
		}); err != nil {
			return nil, fmt.Errorf("record Windows OS update activity: %w", err)
		}
	}

	return team, nil
}

func osUpdatesOnlyTeamPayload(payload fleet.TeamPayload) bool {
	if payload.MDM == nil {
		return false
	}
	if payload.MDM.MacOSUpdates == nil && payload.MDM.IOSUpdates == nil &&
		payload.MDM.IPadOSUpdates == nil && payload.MDM.WindowsUpdates == nil {
		return false
	}
	if payload.Name != nil || payload.Description != nil || payload.Secrets != nil ||
		payload.WebhookSettings != nil || payload.Integrations != nil ||
		payload.HostExpirySettings != nil || payload.Features != nil {
		return false
	}
	mdm := payload.MDM
	return !mdm.EnableDiskEncryption.Valid &&
		!mdm.EnableRecoveryLockPassword.Valid &&
		!mdm.RequireBitLockerPIN.Valid &&
		mdm.MacOSSetup == nil &&
		!mdm.HostNameTemplate.Set &&
		mdm.MacOSSettings == nil &&
		mdm.WindowsSettings == nil &&
		mdm.LinuxSettings == nil
}

func appleOSSettingsTouched(s *fleet.AppleOSUpdateSettings) bool {
	return s.MinimumVersion.Set || s.Deadline.Set || s.DeadlineDays.Set || s.UpdateNewHosts.Set
}

func windowsOSSettingsTouched(s *fleet.WindowsUpdates) bool {
	return s.DeadlineDays.Set || s.GracePeriodDays.Set
}

func appleOSSettingsEqual(a, b fleet.AppleOSUpdateSettings) bool {
	return a.MinimumVersion == b.MinimumVersion &&
		a.Deadline == b.Deadline &&
		a.DeadlineDays == b.DeadlineDays &&
		a.UpdateNewHosts == b.UpdateNewHosts
}

func appleDeviceKey(device fleet.AppleDevice) string {
	switch device {
	case fleet.MacOS:
		return "macos"
	case fleet.IOS:
		return "ios"
	case fleet.IPadOS:
		return "ipados"
	default:
		return ""
	}
}

func appleUpdateActivity(team *fleet.Team, device fleet.AppleDevice, settings fleet.AppleOSUpdateSettings) fleet.ActivityDetails {
	switch device {
	case fleet.MacOS:
		return fleet.ActivityTypeEditedMacOSMinVersion{
			TeamID:         &team.ID,
			TeamName:       &team.Name,
			MinimumVersion: settings.MinimumVersion.Value,
			Deadline:       settings.Deadline.Value,
		}
	case fleet.IOS:
		return fleet.ActivityTypeEditedIOSMinVersion{
			TeamID:         &team.ID,
			TeamName:       &team.Name,
			MinimumVersion: settings.MinimumVersion.Value,
			Deadline:       settings.Deadline.Value,
		}
	case fleet.IPadOS:
		return fleet.ActivityTypeEditedIPadOSMinVersion{
			TeamID:         &team.ID,
			TeamName:       &team.Name,
			MinimumVersion: settings.MinimumVersion.Value,
			Deadline:       settings.Deadline.Value,
		}
	default:
		panic("unsupported Apple device type")
	}
}
