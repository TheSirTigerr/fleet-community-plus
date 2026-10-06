// Package setupexperience implements Community+ setup-experience configuration.
package setupexperience

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/nanodep/godep"
)

type Service struct {
	ds         fleet.Datastore
	authorizer *authz.Authorizer
}

func New(ds fleet.Datastore, authorizer *authz.Authorizer) (*Service, error) {
	if ds == nil {
		return nil, errors.New("setup experience datastore is nil")
	}
	if authorizer == nil {
		return nil, errors.New("setup experience authorizer is nil")
	}
	return &Service{ds: ds, authorizer: authorizer}, nil
}

// UpdateAppleSetup applies the setup-experience settings accepted by Fleet's
// public service contract without relying on Fleet's Premium service.
func (s *Service) UpdateAppleSetup(ctx context.Context, payload fleet.MDMAppleSetupPayload) error {
	if err := s.authorizer.Authorize(ctx, payload, fleet.ActionWrite); err != nil {
		return err
	}

	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("load app config for setup experience: %w", err)
	}
	if err := s.validateEnvironment(ctx, appConfig, payload); err != nil {
		return err
	}

	if payload.TeamID != nil && *payload.TeamID != 0 {
		team, err := s.ds.TeamWithExtras(ctx, *payload.TeamID)
		if err != nil {
			return fmt.Errorf("load fleet for setup experience: %w", err)
		}
		if err := s.apply(ctx, &team.Config.MDM.MacOSSetup, payload); err != nil {
			return err
		}
		if _, err := s.ds.SaveTeam(ctx, team); err != nil {
			return fmt.Errorf("save fleet setup experience: %w", err)
		}
		return nil
	}

	if err := s.apply(ctx, &appConfig.MDM.MacOSSetup, payload); err != nil {
		return err
	}
	if err := s.ds.SaveAppConfig(ctx, appConfig); err != nil {
		return fmt.Errorf("save global setup experience: %w", err)
	}
	return nil
}

func (s *Service) validateEnvironment(ctx context.Context, appConfig *fleet.AppConfig, payload fleet.MDMAppleSetupPayload) error {
	if appConfig == nil {
		return errors.New("app config is nil")
	}

	// End-user authentication can be disabled even after Apple MDM is turned
	// off. Every other setup-experience option requires active Apple MDM.
	if (payload.RequireAllSoftware != nil || payload.EnableReleaseDeviceManually != nil ||
		payload.ManualAgentInstall != nil || payload.EnableManagedLocalAccount != nil ||
		payload.EndUserLocalAccountType != nil || payload.LockEndUserInfo != nil) &&
		!appConfig.MDM.EnabledAndConfigured {
		return fleet.ErrMDMNotConfigured
	}

	if payload.RequireAllSoftwareWindows != nil && *payload.RequireAllSoftwareWindows && !appConfig.MDM.WindowsEnabledAndConfigured {
		return fleet.ErrWindowsMDMNotConfigured
	}

	if payload.EnableEndUserAuthentication != nil && *payload.EnableEndUserAuthentication {
		if appConfig.MDM.EndUserAuthentication.IsEmpty() {
			return fleet.NewInvalidArgumentError(
				"enable_end_user_authentication",
				"Couldn't enable setup_experience.enable_end_user_authentication because no IdP is configured for MDM features.",
			)
		}
		hasCustomWebURL, err := s.hasCustomConfigurationWebURL(ctx, payload.TeamID)
		if err != nil {
			return err
		}
		if hasCustomWebURL {
			return fleet.NewInvalidArgumentError("setup_experience.enable_end_user_authentication", fleet.EndUserAuthDEPWebURLConfiguredErrMsg)
		}
	}
	return nil
}

func (s *Service) hasCustomConfigurationWebURL(ctx context.Context, teamID *uint) (bool, error) {
	assistant, err := s.ds.GetMDMAppleSetupAssistant(ctx, teamID)
	if err != nil {
		if fleet.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("load Apple setup assistant: %w", err)
	}
	if assistant == nil || len(assistant.Profile) == 0 {
		return false, nil
	}
	var profile godep.Profile
	if err := json.Unmarshal(assistant.Profile, &profile); err != nil {
		return false, fmt.Errorf("parse Apple setup assistant profile: %w", err)
	}
	return profile.ConfigurationWebURL != "", nil
}

func (s *Service) apply(ctx context.Context, setup *fleet.MacOSSetup, payload fleet.MDMAppleSetupPayload) error {
	if setup == nil {
		return errors.New("setup experience config is nil")
	}

	endUserAuthChanged := false
	if payload.EnableEndUserAuthentication != nil && setup.EnableEndUserAuthentication != *payload.EnableEndUserAuthentication {
		setup.EnableEndUserAuthentication = *payload.EnableEndUserAuthentication
		endUserAuthChanged = true
	}
	if payload.LockEndUserInfo != nil {
		setup.LockEndUserInfo = optjson.SetBool(*payload.LockEndUserInfo)
	} else if endUserAuthChanged {
		setup.LockEndUserInfo = optjson.SetBool(setup.EnableEndUserAuthentication)
	}
	if setup.LockEndUserInfo.Value && !setup.EnableEndUserAuthentication {
		return fleet.NewUserMessageError(
			errors.New(`Couldn't edit. "enable_end_user_authentication" must be set to "true" in order to enable "lock_end_user_info".`),
			http.StatusUnprocessableEntity,
		)
	}

	if payload.RequireAllSoftware != nil {
		setup.RequireAllSoftware = *payload.RequireAllSoftware
	}
	if payload.RequireAllSoftwareWindows != nil {
		setup.RequireAllSoftwareWindows = *payload.RequireAllSoftwareWindows
	}
	if payload.EnableReleaseDeviceManually != nil {
		setup.EnableReleaseDeviceManually = optjson.SetBool(*payload.EnableReleaseDeviceManually)
	}
	if payload.EnableManagedLocalAccount != nil {
		setup.EnableManagedLocalAccount = optjson.SetBool(*payload.EnableManagedLocalAccount)
	}

	if payload.ManualAgentInstall != nil {
		if *payload.ManualAgentInstall {
			if !setup.BootstrapPackage.Valid || setup.BootstrapPackage.Value == "" {
				return fleet.NewUserMessageError(
					errors.New("Couldn’t enable macos_manual_agent_install. To use this option, first specify a macos_bootstrap_package."),
					http.StatusUnprocessableEntity,
				)
			}
			counts, err := s.ds.GetSetupExperienceCount(ctx, string(fleet.MacOSPlatform), payload.TeamID)
			if err != nil {
				return fmt.Errorf("load setup experience contents: %w", err)
			}
			if counts.Installers != 0 || counts.VPP != 0 || counts.InHouseApps != 0 {
				return fleet.NewUserMessageError(
					errors.New("Couldn’t enable macos_manual_agent_install. To use this option, first disable setup experience software."),
					http.StatusUnprocessableEntity,
				)
			}
			if counts.Scripts != 0 {
				return fleet.NewUserMessageError(
					errors.New("Couldn’t enable macos_manual_agent_install. To use this option, first remove your setup experience script."),
					http.StatusUnprocessableEntity,
				)
			}
		}
		setup.ManualAgentInstall = optjson.SetBool(*payload.ManualAgentInstall)
	}

	if _, err := payload.Validate(setup); err != nil {
		return err
	}
	return nil
}

func setupExperienceSoftwareTeamID(teamID uint) *uint {
	if teamID == 0 {
		return nil
	}
	return &teamID
}

func validateSetupExperienceSoftwarePlatform(platforms string) error {
	if strings.TrimSpace(platforms) == "" {
		return fmt.Errorf("setup experience software platform is required")
	}
	for platform := range strings.SplitSeq(platforms, ",") {
		switch strings.TrimSpace(platform) {
		case string(fleet.MacOSPlatform), "windows", "linux", string(fleet.IOSPlatform), string(fleet.IPadOSPlatform), string(fleet.AndroidPlatform):
			// supported
		default:
			return fmt.Errorf("unsupported setup experience software platform %q", platform)
		}
	}
	return nil
}

func (s *Service) setupExperienceSoftwareTeam(ctx context.Context, teamID uint) (string, *fleet.MacOSSetup, error) {
	if teamID == 0 {
		cfg, err := s.ds.AppConfig(ctx)
		if err != nil {
			return "", nil, fmt.Errorf("load app config for setup experience software: %w", err)
		}
		if cfg == nil {
			return "", nil, errors.New("app config is nil")
		}
		return "", &cfg.MDM.MacOSSetup, nil
	}

	team, err := s.ds.TeamWithExtras(ctx, teamID)
	if err != nil {
		return "", nil, fmt.Errorf("load fleet for setup experience software: %w", err)
	}
	return team.Name, &team.Config.MDM.MacOSSetup, nil
}

// SetSoftware replaces the software selected for one platform during setup experience.
func (s *Service) SetSoftware(ctx context.Context, platform string, teamID uint, titleIDs []uint) (string, error) {
	if err := validateSetupExperienceSoftwarePlatform(platform); err != nil {
		return "", err
	}

	target := &fleet.SoftwareInstaller{TeamID: setupExperienceSoftwareTeamID(teamID)}
	if err := s.authorizer.Authorize(ctx, target, fleet.ActionWrite); err != nil {
		return "", err
	}

	teamName, setup, err := s.setupExperienceSoftwareTeam(ctx, teamID)
	if err != nil {
		return "", err
	}
	if platform == string(fleet.MacOSPlatform) && len(titleIDs) > 0 &&
		setup.ManualAgentInstall.Valid && setup.ManualAgentInstall.Value {
		return "", fleet.NewUserMessageError(
			errors.New("Couldn’t add setup experience software while macos_manual_agent_install is enabled. Disable macos_manual_agent_install first."),
			http.StatusUnprocessableEntity,
		)
	}

	if err := s.ds.SetSetupExperienceSoftwareTitles(ctx, platform, teamID, titleIDs); err != nil {
		return "", fmt.Errorf("set setup experience software: %w", err)
	}
	return teamName, nil
}

// ListSoftware returns software eligible for setup experience using Fleet's existing datastore contract.
func (s *Service) ListSoftware(
	ctx context.Context,
	platform string,
	teamID uint,
	opts fleet.ListOptions,
) ([]fleet.SoftwareTitleListResult, int, *fleet.PaginationMetadata, error) {
	if err := validateSetupExperienceSoftwarePlatform(platform); err != nil {
		return nil, 0, nil, err
	}

	target := &fleet.SoftwareInstaller{TeamID: setupExperienceSoftwareTeamID(teamID)}
	if err := s.authorizer.Authorize(ctx, target, fleet.ActionRead); err != nil {
		return nil, 0, nil, err
	}

	return s.ds.ListSetupExperienceSoftwareTitles(ctx, platform, teamID, opts)
}
