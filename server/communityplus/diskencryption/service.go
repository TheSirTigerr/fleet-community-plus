// Package diskencryption implements Community+ disk-encryption controls.
package diskencryption

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxdb"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/mobileconfig"
	"github.com/fleetdm/fleet/v4/server/mdm/assets"
)

type activityWriter interface {
	NewActivity(context.Context, *fleet.User, fleet.ActivityDetails) error
}

type Service struct {
	ds         fleet.Datastore
	authorizer *authz.Authorizer
	activities activityWriter
	config     *config.FleetConfig
}

func New(ds fleet.Datastore, authorizer *authz.Authorizer, activities activityWriter, cfg *config.FleetConfig) (*Service, error) {
	if ds == nil {
		return nil, errors.New("disk encryption datastore is nil")
	}
	if authorizer == nil {
		return nil, errors.New("disk encryption authorizer is nil")
	}
	if activities == nil {
		return nil, errors.New("disk encryption activity service is nil")
	}
	if cfg == nil {
		return nil, errors.New("disk encryption Fleet config is nil")
	}
	return &Service{ds: ds, authorizer: authorizer, activities: activities, config: cfg}, nil
}

func (s *Service) TeamByIDOrName(ctx context.Context, id *uint, name *string) (*fleet.Team, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.Team{}, fleet.ActionRead); err != nil {
		return nil, err
	}
	switch {
	case id != nil:
		return s.ds.TeamWithExtras(ctx, *id)
	case name != nil:
		return s.ds.TeamByName(ctx, *name)
	default:
		return nil, nil
	}
}

func (s *Service) UpdateTeam(ctx context.Context, team *fleet.Team, changes fleet.DiskEncryptionSettingsChanges, requireBitLockerPIN *bool) error {
	if team == nil {
		return &fleet.BadRequestError{Message: "fleet is required for disk encryption update"}
	}

	oldDiskEncryption := team.Config.MDM.DiskEncryptionConfig()
	enabling := false
	apply := func(dst *optjson.Bool, value *bool) bool {
		if value == nil || dst.Value == *value {
			return false
		}
		enabling = enabling || *value
		*dst = optjson.SetBool(*value)
		return true
	}

	macOSChanged := apply(&team.Config.MDM.MacOSSettings.EnableDiskEncryption, changes.MacOSEnable)
	macOSChanged = apply(&team.Config.MDM.MacOSSettings.EnableEscrowDiskEncryptionKey, changes.MacOSEscrow) || macOSChanged
	windowsChanged := apply(&team.Config.MDM.WindowsSettings.EnableDiskEncryption, changes.WindowsEnable)
	linuxChanged := apply(&team.Config.MDM.LinuxSettings.EnableEscrowDiskEncryptionKey, changes.LinuxEscrow)

	if requireBitLockerPIN != nil {
		if oldDiskEncryption.BitLockerPINRequired != *requireBitLockerPIN {
			windowsChanged = true
		}
		team.Config.MDM.RequireBitLockerPIN = *requireBitLockerPIN
		team.Config.MDM.WindowsSettings.RequireBitLockerPIN = optjson.SetBool(*requireBitLockerPIN)
	}

	if !macOSChanged && !windowsChanged && !linuxChanged {
		return nil
	}
	if enabling && s.config.Server.PrivateKey == "" {
		return errors.New("Missing required private key. Learn how to configure the private key here: https://fleetdm.com/learn-more-about/fleet-server-private-key")
	}

	newDiskEncryption := team.Config.MDM.DiskEncryptionConfig()
	if field, message := fleet.BitLockerPINRequirementError(oldDiskEncryption.WindowsEnabled, newDiskEncryption); message != "" {
		return fleet.NewInvalidArgumentError(field, message)
	}

	team.Config.MDM.EnableDiskEncryption = newDiskEncryption.MacOSEnabled && newDiskEncryption.MacOSEscrowEnabled &&
		newDiskEncryption.WindowsEnabled && newDiskEncryption.LinuxEscrowEnabled

	if _, err := s.ds.SaveTeam(ctx, team); err != nil {
		return fmt.Errorf("save fleet disk encryption settings: %w", err)
	}

	if macOSChanged {
		appConfig, err := s.ds.AppConfig(ctx)
		if err != nil {
			return fmt.Errorf("load app config for FileVault reconcile: %w", err)
		}
		if appConfig.MDM.EnabledAndConfigured {
			if err := s.ReconcileFileVault(ctx, &team.ID); err != nil {
				return fmt.Errorf("reconcile fleet FileVault profile: %w", err)
			}
		}
	}

	for _, change := range []struct {
		platform string
		changed  bool
	}{
		{platform: "macos", changed: macOSChanged},
		{platform: "windows", changed: windowsChanged},
		{platform: "linux", changed: linuxChanged},
	} {
		if !change.changed {
			continue
		}
		if err := s.activities.NewActivity(ctx, authz.UserFromContext(ctx), fleet.ActivityTypeEditedDiskEncryptionSettings{
			FleetID:   &team.ID,
			FleetName: &team.Name,
			Platform:  change.platform,
		}); err != nil {
			return fmt.Errorf("record fleet disk encryption activity: %w", err)
		}
	}
	return nil
}

func (s *Service) Summary(ctx context.Context, teamID *uint) (*fleet.MDMDiskEncryptionSummary, error) {
	if err := s.authorizer.Authorize(ctx, fleet.MDMConfigProfileAuthz{TeamID: teamID}, fleet.ActionRead); err != nil {
		return nil, err
	}

	var macOS fleet.MDMAppleFileVaultSummary
	if summary, err := s.ds.GetMDMAppleFileVaultSummary(ctx, teamID); err != nil {
		return nil, fmt.Errorf("get FileVault summary: %w", err)
	} else if summary != nil {
		macOS = *summary
	}

	var windows fleet.MDMWindowsBitLockerSummary
	if summary, err := s.ds.GetMDMWindowsBitLockerSummary(ctx, teamID); err != nil {
		return nil, fmt.Errorf("get BitLocker summary: %w", err)
	} else if summary != nil {
		windows = *summary
	}

	diskEncryption, err := s.ds.GetConfigEnableDiskEncryption(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("get disk encryption config: %w", err)
	}
	var linux fleet.MDMLinuxDiskEncryptionSummary
	if diskEncryption.LinuxEscrowEnabled {
		linux, err = s.ds.GetLinuxDiskEncryptionSummary(ctx, teamID)
		if err != nil {
			return nil, fmt.Errorf("get Linux disk encryption summary: %w", err)
		}
	}

	return &fleet.MDMDiskEncryptionSummary{
		Verified: fleet.MDMPlatformsCounts{MacOS: macOS.Verified, Windows: windows.Verified, Linux: linux.Verified},
		Verifying: fleet.MDMPlatformsCounts{MacOS: macOS.Verifying, Windows: windows.Verifying},
		ActionRequired: fleet.MDMPlatformsCounts{MacOS: macOS.ActionRequired, Windows: windows.ActionRequired, Linux: linux.ActionRequired},
		Enforcing: fleet.MDMPlatformsCounts{MacOS: macOS.Enforcing, Windows: windows.Enforcing},
		Failed: fleet.MDMPlatformsCounts{MacOS: macOS.Failed, Windows: windows.Failed, Linux: linux.Failed},
		RemovingEnforcement: fleet.MDMPlatformsCounts{MacOS: macOS.RemovingEnforcement, Windows: windows.RemovingEnforcement},
	}, nil
}

func (s *Service) ReconcileFileVault(ctx context.Context, teamID *uint) error {
	diskEncryption, err := s.macOSSettings(ctx, teamID)
	if err != nil {
		return fmt.Errorf("read macOS disk encryption settings: %w", err)
	}

	if !diskEncryption.MacOSEnabled && !diskEncryption.MacOSEscrowEnabled {
		err := s.ds.DeleteMDMAppleConfigProfileByTeamAndIdentifier(ctx, teamID, mobileconfig.FleetFileVaultPayloadIdentifier)
		if err != nil && !fleet.IsNotFound(err) {
			return fmt.Errorf("remove FileVault profile: %w", err)
		}
		return nil
	}

	var certB64 string
	if diskEncryption.MacOSEscrowEnabled {
		cert, err := assets.X509Cert(ctx, s.ds, fleet.MDMAssetCACert)
		if err != nil {
			return fmt.Errorf("load FileVault escrow certificate: %w", err)
		}
		certB64 = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	var contents bytes.Buffer
	if err := fileVaultProfileTemplate.Execute(&contents, fileVaultProfileOptions{
		PayloadIdentifier:    mobileconfig.FleetFileVaultPayloadIdentifier,
		PayloadName:          mdm.FleetFileVaultProfileName,
		Base64DerCertificate: certB64,
		EnableEnforcement:    diskEncryption.MacOSEnabled,
		EnableEscrow:         diskEncryption.MacOSEscrowEnabled,
	}); err != nil {
		return fmt.Errorf("render FileVault profile: %w", err)
	}

	profile, err := fleet.NewMDMAppleConfigProfile(contents.Bytes(), teamID)
	if err != nil {
		return fmt.Errorf("build FileVault profile: %w", err)
	}
	if err := s.ds.UpsertMDMAppleFleetConfigProfile(ctx, *profile); err != nil {
		return fmt.Errorf("upsert FileVault profile: %w", err)
	}
	return nil
}

func (s *Service) macOSSettings(ctx context.Context, teamID *uint) (fleet.DiskEncryptionConfig, error) {
	ctx = ctxdb.RequirePrimary(ctx, true)
	if teamID == nil || *teamID == 0 {
		appConfig, err := s.ds.AppConfig(ctx)
		if err != nil {
			return fleet.DiskEncryptionConfig{}, err
		}
		return appConfig.MDM.DiskEncryptionConfig(), nil
	}
	mdmConfig, err := s.ds.TeamMDMConfig(ctx, *teamID)
	if err != nil {
		return fleet.DiskEncryptionConfig{}, err
	}
	return mdmConfig.DiskEncryptionConfig(), nil
}
