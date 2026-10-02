package servicecompat

import (
	"context"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/communityplus/diskencryption"
	"github.com/fleetdm/fleet/v4/server/communityplus/hostnaming"
	"github.com/fleetdm/fleet/v4/server/communityplus/osupdates"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

// installCommunityPlusOverrides wires the small number of standard service
// call-sites that still dispatch through Fleet's historical EnterpriseOverrides
// table. Community+ runs with Fleet's free-license identity, so these callbacks
// must not depend on license.IsPremium().
func installCommunityPlusOverrides(svc fleet.Service, options []any) {
	if svc == nil {
		return
	}

	var ds fleet.Datastore
	var cfg *config.FleetConfig
	for _, option := range options {
		switch value := option.(type) {
		case fleet.Datastore:
			ds = value
		case *config.FleetConfig:
			cfg = value
		}
	}
	if ds == nil {
		return
	}

	var disk *diskencryption.Service
	if cfg != nil {
		if value, err := diskencryption.New(ds, authz.Must(), svc, cfg); err == nil {
			disk = value
		}
	}
	svc.SetEnterpriseOverrides(newCommunityPlusOverrides(svc, ds, disk))
}

// newCommunityPlusOverrides always returns a fully-populated callback table.
// Some core service paths only check that EnterpriseOverrides itself is non-nil
// before invoking a callback, so leaving unsupported entries nil would turn a
// clean feature-gate error into a runtime panic.
func newCommunityPlusOverrides(svc fleet.Service, ds fleet.Datastore, diskServices ...*diskencryption.Service) fleet.EnterpriseOverrides {
	deleteSetupAssistant := func(context.Context, *uint) error { return fleet.ErrMissingLicense }
	deleteBootstrapPackage := func(context.Context, *uint, bool) error { return fleet.ErrMissingLicense }
	updateTeamHostNameTemplate := func(context.Context, *fleet.Team, string) error { return fleet.ErrMissingLicense }
	applyHostNameTemplateChange := func(context.Context, *fleet.Team, string) error { return fleet.ErrMissingLicense }
	teamByIDOrName := func(context.Context, *uint, *string) (*fleet.Team, error) { return nil, fleet.ErrMissingLicense }
	updateTeamDiskEncryption := func(context.Context, *fleet.Team, fleet.DiskEncryptionSettingsChanges, *bool) error {
		return fleet.ErrMissingLicense
	}
	reconcileFileVault := func(context.Context, *uint) error { return fleet.ErrMissingLicense }
	windowsEnableOSUpdates := func(context.Context, *uint, fleet.WindowsUpdates) error { return fleet.ErrMissingLicense }
	windowsDisableOSUpdates := func(context.Context, *uint) error { return fleet.ErrMissingLicense }
	appleEditedOSUpdates := func(context.Context, *uint, fleet.AppleDevice, fleet.AppleOSUpdateSettings) error {
		return fleet.ErrMissingLicense
	}

	if svc != nil {
		deleteSetupAssistant = svc.DeleteMDMAppleSetupAssistant
		deleteBootstrapPackage = svc.DeleteMDMAppleBootstrapPackage
		if hostNaming, err := hostnaming.New(ds, svc); err == nil {
			updateTeamHostNameTemplate = hostNaming.UpdateTeam
			applyHostNameTemplateChange = hostNaming.Apply
		}
	}
	if len(diskServices) > 0 && diskServices[0] != nil {
		disk := diskServices[0]
		teamByIDOrName = disk.TeamByIDOrName
		updateTeamDiskEncryption = disk.UpdateTeam
		reconcileFileVault = disk.ReconcileFileVault
	}
	if updates, err := osupdates.New(ds); err == nil {
		windowsEnableOSUpdates = updates.WindowsEnable
		windowsDisableOSUpdates = updates.WindowsDisable
		appleEditedOSUpdates = updates.AppleEdited
	}

	return fleet.EnterpriseOverrides{
		HostFeatures: func(ctx context.Context, _ *fleet.Host) (*fleet.Features, error) {
			appConfig, err := ds.AppConfig(ctx)
			if err != nil {
				return nil, err
			}
			return &appConfig.Features, nil
		},
		TeamByIDOrName:                    teamByIDOrName,
		UpdateTeamMDMDiskEncryption:       updateTeamDiskEncryption,
		UpdateTeamMDMHostNameTemplate:     updateTeamHostNameTemplate,
		ApplyHostNameTemplateChange:       applyHostNameTemplateChange,
		MDMAppleReconcileFileVaultProfile: reconcileFileVault,
		DeleteMDMAppleSetupAssistant:      deleteSetupAssistant,
		MDMAppleSyncDEPProfiles: func(context.Context) error {
			return fleet.ErrMissingLicense
		},
		DeleteMDMAppleBootstrapPackage: deleteBootstrapPackage,
		MDMWindowsEnableOSUpdates:      windowsEnableOSUpdates,
		MDMWindowsDisableOSUpdates:     windowsDisableOSUpdates,
		MDMAppleEditedAppleOSUpdates:   appleEditedOSUpdates,
		SetupExperienceNextStep: func(context.Context, *fleet.Host) (bool, error) {
			return false, fleet.ErrMissingLicense
		},
		GetVPPTokenIfCanInstallVPPApps: func(context.Context, bool, *fleet.Host) (string, error) {
			return "", fleet.ErrMissingLicense
		},
		InstallVPPAppPostValidation: func(context.Context, *fleet.Host, *fleet.VPPApp, string, fleet.HostSoftwareInstallOptions) (string, error) {
			return "", fleet.ErrMissingLicense
		},
	}
}
