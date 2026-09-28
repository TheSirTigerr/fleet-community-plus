package servicecompat

import (
	"context"

	"github.com/fleetdm/fleet/v4/server/communityplus/hostnaming"
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
	for _, option := range options {
		if value, ok := option.(fleet.Datastore); ok {
			ds = value
			break
		}
	}
	if ds == nil {
		return
	}

	svc.SetEnterpriseOverrides(newCommunityPlusOverrides(svc, ds))
}

// newCommunityPlusOverrides always returns a fully-populated callback table.
// Some core service paths only check that EnterpriseOverrides itself is non-nil
// before invoking a callback, so leaving unsupported entries nil would turn a
// clean feature-gate error into a runtime panic.
func newCommunityPlusOverrides(svc fleet.Service, ds fleet.Datastore) fleet.EnterpriseOverrides {
	deleteSetupAssistant := func(context.Context, *uint) error { return fleet.ErrMissingLicense }
	deleteBootstrapPackage := func(context.Context, *uint, bool) error { return fleet.ErrMissingLicense }
	updateTeamHostNameTemplate := func(context.Context, *fleet.Team, string) error { return fleet.ErrMissingLicense }
	applyHostNameTemplateChange := func(context.Context, *fleet.Team, string) error { return fleet.ErrMissingLicense }
	if svc != nil {
		deleteSetupAssistant = svc.DeleteMDMAppleSetupAssistant
		deleteBootstrapPackage = svc.DeleteMDMAppleBootstrapPackage
		if hostNaming, err := hostnaming.New(ds, svc); err == nil {
			updateTeamHostNameTemplate = hostNaming.UpdateTeam
			applyHostNameTemplateChange = hostNaming.Apply
		}
	}

	return fleet.EnterpriseOverrides{
		HostFeatures: func(ctx context.Context, _ *fleet.Host) (*fleet.Features, error) {
			appConfig, err := ds.AppConfig(ctx)
			if err != nil {
				return nil, err
			}
			return &appConfig.Features, nil
		},
		TeamByIDOrName: func(context.Context, *uint, *string) (*fleet.Team, error) {
			return nil, fleet.ErrMissingLicense
		},
		UpdateTeamMDMDiskEncryption: func(context.Context, *fleet.Team, fleet.DiskEncryptionSettingsChanges, *bool) error {
			return fleet.ErrMissingLicense
		},
		UpdateTeamMDMHostNameTemplate: updateTeamHostNameTemplate,
		ApplyHostNameTemplateChange:   applyHostNameTemplateChange,
		MDMAppleReconcileFileVaultProfile: func(context.Context, *uint) error {
			return fleet.ErrMissingLicense
		},
		DeleteMDMAppleSetupAssistant: deleteSetupAssistant,
		MDMAppleSyncDEPProfiles: func(context.Context) error {
			return fleet.ErrMissingLicense
		},
		DeleteMDMAppleBootstrapPackage: deleteBootstrapPackage,
		MDMWindowsEnableOSUpdates: func(context.Context, *uint, fleet.WindowsUpdates) error {
			return fleet.ErrMissingLicense
		},
		MDMWindowsDisableOSUpdates: func(context.Context, *uint) error {
			return fleet.ErrMissingLicense
		},
		MDMAppleEditedAppleOSUpdates: func(context.Context, *uint, fleet.AppleDevice, fleet.AppleOSUpdateSettings) error {
			return fleet.ErrMissingLicense
		},
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
