package setupexperience

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/optjson"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/nanodep/godep"
	fleetmock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

func boolPtr(v bool) *bool       { return &v }
func stringPtr(v string) *string { return &v }

func TestValidateEnvironmentRequiresAppleMDM(t *testing.T) {
	svc := &Service{}
	cfg := &fleet.AppConfig{}
	err := svc.validateEnvironment(context.Background(), cfg, fleet.MDMAppleSetupPayload{RequireAllSoftware: boolPtr(true)})
	require.ErrorIs(t, err, fleet.ErrMDMNotConfigured)
}

func TestValidateEnvironmentRequiresWindowsMDM(t *testing.T) {
	svc := &Service{}
	cfg := &fleet.AppConfig{}
	cfg.MDM.EnabledAndConfigured = true
	err := svc.validateEnvironment(context.Background(), cfg, fleet.MDMAppleSetupPayload{RequireAllSoftwareWindows: boolPtr(true)})
	require.ErrorIs(t, err, fleet.ErrWindowsMDMNotConfigured)
}

func TestValidateEnvironmentRejectsCustomConfigurationWebURLWithEUA(t *testing.T) {
	ds := new(fleetmock.Store)
	profileJSON, err := json.Marshal(godep.Profile{ConfigurationWebURL: "https://custom.example/setup"})
	require.NoError(t, err)
	ds.GetMDMAppleSetupAssistantFunc = func(context.Context, *uint) (*fleet.MDMAppleSetupAssistant, error) {
		return &fleet.MDMAppleSetupAssistant{Profile: profileJSON}, nil
	}
	svc := &Service{ds: ds}
	cfg := &fleet.AppConfig{}
	cfg.MDM.EnabledAndConfigured = true
	cfg.MDM.EndUserAuthentication.SSOProviderSettings = fleet.SSOProviderSettings{EntityID: "https://idp.example"}

	err = svc.validateEnvironment(context.Background(), cfg, fleet.MDMAppleSetupPayload{EnableEndUserAuthentication: boolPtr(true)})
	require.Error(t, err)
}

func TestApplySynchronizesEndUserLock(t *testing.T) {
	svc := &Service{}
	setup := &fleet.MacOSSetup{}
	payload := fleet.MDMAppleSetupPayload{
		EnableEndUserAuthentication: boolPtr(true),
		RequireAllSoftware:          boolPtr(true),
		EnableReleaseDeviceManually: boolPtr(true),
		EnableManagedLocalAccount:   boolPtr(true),
		EndUserLocalAccountType:     stringPtr("standard"),
	}

	require.NoError(t, svc.apply(context.Background(), setup, payload))
	require.True(t, setup.EnableEndUserAuthentication)
	require.True(t, setup.LockEndUserInfo.Valid)
	require.True(t, setup.LockEndUserInfo.Value)
	require.True(t, setup.RequireAllSoftware)
	require.True(t, setup.EnableReleaseDeviceManually.Value)
	require.True(t, setup.EnableManagedLocalAccount.Value)
	require.Equal(t, "standard", setup.EndUserLocalAccountType.Value)
}

func TestApplyRejectsLockedEndUserInfoWithoutAuthentication(t *testing.T) {
	svc := &Service{}
	setup := &fleet.MacOSSetup{}
	err := svc.apply(context.Background(), setup, fleet.MDMAppleSetupPayload{LockEndUserInfo: boolPtr(true)})
	require.Error(t, err)
}

func TestApplyRejectsUnsupportedLocalAccountType(t *testing.T) {
	svc := &Service{}
	setup := &fleet.MacOSSetup{}
	err := svc.apply(context.Background(), setup, fleet.MDMAppleSetupPayload{EndUserLocalAccountType: stringPtr("root")})
	require.Error(t, err)
	var invalid *fleet.InvalidArgumentError
	require.True(t, errors.As(err, &invalid))
}

func TestValidateSetupExperienceSoftwarePlatform(t *testing.T) {
	for _, platform := range []string{"darwin", "windows", "linux", "ios", "ipados", "android", "darwin,windows"} {
		require.NoError(t, validateSetupExperienceSoftwarePlatform(platform), platform)
	}
	for _, platform := range []string{"", "freebsd", "windows,freebsd"} {
		require.Error(t, validateSetupExperienceSoftwarePlatform(platform), platform)
	}
}

func TestSetupExperienceSoftwareTeamUsesGlobalConfig(t *testing.T) {
	ds := new(fleetmock.Store)
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		cfg := &fleet.AppConfig{}
		cfg.MDM.MacOSSetup.ManualAgentInstall = optjson.SetBool(true)
		return cfg, nil
	}
	svc := &Service{ds: ds}
	name, setup, err := svc.setupExperienceSoftwareTeam(context.Background(), 0)
	require.NoError(t, err)
	require.Empty(t, name)
	require.NotNil(t, setup)
	require.True(t, setup.ManualAgentInstall.Valid)
	require.True(t, setup.ManualAgentInstall.Value)
}

func TestSetupExperienceSoftwareTeamUsesFleetConfig(t *testing.T) {
	ds := new(fleetmock.Store)
	ds.TeamWithExtrasFunc = func(context.Context, uint) (*fleet.Team, error) {
		team := &fleet.Team{ID: 7, Name: "Workstations"}
		team.Config.MDM.MacOSSetup.ManualAgentInstall = optjson.SetBool(false)
		return team, nil
	}
	svc := &Service{ds: ds}
	name, setup, err := svc.setupExperienceSoftwareTeam(context.Background(), 7)
	require.NoError(t, err)
	require.Equal(t, "Workstations", name)
	require.NotNil(t, setup)
	require.True(t, setup.ManualAgentInstall.Valid)
	require.False(t, setup.ManualAgentInstall.Value)
}
