package setupexperience

import (
	"context"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/stretchr/testify/require"
)

func boolPtr(v bool) *bool { return &v }
func stringPtr(v string) *string { return &v }

func TestValidateEnvironmentRequiresAppleMDM(t *testing.T) {
	cfg := &fleet.AppConfig{}
	err := validateEnvironment(cfg, fleet.MDMAppleSetupPayload{RequireAllSoftware: boolPtr(true)})
	require.ErrorIs(t, err, fleet.ErrMDMNotConfigured)
}

func TestValidateEnvironmentRequiresWindowsMDM(t *testing.T) {
	cfg := &fleet.AppConfig{}
	cfg.MDM.EnabledAndConfigured = true
	err := validateEnvironment(cfg, fleet.MDMAppleSetupPayload{RequireAllSoftwareWindows: boolPtr(true)})
	require.ErrorIs(t, err, fleet.ErrWindowsMDMNotConfigured)
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

func TestApplyRejectsLocalAccountTypeWithoutManagedAccount(t *testing.T) {
	svc := &Service{}
	setup := &fleet.MacOSSetup{}
	err := svc.apply(context.Background(), setup, fleet.MDMAppleSetupPayload{EndUserLocalAccountType: stringPtr("admin")})
	require.Error(t, err)
	var invalid *fleet.InvalidArgumentError
	require.True(t, errors.As(err, &invalid))
}
