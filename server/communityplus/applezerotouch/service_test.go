package applezerotouch

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	apple_mdm "github.com/fleetdm/fleet/v4/server/mdm/apple"
	fleetmock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

func testContext(role string) context.Context {
	return viewer.NewContext(context.Background(), viewer.Viewer{User: &fleet.User{GlobalRole: &role}})
}

func testService(t *testing.T) (*Service, *fleetmock.Store) {
	t.Helper()
	ds := new(fleetmock.Store)
	ds.GetABMTokenOrgNamesAssociatedWithTeamFunc = func(context.Context, *uint) ([]string, error) {
		return nil, nil
	}
	dep := apple_mdm.NewDEPService(ds, nil, slog.New(slog.DiscardHandler))
	svc, err := New(ds, dep, authz.Must())
	require.NoError(t, err)
	return svc, ds
}

func TestSetupAssistantCRUDAndAuthorization(t *testing.T) {
	svc, ds := testService(t)
	stored := &fleet.MDMAppleSetupAssistant{
		ID:      7,
		Name:    "ADE profile",
		Profile: []byte(`{"profile_name":"ADE profile","is_supervised":true}`),
	}
	ds.SetOrUpdateMDMAppleSetupAssistantFunc = func(_ context.Context, got *fleet.MDMAppleSetupAssistant) (*fleet.MDMAppleSetupAssistant, error) {
		require.Equal(t, stored.Name, got.Name)
		return stored, nil
	}
	ds.GetMDMAppleSetupAssistantFunc = func(context.Context, *uint) (*fleet.MDMAppleSetupAssistant, error) {
		return stored, nil
	}
	deleted := false
	ds.DeleteMDMAppleSetupAssistantFunc = func(context.Context, *uint) error {
		deleted = true
		return nil
	}

	adminCtx := testContext(fleet.RoleAdmin)
	got, err := svc.SetOrUpdateSetupAssistant(adminCtx, &fleet.MDMAppleSetupAssistant{Name: stored.Name, Profile: stored.Profile})
	require.NoError(t, err)
	require.Equal(t, stored, got)

	got, err = svc.GetSetupAssistant(adminCtx, nil)
	require.NoError(t, err)
	require.Equal(t, stored, got)

	require.NoError(t, svc.DeleteSetupAssistant(adminCtx, nil))
	require.True(t, deleted)

	observerCtx := testContext(fleet.RoleObserver)
	_, err = svc.SetOrUpdateSetupAssistant(observerCtx, &fleet.MDMAppleSetupAssistant{Name: stored.Name, Profile: stored.Profile})
	require.Error(t, err)
}

func TestSetupAssistantRejectsInvalidDEPJSON(t *testing.T) {
	svc, ds := testService(t)
	_, err := svc.SetOrUpdateSetupAssistant(testContext(fleet.RoleAdmin), &fleet.MDMAppleSetupAssistant{
		Name:    "broken",
		Profile: []byte(`{"profile_name":`),
	})
	require.ErrorContains(t, err, "invalid Apple ADE enrollment profile")
	require.False(t, ds.SetOrUpdateMDMAppleSetupAssistantFuncInvoked)
}

func TestDefaultSetupAssistantProfile(t *testing.T) {
	svc, ds := testService(t)
	updatedAt := time.Unix(1_800_000_000, 0).UTC()
	ds.GetMDMAppleEnrollmentProfileByTypeFunc = func(_ context.Context, typ fleet.MDMAppleEnrollmentType) (*fleet.MDMAppleEnrollmentProfile, error) {
		require.Equal(t, fleet.MDMAppleEnrollmentTypeAutomatic, typ)
		return &fleet.MDMAppleEnrollmentProfile{UpdateCreateTimestamps: fleet.UpdateCreateTimestamps{UpdatedAt: updatedAt}}, nil
	}

	profile, gotUpdatedAt, err := svc.GetDefaultSetupAssistantProfile(testContext(fleet.RoleMaintainer))
	require.NoError(t, err)
	require.Equal(t, "Fleet default enrollment profile", profile.ProfileName)
	require.True(t, profile.IsSupervised)
	require.NotNil(t, gotUpdatedAt)
	require.Equal(t, updatedAt, *gotUpdatedAt)
}
