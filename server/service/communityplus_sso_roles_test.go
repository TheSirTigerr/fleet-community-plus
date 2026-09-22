package service

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/server/contexts/license"
	"github.com/fleetdm/fleet/v4/server/fleet"
	fleet_mock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

func TestCommunityPlusSyncSSORolesProtectsLastGlobalAdmin(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})

	adminRole := fleet.RoleAdmin
	observerRole := fleet.RoleObserver
	user := &fleet.User{
		ID:         7,
		Email:      "admin@example.com",
		SSOEnabled: true,
		GlobalRole: &adminRole,
	}

	ds.SaveUserIfNotLastAdminFunc = func(context.Context, *fleet.User) error {
		return fleet.ErrLastGlobalAdmin
	}

	err := svc.communityPlusSyncSSORoles(ctx, user, &observerRole, nil)
	require.ErrorIs(t, err, fleet.ErrLastGlobalAdmin)
	require.NotNil(t, user.GlobalRole)
	require.Equal(t, fleet.RoleAdmin, *user.GlobalRole)
	require.Empty(t, user.Teams)
}
