package scim

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fleetdm/fleet/v4/server/fleet"
	fleet_mock "github.com/fleetdm/fleet/v4/server/mock"
)

func TestLinkMatchingFleetUserIsDurable(t *testing.T) {
	ds := new(fleet_mock.Store)
	ds.UserByEmailFunc = func(_ context.Context, email string) (*fleet.User, error) {
		require.Equal(t, "user@example.com", email)
		return &fleet.User{ID: 42, Email: email, SSOEnabled: true}, nil
	}
	var scimID, fleetID uint
	ds.SetScimUserFleetUserIDFunc = func(_ context.Context, gotScimID, gotFleetID uint) error {
		scimID, fleetID = gotScimID, gotFleetID
		return nil
	}
	p := &provider{ds: ds}
	user := &fleet.ScimUser{ID: 7, UserName: "USER@Example.COM"}

	require.NoError(t, p.linkMatchingFleetUser(context.Background(), user))
	require.Equal(t, uint(7), scimID)
	require.Equal(t, uint(42), fleetID)
	require.NotNil(t, user.FleetUserID)
	require.Equal(t, uint(42), *user.FleetUserID)
}

func TestDeprovisionDoesNotDeleteLocalUser(t *testing.T) {
	ds := new(fleet_mock.Store)
	fleetUserID := uint(42)
	ds.UserByIDFunc = func(context.Context, uint) (*fleet.User, error) {
		return &fleet.User{ID: fleetUserID, Email: "user@example.com", SSOEnabled: false}, nil
	}
	p := &provider{ds: ds}

	require.NoError(t, p.deprovisionMatchingFleetUser(context.Background(), &fleet.ScimUser{ID: 7, FleetUserID: &fleetUserID}))
	require.False(t, ds.DeleteUserFuncInvoked)
	require.False(t, ds.DeleteUserIfNotLastAdminFuncInvoked)
}

func TestDeprovisionDeletesLinkedSSOUser(t *testing.T) {
	ds := new(fleet_mock.Store)
	fleetUserID := uint(42)
	role := fleet.RoleObserver
	ds.UserByIDFunc = func(context.Context, uint) (*fleet.User, error) {
		return &fleet.User{ID: fleetUserID, Email: "user@example.com", SSOEnabled: true, GlobalRole: &role}, nil
	}
	var deleted uint
	ds.DeleteUserFunc = func(_ context.Context, id uint) error {
		deleted = id
		return nil
	}
	p := &provider{ds: ds}

	require.NoError(t, p.deprovisionMatchingFleetUser(context.Background(), &fleet.ScimUser{ID: 7, FleetUserID: &fleetUserID}))
	require.Equal(t, fleetUserID, deleted)
}

func TestDeprovisionProtectsLastGlobalAdmin(t *testing.T) {
	ds := new(fleet_mock.Store)
	fleetUserID := uint(42)
	role := fleet.RoleAdmin
	ds.UserByIDFunc = func(context.Context, uint) (*fleet.User, error) {
		return &fleet.User{ID: fleetUserID, Email: "admin@example.com", SSOEnabled: true, GlobalRole: &role}, nil
	}
	ds.DeleteUserIfNotLastAdminFunc = func(context.Context, uint) error {
		return fleet.ErrLastGlobalAdmin
	}
	p := &provider{ds: ds}

	require.NoError(t, p.deprovisionMatchingFleetUser(context.Background(), &fleet.ScimUser{ID: 7, FleetUserID: &fleetUserID}))
	require.True(t, ds.DeleteUserIfNotLastAdminFuncInvoked)
	require.False(t, ds.DeleteUserFuncInvoked)
}
