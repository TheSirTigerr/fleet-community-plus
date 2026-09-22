package service

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/contexts/license"
	"github.com/fleetdm/fleet/v4/server/fleet"
	fleet_mock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

type communityPlusTestAuth struct {
	email string
	name  string
}

func (a communityPlusTestAuth) UserID() string                             { return a.email }
func (a communityPlusTestAuth) UserDisplayName() string                    { return a.name }
func (a communityPlusTestAuth) AssertionAttributes() []fleet.SAMLAttribute { return nil }

type communityPlusNotFoundError struct{}

func (communityPlusNotFoundError) Error() string    { return "not found" }
func (communityPlusNotFoundError) IsNotFound() bool { return true }

func newCommunityPlusJITTestService(t *testing.T, ds *fleet_mock.Store) *Service {
	t.Helper()
	authorizer, err := authz.NewAuthorizer()
	require.NoError(t, err)
	svc := &Service{
		ds:     ds,
		authz:  authorizer,
		config: config.TestConfig(),
	}
	svc.SetActivityService(&fleet_mock.MockActivityService{})
	return svc
}

func TestCommunityPlusGetSSOUserJITProvisioning(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})

	ds.UserByEmailFunc = func(context.Context, string) (*fleet.User, error) {
		return nil, communityPlusNotFoundError{}
	}
	var created *fleet.User
	ds.NewUserFunc = func(_ context.Context, user *fleet.User) (*fleet.User, error) {
		user.ID = 42
		created = user
		return user, nil
	}

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{
		email: "  USER@Example.COM ",
		name:  "Example User",
	}, true)
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Same(t, created, user)
	require.Equal(t, uint(42), user.ID)
	require.Equal(t, "user@example.com", user.Email)
	require.Equal(t, "Example User", user.Name)
	require.True(t, user.SSOEnabled)
	require.NotNil(t, user.GlobalRole)
	require.Equal(t, fleet.RoleObserver, *user.GlobalRole)
	require.False(t, user.AdminForcedPasswordReset)
}

func TestCommunityPlusGetSSOUserJITDisabled(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})

	ds.UserByEmailFunc = func(context.Context, string) (*fleet.User, error) {
		return nil, communityPlusNotFoundError{}
	}

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{email: "user@example.com"}, false)
	require.Error(t, err)
	require.Nil(t, user)
	require.False(t, ds.NewUserFuncInvoked)
}

func TestCommunityPlusGetSSOUserKeepsExistingUser(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})
	existing := &fleet.User{ID: 7, Email: "user@example.com", SSOEnabled: true}

	ds.UserByEmailFunc = func(_ context.Context, email string) (*fleet.User, error) {
		require.Equal(t, "user@example.com", email)
		return existing, nil
	}

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{email: "USER@example.com"}, true)
	require.NoError(t, err)
	require.Same(t, existing, user)
	require.False(t, ds.NewUserFuncInvoked)
}
