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
	attrs []fleet.SAMLAttribute
}

func (a communityPlusTestAuth) UserID() string          { return a.email }
func (a communityPlusTestAuth) UserDisplayName() string { return a.name }
func (a communityPlusTestAuth) AssertionAttributes() []fleet.SAMLAttribute {
	return append([]fleet.SAMLAttribute(nil), a.attrs...)
}

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

func jitRoleAttribute(name, role string) fleet.SAMLAttribute {
	return fleet.SAMLAttribute{Name: name, Values: []fleet.SAMLAttributeValue{{Value: role}}}
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

func TestCommunityPlusGetSSOUserJITUsesMappedGlobalRole(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})
	ds.UserByEmailFunc = func(context.Context, string) (*fleet.User, error) {
		return nil, communityPlusNotFoundError{}
	}
	var created *fleet.User
	ds.NewUserFunc = func(_ context.Context, user *fleet.User) (*fleet.User, error) {
		user.ID = 43
		created = user
		return user, nil
	}

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{
		email: "admin@example.com",
		attrs: []fleet.SAMLAttribute{jitRoleAttribute("FLEET_JIT_USER_ROLE_GLOBAL", fleet.RoleAdmin)},
	}, true)
	require.NoError(t, err)
	require.Same(t, created, user)
	require.NotNil(t, user.GlobalRole)
	require.Equal(t, fleet.RoleAdmin, *user.GlobalRole)
	require.Empty(t, user.Teams)
}

func TestCommunityPlusGetSSOUserJITUsesMappedFleetRole(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})
	ds.UserByEmailFunc = func(context.Context, string) (*fleet.User, error) {
		return nil, communityPlusNotFoundError{}
	}
	ds.TeamWithExtrasFunc = func(_ context.Context, id uint) (*fleet.Team, error) {
		require.Equal(t, uint(12), id)
		return &fleet.Team{ID: id, Name: "Engineering"}, nil
	}
	var created *fleet.User
	ds.NewUserFunc = func(_ context.Context, user *fleet.User) (*fleet.User, error) {
		user.ID = 44
		created = user
		return user, nil
	}

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{
		email: "fleet-user@example.com",
		attrs: []fleet.SAMLAttribute{jitRoleAttribute("FLEET_JIT_USER_ROLE_FLEET_12", fleet.RoleMaintainer)},
	}, true)
	require.NoError(t, err)
	require.Same(t, created, user)
	require.Nil(t, user.GlobalRole)
	require.Len(t, user.Teams, 1)
	require.Equal(t, uint(12), user.Teams[0].ID)
	require.Equal(t, fleet.RoleMaintainer, user.Teams[0].Role)
}

func TestCommunityPlusGetSSOUserSyncsExistingMappedRole(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})
	oldRole := fleet.RoleObserver
	existing := &fleet.User{ID: 7, Email: "user@example.com", SSOEnabled: true, GlobalRole: &oldRole}
	ds.UserByEmailFunc = func(context.Context, string) (*fleet.User, error) { return existing, nil }
	var saved *fleet.User
	ds.SaveUserIfNotLastAdminFunc = func(_ context.Context, user *fleet.User) error {
		saved = user
		return nil
	}

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{
		email: "user@example.com",
		attrs: []fleet.SAMLAttribute{jitRoleAttribute("FLEET_JIT_USER_ROLE_GLOBAL", fleet.RoleAdmin)},
	}, true)
	require.NoError(t, err)
	require.Same(t, existing, user)
	require.Same(t, existing, saved)
	require.NotNil(t, user.GlobalRole)
	require.Equal(t, fleet.RoleAdmin, *user.GlobalRole)
}

func TestCommunityPlusGetSSOUserExistingNoRoleAttributesDoesNotWrite(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})
	existing := &fleet.User{ID: 7, Email: "user@example.com", SSOEnabled: true}
	ds.UserByEmailFunc = func(context.Context, string) (*fleet.User, error) { return existing, nil }

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{email: "user@example.com"}, true)
	require.NoError(t, err)
	require.Same(t, existing, user)
	require.False(t, ds.SaveUserIfNotLastAdminFuncInvoked)
}

func TestCommunityPlusGetSSOUserRejectsConflictingRoleAttributes(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})
	ds.UserByEmailFunc = func(context.Context, string) (*fleet.User, error) {
		return nil, communityPlusNotFoundError{}
	}

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{
		email: "user@example.com",
		attrs: []fleet.SAMLAttribute{
			jitRoleAttribute("FLEET_JIT_USER_ROLE_GLOBAL", fleet.RoleAdmin),
			jitRoleAttribute("FLEET_JIT_USER_ROLE_FLEET_12", fleet.RoleObserver),
		},
	}, true)
	require.Error(t, err)
	require.Nil(t, user)
	require.False(t, ds.NewUserFuncInvoked)
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

func TestCommunityPlusGetSSOUserJITRejectsInvalidEmail(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{email: "not-an-email"}, true)
	require.Error(t, err)
	require.Nil(t, user)
	require.False(t, ds.UserByEmailFuncInvoked)
	require.False(t, ds.NewUserFuncInvoked)
}

func TestCommunityPlusGetSSOUserKeepsExistingUserWhenJITDisabled(t *testing.T) {
	ds := new(fleet_mock.Store)
	svc := newCommunityPlusJITTestService(t, ds)
	ctx := license.NewContext(context.Background(), &fleet.LicenseInfo{Tier: fleet.TierFree})
	existing := &fleet.User{ID: 7, Email: "user@example.com", SSOEnabled: true}

	ds.UserByEmailFunc = func(_ context.Context, email string) (*fleet.User, error) {
		require.Equal(t, "user@example.com", email)
		return existing, nil
	}

	user, err := svc.CommunityPlusGetSSOUser(ctx, communityPlusTestAuth{
		email: "USER@example.com",
		attrs: []fleet.SAMLAttribute{jitRoleAttribute("FLEET_JIT_USER_ROLE_GLOBAL", fleet.RoleAdmin)},
	}, false)
	require.NoError(t, err)
	require.Same(t, existing, user)
	require.False(t, ds.SaveUserIfNotLastAdminFuncInvoked)
}
