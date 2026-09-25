package applezerotouch

import (
	"context"
	"log/slog"
	"testing"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
	fleetmock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

func testABMService(ds *fleetmock.Store) *ABMService {
	if ds.ListABMTokensFunc == nil {
		ds.ListABMTokensFunc = func(context.Context) ([]*fleet.ABMToken, error) { return nil, nil }
	}
	if ds.AppConfigFunc == nil {
		ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) { return &fleet.AppConfig{}, nil }
	}
	if ds.SaveAppConfigFunc == nil {
		ds.SaveAppConfigFunc = func(context.Context, *fleet.AppConfig) error { return nil }
	}
	return &ABMService{ds: ds, authorizer: authz.Must(), logger: slog.New(slog.DiscardHandler)}
}

func TestABMListAndCount(t *testing.T) {
	ds := new(fleetmock.Store)
	tokens := []*fleet.ABMToken{{ID: 1, OrganizationName: "Example ABM"}}
	ds.ListABMTokensFunc = func(context.Context) ([]*fleet.ABMToken, error) { return tokens, nil }
	ds.GetABMTokenCountFunc = func(context.Context) (int, error) { return 1, nil }
	svc := testABMService(ds)

	got, err := svc.ListTokens(testContext(fleet.RoleAdmin))
	require.NoError(t, err)
	require.Equal(t, tokens, got)

	count, err := svc.CountTokens(testContext(fleet.RoleAdmin))
	require.NoError(t, err)
	require.Equal(t, 1, count)

	_, err = svc.ListTokens(testContext(fleet.RoleObserver))
	require.Error(t, err)
}

func TestABMUpdateTokenTeams(t *testing.T) {
	ds := new(fleetmock.Store)
	token := &fleet.ABMToken{ID: 9}
	ds.TeamWithExtrasFunc = func(_ context.Context, id uint) (*fleet.Team, error) {
		return &fleet.Team{ID: id}, nil
	}
	ds.GetABMTokenByIDFunc = func(context.Context, uint) (*fleet.ABMToken, error) { return token, nil }
	var saved *fleet.ABMToken
	ds.SaveABMTokenFunc = func(_ context.Context, tok *fleet.ABMToken) error {
		saved = tok
		return nil
	}
	svc := testABMService(ds)
	macOS, iOS := uint(4), uint(5)

	got, err := svc.UpdateTokenTeams(testContext(fleet.RoleAdmin), 9, &macOS, &iOS, nil, nil)
	require.NoError(t, err)
	require.Same(t, token, got)
	require.Same(t, token, saved)
	require.Equal(t, uint(4), *saved.MacOSDefaultTeamID)
	require.Equal(t, uint(5), *saved.IOSDefaultTeamID)
	require.Nil(t, saved.IPadOSDefaultTeamID)
	require.Nil(t, saved.BYODDefaultTeamID)
}

func TestABMSetDefaultToken(t *testing.T) {
	ds := new(fleetmock.Store)
	token := &fleet.ABMToken{ID: 7}
	ds.GetABMTokenByIDFunc = func(context.Context, uint) (*fleet.ABMToken, error) { return token, nil }
	var setID uint
	ds.SetABMTokenDefaultFunc = func(_ context.Context, id uint) error {
		setID = id
		token.IsDefault = true
		return nil
	}
	ds.ClearABMTokenDefaultFunc = func(context.Context) error {
		token.IsDefault = false
		return nil
	}
	svc := testABMService(ds)

	got, err := svc.SetDefaultToken(testContext(fleet.RoleAdmin), 7, new(true))
	require.NoError(t, err)
	require.Equal(t, uint(7), setID)
	require.True(t, got.IsDefault)

	got, err = svc.SetDefaultToken(testContext(fleet.RoleAdmin), 7, new(false))
	require.NoError(t, err)
	require.False(t, got.IsDefault)

	_, err = svc.SetDefaultToken(testContext(fleet.RoleAdmin), 7, nil)
	require.ErrorContains(t, err, "default is required")
}

func TestABMDeleteLastTokenDisablesABM(t *testing.T) {
	ds := new(fleetmock.Store)
	ds.GetABMTokenByIDFunc = func(context.Context, uint) (*fleet.ABMToken, error) {
		return &fleet.ABMToken{ID: 3}, nil
	}
	deleted := false
	ds.DeleteABMTokenFunc = func(context.Context, uint) error {
		deleted = true
		return nil
	}
	ds.ListABMTokensFunc = func(context.Context) ([]*fleet.ABMToken, error) { return nil, nil }
	cfg := &fleet.AppConfig{}
	cfg.MDM.AppleBMEnabledAndConfigured = true
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) { return cfg, nil }
	saved := false
	ds.SaveAppConfigFunc = func(_ context.Context, got *fleet.AppConfig) error {
		saved = true
		require.False(t, got.MDM.AppleBMEnabledAndConfigured)
		require.True(t, got.MDM.AppleBusinessManager.Set)
		require.Empty(t, got.MDM.AppleBusinessManager.Value)
		return nil
	}
	svc := testABMService(ds)

	require.NoError(t, svc.DeleteToken(testContext(fleet.RoleAdmin), 3))
	require.True(t, deleted)
	require.True(t, saved)
}

func TestABMSyncAppConfigMirrorsTokens(t *testing.T) {
	ds := new(fleetmock.Store)
	tokens := []*fleet.ABMToken{
		{ID: 1, OrganizationName: "Org A", IsDefault: true, MacOSTeamName: "Mac fleet", IOSTeamName: "No team"},
		{ID: 2, OrganizationName: "Org B", TermsExpired: true, IPadOSTeamName: "iPad fleet", BYODTeamName: "BYOD fleet"},
	}
	ds.ListABMTokensFunc = func(context.Context) ([]*fleet.ABMToken, error) { return tokens, nil }
	cfg := &fleet.AppConfig{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) { return cfg, nil }
	ds.SaveAppConfigFunc = func(context.Context, *fleet.AppConfig) error { return nil }
	svc := testABMService(ds)

	require.NoError(t, svc.syncAppConfig(testContext(fleet.RoleAdmin)))
	require.True(t, cfg.MDM.AppleBMEnabledAndConfigured)
	require.True(t, cfg.MDM.AppleBMTermsExpired)
	require.True(t, cfg.MDM.AppleBusinessManager.Set)
	require.Len(t, cfg.MDM.AppleBusinessManager.Value, 2)
	require.Equal(t, fleet.MDMAppleABMAssignmentInfo{
		OrganizationName: "Org A",
		Default:          true,
		MacOSTeam:        "Mac fleet",
	}, cfg.MDM.AppleBusinessManager.Value[0])
	require.Equal(t, "iPad fleet", cfg.MDM.AppleBusinessManager.Value[1].IpadOSTeam)
	require.Equal(t, "BYOD fleet", cfg.MDM.AppleBusinessManager.Value[1].BYODTeam)
}
