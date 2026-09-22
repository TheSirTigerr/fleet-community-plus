package scim

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/fleet/v4/server/fleet"
	fleet_mock "github.com/fleetdm/fleet/v4/server/mock"
)

func TestRegisterSCIMRejectsMissingDependencies(t *testing.T) {
	require.Error(t, RegisterSCIM(nil, nil, nil, nil, nil))
}

func TestRegisterValidationRoutes(t *testing.T) {
	r := mux.NewRouter()
	RegisterValidationRoutes(r, nil)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/fleet/scim/Users"},
		{http.MethodPatch, "/api/v1/fleet/scim/Users/123"},
		{http.MethodDelete, "/api/v1/fleet/scim/Groups/456"},
		{http.MethodGet, "/api/v1/fleet/scim/ServiceProviderConfig"},
	} {
		req, err := http.NewRequest(tc.method, tc.path, nil)
		require.NoError(t, err)
		match := &mux.RouteMatch{}
		require.Truef(t, r.Match(req, match), "route not declared: %s %s", tc.method, tc.path)
	}
}

func TestListUsersSupportsEntraFilter(t *testing.T) {
	ds := new(fleet_mock.Store)
	ds.ListScimUsersFunc = func(_ context.Context, opts fleet.ScimUsersListOptions) ([]fleet.ScimUser, uint, error) {
		require.NotNil(t, opts.EmailTypeFilter)
		require.NotNil(t, opts.EmailValueFilter)
		require.Equal(t, "work", *opts.EmailTypeFilter)
		require.Equal(t, "user@example.com", *opts.EmailValueFilter)
		active := true
		return []fleet.ScimUser{{ID: 7, UserName: "user@example.com", Active: &active}}, 1, nil
	}
	p := &provider{ds: ds, logger: slog.Default()}
	req := httptest.NewRequest(http.MethodGet, `/api/v1/fleet/scim/Users?filter=emails%5Btype%20eq%20%22work%22%5D.value%20eq%20%22user%40example.com%22`, nil)
	res := httptest.NewRecorder()
	p.serveHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.Contains(t, res.Body.String(), `"totalResults":1`)
	require.Contains(t, res.Body.String(), `"userName":"user@example.com"`)
}

func TestPatchUserActive(t *testing.T) {
	ds := new(fleet_mock.Store)
	active := true
	fleetUserID := uint(99)
	ds.ScimUserByIDFunc = func(_ context.Context, id uint) (*fleet.ScimUser, error) {
		require.Equal(t, uint(7), id)
		return &fleet.ScimUser{ID: 7, UserName: "user@example.com", Active: &active, FleetUserID: &fleetUserID}, nil
	}
	ds.UserByIDFunc = func(_ context.Context, id uint) (*fleet.User, error) {
		require.Equal(t, fleetUserID, id)
		return &fleet.User{ID: id, Email: "user@example.com", SSOEnabled: false}, nil
	}
	var replaced *fleet.ScimUser
	ds.ReplaceScimUserFunc = func(_ context.Context, user *fleet.ScimUser) ([]fleet.ActivityTypeResentCertificate, error) {
		replaced = user
		return nil, nil
	}
	p := &provider{ds: ds, logger: slog.Default()}
	body := `{"schemas":["` + patchSchemaURN + `"],"Operations":[{"op":"Replace","path":"active","value":false}]}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/fleet/scim/Users/7", strings.NewReader(body))
	res := httptest.NewRecorder()
	p.serveHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NotNil(t, replaced)
	require.NotNil(t, replaced.Active)
	require.False(t, *replaced.Active)
	require.False(t, ds.DeleteUserFuncInvoked)
}
