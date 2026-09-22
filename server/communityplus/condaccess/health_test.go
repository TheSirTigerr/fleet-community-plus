package condaccess

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	fleetmock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

func newHealthProvider(ds fleet.Datastore) *deviceHealthSessionProvider {
	return &deviceHealthSessionProvider{ds: ds, logger: slog.New(slog.DiscardHandler), hostID: 42}
}

func setHealthHostMocks(ds *fleetmock.Store, protected []uint, policies []*fleet.HostPolicy) {
	ds.HostLiteFunc = func(context.Context, uint) (*fleet.Host, error) {
		return &fleet.Host{ID: 42, Platform: "darwin"}, nil
	}
	ds.GetPoliciesForConditionalAccessFunc = func(context.Context, uint, string) ([]uint, error) {
		return protected, nil
	}
	ds.ListPoliciesForHostFunc = func(context.Context, *fleet.Host) ([]*fleet.HostPolicy, error) {
		return policies, nil
	}
}

func setValidRemediationTokenMocks(ds *fleetmock.Store) {
	ds.GetDeviceAuthTokenFunc = func(context.Context, uint) (string, error) {
		return "device-token", nil
	}
	ds.LoadHostByDeviceAuthTokenFunc = func(context.Context, string, time.Duration) (*fleet.Host, error) {
		return &fleet.Host{ID: 42}, nil
	}
}

func TestDeviceHealthAllowsCompliantHost(t *testing.T) {
	ds := new(fleetmock.Store)
	setHealthHostMocks(ds, []uint{1}, []*fleet.HostPolicy{{
		PolicyData: fleet.PolicyData{ID: 1},
		Response:   "pass",
	}})

	req := httptest.NewRequest(http.MethodPost, conditionalAccessIdPSSOPath, nil)
	w := httptest.NewRecorder()
	session := newHealthProvider(ds).GetSession(w, req, nil)

	require.NotNil(t, session)
	require.Equal(t, "host-42", session.NameID)
	require.Equal(t, http.StatusOK, w.Code)
	require.False(t, ds.AppConfigFuncInvoked)
}

func TestDeviceHealthIgnoresFailingUnprotectedPolicy(t *testing.T) {
	ds := new(fleetmock.Store)
	setHealthHostMocks(ds, []uint{1}, []*fleet.HostPolicy{{
		PolicyData: fleet.PolicyData{ID: 2, Critical: true},
		Response:   "fail",
	}})

	req := httptest.NewRequest(http.MethodPost, conditionalAccessIdPSSOPath, nil)
	w := httptest.NewRecorder()
	session := newHealthProvider(ds).GetSession(w, req, nil)

	require.NotNil(t, session)
	require.Equal(t, "host-42", session.NameID)
	require.False(t, ds.AppConfigFuncInvoked)
}

func TestDeviceHealthCriticalFailureCannotBypass(t *testing.T) {
	ds := new(fleetmock.Store)
	setHealthHostMocks(ds, []uint{1}, []*fleet.HostPolicy{{
		PolicyData: fleet.PolicyData{ID: 1, Critical: true},
		Response:   "fail",
	}})
	setValidRemediationTokenMocks(ds)
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{ServerSettings: fleet.ServerSettings{ServerURL: "https://fleet.example"}}, nil
	}
	ds.ConditionalAccessConsumeBypassFunc = func(context.Context, uint) (*time.Time, error) {
		t.Fatal("critical policy failure must not consume bypass")
		return nil, nil
	}

	req := httptest.NewRequest(http.MethodPost, conditionalAccessIdPSSOPath, nil)
	w := httptest.NewRecorder()
	session := newHealthProvider(ds).GetSession(w, req, nil)

	require.Nil(t, session)
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "https://fleet.example/device/device-token/policies", w.Header().Get("Location"))
}

func TestDeviceHealthConsumesNonCriticalBypass(t *testing.T) {
	ds := new(fleetmock.Store)
	setHealthHostMocks(ds, []uint{1}, []*fleet.HostPolicy{{
		PolicyData: fleet.PolicyData{ID: 1},
		Response:   "fail",
	}})
	setValidRemediationTokenMocks(ds)
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{ServerSettings: fleet.ServerSettings{ServerURL: "https://fleet.example"}}, nil
	}
	now := time.Now()
	ds.ConditionalAccessConsumeBypassFunc = func(_ context.Context, hostID uint) (*time.Time, error) {
		require.Equal(t, uint(42), hostID)
		return &now, nil
	}

	req := httptest.NewRequest(http.MethodPost, conditionalAccessIdPSSOPath, nil)
	w := httptest.NewRecorder()
	session := newHealthProvider(ds).GetSession(w, req, nil)

	require.NotNil(t, session)
	require.Equal(t, "host-42", session.NameID)
	require.Equal(t, http.StatusOK, w.Code)
}
