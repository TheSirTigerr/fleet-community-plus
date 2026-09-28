package service

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/android"
	android_mock "github.com/fleetdm/fleet/v4/server/mdm/android/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/androidmanagement/v1"
)

func TestCreateEnrollmentTokenCarriesFullyManagedFlag(t *testing.T) {
	client := android_mock.Client{}
	client.InitCommonMocks()

	ds := InitCommonDSMocks()
	ds.Store.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{MDM: fleet.MDM{AndroidEnabledAndConfigured: true}}, nil
	}
	ds.Store.VerifyEnrollSecretFunc = func(context.Context, string) (*fleet.EnrollSecret, error) {
		return &fleet.EnrollSecret{Secret: "secret"}, nil
	}
	ds.Store.GetEnterpriseFunc = func(context.Context) (*android.Enterprise, error) {
		return &android.Enterprise{EnterpriseID: "test-enterprise"}, nil
	}

	var created *androidmanagement.EnrollmentToken
	client.EnterprisesEnrollmentTokensCreateFunc = func(_ context.Context, _ string, token *androidmanagement.EnrollmentToken) (*androidmanagement.EnrollmentToken, error) {
		created = token
		return &androidmanagement.EnrollmentToken{Value: "token", QrCode: "qr"}, nil
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := NewServiceWithClient(logger, ds, &client, "test-private-key", &ds.DataStore, noopNewActivity, config.AndroidAgentConfig{})
	require.NoError(t, err)

	_, err = svc.CreateEnrollmentToken(t.Context(), "secret", "", true)
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Equal(t, "PERSONAL_USAGE_DISALLOWED", created.AllowPersonalUsage)

	var additional enrollmentTokenRequest
	require.NoError(t, json.Unmarshal([]byte(created.AdditionalData), &additional))
	require.Equal(t, "secret", additional.EnrollSecret)
	require.True(t, additional.FullyManaged)
}
