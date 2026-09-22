package condaccess

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	scepserver "github.com/fleetdm/fleet/v4/server/mdm/scep/server"
	fleetmock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/smallstep/scep"
	"github.com/stretchr/testify/require"
)

type conditionalAccessNotFoundError struct{}

func (conditionalAccessNotFoundError) Error() string    { return "not found" }
func (conditionalAccessNotFoundError) IsNotFound() bool { return true }

func TestConditionalAccessSCEPCapabilitiesDisableRenewal(t *testing.T) {
	svc := noRenewalSCEPService{}
	caps, err := svc.GetCACaps(context.Background())
	require.NoError(t, err)
	require.Equal(t, conditionalAccessCACaps, string(caps))

	_, err = svc.GetNextCACert(context.Background())
	require.ErrorContains(t, err, "renewal is not supported")
}

func TestRequireGlobalEnrollSecret(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: nil}

	t.Run("accepts global secret", func(t *testing.T) {
		ds := new(fleetmock.Store)
		ds.VerifyEnrollSecretFunc = func(_ context.Context, secret string) (*fleet.EnrollSecret, error) {
			require.Equal(t, "global-secret", secret)
			return &fleet.EnrollSecret{}, nil
		}
		called := false
		next := scepserver.CSRSignerContextFunc(func(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error) {
			called = true
			return cert, nil
		})

		got, err := requireGlobalEnrollSecret(ds, next).SignCSRContext(context.Background(), &scep.CSRReqMessage{ChallengePassword: "global-secret"})
		require.NoError(t, err)
		require.Same(t, cert, got)
		require.True(t, called)
	})

	t.Run("rejects team secret", func(t *testing.T) {
		ds := new(fleetmock.Store)
		teamID := uint(7)
		ds.VerifyEnrollSecretFunc = func(context.Context, string) (*fleet.EnrollSecret, error) {
			return &fleet.EnrollSecret{TeamID: &teamID}, nil
		}
		next := scepserver.CSRSignerContextFunc(func(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error) {
			t.Fatal("next signer must not be called")
			return nil, nil
		})

		_, err := requireGlobalEnrollSecret(ds, next).SignCSRContext(context.Background(), &scep.CSRReqMessage{ChallengePassword: "team-secret"})
		require.EqualError(t, err, "invalid challenge")
	})

	t.Run("rejects unknown secret", func(t *testing.T) {
		ds := new(fleetmock.Store)
		ds.VerifyEnrollSecretFunc = func(context.Context, string) (*fleet.EnrollSecret, error) {
			return nil, conditionalAccessNotFoundError{}
		}
		next := scepserver.CSRSignerContextFunc(func(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error) {
			t.Fatal("next signer must not be called")
			return nil, nil
		})

		_, err := requireGlobalEnrollSecret(ds, next).SignCSRContext(context.Background(), &scep.CSRReqMessage{ChallengePassword: "missing"})
		require.EqualError(t, err, "invalid challenge")
	})

	t.Run("rejects missing challenge", func(t *testing.T) {
		ds := new(fleetmock.Store)
		next := scepserver.CSRSignerContextFunc(func(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error) {
			return nil, errors.New("unexpected call")
		})
		_, err := requireGlobalEnrollSecret(ds, next).SignCSRContext(context.Background(), &scep.CSRReqMessage{})
		require.EqualError(t, err, "missing challenge")
		require.False(t, ds.VerifyEnrollSecretFuncInvoked)
	})
}
