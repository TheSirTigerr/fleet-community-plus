package servicecompat

import (
	"context"
	"log/slog"

	"github.com/fleetdm/fleet/v4/server/communityplus/applepsso"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

// applePSSOWrapper overrides only the PSSO service methods implemented by
// Community+. All other Fleet service behavior continues through the embedded
// base service.
type applePSSOWrapper struct {
	fleet.Service
	psso *applepsso.Service
}

func wrapApplePSSO(base fleet.Service, options []any) (fleet.Service, error) {
	if base == nil {
		return nil, nil
	}

	var (
		ds         fleet.Datastore
		nonceStore fleet.PSSONonceStore
		logger     *slog.Logger
	)
	for _, option := range options {
		switch value := option.(type) {
		case fleet.Datastore:
			ds = value
		case fleet.PSSONonceStore:
			nonceStore = value
		case *slog.Logger:
			logger = value
		}
	}

	// Keep lightweight callers that do not supply the production PSSO
	// dependencies compatible with the base service. fleet serve supplies both.
	if ds == nil || nonceStore == nil {
		return base, nil
	}
	pssoService, err := applepsso.New(ds, nonceStore, logger)
	if err != nil {
		return nil, err
	}
	return &applePSSOWrapper{Service: base, psso: pssoService}, nil
}

func (s *applePSSOWrapper) PSSONonce(ctx context.Context) (string, error) {
	return s.psso.Nonce(ctx)
}

func (s *applePSSOWrapper) PSSORegisterDevice(ctx context.Context, req fleet.PSSODeviceRegistrationRequest) error {
	return s.psso.RegisterDevice(ctx, req)
}

func (s *applePSSOWrapper) PSSOJWKS(ctx context.Context) ([]byte, error) {
	return s.psso.JWKS(ctx)
}

func (s *applePSSOWrapper) PSSOAASA(ctx context.Context) ([]byte, error) {
	return s.psso.AASA(ctx)
}
