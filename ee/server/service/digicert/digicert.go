// Package digicert is a compatibility facade for Fleet's historical EE import
// path. The implementation lives in the clean-room Community+ tree.
package digicert

import (
	"context"
	"log/slog"

	communityplus "github.com/fleetdm/fleet/v4/server/communityplus/digicert"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type Option func(*options)

type options struct{}

// WithLogger preserves the existing constructor API. The implementation never
// logs certificate material or API credentials.
func WithLogger(_ *slog.Logger) Option {
	return func(*options) {}
}

type Service struct {
	inner *communityplus.Service
}

func NewService(opts ...Option) *Service {
	configured := &options{}
	for _, opt := range opts {
		if opt != nil {
			opt(configured)
		}
	}
	return &Service{inner: communityplus.NewService()}
}

func (s *Service) VerifyProfileID(ctx context.Context, config fleet.DigiCertCA) error {
	return s.inner.VerifyProfileID(ctx, toConfig(config))
}

func (s *Service) GetCertificate(ctx context.Context, config fleet.DigiCertCA) (*fleet.DigiCertCertificate, error) {
	certificate, err := s.inner.GetCertificate(ctx, toConfig(config))
	if err != nil {
		return nil, err
	}
	return &fleet.DigiCertCertificate{
		PfxData:        certificate.PFXData,
		Password:       certificate.Password,
		NotValidBefore: certificate.NotValidBefore,
		NotValidAfter:  certificate.NotValidAfter,
		SerialNumber:   certificate.SerialNumber,
	}, nil
}

func toConfig(config fleet.DigiCertCA) communityplus.Config {
	return communityplus.Config{
		URL:                   config.URL,
		APIToken:              config.APIToken,
		ProfileID:             config.ProfileID,
		CertificateCommonName: config.CertificateCommonName,
		UserPrincipalNames:    config.CertificateUserPrincipalNames,
		CertificateSeatID:     config.CertificateSeatID,
	}
}

var _ fleet.DigiCertService = (*Service)(nil)
