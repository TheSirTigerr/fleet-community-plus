package digicert

import (
	"context"
	"log/slog"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// FleetService adapts the clean-room DigiCert client to Fleet's certificate
// authority service contract.
type FleetService struct {
	inner *Service
}

// NewFleetService constructs the Fleet-facing DigiCert service. The logger is
// accepted to keep server startup wiring explicit; certificate material and API
// credentials are never logged by this adapter.
func NewFleetService(_ *slog.Logger, opts ...Option) fleet.DigiCertService {
	return &FleetService{inner: NewService(opts...)}
}

func (s *FleetService) VerifyProfileID(ctx context.Context, config fleet.DigiCertCA) error {
	return s.inner.VerifyProfileID(ctx, fleetConfig(config))
}

func (s *FleetService) GetCertificate(ctx context.Context, config fleet.DigiCertCA) (*fleet.DigiCertCertificate, error) {
	certificate, err := s.inner.GetCertificate(ctx, fleetConfig(config))
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

func fleetConfig(config fleet.DigiCertCA) Config {
	return Config{
		URL:                   config.URL,
		APIToken:              config.APIToken,
		ProfileID:             config.ProfileID,
		CertificateCommonName: config.CertificateCommonName,
		UserPrincipalNames:    append([]string(nil), config.CertificateUserPrincipalNames...),
		CertificateSeatID:     config.CertificateSeatID,
	}
}

var _ fleet.DigiCertService = (*FleetService)(nil)
