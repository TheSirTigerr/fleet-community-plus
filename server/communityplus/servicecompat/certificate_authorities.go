package servicecompat

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type certificateAuthorityWrapper struct {
	fleet.Service
	ds         fleet.Datastore
	authorizer *authz.Authorizer
	cfg        *config.FleetConfig
	scep       fleet.SCEPConfigService
	digicert   fleet.DigiCertService
}

func wrapCertificateAuthorities(base fleet.Service, options []any) fleet.Service {
	if base == nil {
		return nil
	}
	var (
		ds       fleet.Datastore
		cfg      *config.FleetConfig
		scepSvc  fleet.SCEPConfigService
		digiSvc  fleet.DigiCertService
	)
	for _, option := range options {
		switch value := option.(type) {
		case fleet.Datastore:
			ds = value
		case *config.FleetConfig:
			cfg = value
		case fleet.SCEPConfigService:
			scepSvc = value
		case fleet.DigiCertService:
			digiSvc = value
		}
	}
	if ds == nil || cfg == nil {
		return base
	}
	return &certificateAuthorityWrapper{
		Service:    base,
		ds:         ds,
		authorizer: authz.Must(),
		cfg:        cfg,
		scep:       scepSvc,
		digicert:   digiSvc,
	}
}

func (s *certificateAuthorityWrapper) ListCertificateAuthorities(ctx context.Context) ([]*fleet.CertificateAuthoritySummary, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.CertificateAuthority{}, fleet.ActionList); err != nil {
		return nil, err
	}
	return s.ds.ListCertificateAuthorities(ctx)
}

func (s *certificateAuthorityWrapper) GetCertificateAuthority(ctx context.Context, id uint) (*fleet.CertificateAuthority, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.CertificateAuthority{}, fleet.ActionRead); err != nil {
		return nil, err
	}
	return s.ds.GetCertificateAuthorityByID(ctx, id, false)
}

func (s *certificateAuthorityWrapper) NewCertificateAuthority(ctx context.Context, payload fleet.CertificateAuthorityPayload) (*fleet.CertificateAuthority, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.CertificateAuthority{}, fleet.ActionWrite); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.cfg.Server.PrivateKey) == "" {
		return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Private key must be configured."}
	}

	count := 0
	if payload.DigiCert != nil {
		count++
	}
	if payload.NDESSCEPProxy != nil {
		count++
	}
	if payload.CustomSCEPProxy != nil {
		count++
	}
	if payload.Smallstep != nil {
		count++
	}
	if payload.Hydrant != nil {
		count++
	}
	if payload.CustomESTProxy != nil {
		count++
	}
	if count != 1 {
		return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Exactly one certificate authority must be specified."}
	}

	var (
		ca       fleet.CertificateAuthority
		activity fleet.ActivityDetails
	)
	switch {
	case payload.DigiCert != nil:
		if s.digicert == nil {
			return nil, errors.New("Community+ certificate authorities: DigiCert service is unavailable")
		}
		item := payload.DigiCert
		item.Preprocess()
		if item.Name == "" || item.URL == "" || item.APIToken == "" || item.ProfileID == "" ||
			item.CertificateCommonName == "" || item.CertificateSeatID == "" {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. DigiCert fields are incomplete."}
		}
		if err := s.digicert.VerifyProfileID(ctx, *item); err != nil {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. DigiCert profile validation failed."}
		}
		ca = fleet.CertificateAuthority{
			Type:                          string(fleet.CATypeDigiCert),
			Name:                          &item.Name,
			URL:                           &item.URL,
			APIToken:                      &item.APIToken,
			ProfileID:                     &item.ProfileID,
			CertificateCommonName:         &item.CertificateCommonName,
			CertificateUserPrincipalNames: &item.CertificateUserPrincipalNames,
			CertificateSeatID:             &item.CertificateSeatID,
		}
		activity = fleet.ActivityAddedDigiCert{Name: item.Name}

	case payload.NDESSCEPProxy != nil:
		if s.scep == nil {
			return nil, errors.New("Community+ certificate authorities: SCEP config service is unavailable")
		}
		item := payload.NDESSCEPProxy
		item.Preprocess()
		if item.URL == "" || item.AdminURL == "" || item.Username == "" || item.Password == "" {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. NDES fields are incomplete."}
		}
		if err := s.scep.ValidateSCEPURL(ctx, item.URL); err != nil {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Invalid NDES SCEP URL."}
		}
		if err := s.scep.ValidateNDESSCEPAdminURL(ctx, *item); err != nil {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Invalid NDES admin URL or credentials."}
		}
		name := "NDES"
		ca = fleet.CertificateAuthority{
			Type:     string(fleet.CATypeNDESSCEPProxy),
			Name:     &name,
			URL:      &item.URL,
			AdminURL: &item.AdminURL,
			Username: &item.Username,
			Password: &item.Password,
		}
		activity = fleet.ActivityAddedNDESSCEPProxy{}

	case payload.CustomSCEPProxy != nil:
		if s.scep == nil {
			return nil, errors.New("Community+ certificate authorities: SCEP config service is unavailable")
		}
		item := payload.CustomSCEPProxy
		item.Preprocess()
		if item.Name == "" || item.URL == "" || item.Challenge == "" {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Custom SCEP fields are incomplete."}
		}
		if err := s.scep.ValidateSCEPURL(ctx, item.URL); err != nil {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Invalid SCEP URL."}
		}
		ca = fleet.CertificateAuthority{
			Type:      string(fleet.CATypeCustomSCEPProxy),
			Name:      &item.Name,
			URL:       &item.URL,
			Challenge: &item.Challenge,
		}
		activity = fleet.ActivityAddedCustomSCEPProxy{Name: item.Name}

	case payload.Smallstep != nil:
		if s.scep == nil {
			return nil, errors.New("Community+ certificate authorities: SCEP config service is unavailable")
		}
		item := payload.Smallstep
		item.Preprocess()
		if item.Name == "" || item.URL == "" || item.ChallengeURL == "" || item.Username == "" || item.Password == "" {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Smallstep fields are incomplete."}
		}
		if err := s.scep.ValidateSCEPURL(ctx, item.URL); err != nil {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Invalid Smallstep SCEP URL."}
		}
		if err := s.scep.ValidateSmallstepChallengeURL(ctx, *item); err != nil {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. Invalid Smallstep challenge URL or credentials."}
		}
		ca = fleet.CertificateAuthority{
			Type:         string(fleet.CATypeSmallstep),
			Name:         &item.Name,
			URL:          &item.URL,
			ChallengeURL: &item.ChallengeURL,
			Username:     &item.Username,
			Password:     &item.Password,
		}
		activity = fleet.ActivityAddedSmallstep{Name: item.Name}

	default:
		return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. This certificate authority type is not implemented in Community+ yet."}
	}

	created, err := s.ds.NewCertificateAuthority(ctx, &ca)
	if err != nil {
		var conflict fleet.ConflictError
		if errors.As(err, &conflict) {
			return nil, &fleet.BadRequestError{Message: "Couldn't add certificate authority. A certificate authority with this name already exists."}
		}
		return nil, ctxerr.Wrap(ctx, err, "create certificate authority")
	}
	if activity != nil {
		if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), activity); err != nil {
			return nil, ctxerr.Wrap(ctx, err, fmt.Sprintf("record certificate authority activity for %s", created.Type))
		}
	}
	return created, nil
}

func (s *certificateAuthorityWrapper) DeleteCertificateAuthority(ctx context.Context, id uint) error {
	if err := s.authorizer.Authorize(ctx, &fleet.CertificateAuthority{}, fleet.ActionWrite); err != nil {
		return err
	}
	deleted, err := s.ds.DeleteCertificateAuthority(ctx, id)
	if err != nil {
		return err
	}

	var activity fleet.ActivityDetails
	switch deleted.Type {
	case string(fleet.CATypeDigiCert):
		activity = fleet.ActivityDeletedDigiCert{Name: deleted.Name}
	case string(fleet.CATypeNDESSCEPProxy):
		activity = fleet.ActivityDeletedNDESSCEPProxy{}
	case string(fleet.CATypeCustomSCEPProxy):
		activity = fleet.ActivityDeletedCustomSCEPProxy{Name: deleted.Name}
	case string(fleet.CATypeSmallstep):
		activity = fleet.ActivityDeletedSmallstep{Name: deleted.Name}
	}
	if activity != nil {
		return s.Service.NewActivity(ctx, authz.UserFromContext(ctx), activity)
	}
	return nil
}
