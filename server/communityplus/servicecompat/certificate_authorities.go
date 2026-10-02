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
		ds      fleet.Datastore
		cfg     *config.FleetConfig
		scepSvc fleet.SCEPConfigService
		digiSvc fleet.DigiCertService
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

func (s *certificateAuthorityWrapper) UpdateCertificateAuthority(ctx context.Context, id uint, payload fleet.CertificateAuthorityUpdatePayload) error {
	if err := s.authorizer.Authorize(ctx, &fleet.CertificateAuthority{}, fleet.ActionWrite); err != nil {
		return err
	}
	const prefix = "Couldn't edit certificate authority. "
	if err := payload.ValidatePayload(s.cfg.Server.PrivateKey, prefix); err != nil {
		return err
	}

	oldCA, err := s.ds.GetCertificateAuthorityByID(ctx, id, true)
	if err != nil {
		return err
	}
	if oldCA == nil || oldCA.Name == nil {
		return &fleet.BadRequestError{Message: prefix + "Certificate authority is incomplete."}
	}

	var (
		update   fleet.CertificateAuthority
		activity fleet.ActivityDetails
	)
	switch {
	case payload.DigiCertCAUpdatePayload != nil:
		if oldCA.Type != string(fleet.CATypeDigiCert) {
			return &fleet.BadRequestError{Message: prefix + "The certificate authority types must be the same."}
		}
		if payload.DigiCertCAUpdatePayload.IsEmpty() {
			return &fleet.BadRequestError{Message: prefix + "DigiCert CA update payload is empty."}
		}
		item := payload.DigiCertCAUpdatePayload
		if err := item.ValidateRelatedFields(prefix, *oldCA.Name); err != nil {
			return err
		}
		item.Preprocess()
		if item.APIToken != nil && *item.APIToken == fleet.MaskedPassword {
			item.APIToken = nil
		}
		if item.Name != nil && *item.Name == *oldCA.Name {
			item.Name = nil
		}
		merged := fleet.DigiCertCA{
			Name:                          certificateValue(oldCA.Name),
			URL:                           certificateValue(oldCA.URL),
			APIToken:                      certificateValue(oldCA.APIToken),
			ProfileID:                     certificateValue(oldCA.ProfileID),
			CertificateCommonName:         certificateValue(oldCA.CertificateCommonName),
			CertificateUserPrincipalNames: certificateSliceValue(oldCA.CertificateUserPrincipalNames),
			CertificateSeatID:             certificateValue(oldCA.CertificateSeatID),
		}
		if item.Name != nil {
			merged.Name = *item.Name
		}
		if item.URL != nil {
			merged.URL = *item.URL
		}
		if item.APIToken != nil {
			merged.APIToken = *item.APIToken
		}
		if item.ProfileID != nil {
			merged.ProfileID = *item.ProfileID
		}
		if item.CertificateCommonName != nil {
			merged.CertificateCommonName = *item.CertificateCommonName
		}
		if item.CertificateUserPrincipalNames != nil {
			merged.CertificateUserPrincipalNames = append([]string(nil), (*item.CertificateUserPrincipalNames)...)
		}
		if item.CertificateSeatID != nil {
			merged.CertificateSeatID = *item.CertificateSeatID
		}
		if merged.Name == "" || merged.URL == "" || merged.APIToken == "" || merged.ProfileID == "" ||
			merged.CertificateCommonName == "" || merged.CertificateSeatID == "" {
			return &fleet.BadRequestError{Message: prefix + "DigiCert fields are incomplete."}
		}
		if s.digicert == nil {
			return errors.New("Community+ certificate authorities: DigiCert service is unavailable")
		}
		if err := s.digicert.VerifyProfileID(ctx, merged); err != nil {
			return &fleet.BadRequestError{Message: prefix + "DigiCert profile validation failed."}
		}
		update = fleet.CertificateAuthority{
			Type:                          string(fleet.CATypeDigiCert),
			Name:                          item.Name,
			URL:                           item.URL,
			APIToken:                      item.APIToken,
			ProfileID:                     item.ProfileID,
			CertificateCommonName:         item.CertificateCommonName,
			CertificateUserPrincipalNames: item.CertificateUserPrincipalNames,
			CertificateSeatID:             item.CertificateSeatID,
		}
		activity = fleet.ActivityEditedDigiCert{Name: merged.Name}

	case payload.NDESSCEPProxyCAUpdatePayload != nil:
		if oldCA.Type != string(fleet.CATypeNDESSCEPProxy) {
			return &fleet.BadRequestError{Message: prefix + "The certificate authority types must be the same."}
		}
		if payload.NDESSCEPProxyCAUpdatePayload.IsEmpty() {
			return &fleet.BadRequestError{Message: prefix + "NDES SCEP Proxy CA update payload is empty."}
		}
		item := payload.NDESSCEPProxyCAUpdatePayload
		if err := item.ValidateRelatedFields(prefix, *oldCA.Name); err != nil {
			return err
		}
		item.Preprocess()
		if item.Password != nil && *item.Password == fleet.MaskedPassword {
			item.Password = nil
		}
		merged := fleet.NDESSCEPProxyCA{
			URL:      certificateValue(oldCA.URL),
			AdminURL: certificateValue(oldCA.AdminURL),
			Username: certificateValue(oldCA.Username),
			Password: certificateValue(oldCA.Password),
		}
		if item.URL != nil {
			merged.URL = *item.URL
		}
		if item.AdminURL != nil {
			merged.AdminURL = *item.AdminURL
		}
		if item.Username != nil {
			merged.Username = *item.Username
		}
		if item.Password != nil {
			merged.Password = *item.Password
		}
		if merged.URL == "" || merged.AdminURL == "" || merged.Username == "" || merged.Password == "" {
			return &fleet.BadRequestError{Message: prefix + "NDES fields are incomplete."}
		}
		if s.scep == nil {
			return errors.New("Community+ certificate authorities: SCEP config service is unavailable")
		}
		if err := s.scep.ValidateSCEPURL(ctx, merged.URL); err != nil {
			return &fleet.BadRequestError{Message: prefix + "Invalid NDES SCEP URL."}
		}
		if err := s.scep.ValidateNDESSCEPAdminURL(ctx, merged); err != nil {
			return &fleet.BadRequestError{Message: prefix + "Invalid NDES admin URL or credentials."}
		}
		update = fleet.CertificateAuthority{
			Type:     string(fleet.CATypeNDESSCEPProxy),
			URL:      item.URL,
			AdminURL: item.AdminURL,
			Username: item.Username,
			Password: item.Password,
		}
		activity = fleet.ActivityEditedNDESSCEPProxy{}

	case payload.CustomSCEPProxyCAUpdatePayload != nil:
		if oldCA.Type != string(fleet.CATypeCustomSCEPProxy) {
			return &fleet.BadRequestError{Message: prefix + "The certificate authority types must be the same."}
		}
		if payload.CustomSCEPProxyCAUpdatePayload.IsEmpty() {
			return &fleet.BadRequestError{Message: prefix + "Custom SCEP Proxy CA update payload is empty."}
		}
		item := payload.CustomSCEPProxyCAUpdatePayload
		if err := item.ValidateRelatedFields(prefix, *oldCA.Name); err != nil {
			return err
		}
		item.Preprocess()
		if item.Challenge != nil && *item.Challenge == fleet.MaskedPassword {
			item.Challenge = nil
		}
		if item.Name != nil && *item.Name == *oldCA.Name {
			item.Name = nil
		}
		name := certificateValue(oldCA.Name)
		url := certificateValue(oldCA.URL)
		challenge := certificateValue(oldCA.Challenge)
		if item.Name != nil {
			name = *item.Name
		}
		if item.URL != nil {
			url = *item.URL
		}
		if item.Challenge != nil {
			challenge = *item.Challenge
		}
		if name == "" || url == "" || challenge == "" {
			return &fleet.BadRequestError{Message: prefix + "Custom SCEP fields are incomplete."}
		}
		if s.scep == nil {
			return errors.New("Community+ certificate authorities: SCEP config service is unavailable")
		}
		if err := s.scep.ValidateSCEPURL(ctx, url); err != nil {
			return &fleet.BadRequestError{Message: prefix + "Invalid SCEP URL."}
		}
		update = fleet.CertificateAuthority{
			Type:      string(fleet.CATypeCustomSCEPProxy),
			Name:      item.Name,
			URL:       item.URL,
			Challenge: item.Challenge,
		}
		activity = fleet.ActivityEditedCustomSCEPProxy{Name: name}

	case payload.SmallstepSCEPProxyCAUpdatePayload != nil:
		if oldCA.Type != string(fleet.CATypeSmallstep) {
			return &fleet.BadRequestError{Message: prefix + "The certificate authority types must be the same."}
		}
		if payload.SmallstepSCEPProxyCAUpdatePayload.IsEmpty() {
			return &fleet.BadRequestError{Message: prefix + "Smallstep SCEP Proxy CA update payload is empty."}
		}
		item := payload.SmallstepSCEPProxyCAUpdatePayload
		if err := item.ValidateRelatedFields(prefix, *oldCA.Name); err != nil {
			return err
		}
		item.Preprocess()
		if item.Password != nil && *item.Password == fleet.MaskedPassword {
			item.Password = nil
		}
		if item.Name != nil && *item.Name == *oldCA.Name {
			item.Name = nil
		}
		merged := fleet.SmallstepSCEPProxyCA{
			Name:         certificateValue(oldCA.Name),
			URL:          certificateValue(oldCA.URL),
			ChallengeURL: certificateValue(oldCA.ChallengeURL),
			Username:     certificateValue(oldCA.Username),
			Password:     certificateValue(oldCA.Password),
		}
		if item.Name != nil {
			merged.Name = *item.Name
		}
		if item.URL != nil {
			merged.URL = *item.URL
		}
		if item.ChallengeURL != nil {
			merged.ChallengeURL = *item.ChallengeURL
		}
		if item.Username != nil {
			merged.Username = *item.Username
		}
		if item.Password != nil {
			merged.Password = *item.Password
		}
		if merged.Name == "" || merged.URL == "" || merged.ChallengeURL == "" ||
			merged.Username == "" || merged.Password == "" {
			return &fleet.BadRequestError{Message: prefix + "Smallstep fields are incomplete."}
		}
		if s.scep == nil {
			return errors.New("Community+ certificate authorities: SCEP config service is unavailable")
		}
		if err := s.scep.ValidateSCEPURL(ctx, merged.URL); err != nil {
			return &fleet.BadRequestError{Message: prefix + "Invalid Smallstep SCEP URL."}
		}
		if err := s.scep.ValidateSmallstepChallengeURL(ctx, merged); err != nil {
			return &fleet.BadRequestError{Message: prefix + "Invalid Smallstep challenge URL or credentials."}
		}
		update = fleet.CertificateAuthority{
			Type:         string(fleet.CATypeSmallstep),
			Name:         item.Name,
			URL:          item.URL,
			ChallengeURL: item.ChallengeURL,
			Username:     item.Username,
			Password:     item.Password,
		}
		activity = fleet.ActivityEditedSmallstep{Name: merged.Name}

	default:
		return &fleet.BadRequestError{Message: prefix + "This certificate authority type is not implemented in Community+ yet."}
	}

	if err := s.ds.UpdateCertificateAuthorityByID(ctx, id, &update); err != nil {
		return ctxerr.Wrap(ctx, err, "update certificate authority")
	}
	if activity != nil {
		if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), activity); err != nil {
			return ctxerr.Wrap(ctx, err, "record certificate authority update activity")
		}
	}
	return nil
}

func certificateValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func certificateSliceValue(value *[]string) []string {
	if value == nil {
		return nil
	}
	return append([]string(nil), (*value)...)
}
