package servicecompat

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

func (s *certificateAuthorityWrapper) BatchApplyCertificateAuthorities(
	ctx context.Context,
	incoming fleet.GroupedCertificateAuthorities,
	opts fleet.BatchApplyCertificateAuthoritiesOpts,
) error {
	if err := s.authorizer.Authorize(ctx, &fleet.CertificateAuthority{}, fleet.ActionWrite); err != nil {
		return err
	}
	if !opts.ViaGitOps {
		return fleet.NewInvalidArgumentError("gitops", "certificate_authorities: batch apply is intended only for use with gitops")
	}
	if !incoming.IsEmpty() && strings.TrimSpace(s.cfg.Server.PrivateKey) == "" {
		return &fleet.BadRequestError{Message: "Server private key must be configured before certificate authorities can be applied."}
	}

	existingGrouped, err := s.ds.GetGroupedCertificateAuthorities(ctx, true)
	if err != nil {
		return fmt.Errorf("load existing certificate authorities: %w", err)
	}
	existing, err := flattenCertificateAuthorities(existingGrouped)
	if err != nil {
		return err
	}
	desired, err := s.prepareCertificateAuthorities(ctx, &incoming, existing)
	if err != nil {
		return err
	}

	ops := fleet.CertificateAuthoritiesBatchOperations{}
	for key, want := range desired {
		have, ok := existing[key]
		switch {
		case !ok:
			ops.Add = append(ops.Add, want)
		case !reflect.DeepEqual(have, want):
			ops.Update = append(ops.Update, want)
		}
	}
	if !opts.SkipDeletes {
		for key, have := range existing {
			if _, ok := desired[key]; !ok {
				ops.Delete = append(ops.Delete, have)
			}
		}
	}

	if opts.DryRun || (len(ops.Add) == 0 && len(ops.Update) == 0 && len(ops.Delete) == 0) {
		return nil
	}
	if err := s.ds.BatchApplyCertificateAuthorities(ctx, ops); err != nil {
		return err
	}
	for _, ca := range ops.Add {
		if activity := certificateAuthorityActivity(ca, "add"); activity != nil {
			if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), activity); err != nil {
				return err
			}
		}
	}
	for _, ca := range ops.Update {
		if activity := certificateAuthorityActivity(ca, "edit"); activity != nil {
			if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), activity); err != nil {
				return err
			}
		}
	}
	for _, ca := range ops.Delete {
		if activity := certificateAuthorityActivity(ca, "delete"); activity != nil {
			if err := s.Service.NewActivity(ctx, authz.UserFromContext(ctx), activity); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *certificateAuthorityWrapper) prepareCertificateAuthorities(
	ctx context.Context,
	grouped *fleet.GroupedCertificateAuthorities,
	existing map[string]*fleet.CertificateAuthority,
) (map[string]*fleet.CertificateAuthority, error) {
	result := make(map[string]*fleet.CertificateAuthority)
	add := func(ca *fleet.CertificateAuthority) error {
		key := certificateAuthorityKey(ca)
		if _, exists := result[key]; exists {
			return fleet.NewInvalidArgumentError("name", "duplicate certificate authority name for the same type")
		}
		result[key] = ca
		return nil
	}

	for i := range grouped.DigiCert {
		item := grouped.DigiCert[i]
		item.Preprocess()
		key := certificateAuthorityKeyParts(string(fleet.CATypeDigiCert), item.Name)
		if previous := existing[key]; previous != nil && (item.APIToken == "" || item.APIToken == fleet.MaskedPassword) {
			item.APIToken = certificateValue(previous.APIToken)
		}
		if item.Name == "" || item.URL == "" || item.APIToken == "" || item.ProfileID == "" ||
			item.CertificateCommonName == "" || item.CertificateSeatID == "" {
			return nil, fleet.NewInvalidArgumentError("digicert", "DigiCert certificate authority fields are incomplete")
		}
		if s.digicert == nil {
			return nil, errors.New("DigiCert service is unavailable")
		}
		if err := s.digicert.VerifyProfileID(ctx, item); err != nil {
			return nil, fleet.NewInvalidArgumentError("digicert", "DigiCert profile validation failed")
		}
		if err := add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeDigiCert), Name: &item.Name, URL: &item.URL, APIToken: &item.APIToken,
			ProfileID: &item.ProfileID, CertificateCommonName: &item.CertificateCommonName,
			CertificateUserPrincipalNames: &item.CertificateUserPrincipalNames, CertificateSeatID: &item.CertificateSeatID,
		}); err != nil {
			return nil, err
		}
	}

	if grouped.NDESSCEP != nil {
		item := *grouped.NDESSCEP
		item.Preprocess()
		key := certificateAuthorityKeyParts(string(fleet.CATypeNDESSCEPProxy), "NDES")
		if previous := existing[key]; previous != nil && (item.Password == "" || item.Password == fleet.MaskedPassword) {
			item.Password = certificateValue(previous.Password)
		}
		if item.URL == "" || item.AdminURL == "" || item.Username == "" || item.Password == "" {
			return nil, fleet.NewInvalidArgumentError("ndes_scep_proxy", "NDES certificate authority fields are incomplete")
		}
		if s.scep == nil {
			return nil, errors.New("SCEP config service is unavailable")
		}
		if err := s.scep.ValidateSCEPURL(ctx, item.URL); err != nil {
			return nil, fleet.NewInvalidArgumentError("ndes_scep_proxy.url", "invalid NDES SCEP URL")
		}
		if err := s.scep.ValidateNDESSCEPAdminURL(ctx, item); err != nil {
			return nil, fleet.NewInvalidArgumentError("ndes_scep_proxy.admin_url", "invalid NDES admin URL or credentials")
		}
		name := "NDES"
		if err := add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeNDESSCEPProxy), Name: &name, URL: &item.URL, AdminURL: &item.AdminURL,
			Username: &item.Username, Password: &item.Password,
		}); err != nil {
			return nil, err
		}
	}

	for i := range grouped.CustomScepProxy {
		item := grouped.CustomScepProxy[i]
		item.Preprocess()
		key := certificateAuthorityKeyParts(string(fleet.CATypeCustomSCEPProxy), item.Name)
		if previous := existing[key]; previous != nil && (item.Challenge == "" || item.Challenge == fleet.MaskedPassword) {
			item.Challenge = certificateValue(previous.Challenge)
		}
		if item.Name == "" || item.URL == "" || item.Challenge == "" {
			return nil, fleet.NewInvalidArgumentError("custom_scep_proxy", "Custom SCEP certificate authority fields are incomplete")
		}
		if s.scep == nil {
			return nil, errors.New("SCEP config service is unavailable")
		}
		if err := s.scep.ValidateSCEPURL(ctx, item.URL); err != nil {
			return nil, fleet.NewInvalidArgumentError("custom_scep_proxy.url", "invalid SCEP URL")
		}
		if err := add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeCustomSCEPProxy), Name: &item.Name, URL: &item.URL, Challenge: &item.Challenge,
		}); err != nil {
			return nil, err
		}
	}

	for i := range grouped.Smallstep {
		item := grouped.Smallstep[i]
		item.Preprocess()
		key := certificateAuthorityKeyParts(string(fleet.CATypeSmallstep), item.Name)
		if previous := existing[key]; previous != nil && (item.Password == "" || item.Password == fleet.MaskedPassword) {
			item.Password = certificateValue(previous.Password)
		}
		if item.Name == "" || item.URL == "" || item.ChallengeURL == "" || item.Username == "" || item.Password == "" {
			return nil, fleet.NewInvalidArgumentError("smallstep", "Smallstep certificate authority fields are incomplete")
		}
		if s.scep == nil {
			return nil, errors.New("SCEP config service is unavailable")
		}
		if err := s.scep.ValidateSCEPURL(ctx, item.URL); err != nil {
			return nil, fleet.NewInvalidArgumentError("smallstep.url", "invalid Smallstep SCEP URL")
		}
		if err := s.scep.ValidateSmallstepChallengeURL(ctx, item); err != nil {
			return nil, fleet.NewInvalidArgumentError("smallstep.challenge_url", "invalid Smallstep challenge URL or credentials")
		}
		if err := add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeSmallstep), Name: &item.Name, URL: &item.URL, ChallengeURL: &item.ChallengeURL,
			Username: &item.Username, Password: &item.Password,
		}); err != nil {
			return nil, err
		}
	}

	for i := range grouped.Hydrant {
		item := grouped.Hydrant[i]
		item.Preprocess()
		key := certificateAuthorityKeyParts(string(fleet.CATypeHydrant), item.Name)
		if previous := existing[key]; previous != nil && (item.ClientSecret == "" || item.ClientSecret == fleet.MaskedPassword) {
			item.ClientSecret = certificateValue(previous.ClientSecret)
		}
		if item.Name == "" || item.URL == "" || item.ClientID == "" || item.ClientSecret == "" {
			return nil, fleet.NewInvalidArgumentError("hydrant", "Hydrant certificate authority fields are incomplete")
		}
		if s.est == nil {
			return nil, errors.New("EST service is unavailable")
		}
		if err := s.est.ValidateESTURL(ctx, fleet.ESTProxyCA{
			Name: item.Name, URL: item.URL, Username: item.ClientID, Password: item.ClientSecret,
		}); err != nil {
			return nil, fleet.NewInvalidArgumentError("hydrant.url", "invalid Hydrant EST URL")
		}
		if err := add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeHydrant), Name: &item.Name, URL: &item.URL,
			ClientID: &item.ClientID, ClientSecret: &item.ClientSecret,
		}); err != nil {
			return nil, err
		}
	}

	for i := range grouped.EST {
		item := grouped.EST[i]
		item.Preprocess()
		key := certificateAuthorityKeyParts(string(fleet.CATypeCustomESTProxy), item.Name)
		if previous := existing[key]; previous != nil && (item.Password == "" || item.Password == fleet.MaskedPassword) {
			item.Password = certificateValue(previous.Password)
		}
		if item.Name == "" || item.URL == "" || item.Username == "" || item.Password == "" {
			return nil, fleet.NewInvalidArgumentError("custom_est_proxy", "Custom EST certificate authority fields are incomplete")
		}
		if s.est == nil {
			return nil, errors.New("EST service is unavailable")
		}
		if err := s.est.ValidateESTURL(ctx, item); err != nil {
			return nil, fleet.NewInvalidArgumentError("custom_est_proxy.url", "invalid EST URL")
		}
		if err := add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeCustomESTProxy), Name: &item.Name, URL: &item.URL,
			Username: &item.Username, Password: &item.Password,
		}); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func flattenCertificateAuthorities(grouped *fleet.GroupedCertificateAuthorities) (map[string]*fleet.CertificateAuthority, error) {
	if grouped == nil {
		return map[string]*fleet.CertificateAuthority{}, nil
	}
	result := make(map[string]*fleet.CertificateAuthority)
	add := func(ca *fleet.CertificateAuthority) {
		result[certificateAuthorityKey(ca)] = ca
	}
	for i := range grouped.DigiCert {
		item := grouped.DigiCert[i]
		add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeDigiCert), Name: &item.Name, URL: &item.URL, APIToken: &item.APIToken,
			ProfileID: &item.ProfileID, CertificateCommonName: &item.CertificateCommonName,
			CertificateUserPrincipalNames: &item.CertificateUserPrincipalNames, CertificateSeatID: &item.CertificateSeatID,
		})
	}
	if grouped.NDESSCEP != nil {
		item := *grouped.NDESSCEP
		name := "NDES"
		add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeNDESSCEPProxy), Name: &name, URL: &item.URL, AdminURL: &item.AdminURL,
			Username: &item.Username, Password: &item.Password,
		})
	}
	for i := range grouped.CustomScepProxy {
		item := grouped.CustomScepProxy[i]
		add(&fleet.CertificateAuthority{Type: string(fleet.CATypeCustomSCEPProxy), Name: &item.Name, URL: &item.URL, Challenge: &item.Challenge})
	}
	for i := range grouped.Smallstep {
		item := grouped.Smallstep[i]
		add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeSmallstep), Name: &item.Name, URL: &item.URL, ChallengeURL: &item.ChallengeURL,
			Username: &item.Username, Password: &item.Password,
		})
	}
	for i := range grouped.Hydrant {
		item := grouped.Hydrant[i]
		add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeHydrant), Name: &item.Name, URL: &item.URL, ClientID: &item.ClientID, ClientSecret: &item.ClientSecret,
		})
	}
	for i := range grouped.EST {
		item := grouped.EST[i]
		add(&fleet.CertificateAuthority{
			Type: string(fleet.CATypeCustomESTProxy), Name: &item.Name, URL: &item.URL, Username: &item.Username, Password: &item.Password,
		})
	}
	return result, nil
}

func certificateAuthorityKey(ca *fleet.CertificateAuthority) string {
	if ca == nil {
		return ""
	}
	return certificateAuthorityKeyParts(ca.Type, certificateValue(ca.Name))
}

func certificateAuthorityKeyParts(caType, name string) string {
	return caType + "\x00" + name
}

func certificateAuthorityActivity(ca *fleet.CertificateAuthority, action string) fleet.ActivityDetails {
	name := certificateValue(ca.Name)
	switch fleet.CAType(ca.Type) {
	case fleet.CATypeDigiCert:
		switch action {
		case "add":
			return fleet.ActivityAddedDigiCert{Name: name}
		case "edit":
			return fleet.ActivityEditedDigiCert{Name: name}
		case "delete":
			return fleet.ActivityDeletedDigiCert{Name: name}
		}
	case fleet.CATypeNDESSCEPProxy:
		switch action {
		case "add":
			return fleet.ActivityAddedNDESSCEPProxy{}
		case "edit":
			return fleet.ActivityEditedNDESSCEPProxy{}
		case "delete":
			return fleet.ActivityDeletedNDESSCEPProxy{}
		}
	case fleet.CATypeCustomSCEPProxy:
		switch action {
		case "add":
			return fleet.ActivityAddedCustomSCEPProxy{Name: name}
		case "edit":
			return fleet.ActivityEditedCustomSCEPProxy{Name: name}
		case "delete":
			return fleet.ActivityDeletedCustomSCEPProxy{Name: name}
		}
	case fleet.CATypeSmallstep:
		switch action {
		case "add":
			return fleet.ActivityAddedSmallstep{Name: name}
		case "edit":
			return fleet.ActivityEditedSmallstep{Name: name}
		case "delete":
			return fleet.ActivityDeletedSmallstep{Name: name}
		}
	case fleet.CATypeHydrant:
		switch action {
		case "add":
			return fleet.ActivityAddedHydrant{Name: name}
		case "edit":
			return fleet.ActivityEditedHydrant{Name: name}
		case "delete":
			return fleet.ActivityDeletedHydrant{Name: name}
		}
	case fleet.CATypeCustomESTProxy:
		switch action {
		case "add":
			return fleet.ActivityAddedCustomESTProxy{Name: name}
		case "edit":
			return fleet.ActivityEditedCustomESTProxy{Name: name}
		case "delete":
			return fleet.ActivityDeletedCustomESTProxy{Name: name}
		}
	}
	return nil
}
