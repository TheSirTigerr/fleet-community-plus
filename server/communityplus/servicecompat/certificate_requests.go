package servicecompat

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/fleethttp"
	"github.com/fleetdm/fleet/v4/server/communityplus/hostidentity/httpsig"
	authzctx "github.com/fleetdm/fleet/v4/server/contexts/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/smallstep/pkcs7"
)

func (s *certificateAuthorityWrapper) RequestCertificate(ctx context.Context, payload fleet.RequestCertificatePayload) (*string, error) {
	authCtx, ok := authzctx.FromContext(ctx)
	if !ok {
		return nil, &fleet.BadRequestError{Message: "Missing authentication authorization context"}
	}

	var hostID *uint
	if authCtx.AuthnMethod() == authzctx.AuthnHTTPMessageSignature {
		s.authorizer.SkipAuthorization(ctx)
		identity, ok := httpsig.FromContext(ctx)
		if !ok {
			return nil, fleet.NewPermissionError("Missing host identity certificate for signed certificate request.")
		}
		if identity.HostID == nil {
			return nil, fleet.NewPermissionError("Host identity certificate is not associated with an enrolled host.")
		}
		hostID = identity.HostID
	} else if err := s.authorizer.Authorize(ctx, &payload, fleet.ActionWrite); err != nil {
		return nil, err
	}

	csr, err := parseCertificateCSR(payload.CSR)
	if err != nil {
		return nil, &fleet.BadRequestError{Message: "Invalid certificate signing request.", InternalErr: err}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &fleet.BadRequestError{Message: "Invalid certificate signing request signature.", InternalErr: err}
	}

	ca, err := s.ds.GetCertificateAuthorityByID(ctx, payload.ID, true)
	if err != nil {
		return nil, err
	}
	if err := s.verifyCertificateRequester(ctx, payload, hostID, csr); err != nil {
		return nil, err
	}

	envelope, err := s.issueCertificate(ctx, ca, csr)
	if err != nil {
		var transient fleet.CertificateAuthorityTransientError
		if errors.As(err, &transient) {
			return nil, err
		}
		return nil, &fleet.BadRequestError{Message: err.Error(), InternalErr: err}
	}

	if !payload.ReturnPEMCertificate {
		return new("-----BEGIN PKCS7-----\n" + string(envelope) + "\n-----END PKCS7-----\n"), nil
	}
	cert, err := certificateEnvelopeToPEM(envelope)
	if err != nil {
		return nil, fmt.Errorf("convert issued certificate to PEM: %w", err)
	}
	return &cert, nil
}

func (s *certificateAuthorityWrapper) issueCertificate(ctx context.Context, ca *fleet.CertificateAuthority, csr *x509.CertificateRequest) ([]byte, error) {
	if ca == nil {
		return nil, errors.New("certificate authority is missing")
	}
	switch fleet.CAType(ca.Type) {
	case fleet.CATypeHydrant:
		if s.est == nil {
			return nil, errors.New("EST service is unavailable")
		}
		if ca.URL == nil || ca.ClientID == nil || ca.ClientSecret == nil {
			return nil, errors.New("Hydrant certificate authority is incomplete")
		}
		return issueEST(ctx, s.est, fleet.ESTProxyCA{
			Name: certificateValue(ca.Name), URL: *ca.URL, Username: *ca.ClientID, Password: *ca.ClientSecret,
		}, csr)
	case fleet.CATypeCustomESTProxy:
		if s.est == nil {
			return nil, errors.New("EST service is unavailable")
		}
		if ca.URL == nil || ca.Username == nil || ca.Password == nil {
			return nil, errors.New("EST certificate authority is incomplete")
		}
		return issueEST(ctx, s.est, fleet.ESTProxyCA{
			Name: certificateValue(ca.Name), URL: *ca.URL, Username: *ca.Username, Password: *ca.Password,
		}, csr)
	case fleet.CATypeNDESSCEPProxy:
		if s.scepEnrollment == nil {
			return nil, errors.New("SCEP enrollment client is unavailable")
		}
		if ca.URL == nil || strings.TrimSpace(*ca.URL) == "" {
			return nil, errors.New("NDES certificate authority is missing its SCEP URL")
		}
		cert, err := s.scepEnrollment.GetCertificate(ctx, *ca.URL, csr)
		if err != nil {
			return nil, fmt.Errorf("SCEP certificate request failed: %w", err)
		}
		der, err := pkcs7.DegenerateCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("encode SCEP certificate as PKCS7: %w", err)
		}
		return wrapCertificateBase64(der), nil
	default:
		return nil, fmt.Errorf("certificate requests are not supported for certificate authority type %q", ca.Type)
	}
}

func issueEST(ctx context.Context, service fleet.ESTService, ca fleet.ESTProxyCA, csr *x509.CertificateRequest) ([]byte, error) {
	cert, err := service.GetCertificate(ctx, ca, string(wrapCertificateBase64(csr.Raw)))
	if err != nil {
		return nil, fmt.Errorf("EST certificate request failed: %w", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("EST certificate authority returned an empty certificate")
	}
	return cert.Certificate, nil
}

func (s *certificateAuthorityWrapper) verifyCertificateRequester(ctx context.Context, payload fleet.RequestCertificatePayload, hostID *uint, csr *x509.CertificateRequest) error {
	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("load app config for certificate request: %w", err)
	}

	idpProvided, err := payload.IdPCredentialsProvided()
	if err != nil {
		return err
	}

	var bindHostID *uint
	if !s.cfg.Server.AllowRequestCertificateAnyIdP {
		if err := appConfig.Integrations.CheckCertIdPIntrospection(payload.IDPOauthURL, payload.IDPClientID); err != nil {
			return err
		}
		if !appConfig.Integrations.CertificatesDisableHostEndUserBinding.Value {
			bindHostID = hostID
		}
	}

	var email, upn string
	if bindHostID != nil || idpProvided {
		email, upn, err = certificateCSRIdentity(csr)
		if err != nil {
			return &fleet.BadRequestError{Message: "Certificate signing request must contain exactly one email address and UPN.", InternalErr: err}
		}
	}

	if bindHostID != nil {
		if !certificateUPNMatchesEmail(email, upn) {
			return fleet.NewPermissionError("Certificate subject does not match the end user identity recorded for this host.")
		}
		endUsers, err := fleet.GetEndUsers(ctx, s.ds, *bindHostID)
		if err != nil {
			return fmt.Errorf("get host end users for certificate request: %w", err)
		}
		if len(endUsers) == 0 || endUsers[0].IdpUserName == "" || !strings.EqualFold(endUsers[0].IdpUserName, email) {
			return fleet.NewPermissionError("Certificate subject does not match the end user identity recorded for this host.")
		}
	}

	if !idpProvided {
		return nil
	}
	result, err := introspectCertificateToken(ctx, *payload.IDPClientID, *payload.IDPToken, *payload.IDPOauthURL)
	if err != nil || result == nil || !result.Active || result.Username == nil || *result.Username == "" {
		return fleet.NewPermissionError("IdP token is invalid.")
	}
	if !certificateUPNMatchesEmail(email, upn) || !strings.EqualFold(email, *result.Username) {
		return fleet.NewPermissionError("Certificate identity does not match the IdP identity.")
	}
	return nil
}

type certificateTokenIntrospection struct {
	Active   bool    `json:"active"`
	Username *string `json:"username"`
}

func introspectCertificateToken(ctx context.Context, clientID, token, rawURL string) (*certificateTokenIntrospection, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
		return nil, errors.New("IdP introspection URL must be absolute HTTPS")
	}
	values := url.Values{"client_id": {clientID}, "token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := fleethttp.NewClient(fleethttp.WithTimeout(20 * time.Second))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IdP introspection returned HTTP %d", resp.StatusCode)
	}
	var result certificateTokenIntrospection
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func parseCertificateCSR(value string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(strings.ReplaceAll(value, "\\n", "\n")))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR must be PEM encoded")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func certificateCSRIdentity(csr *x509.CertificateRequest) (string, string, error) {
	if len(csr.EmailAddresses) != 1 {
		return "", "", fmt.Errorf("expected exactly one email address, got %d", len(csr.EmailAddresses))
	}
	upn, err := certificateCSRUPN(csr)
	if err != nil {
		return "", "", err
	}
	return csr.EmailAddresses[0], upn, nil
}

func certificateCSRUPN(csr *x509.CertificateRequest) (string, error) {
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	var values []string
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(sanOID) {
			continue
		}
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &names); err != nil {
			return "", fmt.Errorf("parse SAN extension: %w", err)
		}
		for _, name := range names {
			if name.Tag != 0 {
				continue
			}
			remaining := name.Bytes
			for len(remaining) > 0 {
				var oid asn1.ObjectIdentifier
				var raw asn1.RawValue
				var err error
				remaining, err = asn1.Unmarshal(remaining, &oid)
				if err != nil {
					return "", err
				}
				remaining, err = asn1.Unmarshal(remaining, &raw)
				if err != nil {
					return "", err
				}
				if oid.Equal(upnOID) {
					var upn string
					if _, err := asn1.Unmarshal(raw.Bytes, &upn); err != nil {
						return "", err
					}
					values = append(values, upn)
				}
			}
		}
	}
	if len(values) != 1 {
		return "", fmt.Errorf("expected exactly one UPN, got %d", len(values))
	}
	return values[0], nil
}

func certificateUPNMatchesEmail(email, upn string) bool {
	if upn == "" {
		return false
	}
	return strings.EqualFold(upn, email) || strings.EqualFold(upn, fleet.EmailLocalPart(email))
}

func wrapCertificateBase64(data []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(data)
	const lineLength = 64
	var out strings.Builder
	for len(encoded) > lineLength {
		out.WriteString(encoded[:lineLength])
		out.WriteByte('\n')
		encoded = encoded[lineLength:]
	}
	out.WriteString(encoded)
	return []byte(out.String())
}

func certificateEnvelopeToPEM(envelope []byte) (string, error) {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', ' ', '\t':
			return -1
		default:
			return r
		}
	}, string(envelope))
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return "", err
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return "", err
	}
	if len(p7.Certificates) != 1 {
		return "", fmt.Errorf("expected exactly one issued certificate, got %d", len(p7.Certificates))
	}
	result := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p7.Certificates[0].Raw})
	if result == nil {
		return "", errors.New("encode issued certificate")
	}
	return string(result), nil
}
