package condaccess

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/dev_mode"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/assets"
	"github.com/fleetdm/fleet/v4/server/platform/endpointer"
	"github.com/fleetdm/fleet/v4/server/platform/middleware/ratelimit"
	logmw "github.com/fleetdm/fleet/v4/server/service/middleware/log"
	"github.com/fleetdm/fleet/v4/server/service/middleware/otel"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/throttled/throttled/v2"
)

const (
	conditionalAccessIdPMetadataPath = "/api/fleet/conditional_access/idp/metadata"
	conditionalAccessIdPSSOPath      = "/api/fleet/conditional_access/idp/sso"
	conditionalAccessCertHeader      = "X-Client-Cert-Serial"
	conditionalAccessCertErrorURL    = "https://fleetdm.com/okta-conditional-access-error"
	conditionalAccessMetadataTTL     = time.Minute
	conditionalAccessSAMLPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

type cachedMetadata struct {
	mu      sync.RWMutex
	body    []byte
	header  http.Header
	expires time.Time
}

func (c *cachedMetadata) load(now time.Time) ([]byte, http.Header, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.body) == 0 || !now.Before(c.expires) {
		return nil, nil, false
	}
	return append([]byte(nil), c.body...), c.header.Clone(), true
}

func (c *cachedMetadata) store(body []byte, header http.Header, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.body = append(c.body[:0], body...)
	c.header = header.Clone()
	c.expires = expires
}

type idpService struct {
	ds               fleet.Datastore
	logger           *slog.Logger
	certSerialFormat string
	metadata         cachedMetadata
}

// RegisterIdP mounts the public SAML endpoints used by Okta Device Assurance.
// Authentication of the device itself is performed with the client-certificate
// serial supplied by the trusted TLS terminator; a valid Fleet conditional-
// access certificate is required before a SAML assertion can be produced.
func RegisterIdP(
	mux *http.ServeMux,
	ds fleet.Datastore,
	logger *slog.Logger,
	fleetConfig *config.FleetConfig,
	limitStore throttled.GCRAStore,
) error {
	if mux == nil || ds == nil || logger == nil || fleetConfig == nil {
		return errors.New("conditional access IdP dependencies are incomplete")
	}
	if limitStore == nil {
		return errors.New("conditional access IdP rate-limit store is nil")
	}
	if err := ensureAssets(context.Background(), ds); err != nil {
		return err
	}

	clientIP, err := endpointer.NewClientIPStrategy(fleetConfig.Server.TrustedProxies)
	if err != nil {
		return fmt.Errorf("configure conditional access client IP strategy: %w", err)
	}
	limiter, err := ratelimit.NewHTTPRateLimiter(limitStore, ratelimit.DefaultHTTPRateQuota(), clientIP)
	if err != nil {
		return fmt.Errorf("configure conditional access rate limiter: %w", err)
	}

	svc := &idpService{
		ds:               ds,
		logger:           logger.With("component", "communityplus-conditional-access-idp"),
		certSerialFormat: fleetConfig.ConditionalAccess.CertSerialFormat,
	}
	logging := logmw.NewLoggingMiddleware(svc.logger)
	wrap := func(path string, h http.Handler) http.Handler {
		h = limiter.RateLimit(h)
		h = logging(h)
		return otel.WrapHandler(h, path, *fleetConfig)
	}
	mux.Handle(conditionalAccessIdPMetadataPath, wrap(conditionalAccessIdPMetadataPath, http.HandlerFunc(svc.serveMetadata)))
	mux.Handle(conditionalAccessIdPSSOPath, wrap(conditionalAccessIdPSSOPath, http.HandlerFunc(svc.serveSSO)))
	return nil
}

func (s *idpService) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if body, header, ok := s.metadata.load(time.Now()); ok {
		copyHTTPHeaders(w.Header(), header)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	idp, err := s.identityProvider(r.Context())
	if err != nil {
		s.logger.ErrorContext(r.Context(), "build conditional access metadata", "err", err)
		http.Error(w, "conditional access IdP is not configured", http.StatusNotFound)
		return
	}

	recorder := &metadataResponseRecorder{header: make(http.Header)}
	idp.ServeMetadata(recorder, r)
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	if status == http.StatusOK {
		s.metadata.store(recorder.body, recorder.header, time.Now().Add(conditionalAccessMetadataTTL))
	}
	copyHTTPHeaders(w.Header(), recorder.header)
	w.WriteHeader(status)
	_, _ = w.Write(recorder.body)
}

func (s *idpService) serveSSO(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	serialText := r.Header.Get(conditionalAccessCertHeader)
	serial, err := parseCertificateSerial(serialText, s.certSerialFormat)
	if err != nil {
		s.logger.WarnContext(r.Context(), "reject conditional access certificate serial", "err", err)
		http.Redirect(w, r, conditionalAccessCertErrorURL, http.StatusSeeOther)
		return
	}
	hostID, err := s.ds.GetConditionalAccessCertHostIDBySerialNumber(r.Context(), serial)
	if err != nil {
		s.logger.WarnContext(r.Context(), "conditional access certificate not recognized", "serial", serial, "err", err)
		http.Redirect(w, r, conditionalAccessCertErrorURL, http.StatusSeeOther)
		return
	}

	idp, err := s.identityProvider(r.Context())
	if err != nil {
		s.logger.ErrorContext(r.Context(), "build conditional access IdP", "err", err)
		http.Error(w, "conditional access IdP unavailable", http.StatusInternalServerError)
		return
	}
	idp.SessionProvider = &deviceHealthSessionProvider{ds: s.ds, logger: s.logger, hostID: hostID}
	idp.ServeSSO(w, r)
}

func (s *idpService) identityProvider(ctx context.Context) (*saml.IdentityProvider, error) {
	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load app config: %w", err)
	}
	if appConfig.ServerSettings.ServerURL == "" {
		return nil, errors.New("Fleet server URL is not configured")
	}

	pair, err := assets.KeyPair(ctx, s.ds, fleet.MDMAssetConditionalAccessIDPCert, fleet.MDMAssetConditionalAccessIDPKey)
	if err != nil {
		return nil, fmt.Errorf("load conditional access IdP keypair: %w", err)
	}
	if pair == nil || pair.Leaf == nil {
		return nil, errors.New("conditional access IdP keypair is incomplete")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("conditional access IdP private key cannot sign")
	}

	metadataURL, err := endpointURL(appConfig.ServerSettings.ServerURL, conditionalAccessIdPMetadataPath)
	if err != nil {
		return nil, fmt.Errorf("build conditional access metadata URL: %w", err)
	}
	ssoBase, err := appConfig.ConditionalAccessIdPSSOURL(dev_mode.Env)
	if err != nil {
		return nil, fmt.Errorf("build conditional access SSO base URL: %w", err)
	}
	ssoURL, err := endpointURL(ssoBase, conditionalAccessIdPSSOPath)
	if err != nil {
		return nil, fmt.Errorf("build conditional access SSO URL: %w", err)
	}

	return &saml.IdentityProvider{
		Key:                     signer,
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
		Certificate:             pair.Leaf,
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		ServiceProviderProvider: &oktaServiceProvider{ds: s.ds},
	}, nil
}

type oktaServiceProvider struct {
	ds fleet.Datastore
}

func (p *oktaServiceProvider) GetServiceProvider(r *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	appConfig, err := p.ds.AppConfig(r.Context())
	if err != nil {
		return nil, fmt.Errorf("load Okta conditional access settings: %w", err)
	}
	settings := appConfig.ConditionalAccess
	if settings == nil || !settings.OktaConfigured() || entityID != settings.OktaAudienceURI.Value {
		return nil, errors.New("unknown SAML service provider")
	}
	acs, err := url.Parse(settings.OktaAssertionConsumerServiceURL.Value)
	if err != nil || acs.Scheme != "https" || acs.Host == "" || acs.User != nil {
		return nil, errors.New("invalid Okta assertion consumer service URL")
	}
	certificate, err := parsePEMCertificate([]byte(settings.OktaCertificate.Value))
	if err != nil {
		return nil, fmt.Errorf("parse Okta signing certificate: %w", err)
	}

	descriptor := saml.SPSSODescriptor{
		AssertionConsumerServices: []saml.IndexedEndpoint{{
			Binding:  conditionalAccessSAMLPostBinding,
			Location: acs.String(),
			Index:    0,
		}},
	}
	descriptor.SSODescriptor.RoleDescriptor.KeyDescriptors = []saml.KeyDescriptor{{
		Use: "signing",
		KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{
			Data: base64.StdEncoding.EncodeToString(certificate.Raw),
		}}}},
	}}
	return &saml.EntityDescriptor{EntityID: settings.OktaAudienceURI.Value, SPSSODescriptors: []saml.SPSSODescriptor{descriptor}}, nil
}

func endpointURL(baseURL, path string) (*url.URL, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("base URL must be canonical HTTPS")
	}
	return base.JoinPath(path), nil
}

func parsePEMCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate PEM is invalid")
	}
	return x509.ParseCertificate(block.Bytes)
}

func copyHTTPHeaders(dst, src http.Header) {
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
}

type metadataResponseRecorder struct {
	header http.Header
	body   []byte
	status int
}

func (r *metadataResponseRecorder) Header() http.Header { return r.header }
func (r *metadataResponseRecorder) Write(data []byte) (int, error) {
	r.body = append(r.body, data...)
	return len(data), nil
}
func (r *metadataResponseRecorder) WriteHeader(status int) { r.status = status }
