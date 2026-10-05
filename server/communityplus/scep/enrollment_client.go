package scep

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	scepclient "github.com/fleetdm/fleet/v4/server/mdm/scep/client"
	"github.com/fleetdm/fleet/v4/server/mdm/scep/enrollment"
	scepserver "github.com/fleetdm/fleet/v4/server/mdm/scep/server"
	smallstepscep "github.com/smallstep/scep"
)

const (
	enrollmentTimeout          = 30 * time.Second
	enrollmentCACacheTTL       = 10 * time.Minute
	enrollmentRetryAfterSecond = 30
)

type EnrollmentClient struct {
	logger *slog.Logger

	mu      sync.Mutex
	caCerts map[string]cachedEnrollmentCA
	now     func() time.Time
}

type cachedEnrollmentCA struct {
	certs     []*x509.Certificate
	fetchedAt time.Time
}

func NewEnrollmentClient(logger *slog.Logger) fleet.SCEPEnrollmentClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &EnrollmentClient{
		logger:  logger,
		caCerts: make(map[string]cachedEnrollmentCA),
		now:     time.Now,
	}
}

func (c *EnrollmentClient) GetCertificate(ctx context.Context, rawURL string, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if csr == nil {
		return nil, errors.New("SCEP certificate request CSR is nil")
	}
	timeout := enrollmentTimeout
	client, err := scepclient.New(rawURL, c.logger, scepclient.WithTimeout(&timeout))
	if err != nil {
		return nil, fmt.Errorf("create SCEP enrollment client: %w", err)
	}

	certs, err := c.getCACerts(ctx, client, rawURL)
	if err != nil {
		return nil, err
	}

	key, signer, err := enrollment.NewEphemeralSigner(csr.Subject)
	if err != nil {
		return nil, fmt.Errorf("create SCEP enrollment signer: %w", err)
	}
	cert, err := enrollment.Enroll(ctx, client, certs, enrollment.Request{
		CSR:        csr,
		SignerKey:  key,
		SignerCert: signer,
		Logger:     c.logger,
	})
	if err != nil {
		c.mu.Lock()
		delete(c.caCerts, rawURL)
		c.mu.Unlock()
		return nil, normalizeEnrollmentError(err)
	}
	return cert, nil
}

func (c *EnrollmentClient) getCACerts(ctx context.Context, client scepclient.Client, rawURL string) ([]*x509.Certificate, error) {
	now := c.now()
	c.mu.Lock()
	cached, ok := c.caCerts[rawURL]
	c.mu.Unlock()
	if ok && now.Sub(cached.fetchedAt) < enrollmentCACacheTTL {
		return cached.certs, nil
	}

	certs, err := enrollment.FetchCACerts(ctx, client)
	if err != nil {
		return nil, normalizeEnrollmentError(err)
	}
	if len(certs) == 0 {
		return nil, errors.New("SCEP server returned no CA certificates")
	}

	c.mu.Lock()
	c.caCerts[rawURL] = cachedEnrollmentCA{certs: certs, fetchedAt: now}
	c.mu.Unlock()
	return certs, nil
}

func normalizeEnrollmentError(err error) error {
	if rejected, ok := errors.AsType[enrollment.RejectedError](err); ok && rejected.Status == smallstepscep.FAILURE {
		return fmt.Errorf("%w; include the CSR challengePassword attribute when required by the certificate authority", err)
	}

	requestErr, ok := errors.AsType[enrollment.RequestError](err)
	if !ok {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return err
	}

	transient := true
	if statusErr, ok := errors.AsType[scepserver.ResponseStatusError](err); ok {
		transient = statusErr.Code == http.StatusRequestTimeout ||
			statusErr.Code == http.StatusTooManyRequests ||
			statusErr.Code >= http.StatusInternalServerError
	}
	if !transient {
		return err
	}

	return fleet.CertificateAuthorityTransientError{
		Message:           requestErr.Error(),
		RetryAfterSeconds: enrollmentRetryAfterSecond,
	}
}

var _ fleet.SCEPEnrollmentClient = (*EnrollmentClient)(nil)
