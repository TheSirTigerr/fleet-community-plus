// Package est implements Community+'s EST certificate authority client.
package est

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/fleethttp"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

const defaultTimeout = 20 * time.Second

type Service struct {
	logger  *slog.Logger
	timeout time.Duration
	client  *http.Client
}

type Option func(*Service)

func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(s *Service) {
		s.timeout = timeout
	}
}

func NewService(opts ...Option) fleet.ESTService {
	svc := &Service{}
	for _, opt := range opts {
		opt(svc)
	}
	if svc.timeout <= 0 {
		svc.timeout = defaultTimeout
	}
	if svc.logger == nil {
		svc.logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	svc.client = fleethttp.NewClient(fleethttp.WithTimeout(svc.timeout))
	return svc
}

func (s *Service) ValidateESTURL(ctx context.Context, ca fleet.ESTProxyCA) error {
	endpoint, err := estEndpoint(ca.URL, "cacerts")
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("create EST cacerts request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("request EST cacerts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EST cacerts returned HTTP %d", resp.StatusCode)
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/pkcs7-mime") {
		return fmt.Errorf("EST cacerts returned unexpected content type %q", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("read EST cacerts response: %w", err)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return errors.New("EST cacerts response is empty")
	}
	return nil
}

func (s *Service) GetCertificate(ctx context.Context, ca fleet.ESTProxyCA, csr string) (*fleet.ESTCertificate, error) {
	endpoint, err := estEndpoint(ca.URL, "simpleenroll")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(ca.Username) == "" || ca.Password == "" || ca.Password == fleet.MaskedPassword {
		return nil, errors.New("EST credentials are incomplete")
	}
	if strings.TrimSpace(csr) == "" {
		return nil, errors.New("EST certificate request CSR is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(csr))
	if err != nil {
		return nil, fmt.Errorf("create EST enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Accept", "application/pkcs7-mime")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(ca.Username+":"+ca.Password)))

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request EST simpleenroll: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read EST enrollment response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		s.logger.ErrorContext(ctx, "EST enrollment failed", "status_code", resp.StatusCode)
		return nil, fmt.Errorf("EST simpleenroll returned HTTP %d", resp.StatusCode)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, errors.New("EST simpleenroll response is empty")
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType != "" && !strings.HasPrefix(contentType, "application/pkcs7-mime") {
		return nil, fmt.Errorf("EST simpleenroll returned unexpected content type %q", resp.Header.Get("Content-Type"))
	}

	return &fleet.ESTCertificate{Certificate: body}, nil
}

func estEndpoint(rawBaseURL, operation string) (*url.URL, error) {
	base, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil {
		return nil, fmt.Errorf("parse EST base URL: %w", err)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return nil, errors.New("EST URL must use HTTP or HTTPS")
	}
	if base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("EST URL must be an absolute URL without credentials, query, or fragment")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + operation
	base.RawPath = ""
	return base, nil
}

var _ fleet.ESTService = (*Service)(nil)
