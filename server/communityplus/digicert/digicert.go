// Package digicert implements the small subset of the DigiCert ONE REST API
// used to validate certificate profiles and issue client certificates.
package digicert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	defaultTimeout  = 30 * time.Second
	maxResponseSize = 4 << 20
)

type Config struct {
	URL                   string
	APIToken              string
	ProfileID             string
	CertificateCommonName string
	UserPrincipalNames    []string
	CertificateSeatID     string
}

type Certificate struct {
	PFXData        []byte
	Password       string
	NotValidBefore time.Time
	NotValidAfter  time.Time
	SerialNumber   string
}

type Service struct {
	client *http.Client
}

type Option func(*Service)

func WithHTTPClient(client *http.Client) Option {
	return func(service *Service) {
		if client != nil {
			service.client = client
		}
	}
}

func NewService(opts ...Option) *Service {
	service := &Service{client: &http.Client{
		Timeout: defaultTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// The API token is carried in a custom header that net/http does not
			// automatically strip on cross-origin redirects.
			return http.ErrUseLastResponse
		},
	}}
	for _, opt := range opts {
		if opt != nil {
			opt(service)
		}
	}
	return service
}

func (s *Service) VerifyProfileID(ctx context.Context, config Config) error {
	endpoint, err := endpointURL(config.URL, "mpki/api/v2/profile", config.ProfileID)
	if err != nil {
		return err
	}

	var profile struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := s.doJSON(ctx, http.MethodGet, endpoint, config.APIToken, nil, http.StatusOK, &profile); err != nil {
		return fmt.Errorf("verify DigiCert profile: %w", err)
	}
	if profile.ID != config.ProfileID {
		return fmt.Errorf("verify DigiCert profile: response ID %q does not match requested profile %q", profile.ID, config.ProfileID)
	}
	if !strings.EqualFold(profile.Status, "active") {
		return fmt.Errorf("verify DigiCert profile: profile %q is not active", config.ProfileID)
	}
	return nil
}

func (s *Service) GetCertificate(ctx context.Context, config Config) (*Certificate, error) {
	endpoint, err := endpointURL(config.URL, "mpki/api/v1/certificate")
	if err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate DigiCert private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: config.CertificateCommonName},
	}, privateKey)
	if err != nil {
		return nil, fmt.Errorf("generate DigiCert CSR: %w", err)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	request := certificateRequest{
		CSR:            string(csr),
		Profile:        map[string]string{"id": config.ProfileID},
		Seat:           map[string]string{"seat_id": config.CertificateSeatID},
		DeliveryFormat: "x509",
		Attributes: certificateAttributes{
			Subject: certificateSubject{CommonName: config.CertificateCommonName},
			Extensions: certificateExtensions{SAN: certificateSAN{
				UserPrincipalNames: append([]string(nil), config.UserPrincipalNames...),
			}},
		},
	}

	var response struct {
		SerialNumber   string `json:"serial_number"`
		DeliveryFormat string `json:"delivery_format"`
		Certificate    string `json:"certificate"`
	}
	if err := s.doJSON(ctx, http.MethodPost, endpoint, config.APIToken, request, http.StatusCreated, &response); err != nil {
		return nil, fmt.Errorf("request DigiCert certificate: %w", err)
	}
	if !strings.EqualFold(response.DeliveryFormat, "x509") {
		return nil, fmt.Errorf("request DigiCert certificate: unsupported delivery format %q", response.DeliveryFormat)
	}
	block, rest := pem.Decode([]byte(response.Certificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("request DigiCert certificate: response contains an invalid PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse DigiCert certificate: %w", err)
	}

	passwordBytes := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, passwordBytes); err != nil {
		return nil, fmt.Errorf("generate PKCS#12 password: %w", err)
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	pfxData, err := pkcs12.Modern.Encode(privateKey, certificate, nil, password)
	if err != nil {
		return nil, fmt.Errorf("encode DigiCert PKCS#12 bundle: %w", err)
	}

	serialNumber := response.SerialNumber
	if serialNumber == "" {
		serialNumber = certificate.SerialNumber.String()
	}
	return &Certificate{
		PFXData:        pfxData,
		Password:       password,
		NotValidBefore: certificate.NotBefore,
		NotValidAfter:  certificate.NotAfter,
		SerialNumber:   serialNumber,
	}, nil
}

type certificateRequest struct {
	CSR            string                `json:"csr"`
	Profile        map[string]string     `json:"profile"`
	Seat           map[string]string     `json:"seat"`
	DeliveryFormat string                `json:"delivery_format"`
	Attributes     certificateAttributes `json:"attributes"`
}

type certificateAttributes struct {
	Subject    certificateSubject    `json:"subject"`
	Extensions certificateExtensions `json:"extensions"`
}

type certificateSubject struct {
	CommonName string `json:"common_name"`
}

type certificateExtensions struct {
	SAN certificateSAN `json:"san"`
}

type certificateSAN struct {
	UserPrincipalNames []string `json:"user_principal_names"`
}

func endpointURL(baseURL string, segments ...string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid DigiCert URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("invalid DigiCert URL: scheme must be http or https")
	}
	if parsed.Host == "" || parsed.User != nil {
		return "", errors.New("invalid DigiCert URL: host is required and credentials are not allowed")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid DigiCert URL: query strings and fragments are not allowed")
	}
	parts := append([]string{parsed.Path}, segments...)
	parsed.Path = path.Join(parts...)
	parsed.RawPath = ""
	return parsed.String(), nil
}

func (s *Service) doJSON(ctx context.Context, method, endpoint, apiToken string, body any, expectedStatus int, target any) error {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", apiToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	response, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(data) > maxResponseSize {
		return errors.New("response exceeds size limit")
	}
	if response.StatusCode != expectedStatus {
		return statusError(response.StatusCode, data)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func statusError(status int, body []byte) error {
	var response struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &response) == nil && len(response.Errors) > 0 {
		messages := make([]string, 0, len(response.Errors))
		for _, item := range response.Errors {
			if item.Message != "" {
				messages = append(messages, item.Message)
			}
		}
		if len(messages) > 0 {
			return fmt.Errorf("DigiCert API returned HTTP %d: %s", status, strings.Join(messages, "; "))
		}
	}
	return fmt.Errorf("DigiCert API returned HTTP %d", status)
}
