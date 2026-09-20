package scep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

const maxConfigResponse = 1 << 20

var challengePattern = regexp.MustCompile(`(?is)enrollment challenge password is:\s*<b>\s*([^<\s]+)\s*</b>`)

type NDESConfig struct{ AdminURL, Username, Password string }
type SmallstepConfig struct{ SCEPURL, ChallengeURL, Username, Password string }

type ConfigService struct {
	logger  *slog.Logger
	timeout *time.Duration
}

func NewConfigService(logger *slog.Logger, timeout *time.Duration) *ConfigService {
	if logger == nil {
		logger = slog.Default()
	}
	if timeout == nil {
		value := 10 * time.Second
		timeout = &value
	}
	return &ConfigService{logger: logger, timeout: timeout}
}

func (s *ConfigService) ValidateSCEPURL(ctx context.Context, rawURL string) error {
	parsed, err := validatedURL(rawURL)
	if err != nil {
		return err
	}
	query := parsed.Query()
	query.Set("operation", "GetCACaps")
	parsed.RawQuery = query.Encode()
	if _, err := s.request(ctx, http.MethodGet, parsed.String(), "", "", nil, false); err != nil {
		return fmt.Errorf("validate SCEP URL: %w", err)
	}
	return nil
}

func (s *ConfigService) ValidateNDESAdminURL(ctx context.Context, config NDESConfig) error {
	_, err := s.GetNDESChallenge(ctx, config)
	return err
}

func (s *ConfigService) GetNDESChallenge(ctx context.Context, config NDESConfig) (string, error) {
	if _, err := validatedURL(config.AdminURL); err != nil {
		return "", newNDESInvalid(err.Error())
	}
	body, err := s.request(ctx, http.MethodGet, config.AdminURL, config.Username, config.Password, nil, true)
	if err != nil {
		var statusErr *remoteStatusError
		if errors.As(err, &statusErr) {
			return "", newNDESInvalid("NDES rejected the admin URL or credentials")
		}
		return "", err
	}
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "password cache is full"):
		return "", NewNDESPasswordCacheFullError("NDES password cache is full")
	case strings.Contains(lower, "do not have sufficient permission"):
		return "", NewNDESInsufficientPermissionsError("NDES account has insufficient permissions")
	}
	matches := challengePattern.FindSubmatch(body)
	if len(matches) != 2 {
		return "", newNDESInvalid("NDES response did not contain an enrollment challenge")
	}
	return string(matches[1]), nil
}

func (s *ConfigService) ValidateSmallstepChallengeURL(ctx context.Context, config SmallstepConfig) error {
	_, err := s.GetSmallstepChallenge(ctx, config)
	return err
}

func (s *ConfigService) GetSmallstepChallenge(ctx context.Context, config SmallstepConfig) (string, error) {
	if _, err := validatedURL(config.ChallengeURL); err != nil {
		return "", fmt.Errorf("invalid challenge URL or credentials: %w", err)
	}
	payload := map[string]any{
		"webhook": map[string]any{"webhookEvent": "SCEPChallenge", "id": 1, "eventTimestamp": time.Now().Unix(), "name": ""},
		"event":   map[string]any{"scepServerUrl": config.SCEPURL, "payloadIdentifier": "", "payloadTypes": []string{"com.apple.security.scep"}},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	body, err := s.request(ctx, http.MethodPost, config.ChallengeURL, config.Username, config.Password, bytes.NewReader(encoded), false)
	if err != nil {
		return "", fmt.Errorf("invalid challenge URL or credentials: %w", err)
	}
	challenge := strings.TrimSpace(string(body))
	if challenge == "" {
		return "", errors.New("invalid challenge URL or credentials: empty challenge")
	}
	return challenge, nil
}

func (s *ConfigService) request(ctx context.Context, method, endpoint, username, password string, body io.Reader, negotiate bool) ([]byte, error) {
	transport := http.RoundTripper(http.DefaultTransport.(*http.Transport).Clone())
	if negotiate {
		transport = ntlmssp.Negotiator{RoundTripper: transport, AllowBasicAuth: true}
	}
	client := &http.Client{Timeout: *s.timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxConfigResponse+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigResponse {
		return nil, errors.New("response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &remoteStatusError{status: response.StatusCode}
	}
	return data, nil
}

type remoteStatusError struct{ status int }

func (e *remoteStatusError) Error() string {
	return fmt.Sprintf("remote server returned HTTP %d", e.status)
}

func validatedURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("URL must use http or https and include a host")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("URL credentials and fragments are not allowed")
	}
	return parsed, nil
}

type ndesErrorKind uint8

const (
	ndesInvalid ndesErrorKind = iota + 1
	ndesCacheFull
	ndesInsufficientPermissions
)

type NDESError struct {
	kind    ndesErrorKind
	message string
}

func (e *NDESError) Error() string             { return e.message }
func newNDESInvalid(message string) error      { return &NDESError{kind: ndesInvalid, message: message} }
func NewNDESInvalidError(message string) error { return newNDESInvalid(message) }
func NewNDESPasswordCacheFullError(message string) error {
	return &NDESError{kind: ndesCacheFull, message: message}
}
func NewNDESInsufficientPermissionsError(message string) error {
	return &NDESError{kind: ndesInsufficientPermissions, message: message}
}
func IsTerminalNDESChallengeError(err error) bool {
	var target *NDESError
	return errors.As(err, &target)
}
func NDESChallengeErrorToDetail(err error) string {
	var target *NDESError
	if !errors.As(err, &target) {
		return "Fleet couldn't retrieve an NDES challenge. Check connectivity to the NDES server."
	}
	switch target.kind {
	case ndesCacheFull:
		return "Fleet couldn't retrieve an NDES challenge because all cached passwords are currently in use."
	case ndesInsufficientPermissions:
		return "Fleet couldn't retrieve an NDES challenge because the configured account does not have sufficient permissions."
	default:
		return "Fleet couldn't retrieve an NDES challenge. Check the NDES URL and update credentials."
	}
}
