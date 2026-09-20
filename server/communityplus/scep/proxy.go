package scep

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	scepclient "github.com/fleetdm/fleet/v4/server/mdm/scep/client"
)

const (
	MessageSCEPProxyNotConfigured  = "SCEP proxy is not configured"
	NDESChallengeInvalidAfter      = 57 * time.Minute
	SmallstepChallengeInvalidAfter = 57 * time.Minute
)

type CA struct{ Name, URL, Type string }
type GroupedCAs struct {
	NDES              *CA
	Custom, Smallstep []CA
}
type CertificateProfile struct {
	Status               *string
	ChallengeRetrievedAt *time.Time
	Type, CAName         string
}

type Store interface {
	GroupedCertificateAuthorities(context.Context) (*GroupedCAs, error)
	CertificateProfile(context.Context, string, string, string, string) (*CertificateProfile, error)
	ResendCertificateProfile(context.Context, string, string, string) error
}

type ProxyService struct {
	store   Store
	logger  *slog.Logger
	timeout *time.Duration
}

func NewProxyService(store Store, logger *slog.Logger, timeout *time.Duration) *ProxyService {
	if logger == nil {
		logger = slog.Default()
	}
	if timeout == nil {
		value := 10 * time.Second
		timeout = &value
	}
	return &ProxyService{store: store, logger: logger, timeout: timeout}
}

func (s *ProxyService) GetCACaps(ctx context.Context, identifier string) ([]byte, error) {
	client, _, err := s.client(ctx, identifier, false)
	if err != nil {
		return nil, err
	}
	data, err := client.GetCACaps(ctx)
	if err != nil {
		return nil, publicProxyError("Could not GetCACaps from SCEP server", err)
	}
	return data, nil
}

func (s *ProxyService) GetCACert(ctx context.Context, message, identifier string) ([]byte, int, error) {
	client, _, err := s.client(ctx, identifier, false)
	if err != nil {
		return nil, 0, err
	}
	data, count, err := client.GetCACert(ctx, message)
	if err != nil {
		return nil, 0, publicProxyError("Could not GetCACert from SCEP server", err)
	}
	return data, count, nil
}

func (s *ProxyService) PKIOperation(ctx context.Context, message []byte, identifier string) ([]byte, error) {
	client, target, err := s.client(ctx, identifier, true)
	if err != nil {
		return nil, err
	}
	data, err := client.PKIOperation(ctx, message)
	if err != nil {
		s.logger.WarnContext(ctx, "SCEP proxy PKI operation failed", "ca_type", target.Type, "err", err)
		return nil, publicProxyError("Could not do PKIOperation on SCEP server", err)
	}
	return data, nil
}

func (s *ProxyService) GetNextCACert(context.Context) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *ProxyService) client(ctx context.Context, identifier string, requirePending bool) (scepclient.Client, CA, error) {
	platform, hostUUID, profileUUID, caName, err := parseIdentifier(identifier)
	if err != nil {
		return nil, CA{}, err
	}
	profile, err := s.store.CertificateProfile(ctx, platform, hostUUID, profileUUID, caName)
	if err != nil {
		return nil, CA{}, errors.New("could not validate SCEP identifier")
	}
	if profile == nil {
		return nil, CA{}, errors.New("unknown identifier")
	}
	if requirePending && (profile.Status == nil || *profile.Status != "pending") {
		return nil, CA{}, errors.New("profile status does not allow certificate enrollment")
	}
	if requirePending && challengeExpired(profile) {
		if err := s.store.ResendCertificateProfile(ctx, platform, hostUUID, profileUUID); err != nil {
			s.logger.ErrorContext(ctx, "failed to queue profile after expired SCEP challenge", "err", err)
		}
		return nil, CA{}, errors.New("challenge password expired")
	}
	grouped, err := s.store.GroupedCertificateAuthorities(ctx)
	if err != nil || grouped == nil {
		return nil, CA{}, errors.New(MessageSCEPProxyNotConfigured)
	}
	target, ok := selectCA(grouped, profile.Type, profile.CAName)
	if !ok || target.URL == "" {
		return nil, CA{}, errors.New(MessageSCEPProxyNotConfigured)
	}
	client, err := scepclient.New(target.URL, s.logger, scepclient.WithTimeout(s.timeout))
	if err != nil {
		return nil, CA{}, errors.New("invalid SCEP server configuration")
	}
	return client, target, nil
}

func parseIdentifier(identifier string) (platform, hostUUID, profileUUID, caName string, err error) {
	parts := strings.Split(identifier, ",")
	if len(parts) != 2 && len(parts) != 3 {
		return "", "", "", "", errors.New("invalid identifier")
	}
	hostUUID, profileUUID = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if hostUUID == "" || profileUUID == "" {
		return "", "", "", "", errors.New("invalid identifier")
	}
	switch profileUUID[0] {
	case 'a':
		platform = "apple"
	case 'w':
		platform = "windows"
	default:
		return "", "", "", "", errors.New("invalid profile UUID")
	}
	caName = "NDES"
	if len(parts) == 3 {
		caName = strings.TrimSpace(parts[2])
		if caName == "" {
			return "", "", "", "", errors.New("invalid identifier")
		}
	}
	return platform, hostUUID, profileUUID, caName, nil
}

func challengeExpired(profile *CertificateProfile) bool {
	var lifetime time.Duration
	switch profile.Type {
	case "ndes":
		lifetime = NDESChallengeInvalidAfter
	case "smallstep":
		lifetime = SmallstepChallengeInvalidAfter
	default:
		return false
	}
	return profile.ChallengeRetrievedAt == nil || !profile.ChallengeRetrievedAt.Add(lifetime).After(time.Now())
}

func selectCA(grouped *GroupedCAs, caType, name string) (CA, bool) {
	if caType == "ndes" && grouped.NDES != nil {
		return *grouped.NDES, true
	}
	var candidates []CA
	switch caType {
	case "custom_scep_proxy":
		candidates = grouped.Custom
	case "smallstep":
		candidates = grouped.Smallstep
	}
	for _, ca := range candidates {
		if ca.Name == name {
			return ca, true
		}
	}
	return CA{}, false
}

func publicProxyError(message string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New(message)
}
