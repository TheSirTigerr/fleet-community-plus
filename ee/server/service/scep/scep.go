// Package scep preserves Fleet's historical EE import path while delegating
// to the independently implemented Community+ SCEP services.
package scep

import (
	"context"
	"log/slog"
	"time"

	communityscep "github.com/fleetdm/fleet/v4/server/communityplus/scep"
	"github.com/fleetdm/fleet/v4/server/fleet"
	scepserver "github.com/fleetdm/fleet/v4/server/mdm/scep/server"
)

const (
	MessageSCEPProxyNotConfigured  = communityscep.MessageSCEPProxyNotConfigured
	NDESChallengeInvalidAfter      = communityscep.NDESChallengeInvalidAfter
	SmallstepChallengeInvalidAfter = communityscep.SmallstepChallengeInvalidAfter
)

type SCEPConfigService struct {
	Timeout *time.Duration
	inner   *communityscep.ConfigService
}

func NewSCEPConfigService(logger *slog.Logger, timeout *time.Duration) fleet.SCEPConfigService {
	if timeout == nil {
		value := 10 * time.Second
		timeout = &value
	}
	return &SCEPConfigService{Timeout: timeout, inner: communityscep.NewConfigService(logger, timeout)}
}

func (s *SCEPConfigService) ValidateNDESSCEPAdminURL(ctx context.Context, config fleet.NDESSCEPProxyCA) error {
	return s.inner.ValidateNDESAdminURL(ctx, communityscep.NDESConfig{AdminURL: config.AdminURL, Username: config.Username, Password: config.Password})
}
func (s *SCEPConfigService) GetNDESSCEPChallenge(ctx context.Context, config fleet.NDESSCEPProxyCA) (string, error) {
	return s.inner.GetNDESChallenge(ctx, communityscep.NDESConfig{AdminURL: config.AdminURL, Username: config.Username, Password: config.Password})
}
func (s *SCEPConfigService) ValidateSCEPURL(ctx context.Context, rawURL string) error {
	return s.inner.ValidateSCEPURL(ctx, rawURL)
}
func (s *SCEPConfigService) ValidateSmallstepChallengeURL(ctx context.Context, config fleet.SmallstepSCEPProxyCA) error {
	return s.inner.ValidateSmallstepChallengeURL(ctx, toSmallstepConfig(config))
}
func (s *SCEPConfigService) GetSmallstepSCEPChallenge(ctx context.Context, config fleet.SmallstepSCEPProxyCA) (string, error) {
	return s.inner.GetSmallstepChallenge(ctx, toSmallstepConfig(config))
}
func toSmallstepConfig(config fleet.SmallstepSCEPProxyCA) communityscep.SmallstepConfig {
	return communityscep.SmallstepConfig{SCEPURL: config.URL, ChallengeURL: config.ChallengeURL, Username: config.Username, Password: config.Password}
}

func NewNDESInvalidError(message string) error { return communityscep.NewNDESInvalidError(message) }
func NewNDESPasswordCacheFullError(message string) error {
	return communityscep.NewNDESPasswordCacheFullError(message)
}
func NewNDESInsufficientPermissionsError(message string) error {
	return communityscep.NewNDESInsufficientPermissionsError(message)
}
func IsTerminalNDESChallengeError(err error) bool {
	return communityscep.IsTerminalNDESChallengeError(err)
}
func NDESChallengeErrorToDetail(err error) string {
	return communityscep.NDESChallengeErrorToDetail(err)
}

type fleetStore struct{ ds fleet.Datastore }

func (s fleetStore) GroupedCertificateAuthorities(ctx context.Context) (*communityscep.GroupedCAs, error) {
	grouped, err := s.ds.GetGroupedCertificateAuthorities(ctx, true)
	if err != nil {
		return nil, err
	}
	result := &communityscep.GroupedCAs{}
	if grouped.NDESSCEP != nil {
		result.NDES = &communityscep.CA{Name: "NDES", URL: grouped.NDESSCEP.URL, Type: string(fleet.CAConfigNDES)}
	}
	for _, ca := range grouped.CustomScepProxy {
		result.Custom = append(result.Custom, communityscep.CA{Name: ca.Name, URL: ca.URL, Type: string(fleet.CAConfigCustomSCEPProxy)})
	}
	for _, ca := range grouped.Smallstep {
		result.Smallstep = append(result.Smallstep, communityscep.CA{Name: ca.Name, URL: ca.URL, Type: string(fleet.CAConfigSmallstep)})
	}
	return result, nil
}
func (s fleetStore) CertificateProfile(ctx context.Context, platform, hostUUID, profileUUID, caName string) (*communityscep.CertificateProfile, error) {
	var profile *fleet.HostMDMCertificateProfile
	var err error
	if platform == "windows" {
		profile, err = s.ds.GetWindowsHostMDMCertificateProfile(ctx, hostUUID, profileUUID, caName)
	} else {
		profile, err = s.ds.GetAppleHostMDMCertificateProfile(ctx, hostUUID, profileUUID, caName)
	}
	if err != nil || profile == nil {
		return nil, err
	}
	var status *string
	if profile.Status != nil {
		value := string(*profile.Status)
		status = &value
	}
	return &communityscep.CertificateProfile{Status: status, ChallengeRetrievedAt: profile.ChallengeRetrievedAt, Type: string(profile.Type), CAName: profile.CAName}, nil
}
func (s fleetStore) ResendCertificateProfile(ctx context.Context, platform, hostUUID, profileUUID string) error {
	if platform == "windows" {
		return s.ds.ResendWindowsHostCertificateProfile(ctx, hostUUID, profileUUID)
	}
	return s.ds.ResendHostCertificateProfile(ctx, hostUUID, profileUUID)
}
func NewSCEPProxyService(ds fleet.Datastore, logger *slog.Logger, timeout *time.Duration) scepserver.ServiceWithIdentifier {
	return communityscep.NewProxyService(fleetStore{ds: ds}, logger, timeout)
}

var _ fleet.SCEPConfigService = (*SCEPConfigService)(nil)
var _ scepserver.ServiceWithIdentifier = (*communityscep.ProxyService)(nil)
