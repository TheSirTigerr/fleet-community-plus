// Package adue implements Community+ Apple Account-Driven User Enrollment.
package adue

import (
	"context"
	"fmt"

	"github.com/fleetdm/fleet/v4/server/fleet"
	apple_mdm "github.com/fleetdm/fleet/v4/server/mdm/apple"
	"github.com/fleetdm/fleet/v4/server/mdm/crypto"
)

// Service implements the license-independent parts of Apple's account-driven
// enrollment flow on top of the Community datastore and MDM primitives.
type Service struct {
	ds fleet.Datastore

	pushTopic func(context.Context, fleet.Datastore) (string, error)
	generate  func(orgName, enrollURL, scepChallenge, topic, email string, freshEnrollment bool) ([]byte, error)
	sign      func(context.Context, []byte, fleet.Datastore) ([]byte, error)
}

func New(ds fleet.Datastore) *Service {
	return &Service{
		ds:        ds,
		pushTopic: apple_mdm.MDMPushCertTopic,
		generate:  apple_mdm.GenerateAccountDrivenEnrollmentProfileMobileconfig,
		sign:      crypto.Sign,
	}
}

// SSOURL returns the account-driven enrollment SSO endpoint for the current
// Fleet server. Apple Business-only enrollment mode intentionally rejects ADUE.
func (s *Service) SSOURL(ctx context.Context, enrollmentToken string) (string, error) {
	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("get app config: %w", err)
	}
	if appConfig.MDM.OnlyAllowAppleBusinessEnrollment {
		return "", &fleet.ABOnlyEnrollmentForbiddenError{}
	}

	base := appConfig.MDMUrl() + "/mdm/apple/account_driven_enroll/sso"
	if enrollmentToken != "" {
		base += "/" + enrollmentToken
	}
	return base, nil
}

// EnrollmentProfile consumes a one-time ADUE challenge and returns a signed
// user-enrollment profile bound to the IdP account that authenticated it.
func (s *Service) EnrollmentProfile(ctx context.Context, enrollRef string) ([]byte, error) {
	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("get app config: %w", err)
	}
	if appConfig.MDM.OnlyAllowAppleBusinessEnrollment {
		return nil, &fleet.ABOnlyEnrollmentForbiddenError{}
	}

	challenge, err := s.ds.ConsumeADUEEnrollmentChallenge(ctx, enrollRef)
	if err != nil {
		return nil, fmt.Errorf("consume account-driven enrollment challenge: %w", err)
	}
	if challenge == nil {
		return nil, &fleet.BadRequestError{Message: "account driven enrollment challenge not found"}
	}

	idpAccount, err := s.ds.GetMDMIdPAccountByUUID(ctx, challenge.IdPAccountUUID)
	if err != nil {
		return nil, fmt.Errorf("get MDM IdP account: %w", err)
	}

	topic, err := s.pushTopic(ctx, s.ds)
	if err != nil {
		return nil, fmt.Errorf("get APNs push topic: %w", err)
	}

	assets, err := s.ds.GetAllMDMConfigAssetsByName(ctx, []fleet.MDMAssetName{fleet.MDMAssetSCEPChallenge}, nil)
	if err != nil {
		return nil, fmt.Errorf("load SCEP challenge: %w", err)
	}
	asset, ok := assets[fleet.MDMAssetSCEPChallenge]
	if !ok || asset == nil {
		return nil, fmt.Errorf("load SCEP challenge: asset is missing")
	}

	profile, err := s.generate(
		appConfig.OrgInfo.OrgName,
		appConfig.MDMUrl(),
		string(asset.Value),
		topic,
		idpAccount.Email,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("generate account-driven enrollment profile: %w", err)
	}

	signed, err := s.sign(ctx, profile, s.ds)
	if err != nil {
		return nil, fmt.Errorf("sign account-driven enrollment profile: %w", err)
	}
	return signed, nil
}
