package adue

import (
	"context"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/jmoiron/sqlx"
)

func TestSSOURL(t *testing.T) {
	ds := &mock.DataStore{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{
			MDM: fleet.MDM{AppleServerURL: "https://mdm.example.test"},
		}, nil
	}
	svc := New(ds)

	got, err := svc.SSOURL(context.Background(), "token-123")
	if err != nil {
		t.Fatalf("SSOURL: %v", err)
	}
	want := "https://mdm.example.test/mdm/apple/account_driven_enroll/sso/token-123"
	if got != want {
		t.Fatalf("SSOURL = %q, want %q", got, want)
	}

	got, err = svc.SSOURL(context.Background(), "")
	if err != nil {
		t.Fatalf("SSOURL without token: %v", err)
	}
	want = "https://mdm.example.test/mdm/apple/account_driven_enroll/sso"
	if got != want {
		t.Fatalf("SSOURL without token = %q, want %q", got, want)
	}
}

func TestSSOURLRejectsAppleBusinessOnlyMode(t *testing.T) {
	ds := &mock.DataStore{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{
			MDM: fleet.MDM{OnlyAllowAppleBusinessEnrollment: true},
		}, nil
	}

	_, err := New(ds).SSOURL(context.Background(), "")
	var forbidden *fleet.ABOnlyEnrollmentForbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatalf("expected ABOnlyEnrollmentForbiddenError, got %v", err)
	}
}

func TestEnrollmentProfileConsumesChallengeAndSignsProfile(t *testing.T) {
	ds := &mock.DataStore{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{
			OrgInfo: fleet.OrgInfo{OrgName: "Example Org"},
			MDM:     fleet.MDM{AppleServerURL: "https://mdm.example.test"},
		}, nil
	}
	ds.ConsumeADUEEnrollmentChallengeFunc = func(_ context.Context, challenge string) (*fleet.ADUEEnrollmentChallenge, error) {
		if challenge != "challenge-123" {
			t.Fatalf("unexpected challenge %q", challenge)
		}
		return &fleet.ADUEEnrollmentChallenge{IdPAccountUUID: "idp-1"}, nil
	}
	ds.GetMDMIdPAccountByUUIDFunc = func(_ context.Context, uuid string) (*fleet.MDMIdPAccount, error) {
		if uuid != "idp-1" {
			t.Fatalf("unexpected IdP UUID %q", uuid)
		}
		return &fleet.MDMIdPAccount{Email: "user@example.test"}, nil
	}
	ds.GetAllMDMConfigAssetsByNameFunc = func(_ context.Context, names []fleet.MDMAssetName, _ sqlx.QueryerContext) (map[fleet.MDMAssetName]fleet.MDMConfigAsset, error) {
		if len(names) != 1 || names[0] != fleet.MDMAssetSCEPChallenge {
			t.Fatalf("unexpected asset names %#v", names)
		}
		return map[fleet.MDMAssetName]fleet.MDMConfigAsset{
			fleet.MDMAssetSCEPChallenge: {Value: []byte("scep-challenge")},
		}, nil
	}

	svc := New(ds)
	svc.pushTopic = func(context.Context, fleet.MDMAssetRetriever) (string, error) {
		return "com.apple.mgmt.External.example", nil
	}
	svc.generate = func(orgName, enrollURL, scepChallenge, topic, email string, fresh bool) ([]byte, error) {
		if orgName != "Example Org" || enrollURL != "https://mdm.example.test" || scepChallenge != "scep-challenge" || topic != "com.apple.mgmt.External.example" || email != "user@example.test" || !fresh {
			t.Fatalf("unexpected profile generator inputs: org=%q url=%q challenge=%q topic=%q email=%q fresh=%v", orgName, enrollURL, scepChallenge, topic, email, fresh)
		}
		return []byte("unsigned-profile"), nil
	}
	svc.sign = func(_ context.Context, profile []byte, _ fleet.Datastore) ([]byte, error) {
		if string(profile) != "unsigned-profile" {
			t.Fatalf("unexpected unsigned profile %q", profile)
		}
		return []byte("signed-profile"), nil
	}

	got, err := svc.EnrollmentProfile(context.Background(), "challenge-123")
	if err != nil {
		t.Fatalf("EnrollmentProfile: %v", err)
	}
	if string(got) != "signed-profile" {
		t.Fatalf("EnrollmentProfile = %q, want signed-profile", got)
	}
}

func TestEnrollmentProfileRejectsMissingChallenge(t *testing.T) {
	ds := &mock.DataStore{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) { return &fleet.AppConfig{}, nil }
	ds.ConsumeADUEEnrollmentChallengeFunc = func(context.Context, string) (*fleet.ADUEEnrollmentChallenge, error) { return nil, nil }

	_, err := New(ds).EnrollmentProfile(context.Background(), "missing")
	var badRequest *fleet.BadRequestError
	if !errors.As(err, &badRequest) {
		t.Fatalf("expected BadRequestError, got %v", err)
	}
}
