package digicert

import (
	"log/slog"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestFleetConfig(t *testing.T) {
	input := fleet.DigiCertCA{
		URL:                           "https://one.digicert.com",
		APIToken:                      "token",
		ProfileID:                     "profile",
		CertificateCommonName:         "device.example",
		CertificateUserPrincipalNames: []string{"user@example.test"},
		CertificateSeatID:             "seat",
	}
	got := fleetConfig(input)
	if got.URL != input.URL || got.APIToken != input.APIToken || got.ProfileID != input.ProfileID || got.CertificateCommonName != input.CertificateCommonName || got.CertificateSeatID != input.CertificateSeatID {
		t.Fatalf("unexpected DigiCert config mapping: %#v", got)
	}
	if len(got.UserPrincipalNames) != 1 || got.UserPrincipalNames[0] != input.CertificateUserPrincipalNames[0] {
		t.Fatalf("unexpected UPN mapping: %#v", got.UserPrincipalNames)
	}

	input.CertificateUserPrincipalNames[0] = "changed@example.test"
	if got.UserPrincipalNames[0] != "user@example.test" {
		t.Fatal("expected adapter config to copy UPN values")
	}
}

func TestNewFleetService(t *testing.T) {
	if service := NewFleetService(slog.Default()); service == nil {
		t.Fatal("expected DigiCert Fleet service")
	}
	if service := NewFleetService(nil); service == nil {
		t.Fatal("expected DigiCert Fleet service with nil logger")
	}
}
