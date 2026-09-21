package licensing

import (
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestLoad(t *testing.T) {
	license, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if license.Tier != fleet.TierFree || license.IsPremium() {
		t.Fatalf("unexpected license: %#v", license)
	}
	if _, err := Load("not-a-communityplus-capability-token"); !errors.Is(err, ErrExternalLicenseUnsupported) {
		t.Fatalf("expected unsupported external license error, got %v", err)
	}
}

func TestLoadLicenseStartupCompatibility(t *testing.T) {
	license, err := LoadLicense("")
	if err != nil {
		t.Fatalf("load startup license: %v", err)
	}
	if license == nil || license.Tier != fleet.TierFree {
		t.Fatalf("expected free tier startup license, got %#v", license)
	}
	if _, err := LoadLicense("external-enterprise-token"); !errors.Is(err, ErrExternalLicenseUnsupported) {
		t.Fatalf("expected unsupported external license error, got %v", err)
	}
}
