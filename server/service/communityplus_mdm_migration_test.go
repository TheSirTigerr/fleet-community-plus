package service

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestValidateMDMAllowsCommunityPlusMacOSMigrationWithoutPremiumLicense(t *testing.T) {
	svc := &Service{}
	oldMDM := &fleet.MDM{EnabledAndConfigured: true}
	newMDM := *oldMDM
	newMDM.MacOSMigration = fleet.MacOSMigration{
		Enable:     true,
		Mode:       fleet.MacOSMigrationModeVoluntary,
		WebhookURL: "https://example.test/migrate",
	}
	invalid := &fleet.InvalidArgumentError{}

	if err := svc.validateMDM(context.Background(), &fleet.LicenseInfo{}, oldMDM, &newMDM, invalid, false); err != nil {
		t.Fatalf("validate MDM migration config: %v", err)
	}
	if len(invalid.Errors) != 0 {
		t.Fatalf("expected valid Community+ MDM migration configuration on free license, got: %v", invalid)
	}
}
