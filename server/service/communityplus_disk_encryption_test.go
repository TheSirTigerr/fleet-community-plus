package service

import (
	"context"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestValidateMDMAllowsCommunityPlusDiskEncryptionWithoutPremiumLicense(t *testing.T) {
	svc := &Service{}
	oldMDM := &fleet.MDM{
		EnabledAndConfigured: true,
	}
	newMDM := *oldMDM
	newMDM.MacOSSettings.EnableDiskEncryption = optjson.SetBool(true)
	newMDM.MacOSSettings.EnableEscrowDiskEncryptionKey = optjson.SetBool(true)
	newMDM.WindowsSettings.EnableDiskEncryption = optjson.SetBool(true)
	newMDM.LinuxSettings.EnableEscrowDiskEncryptionKey = optjson.SetBool(true)

	invalid := &fleet.InvalidArgumentError{}
	if err := svc.validateMDM(context.Background(), &fleet.LicenseInfo{}, oldMDM, &newMDM, invalid, false); err != nil {
		t.Fatalf("validate disk encryption config: %v", err)
	}
	if len(invalid.Errors) != 0 {
		t.Fatalf("expected Community+ disk encryption settings to be valid on free license, got: %v", invalid)
	}
}

func TestUpdateMDMDiskEncryptionIsNotPremiumLicenseGated(t *testing.T) {
	svc := &Service{authz: authz.Must()}

	err := svc.UpdateMDMDiskEncryption(context.Background(), nil, fleet.MDMDiskEncryptionSettingsPayload{})
	if errors.Is(err, fleet.ErrMissingLicense) {
		t.Fatal("Community+ disk encryption endpoint must not be gated on a Premium license")
	}
	if err == nil {
		t.Fatal("expected normal authorization to reject the unauthenticated request")
	}
}
