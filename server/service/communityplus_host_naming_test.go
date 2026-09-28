package service

import (
	"context"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
)

func TestValidateMDMAllowsCommunityPlusHostNameTemplateWithoutPremiumLicense(t *testing.T) {
	ds := &mock.DataStore{}
	ds.ValidateReferencedCustomHostVitalsFunc = func(context.Context, []string) error { return nil }
	svc := &Service{ds: ds, authz: authz.Must()}
	oldMDM := &fleet.MDM{EnabledAndConfigured: true}
	newMDM := *oldMDM
	newMDM.HostNameTemplate = optjson.SetString("WS-$FLEET_VAR_HOST_HARDWARE_SERIAL")
	invalid := &fleet.InvalidArgumentError{}

	if err := svc.validateMDM(context.Background(), &fleet.LicenseInfo{}, oldMDM, &newMDM, invalid, false); err != nil {
		t.Fatalf("validate host naming config: %v", err)
	}
	if len(invalid.Errors) != 0 {
		t.Fatalf("expected valid Community+ host naming configuration on free license, got: %v", invalid)
	}
	if newMDM.HostNameTemplate.Value != "WS-$FLEET_VAR_HOST_HARDWARE_SERIAL" {
		t.Fatalf("unexpected normalized host naming template %q", newMDM.HostNameTemplate.Value)
	}
}

func TestUpdateMDMHostNameTemplateIsNotPremiumLicenseGated(t *testing.T) {
	svc := &Service{authz: authz.Must()}
	err := svc.UpdateMDMHostNameTemplate(context.Background(), nil, "workstation")
	if errors.Is(err, fleet.ErrMissingLicense) {
		t.Fatal("Community+ host naming endpoint must not be gated on a Premium license")
	}
	// With no authenticated viewer the request should stop at normal RBAC before
	// touching the datastore. The exact authorization error is intentionally not
	// asserted here; this regression only protects the Community+ license gate.
	if err == nil {
		t.Fatal("expected normal authorization to reject the unauthenticated request")
	}
}
