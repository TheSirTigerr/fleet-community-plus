package diskencryption

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
	apple_mdm "github.com/fleetdm/fleet/v4/server/mdm/apple"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/mobileconfig"
	"github.com/fleetdm/fleet/v4/server/mdm/nanodep/tokenpki"
	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/jmoiron/sqlx"
)

type activityRecorder struct {
	activities []fleet.ActivityDetails
}

func (r *activityRecorder) NewActivity(_ context.Context, _ *fleet.User, activity fleet.ActivityDetails) error {
	r.activities = append(r.activities, activity)
	return nil
}

func boolPtr(value bool) *bool { return &value }

func TestUpdateTeamPersistsAndRecordsPlatformActivity(t *testing.T) {
	ds := new(mock.DataStore)
	var saved *fleet.Team
	ds.SaveTeamFunc = func(_ context.Context, team *fleet.Team) (*fleet.Team, error) {
		saved = team
		return team, nil
	}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{}, nil
	}
	recorder := &activityRecorder{}
	svc := &Service{
		ds:         ds,
		activities: recorder,
		config:     &config.FleetConfig{Server: config.ServerConfig{PrivateKey: "configured"}},
	}
	team := &fleet.Team{ID: 7, Name: "Laptops"}

	err := svc.UpdateTeam(context.Background(), team, fleet.DiskEncryptionSettingsChanges{
		MacOSEnable: boolPtr(true),
	}, nil)
	if err != nil {
		t.Fatalf("update fleet disk encryption: %v", err)
	}
	if saved != team {
		t.Fatal("expected fleet to be persisted")
	}
	if !team.Config.MDM.MacOSSettings.EnableDiskEncryption.Value {
		t.Fatal("expected macOS disk encryption to be enabled")
	}
	if len(recorder.activities) != 1 {
		t.Fatalf("expected one activity, got %d", len(recorder.activities))
	}
	activity, ok := recorder.activities[0].(fleet.ActivityTypeEditedDiskEncryptionSettings)
	if !ok {
		t.Fatalf("unexpected activity type %T", recorder.activities[0])
	}
	if activity.FleetID == nil || *activity.FleetID != team.ID || activity.Platform != "macos" {
		t.Fatalf("unexpected activity: %+v", activity)
	}
}

func TestUpdateTeamRequiresPrivateKeyWhenEnablingEscrow(t *testing.T) {
	ds := new(mock.DataStore)
	ds.SaveTeamFunc = func(context.Context, *fleet.Team) (*fleet.Team, error) {
		t.Fatal("fleet must not be saved without a server private key")
		return nil, nil
	}
	svc := &Service{ds: ds, activities: &activityRecorder{}, config: &config.FleetConfig{}}
	team := &fleet.Team{ID: 4, Name: "Servers"}

	err := svc.UpdateTeam(context.Background(), team, fleet.DiskEncryptionSettingsChanges{
		LinuxEscrow: boolPtr(true),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "Missing required private key") {
		t.Fatalf("expected private-key error, got %v", err)
	}
}

func TestReconcileFileVaultRemovesProfileWhenDisabled(t *testing.T) {
	ds := new(mock.DataStore)
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{}, nil
	}
	var deleted bool
	ds.DeleteMDMAppleConfigProfileByTeamAndIdentifierFunc = func(_ context.Context, teamID *uint, identifier string) error {
		if teamID != nil {
			t.Fatalf("expected no-fleet scope, got %v", teamID)
		}
		if identifier != mobileconfig.FleetFileVaultPayloadIdentifier {
			t.Fatalf("unexpected identifier %q", identifier)
		}
		deleted = true
		return nil
	}
	svc := &Service{ds: ds}

	if err := svc.ReconcileFileVault(context.Background(), nil); err != nil {
		t.Fatalf("reconcile disabled FileVault: %v", err)
	}
	if !deleted {
		t.Fatal("expected FileVault profile to be removed")
	}
}

func TestReconcileFileVaultBuildsEnforcementOnlyProfileWithoutCertificate(t *testing.T) {
	ds := new(mock.DataStore)
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		cfg := &fleet.AppConfig{}
		cfg.MDM.MacOSSettings.EnableDiskEncryption = optjson.SetBool(true)
		return cfg, nil
	}
	var profile *fleet.MDMAppleConfigProfile
	ds.UpsertMDMAppleFleetConfigProfileFunc = func(_ context.Context, value fleet.MDMAppleConfigProfile) error {
		profile = &value
		return nil
	}
	svc := &Service{ds: ds}

	if err := svc.ReconcileFileVault(context.Background(), nil); err != nil {
		t.Fatalf("reconcile FileVault profile: %v", err)
	}
	if profile == nil {
		t.Fatal("expected FileVault profile to be upserted")
	}
	if profile.Identifier != mobileconfig.FleetFileVaultPayloadIdentifier {
		t.Fatalf("unexpected identifier %q", profile.Identifier)
	}
	body := string(profile.Mobileconfig)
	if !strings.Contains(body, "dontAllowFDEDisable") {
		t.Fatal("expected FileVault enforcement payload")
	}
	if strings.Contains(body, "FileVault Recovery Key Escrow") {
		t.Fatal("enforcement-only profile must not include escrow payload")
	}
}

func TestReconcileFileVaultBuildsEscrowProfileWithCertificate(t *testing.T) {
	ds := new(mock.DataStore)
	cert, _, err := apple_mdm.NewSCEPCACertKey()
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	certPEM := tokenpki.PEMCertificate(cert.Raw)

	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		cfg := &fleet.AppConfig{}
		cfg.MDM.MacOSSettings.EnableEscrowDiskEncryptionKey = optjson.SetBool(true)
		return cfg, nil
	}
	ds.GetAllMDMConfigAssetsByNameFunc = func(
		_ context.Context,
		names []fleet.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[fleet.MDMAssetName]fleet.MDMConfigAsset, error) {
		if len(names) != 1 || names[0] != fleet.MDMAssetCACert {
			t.Fatalf("unexpected asset request: %v", names)
		}
		return map[fleet.MDMAssetName]fleet.MDMConfigAsset{
			fleet.MDMAssetCACert: {Name: fleet.MDMAssetCACert, Value: certPEM},
		}, nil
	}
	var profile *fleet.MDMAppleConfigProfile
	ds.UpsertMDMAppleFleetConfigProfileFunc = func(_ context.Context, value fleet.MDMAppleConfigProfile) error {
		profile = &value
		return nil
	}

	svc := &Service{ds: ds}
	if err := svc.ReconcileFileVault(context.Background(), nil); err != nil {
		t.Fatalf("reconcile FileVault escrow profile: %v", err)
	}
	if profile == nil {
		t.Fatal("expected FileVault escrow profile to be upserted")
	}

	body := string(profile.Mobileconfig)
	if !strings.Contains(body, "FileVault Recovery Key Escrow") {
		t.Fatal("expected FileVault recovery-key escrow payload")
	}
	if !strings.Contains(body, base64.StdEncoding.EncodeToString(cert.Raw)) {
		t.Fatal("expected escrow profile to embed the Fleet CA certificate")
	}
	if strings.Contains(body, "dontAllowFDEDisable") {
		t.Fatal("escrow-only profile must not enable FileVault enforcement")
	}
}
