package osupdates

import (
	"context"
	"strings"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm"
	"github.com/fleetdm/fleet/v4/server/mock"
)

func TestWindowsEnableAndDisable(t *testing.T) {
	ds := new(mock.DataStore)
	var stored *fleet.MDMWindowsConfigProfile
	ds.SetOrUpdateMDMWindowsConfigProfileFunc = func(_ context.Context, profile fleet.MDMWindowsConfigProfile) error {
		stored = &profile
		return nil
	}
	var deletedName string
	ds.DeleteMDMWindowsConfigProfileByTeamAndNameFunc = func(_ context.Context, _ *uint, name string) error {
		deletedName = name
		return nil
	}
	svc, err := New(ds)
	if err != nil {
		t.Fatal(err)
	}

	teamID := uint(9)
	if err := svc.WindowsEnable(context.Background(), &teamID, fleet.WindowsUpdates{
		DeadlineDays:    optjson.SetInt(5),
		GracePeriodDays: optjson.SetInt(2),
	}); err != nil {
		t.Fatalf("enable Windows updates: %v", err)
	}
	if stored == nil {
		t.Fatal("expected Windows update profile")
	}
	if stored.TeamID == nil || *stored.TeamID != teamID {
		t.Fatalf("unexpected team id: %v", stored.TeamID)
	}
	if stored.Name != mdm.FleetWindowsOSUpdatesProfileName {
		t.Fatalf("unexpected profile name %q", stored.Name)
	}
	body := string(stored.SyncML)
	for _, expected := range []string{
		"ConfigureDeadlineForFeatureUpdates",
		"ConfigureDeadlineForQualityUpdates",
		"ConfigureDeadlineGracePeriod",
		"<Data>5</Data>",
		"<Data>2</Data>",
		"AllowAutoUpdate",
		"SetDisablePauseUXAccess",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected Windows profile to contain %q", expected)
		}
	}

	if err := svc.WindowsDisable(context.Background(), &teamID); err != nil {
		t.Fatalf("disable Windows updates: %v", err)
	}
	if deletedName != mdm.FleetWindowsOSUpdatesProfileName {
		t.Fatalf("unexpected deleted profile %q", deletedName)
	}
}

func TestAppleEditedFixedVersion(t *testing.T) {
	ds := new(mock.DataStore)
	ds.LabelIDsByNameFunc = func(_ context.Context, labels []string, _ fleet.TeamFilter) (map[string]uint, error) {
		if len(labels) != 1 || labels[0] != fleet.BuiltinLabelMacOS14Plus {
			t.Fatalf("unexpected labels: %v", labels)
		}
		return map[string]uint{fleet.BuiltinLabelMacOS14Plus: 77}, nil
	}
	var stored *fleet.MDMAppleDeclaration
	var vars []fleet.FleetVarName
	ds.SetOrUpdateMDMAppleDeclarationFunc = func(
		_ context.Context,
		decl *fleet.MDMAppleDeclaration,
		usesFleetVars []fleet.FleetVarName,
		_ fleet.MDMAppleActivationAction,
	) (*fleet.MDMAppleDeclaration, error) {
		stored = decl
		vars = append([]fleet.FleetVarName(nil), usesFleetVars...)
		return decl, nil
	}
	svc, err := New(ds)
	if err != nil {
		t.Fatal(err)
	}

	err = svc.AppleEdited(context.Background(), nil, fleet.MacOS, fleet.AppleOSUpdateSettings{
		MinimumVersion: optjson.SetString("15.2"),
		Deadline:       optjson.SetString("2026-12-01"),
	})
	if err != nil {
		t.Fatalf("set macOS update declaration: %v", err)
	}
	if stored == nil {
		t.Fatal("expected Apple update declaration")
	}
	if stored.Name != mdm.FleetMacOSUpdatesProfileName {
		t.Fatalf("unexpected declaration name %q", stored.Name)
	}
	if len(stored.LabelsIncludeAll) != 1 || stored.LabelsIncludeAll[0].LabelID != 77 {
		t.Fatalf("unexpected declaration labels: %+v", stored.LabelsIncludeAll)
	}
	if len(vars) != 0 {
		t.Fatalf("specific-version update must not use Fleet variables: %v", vars)
	}
	body := string(stored.RawJSON)
	if !strings.Contains(body, `"TargetOSVersion": "15.2"`) ||
		!strings.Contains(body, `"TargetLocalDateTime": "2026-12-01T12:00:00"`) {
		t.Fatalf("unexpected declaration: %s", body)
	}
}

func TestAppleEditedLatestVersionUsesPerHostVariables(t *testing.T) {
	ds := new(mock.DataStore)
	ds.LabelIDsByNameFunc = func(_ context.Context, labels []string, _ fleet.TeamFilter) (map[string]uint, error) {
		return map[string]uint{fleet.BuiltinLabelIOS: 88}, nil
	}
	var stored *fleet.MDMAppleDeclaration
	var vars []fleet.FleetVarName
	ds.SetOrUpdateMDMAppleDeclarationFunc = func(
		_ context.Context,
		decl *fleet.MDMAppleDeclaration,
		usesFleetVars []fleet.FleetVarName,
		_ fleet.MDMAppleActivationAction,
	) (*fleet.MDMAppleDeclaration, error) {
		stored = decl
		vars = append([]fleet.FleetVarName(nil), usesFleetVars...)
		return decl, nil
	}
	svc, err := New(ds)
	if err != nil {
		t.Fatal(err)
	}

	err = svc.AppleEdited(context.Background(), nil, fleet.IOS, fleet.AppleOSUpdateSettings{
		MinimumVersion: optjson.SetString(fleet.AppleOSUpdateLatestVersion),
		DeadlineDays:   optjson.SetInt(7),
	})
	if err != nil {
		t.Fatalf("set latest iOS update declaration: %v", err)
	}
	if stored == nil {
		t.Fatal("expected Apple update declaration")
	}
	body := string(stored.RawJSON)
	if !strings.Contains(body, "$FLEET_VAR_"+string(fleet.FleetVarHostTargetOSVersion)) ||
		!strings.Contains(body, "${FLEET_VAR_"+string(fleet.FleetVarHostTargetOSDeadline)+"}") {
		t.Fatalf("latest-version declaration does not contain Fleet variables: %s", body)
	}
	if len(vars) != 2 || vars[0] != fleet.FleetVarHostTargetOSVersion || vars[1] != fleet.FleetVarHostTargetOSDeadline {
		t.Fatalf("unexpected Fleet variables: %v", vars)
	}
}

func TestAppleEditedDisabledDeletesDeclaration(t *testing.T) {
	ds := new(mock.DataStore)
	var deleted string
	ds.DeleteMDMAppleDeclarationByNameFunc = func(_ context.Context, _ *uint, name string) error {
		deleted = name
		return nil
	}
	svc, err := New(ds)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.AppleEdited(context.Background(), nil, fleet.IPadOS, fleet.AppleOSUpdateSettings{}); err != nil {
		t.Fatalf("disable iPadOS updates: %v", err)
	}
	if deleted != mdm.FleetIPadOSUpdatesProfileName {
		t.Fatalf("unexpected declaration deleted: %q", deleted)
	}
}
