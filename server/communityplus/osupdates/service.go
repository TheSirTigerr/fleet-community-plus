// Package osupdates implements Community+ OS-update enforcement.
package osupdates

import (
	"bytes"
	"context"
	"fmt"
	"text/template"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm"
	apple_mdm "github.com/fleetdm/fleet/v4/server/mdm/apple"
)

const softwareUpdateIdentifierSuffix = "-software-update-94f4bbdf-f439-4fb1-8d27-ae1bb793e105"

type Service struct {
	ds fleet.Datastore
}

func New(ds fleet.Datastore) (*Service, error) {
	if ds == nil {
		return nil, fmt.Errorf("OS update datastore is nil")
	}
	return &Service{ds: ds}, nil
}

type windowsProfileOptions struct {
	Deadline    int
	GracePeriod int
}

var windowsProfileTemplate = template.Must(template.New("communityplus-windows-updates").Option("missingkey=error").Parse(`
<Atomic>
	<Replace>
		<Item>
			<Target><LocURI>./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineForFeatureUpdates</LocURI></Target>
			<Meta><Type xmlns="syncml:metinf">text/plain</Type><Format xmlns="syncml:metinf">int</Format></Meta>
			<Data>{{ .Deadline }}</Data>
		</Item>
	</Replace>
	<Replace>
		<Item>
			<Target><LocURI>./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineForQualityUpdates</LocURI></Target>
			<Meta><Type xmlns="syncml:metinf">text/plain</Type><Format xmlns="syncml:metinf">int</Format></Meta>
			<Data>{{ .Deadline }}</Data>
		</Item>
	</Replace>
	<Replace>
		<Item>
			<Target><LocURI>./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineGracePeriod</LocURI></Target>
			<Meta><Type xmlns="syncml:metinf">text/plain</Type><Format xmlns="syncml:metinf">int</Format></Meta>
			<Data>{{ .GracePeriod }}</Data>
		</Item>
	</Replace>
	<Replace>
		<Item>
			<Target><LocURI>./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate</LocURI></Target>
			<Meta><Type xmlns="syncml:metinf">text/plain</Type><Format xmlns="syncml:metinf">int</Format></Meta>
			<Data>1</Data>
		</Item>
	</Replace>
	<Replace>
		<Item>
			<Target><LocURI>./Device/Vendor/MSFT/Policy/Config/Update/SetDisablePauseUXAccess</LocURI></Target>
			<Meta><Type xmlns="syncml:metinf">text/plain</Type><Format xmlns="syncml:metinf">int</Format></Meta>
			<Data>1</Data>
		</Item>
	</Replace>
	<Replace>
		<Item>
			<Target><LocURI>./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineNoAutoReboot</LocURI></Target>
			<Meta><Type xmlns="syncml:metinf">text/plain</Type><Format xmlns="syncml:metinf">int</Format></Meta>
			<Data>1</Data>
		</Item>
	</Replace>
</Atomic>
`))

func (s *Service) WindowsEnable(ctx context.Context, teamID *uint, updates fleet.WindowsUpdates) error {
	var contents bytes.Buffer
	if err := windowsProfileTemplate.Execute(&contents, windowsProfileOptions{
		Deadline:    updates.DeadlineDays.Value,
		GracePeriod: updates.GracePeriodDays.Value,
	}); err != nil {
		return fmt.Errorf("render Windows OS update profile: %w", err)
	}
	if err := s.ds.SetOrUpdateMDMWindowsConfigProfile(ctx, fleet.MDMWindowsConfigProfile{
		TeamID: teamID,
		Name:   mdm.FleetWindowsOSUpdatesProfileName,
		SyncML: contents.Bytes(),
	}); err != nil {
		return fmt.Errorf("store Windows OS update profile: %w", err)
	}
	return nil
}

func (s *Service) WindowsDisable(ctx context.Context, teamID *uint) error {
	if err := s.ds.DeleteMDMWindowsConfigProfileByTeamAndName(ctx, teamID, mdm.FleetWindowsOSUpdatesProfileName); err != nil {
		return fmt.Errorf("delete Windows OS update profile: %w", err)
	}
	return nil
}

func (s *Service) AppleEdited(ctx context.Context, teamID *uint, device fleet.AppleDevice, updates fleet.AppleOSUpdateSettings) error {
	var identifier, profileName, labelName string
	switch device {
	case fleet.MacOS:
		identifier = "macos" + softwareUpdateIdentifierSuffix
		profileName = mdm.FleetMacOSUpdatesProfileName
		labelName = fleet.BuiltinLabelMacOS14Plus
	case fleet.IOS:
		identifier = "ios" + softwareUpdateIdentifierSuffix
		profileName = mdm.FleetIOSUpdatesProfileName
		labelName = fleet.BuiltinLabelIOS
	case fleet.IPadOS:
		identifier = "ipados" + softwareUpdateIdentifierSuffix
		profileName = mdm.FleetIPadOSUpdatesProfileName
		labelName = fleet.BuiltinLabelIPadOS
	default:
		return fmt.Errorf("unsupported Apple device type %d", device)
	}

	if updates.MinimumVersion.Value == "" {
		if err := s.ds.DeleteMDMAppleDeclarationByName(ctx, teamID, profileName); err != nil {
			return fmt.Errorf("delete Apple OS update declaration: %w", err)
		}
		return nil
	}

	targetVersion := updates.MinimumVersion.Value
	targetDeadline := updates.Deadline.Value
	var fleetVars []fleet.FleetVarName
	if updates.EnforcesLatestVersion() {
		targetVersion = fmt.Sprintf("$FLEET_VAR_%s", fleet.FleetVarHostTargetOSVersion)
		targetDeadline = fmt.Sprintf("${FLEET_VAR_%s}", fleet.FleetVarHostTargetOSDeadline)
		fleetVars = []fleet.FleetVarName{
			fleet.FleetVarHostTargetOSVersion,
			fleet.FleetVarHostTargetOSDeadline,
		}
	}

	raw := []byte(fmt.Sprintf(`{
	"Identifier": %q,
	"Type": %q,
	"Payload": {
		"TargetOSVersion": %q,
		"TargetLocalDateTime": "%sT12:00:00"
	}
}`, identifier, apple_mdm.DeclarationTypeSoftwareUpdate, targetVersion, targetDeadline))

	declaration := fleet.NewMDMAppleDeclaration(
		raw,
		teamID,
		profileName,
		apple_mdm.DeclarationTypeSoftwareUpdate,
		identifier,
	)
	labelIDs, err := s.ds.LabelIDsByName(ctx, []string{labelName}, fleet.TeamFilter{})
	if err != nil {
		return fmt.Errorf("resolve Apple OS update label: %w", err)
	}
	labelID, ok := labelIDs[labelName]
	if !ok || labelID == 0 {
		return fmt.Errorf("required Apple OS update label %q is unavailable", labelName)
	}
	declaration.LabelsIncludeAll = []fleet.ConfigurationProfileLabel{{
		LabelName: labelName,
		LabelID:   labelID,
	}}
	if _, err := s.ds.SetOrUpdateMDMAppleDeclaration(ctx, declaration, fleetVars, fleet.MDMAppleActivationKeep); err != nil {
		return fmt.Errorf("store Apple OS update declaration: %w", err)
	}
	return nil
}
