package fleetctl

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fleetdm/fleet/v4/pkg/spec"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/ptr"
	"github.com/fleetdm/fleet/v4/server/service"
	"github.com/urfave/cli/v2"
	"golang.org/x/text/unicode/norm"
)

// communityPlusAwareGitOpsCommand keeps Fleet's upstream GitOps command for
// Fleet Premium and ordinary Fleet Free servers. Community+ servers advertise
// their independent fleets capability and use the scoped path below instead of
// pretending that the Fleet license is Premium.
func communityPlusAwareGitOpsCommand() *cli.Command {
	cmd := gitopsCommand()
	upstreamAction := cmd.Action
	cmd.Action = func(c *cli.Context) error {
		fleetClient, err := clientFromCLI(c)
		if err != nil {
			return err
		}
		appConfig, err := fleetClient.GetAppConfig()
		if err != nil {
			return err
		}
		if appConfig.License == nil {
			return errors.New("no license struct found in app config")
		}
		if appConfig.License.IsPremium() {
			return upstreamAction(c)
		}

		supported, err := fleetGitOpsSupported(appConfig.License, fleetClient)
		if err != nil {
			return fmt.Errorf("checking Community+ fleet GitOps support: %w", err)
		}
		if !supported {
			return upstreamAction(c)
		}
		return runCommunityPlusFleetGitOps(c, fleetClient, appConfig)
	}
	return cmd
}

func runCommunityPlusFleetGitOps(c *cli.Context, fleetClient *service.Client, appConfig *fleet.EnrichedAppConfig) error {
	if len(c.Args().Slice()) != 0 {
		return errors.New("No positional arguments are allowed. To load multiple config files, use one -f flag per file.")
	}
	filenames := c.StringSlice("f")
	if len(filenames) == 0 {
		return errors.New("-f must be specified")
	}
	for _, filename := range filenames {
		if strings.TrimSpace(filename) == "" {
			return errors.New("file name cannot be empty")
		}
		if len(filepath.Base(filename)) > filenameMaxLength {
			return fmt.Errorf("file name must be less than %d characters: %s", filenameMaxLength, filepath.Base(filename))
		}
	}

	logf := func(format string, a ...interface{}) {
		_, _ = fmt.Fprintf(c.App.Writer, format, a...)
	}
	gitOpsOpts := spec.GitOpsOptions{AllowUnknownKeys: c.Bool("allow-unknown-keys")}

	configs := make([]ConfigFile, 0, len(filenames))
	globalConfigLoaded := false
	for _, filename := range filenames {
		config, err := spec.GitOpsFromFile(filename, filepath.Dir(filename), appConfig, logf, gitOpsOpts)
		if err != nil {
			return err
		}
		if err := validateCommunityPlusGitOpsConfig(config, filename); err != nil {
			return err
		}
		cf := ConfigFile{Config: config, Filename: filename, IsGlobalConfig: config.TeamName == nil}
		if cf.IsGlobalConfig {
			if globalConfigLoaded {
				return errors.New("only one global config file may be provided to fleetctl gitops")
			}
			globalConfigLoaded = true
			configs = append([]ConfigFile{cf}, configs...)
		} else {
			configs = append(configs, cf)
		}
	}

	if err := validateCommunityPlusFleetNames(configs); err != nil {
		return err
	}

	globalLabels, err := fleetClient.GetLabels(0)
	if err != nil {
		return fmt.Errorf("getting global labels: %w", err)
	}
	teams, err := fleetClient.ListTeams("")
	if err != nil {
		return fmt.Errorf("getting fleets: %w", err)
	}
	teamIDs := map[string]uint{}
	for _, team := range teams {
		teamIDs[norm.NFC.String(team.Name)] = team.ID
	}

	labelChanges := make(map[string][]spec.LabelChange, len(configs))
	for _, cf := range configs {
		teamName := cf.Config.CoercedTeamName()
		var existingLabels []*fleet.LabelSpec
		switch {
		case cf.IsGlobalConfig || cf.Config.IsNoTeam():
			existingLabels = globalLabels
		default:
			if teamID, ok := teamIDs[norm.NFC.String(teamName)]; ok {
				existingLabels, err = fleetClient.GetLabels(teamID)
				if err != nil {
					return fmt.Errorf("getting fleet %q labels: %w", teamName, err)
				}
			}
		}
		labelChanges[teamName] = computeLabelChanges(
			cf.Filename,
			teamName,
			existingLabels,
			cf.Config.Labels,
			appConfig.GitOpsConfig.Exceptions.Labels,
		)
	}
	labelMoves, err := computeLabelMoves(labelChanges)
	if err != nil {
		return err
	}

	dryRun := c.Bool("dry-run")
	deleteOtherFleets := c.Bool("delete-other-fleets") || c.Bool("delete-other-teams")
	teamNames := make([]string, 0, len(configs))
	var teamDryRunAssumptions *fleet.TeamSpecsDryRunAssumptions
	allFleetSecrets := make(map[string]string)
	var labelsToRemove []string
	iconSettings := fleet.IconGitOpsSettings{
		ConcurrentUploads: c.Int("icons-concurrent-uploads"),
		ConcurrentUpdates: c.Int("icons-concurrent-updates"),
	}

	for _, cf := range configs {
		config := cf.Config
		teamName := config.CoercedTeamName()
		config.LabelChangesSummary = spec.NewLabelChangesSummary(labelChanges[teamName], labelMoves[teamName])
		labelsToRemove = append(labelsToRemove, config.LabelChangesSummary.LabelsToRemove...)

		if err := fleetClient.SaveEnvSecrets(allFleetSecrets, config.FleetSecrets, dryRun); err != nil {
			return err
		}

		assumptions, err := fleetClient.DoGitOps(
			c.Context,
			config,
			cf.Filename,
			logf,
			dryRun,
			teamDryRunAssumptions,
			appConfig,
			map[string][]fleet.SoftwarePackageResponse{},
			map[string][]fleet.VPPAppResponse{},
			map[string][]fleet.ScriptResponse{},
			&iconSettings,
		)
		if err != nil {
			return err
		}
		if cf.IsGlobalConfig {
			teamDryRunAssumptions = assumptions
		} else if config.TeamName != nil && !config.IsNoTeam() {
			teamNames = append(teamNames, *config.TeamName)
		}
	}

	if !dryRun {
		for _, label := range slices.Compact(labelsToRemove) {
			if err := fleetClient.DeleteLabel(label); err != nil {
				return err
			}
		}
	}

	if deleteOtherFleets {
		teams, err := fleetClient.ListTeams("")
		if err != nil {
			return err
		}
		for _, team := range teams {
			if containsNormalizedFleetName(teamNames, team.Name) {
				continue
			}
			if dryRun {
				_, _ = fmt.Fprintf(c.App.Writer, "[!] would've deleted fleet %s\n", team.Name)
				continue
			}
			_, _ = fmt.Fprintf(c.App.Writer, "[-] deleting fleet %s\n", team.Name)
			if err := fleetClient.DeleteTeam(team.ID); err != nil {
				return err
			}
		}
	}

	if globalConfigLoaded && !containsNoTeamConfig(configs) {
		defaultNoTeamConfig := new(spec.GitOps)
		defaultNoTeamConfig.TeamName = ptr.String(fleet.TeamNameNoTeam)
		_, err := fleetClient.DoGitOps(
			c.Context,
			defaultNoTeamConfig,
			"unassigned.yml",
			logf,
			dryRun,
			nil,
			appConfig,
			map[string][]fleet.SoftwarePackageResponse{},
			map[string][]fleet.VPPAppResponse{},
			map[string][]fleet.ScriptResponse{},
			&iconSettings,
		)
		if err != nil {
			return err
		}
	}

	if dryRun {
		_, _ = fmt.Fprintln(c.App.Writer, "[!] gitops dry run succeeded")
	} else {
		_, _ = fmt.Fprintln(c.App.Writer, "[!] gitops succeeded")
	}
	return nil
}

func validateCommunityPlusGitOpsConfig(config *spec.GitOps, filename string) error {
	for _, query := range config.Queries {
		if len(query.LabelsIncludeAny) > 0 || len(query.LabelsIncludeAll) > 0 {
			return fmt.Errorf("report %q in %s uses Premium-only label targeting", query.Name, filepath.Base(filename))
		}
	}
	for _, policy := range config.Policies {
		if len(policy.LabelsIncludeAny) > 0 || len(policy.LabelsIncludeAll) > 0 || len(policy.LabelsExcludeAny) > 0 || len(policy.LabelsExcludeAll) > 0 {
			return fmt.Errorf("policy %q in %s uses Premium-only label targeting", policy.Name, filepath.Base(filename))
		}
	}
	if creds, ok := config.OrgSettings["microsoft_graph_credentials"]; ok {
		parsed, err := fleet.ParseMicrosoftGraphCredentials(creds)
		if err != nil {
			return fmt.Errorf("invalid microsoft_graph_credentials: %w", err)
		}
		if len(parsed) > 0 {
			return fmt.Errorf("%s uses Premium-only Microsoft Graph credentials", filepath.Base(filename))
		}
	}
	return nil
}

func validateCommunityPlusFleetNames(configs []ConfigFile) error {
	seen := make(map[string]string)
	for _, cf := range configs {
		if cf.IsGlobalConfig || cf.Config.TeamName == nil || cf.Config.IsNoTeam() {
			continue
		}
		name := strings.TrimSpace(*cf.Config.TeamName)
		key := norm.NFC.String(strings.ToLower(name))
		if key == "" {
			return fmt.Errorf("fleet name in %s cannot be empty", cf.Filename)
		}
		if previous, ok := seen[key]; ok {
			return fmt.Errorf("duplicate fleet names in GitOps files: %q and %q", previous, cf.Filename)
		}
		seen[key] = cf.Filename
	}
	return nil
}

func containsNormalizedFleetName(names []string, candidate string) bool {
	candidate = norm.NFC.String(strings.ToLower(strings.TrimSpace(candidate)))
	for _, name := range names {
		if norm.NFC.String(strings.ToLower(strings.TrimSpace(name))) == candidate {
			return true
		}
	}
	return false
}

func containsNoTeamConfig(configs []ConfigFile) bool {
	for _, cf := range configs {
		if !cf.IsGlobalConfig && cf.Config.IsNoTeam() {
			return true
		}
	}
	return false
}
