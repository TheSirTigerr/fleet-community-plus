// Package servicecompat provides the Fleet-facing Community+ service wrapper
// and compatibility helpers needed by Community server startup.
package servicecompat

import (
	"context"
	"errors"
	"log/slog"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// NewService preserves the base Community service. Community+ capabilities are
// composed through their own services rather than an Enterprise wrapper.
func NewService(base fleet.Service, _ ...any) (fleet.Service, error) { return base, nil }

func UninstallSoftwareMigration(context.Context, fleet.Datastore, fleet.SoftwareInstallerStore, *slog.Logger) error {
	return nil
}

func UpgradeCodeMigration(context.Context, fleet.Datastore, fleet.SoftwareInstallerStore, *slog.Logger) error {
	return nil
}

func AutoUpdateFleetMaintainedApps(context.Context, fleet.Datastore, fleet.SoftwareInstallerStore, *slog.Logger) error {
	return nil
}

func ValidateSoftwareLabels(ctx context.Context, svc fleet.Service, teamID *uint, includeAny, excludeAny, includeAll []string) (*fleet.LabelIdentsWithScope, error) {
	provided := 0
	if includeAny != nil {
		provided++
	}
	if excludeAny != nil {
		provided++
	}
	if includeAll != nil {
		provided++
	}
	if provided > 1 {
		return nil, errors.New(`Only one of "labels_include_all", "labels_include_any" or "labels_exclude_any" can be included.`)
	}

	names, scope := includeAny, fleet.LabelScopeIncludeAny
	if excludeAny != nil {
		names, scope = excludeAny, fleet.LabelScopeExcludeAny
	} else if includeAll != nil {
		names, scope = includeAll, fleet.LabelScopeIncludeAll
	}
	byName, err := svc.BatchValidateLabels(ctx, teamID, names)
	if err != nil {
		var missing *fleet.MissingLabelError
		if errors.As(err, &missing) {
			return nil, errors.New(`Couldn't update. Label "` + missing.MissingLabelName + `" doesn't exist. Please remove the label from the software`)
		}
		return nil, err
	}
	if len(names) == 0 {
		return &fleet.LabelIdentsWithScope{}, nil
	}
	return &fleet.LabelIdentsWithScope{LabelScope: scope, ByName: byName}, nil
}

func ValidateSoftwareLabelsForUpdate(ctx context.Context, svc fleet.Service, existing *fleet.SoftwareInstaller, includeAny, excludeAny, includeAll []string) (bool, *fleet.LabelIdentsWithScope, error) {
	var teamID *uint
	if existing != nil {
		teamID = existing.TeamID
	}
	if _, err := svc.BatchValidateLabels(ctx, teamID, nil); err != nil {
		return false, nil, err
	}
	if existing == nil {
		return false, nil, errors.New("existing installer must be provided")
	}
	if includeAny == nil && excludeAny == nil && includeAll == nil {
		return false, nil, nil
	}
	validated, err := ValidateSoftwareLabels(ctx, svc, existing.TeamID, includeAny, excludeAny, includeAll)
	if err != nil {
		return false, nil, err
	}

	current := &fleet.LabelIdentsWithScope{ByName: map[string]fleet.LabelIdent{}}
	var labels []fleet.SoftwareScopeLabel
	switch {
	case len(existing.LabelsIncludeAny) > 0:
		current.LabelScope, labels = fleet.LabelScopeIncludeAny, existing.LabelsIncludeAny
	case len(existing.LabelsExcludeAny) > 0:
		current.LabelScope, labels = fleet.LabelScopeExcludeAny, existing.LabelsExcludeAny
	case len(existing.LabelsIncludeAll) > 0:
		current.LabelScope, labels = fleet.LabelScopeIncludeAll, existing.LabelsIncludeAll
	}
	for _, label := range labels {
		current.ByName[label.LabelName] = fleet.LabelIdent{LabelID: label.LabelID, LabelName: label.LabelName}
	}
	if len(current.ByName) == 0 {
		current.ByName = nil
	}
	if current.Equal(validated) {
		return false, nil, nil
	}
	return true, validated, nil
}
