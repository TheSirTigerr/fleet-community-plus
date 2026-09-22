// Package service is a compatibility facade for the Community+ service boundary.
package service

import (
	"context"
	"log/slog"

	servicecompat "github.com/fleetdm/fleet/v4/server/communityplus/servicecompat"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

func NewService(base fleet.Service, opts ...any) (fleet.Service, error) {
	return servicecompat.NewService(base, opts...)
}

func UninstallSoftwareMigration(ctx context.Context, ds fleet.Datastore, store fleet.SoftwareInstallerStore, logger *slog.Logger) error {
	return servicecompat.UninstallSoftwareMigration(ctx, ds, store, logger)
}

func UpgradeCodeMigration(ctx context.Context, ds fleet.Datastore, store fleet.SoftwareInstallerStore, logger *slog.Logger) error {
	return servicecompat.UpgradeCodeMigration(ctx, ds, store, logger)
}

func AutoUpdateFleetMaintainedApps(ctx context.Context, ds fleet.Datastore, store fleet.SoftwareInstallerStore, logger *slog.Logger) error {
	return servicecompat.AutoUpdateFleetMaintainedApps(ctx, ds, store, logger)
}

func ValidateSoftwareLabels(ctx context.Context, svc fleet.Service, teamID *uint, includeAny, excludeAny, includeAll []string) (*fleet.LabelIdentsWithScope, error) {
	return servicecompat.ValidateSoftwareLabels(ctx, svc, teamID, includeAny, excludeAny, includeAll)
}

func ValidateSoftwareLabelsForUpdate(ctx context.Context, svc fleet.Service, existing *fleet.SoftwareInstaller, includeAny, excludeAny, includeAll []string) (bool, *fleet.LabelIdentsWithScope, error) {
	return servicecompat.ValidateSoftwareLabelsForUpdate(ctx, svc, existing, includeAny, excludeAny, includeAll)
}
