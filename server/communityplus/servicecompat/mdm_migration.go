package servicecompat

import (
	"context"
	"log/slog"

	"github.com/fleetdm/fleet/v4/server/communityplus/mdmmigration"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type mdmMigrationWrapper struct {
	fleet.Service
	migration *mdmmigration.Service
}

func wrapMDMMigration(base fleet.Service, options []any) (fleet.Service, error) {
	if base == nil {
		return nil, nil
	}
	var (
		ds     fleet.Datastore
		logger *slog.Logger
	)
	for _, option := range options {
		switch value := option.(type) {
		case fleet.Datastore:
			ds = value
		case *slog.Logger:
			logger = value
		}
	}
	if ds == nil {
		return base, nil
	}
	migration, err := mdmmigration.New(ds, logger)
	if err != nil {
		return nil, err
	}
	return &mdmMigrationWrapper{Service: base, migration: migration}, nil
}

func (s *mdmMigrationWrapper) TriggerMigrateMDMDevice(ctx context.Context, host *fleet.Host) error {
	return s.migration.Trigger(ctx, host)
}

func (s *mdmMigrationWrapper) GetFleetDesktopSummary(ctx context.Context) (fleet.DesktopSummary, error) {
	return s.migration.DesktopSummary(ctx)
}
