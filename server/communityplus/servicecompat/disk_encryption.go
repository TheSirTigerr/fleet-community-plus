package servicecompat

import (
	"context"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/communityplus/diskencryption"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type diskEncryptionWrapper struct {
	fleet.Service
	disk *diskencryption.Service
}

func wrapDiskEncryption(base fleet.Service, options []any) (fleet.Service, error) {
	if base == nil {
		return nil, nil
	}
	var ds fleet.Datastore
	var cfg *config.FleetConfig
	for _, option := range options {
		switch value := option.(type) {
		case fleet.Datastore:
			ds = value
		case *config.FleetConfig:
			cfg = value
		}
	}
	if ds == nil || cfg == nil {
		return base, nil
	}
	disk, err := diskencryption.New(ds, authz.Must(), base, cfg)
	if err != nil {
		return nil, err
	}
	return &diskEncryptionWrapper{Service: base, disk: disk}, nil
}

func (s *diskEncryptionWrapper) GetMDMDiskEncryptionSummary(ctx context.Context, teamID *uint) (*fleet.MDMDiskEncryptionSummary, error) {
	return s.disk.Summary(ctx, teamID)
}
