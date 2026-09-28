package servicecompat

import (
	"context"
	"io"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/communityplus/bootstrappackage"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type bootstrapPackageWrapper struct {
	fleet.Service
	bootstrap *bootstrappackage.Service
}

func wrapBootstrapPackage(base fleet.Service, options []any) (fleet.Service, error) {
	if base == nil {
		return nil, nil
	}
	var (
		ds    fleet.Datastore
		store fleet.MDMBootstrapPackageStore
	)
	for _, option := range options {
		switch value := option.(type) {
		case fleet.Datastore:
			ds = value
		case fleet.MDMBootstrapPackageStore:
			store = value
		}
	}
	if ds == nil {
		return base, nil
	}
	bootstrap, err := bootstrappackage.New(ds, store, authz.Must(), base)
	if err != nil {
		return nil, err
	}
	return &bootstrapPackageWrapper{Service: base, bootstrap: bootstrap}, nil
}

func (s *bootstrapPackageWrapper) MDMAppleUploadBootstrapPackage(ctx context.Context, name string, pkg io.Reader, teamID uint, dryRun bool) error {
	return s.bootstrap.Upload(ctx, name, pkg, teamID, dryRun)
}

func (s *bootstrapPackageWrapper) GetMDMAppleBootstrapPackageBytes(ctx context.Context, token string) (*fleet.MDMAppleBootstrapPackage, error) {
	return s.bootstrap.GetBytes(ctx, token)
}

func (s *bootstrapPackageWrapper) GetMDMAppleBootstrapPackageMetadata(ctx context.Context, teamID uint, forUpdate bool) (*fleet.MDMAppleBootstrapPackage, error) {
	return s.bootstrap.GetMetadata(ctx, teamID, forUpdate)
}

func (s *bootstrapPackageWrapper) DeleteMDMAppleBootstrapPackage(ctx context.Context, teamID *uint, dryRun bool) error {
	return s.bootstrap.Delete(ctx, teamID, dryRun)
}

func (s *bootstrapPackageWrapper) GetMDMAppleBootstrapPackageSummary(ctx context.Context, teamID *uint) (*fleet.MDMAppleBootstrapPackageSummary, error) {
	return s.bootstrap.Summary(ctx, teamID)
}
