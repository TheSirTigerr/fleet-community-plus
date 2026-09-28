package servicecompat

import (
	"context"

	"github.com/fleetdm/fleet/v4/server/communityplus/adue"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type appleADUEWrapper struct {
	fleet.Service
	adue *adue.Service
}

func wrapAppleADUE(base fleet.Service, options []any) (fleet.Service, error) {
	if base == nil {
		return nil, nil
	}
	var ds fleet.Datastore
	for _, option := range options {
		if value, ok := option.(fleet.Datastore); ok {
			ds = value
			break
		}
	}
	if ds == nil {
		return base, nil
	}
	return &appleADUEWrapper{Service: base, adue: adue.New(ds)}, nil
}

func (s *appleADUEWrapper) GetMDMAccountDrivenEnrollmentSSOURL(ctx context.Context, enrollmentToken string) (string, error) {
	s.Service.SkipAuth(ctx)
	return s.adue.SSOURL(ctx, enrollmentToken)
}

func (s *appleADUEWrapper) GetMDMAppleAccountEnrollmentProfile(ctx context.Context, enrollReference string) ([]byte, error) {
	s.Service.SkipAuth(ctx)
	return s.adue.EnrollmentProfile(ctx, enrollReference)
}
