package servicecompat

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/communityplus/applezerotouch"
	"github.com/fleetdm/fleet/v4/server/fleet"
	apple_mdm "github.com/fleetdm/fleet/v4/server/mdm/apple"
	"github.com/fleetdm/fleet/v4/server/mdm/nanodep/godep"
	nanodep_storage "github.com/fleetdm/fleet/v4/server/mdm/nanodep/storage"
)

type appleZeroTouchWrapper struct {
	fleet.Service
	zeroTouch *applezerotouch.Service
	abm       *applezerotouch.ABMService
}

func wrapAppleZeroTouch(base fleet.Service, options []any) (fleet.Service, error) {
	if base == nil {
		return nil, nil
	}
	var (
		ds         fleet.Datastore
		depStorage nanodep_storage.AllDEPStorage
		logger     *slog.Logger
	)
	for _, option := range options {
		switch value := option.(type) {
		case fleet.Datastore:
			ds = value
		case nanodep_storage.AllDEPStorage:
			depStorage = value
		case *slog.Logger:
			logger = value
		}
	}
	if ds == nil || depStorage == nil {
		return base, nil
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	authorizer := authz.Must()
	zeroTouch, err := applezerotouch.New(ds, apple_mdm.NewDEPService(ds, depStorage, logger), authorizer)
	if err != nil {
		return nil, err
	}
	abm, err := applezerotouch.NewABMService(ds, depStorage, authorizer, logger)
	if err != nil {
		return nil, err
	}
	return &appleZeroTouchWrapper{Service: base, zeroTouch: zeroTouch, abm: abm}, nil
}

func (s *appleZeroTouchWrapper) SetOrUpdateMDMAppleSetupAssistant(ctx context.Context, asst *fleet.MDMAppleSetupAssistant) (*fleet.MDMAppleSetupAssistant, error) {
	return s.zeroTouch.SetOrUpdateSetupAssistant(ctx, asst)
}

func (s *appleZeroTouchWrapper) GetMDMAppleSetupAssistant(ctx context.Context, teamID *uint) (*fleet.MDMAppleSetupAssistant, error) {
	return s.zeroTouch.GetSetupAssistant(ctx, teamID)
}

func (s *appleZeroTouchWrapper) GetDefaultMDMAppleSetupAssistantProfile(ctx context.Context) (godep.Profile, *time.Time, error) {
	return s.zeroTouch.GetDefaultSetupAssistantProfile(ctx)
}

func (s *appleZeroTouchWrapper) DeleteMDMAppleSetupAssistant(ctx context.Context, teamID *uint) error {
	return s.zeroTouch.DeleteSetupAssistant(ctx, teamID)
}

func (s *appleZeroTouchWrapper) UploadABMToken(ctx context.Context, token io.Reader) (*fleet.ABMToken, error) {
	return s.abm.UploadToken(ctx, token)
}

func (s *appleZeroTouchWrapper) RenewABMToken(ctx context.Context, token io.Reader, tokenID uint) (*fleet.ABMToken, error) {
	return s.abm.RenewToken(ctx, token, tokenID)
}

func (s *appleZeroTouchWrapper) ListABMTokens(ctx context.Context) ([]*fleet.ABMToken, error) {
	return s.abm.ListTokens(ctx)
}

func (s *appleZeroTouchWrapper) CountABMTokens(ctx context.Context) (int, error) {
	return s.abm.CountTokens(ctx)
}

func (s *appleZeroTouchWrapper) UpdateABMTokenTeams(ctx context.Context, tokenID uint, macOSTeamID, iOSTeamID, iPadOSTeamID, byodTeamID *uint) (*fleet.ABMToken, error) {
	return s.abm.UpdateTokenTeams(ctx, tokenID, macOSTeamID, iOSTeamID, iPadOSTeamID, byodTeamID)
}

func (s *appleZeroTouchWrapper) SetABMTokenDefault(ctx context.Context, tokenID uint, isDefault *bool) (*fleet.ABMToken, error) {
	return s.abm.SetDefaultToken(ctx, tokenID, isDefault)
}

func (s *appleZeroTouchWrapper) DeleteABMToken(ctx context.Context, tokenID uint) error {
	return s.abm.DeleteToken(ctx, tokenID)
}
