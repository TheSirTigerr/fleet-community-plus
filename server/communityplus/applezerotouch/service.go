// Package applezerotouch implements Community+ Apple Automated Device Enrollment
// service operations using Fleet's public Community DEP primitives.
package applezerotouch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/nanodep/godep"
)

// depService is the narrow slice of Fleet's public Community DEPService needed
// by the Community+ service. Keeping this boundary small makes the orchestration
// independently testable without constructing an Apple network client.
type depService interface {
	GetDefaultProfile() *godep.Profile
	RegisterProfileWithAppleDEPServer(context.Context, *fleet.Team, *fleet.MDMAppleSetupAssistant, string) (string, time.Time, error)
}

// Service owns the Apple ADE operations that replace the Community license
// stubs. Apple protocol work remains in the public Community DEPService.
type Service struct {
	ds         fleet.Datastore
	dep        depService
	authorizer *authz.Authorizer
}

func New(ds fleet.Datastore, dep depService, authorizer *authz.Authorizer) (*Service, error) {
	if ds == nil {
		return nil, errors.New("apple zero-touch datastore is nil")
	}
	if dep == nil {
		return nil, errors.New("apple zero-touch DEP service is nil")
	}
	if authorizer == nil {
		return nil, errors.New("apple zero-touch authorizer is nil")
	}
	return &Service{ds: ds, dep: dep, authorizer: authorizer}, nil
}

// SetOrUpdateSetupAssistant validates and stores an ADE enrollment profile and,
// when the scope is already associated with Apple Business Manager, registers
// the updated profile with Apple's DEP service immediately.
func (s *Service) SetOrUpdateSetupAssistant(ctx context.Context, asst *fleet.MDMAppleSetupAssistant) (*fleet.MDMAppleSetupAssistant, error) {
	if asst == nil {
		return nil, &fleet.BadRequestError{Message: "setup assistant is required"}
	}
	if len(asst.Profile) == 0 {
		return nil, &fleet.BadRequestError{Message: "enrollment profile is required"}
	}
	// Profile is json.RawMessage and the authorizer serializes its object for
	// OPA. Validate syntax first so malformed input is reported as a bad request
	// instead of being misclassified as an authorization failure.
	var profile godep.Profile
	if err := json.Unmarshal(asst.Profile, &profile); err != nil {
		return nil, &fleet.BadRequestError{Message: "invalid Apple ADE enrollment profile", InternalErr: err}
	}
	if err := s.authorizer.Authorize(ctx, asst, fleet.ActionWrite); err != nil {
		return nil, err
	}
	if asst.TeamID != nil {
		if _, err := s.ds.TeamWithExtras(ctx, *asst.TeamID); err != nil {
			return nil, fmt.Errorf("load fleet for Apple ADE profile: %w", err)
		}
	}

	stored, err := s.ds.SetOrUpdateMDMAppleSetupAssistant(ctx, asst)
	if err != nil {
		return nil, fmt.Errorf("store Apple ADE setup assistant: %w", err)
	}
	if err := s.syncProfile(ctx, stored.TeamID, stored); err != nil {
		return nil, err
	}
	return stored, nil
}

func (s *Service) GetSetupAssistant(ctx context.Context, teamID *uint) (*fleet.MDMAppleSetupAssistant, error) {
	authzObject := &fleet.MDMAppleSetupAssistant{TeamID: teamID}
	if err := s.authorizer.Authorize(ctx, authzObject, fleet.ActionRead); err != nil {
		return nil, err
	}
	return s.ds.GetMDMAppleSetupAssistant(ctx, teamID)
}

// DeleteSetupAssistant removes the custom profile and immediately re-registers
// Fleet's default ADE profile for any ABM token associated with that scope.
func (s *Service) DeleteSetupAssistant(ctx context.Context, teamID *uint) error {
	authzObject := &fleet.MDMAppleSetupAssistant{TeamID: teamID}
	if err := s.authorizer.Authorize(ctx, authzObject, fleet.ActionWrite); err != nil {
		return err
	}
	if err := s.ds.DeleteMDMAppleSetupAssistant(ctx, teamID); err != nil && !fleet.IsNotFound(err) {
		return fmt.Errorf("delete Apple ADE setup assistant: %w", err)
	}
	if err := s.syncProfile(ctx, teamID, nil); err != nil {
		return err
	}
	return nil
}

func (s *Service) GetDefaultSetupAssistantProfile(ctx context.Context) (godep.Profile, *time.Time, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.MDMAppleSetupAssistant{}, fleet.ActionRead); err != nil {
		return godep.Profile{}, nil, err
	}
	profile := *s.dep.GetDefaultProfile()
	stored, err := s.ds.GetMDMAppleEnrollmentProfileByType(ctx, fleet.MDMAppleEnrollmentTypeAutomatic)
	if err != nil {
		return godep.Profile{}, nil, fmt.Errorf("load default Apple ADE enrollment profile: %w", err)
	}
	updatedAt := stored.UpdatedAt
	return profile, &updatedAt, nil
}

func (s *Service) syncProfile(ctx context.Context, teamID *uint, custom *fleet.MDMAppleSetupAssistant) error {
	orgNames, err := s.ds.GetABMTokenOrgNamesAssociatedWithTeam(ctx, teamID)
	if err != nil {
		return fmt.Errorf("list Apple Business organizations for ADE profile: %w", err)
	}
	if len(orgNames) == 0 {
		// It is valid to configure the profile before an ABM token or device is
		// associated. DEP reconciliation will pick it up once an association exists.
		return nil
	}

	var team *fleet.Team
	if teamID != nil {
		team, err = s.ds.TeamWithExtras(ctx, *teamID)
		if err != nil {
			return fmt.Errorf("load fleet for Apple ADE registration: %w", err)
		}
	}
	if _, _, err := s.dep.RegisterProfileWithAppleDEPServer(ctx, team, custom, orgNames[0]); err != nil {
		return fmt.Errorf("register Apple ADE profile: %w", err)
	}
	return nil
}
