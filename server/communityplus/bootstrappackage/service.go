// Package bootstrappackage implements Community+ macOS bootstrap package handling.
package bootstrappackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/fleetdm/fleet/v4/pkg/file"
	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/google/uuid"
)

type activityWriter interface {
	NewActivity(context.Context, *fleet.User, fleet.ActivityDetails) error
}

type Service struct {
	ds         fleet.Datastore
	store      fleet.MDMBootstrapPackageStore
	authorizer *authz.Authorizer
	activities activityWriter
}

func New(ds fleet.Datastore, store fleet.MDMBootstrapPackageStore, authorizer *authz.Authorizer, activities activityWriter) (*Service, error) {
	if ds == nil {
		return nil, errors.New("bootstrap package datastore is nil")
	}
	if authorizer == nil {
		return nil, errors.New("bootstrap package authorizer is nil")
	}
	if activities == nil {
		return nil, errors.New("bootstrap package activity service is nil")
	}
	return &Service{ds: ds, store: store, authorizer: authorizer, activities: activities}, nil
}

func (s *Service) Upload(ctx context.Context, name string, pkg io.Reader, teamID uint, dryRun bool) error {
	if err := s.authorizer.Authorize(ctx, &fleet.MDMAppleBootstrapPackage{TeamID: teamID}, fleet.ActionWrite); err != nil {
		return err
	}
	if pkg == nil {
		return &fleet.BadRequestError{Message: "bootstrap package is required"}
	}

	teamName, teamIDPtr, err := s.scopeDetails(ctx, teamID)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, pkg); err != nil {
		return fmt.Errorf("read bootstrap package: %w", err)
	}
	if buf.Len() == 0 {
		return &fleet.BadRequestError{Message: "bootstrap package is empty"}
	}
	reader := bytes.NewReader(buf.Bytes())
	if err := file.CheckPKGSignature(reader); err != nil {
		message := "invalid package"
		if errors.Is(err, file.ErrInvalidType) || errors.Is(err, file.ErrNotSigned) {
			message = err.Error()
		}
		return &fleet.BadRequestError{Message: message, InternalErr: err}
	}
	reader.Reset(buf.Bytes())
	distribution, err := file.XARHasDistribution(reader)
	if err != nil {
		return &fleet.BadRequestError{Message: err.Error(), InternalErr: err}
	}
	if !distribution {
		return &fleet.BadRequestError{Message: fleet.BootstrapPkgNotDistributionErrMsg}
	}
	if dryRun {
		return nil
	}

	digest := sha256.Sum256(buf.Bytes())
	bp := &fleet.MDMAppleBootstrapPackage{
		TeamID: teamID,
		Name:   name,
		Token:  uuid.NewString(),
		Sha256: digest[:],
		Bytes:  buf.Bytes(),
	}
	if err := s.ds.InsertMDMAppleBootstrapPackage(ctx, bp, s.store); err != nil {
		return fmt.Errorf("store bootstrap package: %w", err)
	}
	if err := s.activities.NewActivity(ctx, authz.UserFromContext(ctx), fleet.ActivityTypeAddedBootstrapPackage{
		BootstrapPackageName: name,
		TeamID:               teamIDPtr,
		TeamName:             teamName,
	}); err != nil {
		return fmt.Errorf("record bootstrap package upload activity: %w", err)
	}
	return nil
}

// GetBytes is token-authorized by the unguessable package token and therefore
// intentionally performs no Fleet-user authorization check.
func (s *Service) GetBytes(ctx context.Context, token string) (*fleet.MDMAppleBootstrapPackage, error) {
	if token == "" {
		return nil, &fleet.BadRequestError{Message: "bootstrap package token is required"}
	}
	pkg, err := s.ds.GetMDMAppleBootstrapPackageBytes(ctx, token, s.store)
	if err != nil {
		return nil, fmt.Errorf("load bootstrap package: %w", err)
	}
	return pkg, nil
}

func (s *Service) GetMetadata(ctx context.Context, teamID uint, forUpdate bool) (*fleet.MDMAppleBootstrapPackage, error) {
	action := fleet.ActionRead
	if forUpdate {
		action = fleet.ActionWrite
	}
	if err := s.authorizer.Authorize(ctx, &fleet.MDMAppleBootstrapPackage{TeamID: teamID}, action); err != nil {
		return nil, err
	}
	meta, err := s.ds.GetMDMAppleBootstrapPackageMeta(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("load bootstrap package metadata: %w", err)
	}
	return meta, nil
}

func (s *Service) Delete(ctx context.Context, teamID *uint, dryRun bool) error {
	var id uint
	if teamID != nil {
		id = *teamID
	}
	if err := s.authorizer.Authorize(ctx, &fleet.MDMAppleBootstrapPackage{TeamID: id}, fleet.ActionWrite); err != nil {
		return err
	}
	teamName, normalizedTeamID, err := s.scopeDetails(ctx, id)
	if err != nil {
		return err
	}
	meta, err := s.ds.GetMDMAppleBootstrapPackageMeta(ctx, id)
	if err != nil {
		return fmt.Errorf("load bootstrap package metadata: %w", err)
	}
	if dryRun {
		return nil
	}
	if err := s.ds.DeleteMDMAppleBootstrapPackage(ctx, id); err != nil {
		return fmt.Errorf("delete bootstrap package: %w", err)
	}
	if err := s.activities.NewActivity(ctx, authz.UserFromContext(ctx), fleet.ActivityTypeDeletedBootstrapPackage{
		BootstrapPackageName: meta.Name,
		TeamID:               normalizedTeamID,
		TeamName:             teamName,
	}); err != nil {
		return fmt.Errorf("record bootstrap package delete activity: %w", err)
	}
	return nil
}

func (s *Service) Summary(ctx context.Context, teamID *uint) (*fleet.MDMAppleBootstrapPackageSummary, error) {
	var id uint
	if teamID != nil {
		id = *teamID
	}
	if err := s.authorizer.Authorize(ctx, &fleet.MDMAppleBootstrapPackage{TeamID: id}, fleet.ActionRead); err != nil {
		return &fleet.MDMAppleBootstrapPackageSummary{}, err
	}
	if teamID != nil {
		if _, err := s.ds.TeamLite(ctx, id); err != nil {
			return &fleet.MDMAppleBootstrapPackageSummary{}, err
		}
	}
	summary, err := s.ds.GetMDMAppleBootstrapPackageSummary(ctx, id)
	if err != nil {
		return &fleet.MDMAppleBootstrapPackageSummary{}, fmt.Errorf("load bootstrap package summary: %w", err)
	}
	return summary, nil
}

func (s *Service) scopeDetails(ctx context.Context, teamID uint) (*string, *uint, error) {
	if teamID == 0 {
		return nil, nil, nil
	}
	team, err := s.ds.TeamLite(ctx, teamID)
	if err != nil {
		return nil, nil, fmt.Errorf("load fleet %d for bootstrap package: %w", teamID, err)
	}
	name := team.Name
	id := teamID
	return &name, &id, nil
}
