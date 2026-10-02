package service

import (
	"context"
	"errors"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/apple_mdm"
	"github.com/google/uuid"
)

type communityPlusRecoveryLockCommander interface {
	RotateRecoveryLock(context.Context, []string, string) error
}

func (svc *Service) communityPlusRotateRecoveryLockPassword(
	ctx context.Context,
	hostID uint,
	commander communityPlusRecoveryLockCommander,
) error {
	if err := svc.authz.Authorize(ctx, &fleet.Host{}, fleet.ActionList); err != nil {
		return err
	}

	host, err := svc.ds.Host(ctx, hostID)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "get host")
	}

	notFoundErr := ctxerr.Wrap(ctx, newNotFoundError(), "rotate recovery lock password")
	if err := svc.authz.AuthorizeOrNotFound(
		ctx,
		fleet.MDMCommandAuthz{TeamID: host.TeamID},
		fleet.ActionWrite,
		notFoundErr,
	); err != nil {
		return err
	}

	if !host.IsAppleSilicon() {
		return &fleet.BadRequestError{Message: "Recovery lock password rotation is only supported on Apple Silicon Macs."}
	}

	connected, err := svc.ds.IsHostConnectedToFleetMDM(ctx, host)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "checking if host is connected to Fleet MDM")
	}
	if !connected {
		return &fleet.BadRequestError{Message: "Host must be enrolled in Fleet MDM to rotate the recovery lock password."}
	}

	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "get app config")
	}
	recoveryLockEnabled := appConfig.MDM.EnableRecoveryLockPassword.Value
	if host.TeamID != nil {
		team, err := svc.ds.TeamLite(ctx, *host.TeamID)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "get fleet")
		}
		recoveryLockEnabled = team.Config.MDM.EnableRecoveryLockPassword
	}
	if !recoveryLockEnabled {
		return &fleet.BadRequestError{Message: "Recovery lock password is not enabled for this host's fleet."}
	}

	status, err := svc.ds.GetRecoveryLockRotationStatus(ctx, host.UUID)
	if err != nil {
		if fleet.IsNotFound(err) {
			return &fleet.BadRequestError{Message: "Host does not have a recovery lock password to rotate."}
		}
		return ctxerr.Wrap(ctx, err, "get recovery lock rotation status")
	}
	if !status.HasPassword {
		return &fleet.BadRequestError{Message: "Host does not have a recovery lock password to rotate."}
	}
	if status.HasPendingRotation {
		return &fleet.ConflictError{Message: "Recovery lock password rotation is already in progress for this host."}
	}
	if status.OperationType == string(fleet.MDMOperationTypeRemove) {
		return &fleet.BadRequestError{Message: "Cannot rotate recovery lock password while a clear operation is in progress."}
	}

	deliveryStatus := ""
	if status.Status != nil {
		deliveryStatus = *status.Status
	}
	if deliveryStatus != string(fleet.MDMDeliveryVerified) && deliveryStatus != string(fleet.MDMDeliveryFailed) {
		return &fleet.BadRequestError{Message: "Cannot rotate recovery lock password while an operation is pending."}
	}

	newPassword := apple_mdm.GenerateRecoveryLockPassword()
	commandUUID := uuid.NewString()
	if err := svc.ds.InitiateRecoveryLockRotation(ctx, host.UUID, commandUUID, newPassword); err != nil {
		return ctxerr.Wrap(ctx, err, "initiate recovery lock rotation")
	}

	if commander == nil {
		_ = svc.ds.ClearRecoveryLockRotation(ctx, host.UUID)
		return ctxerr.New(ctx, "Apple MDM commander is not configured")
	}
	if err := commander.RotateRecoveryLock(ctx, []string{host.UUID}, commandUUID); err != nil {
		var apnsErr *apple_mdm.APNSDeliveryError
		if !errors.As(err, &apnsErr) {
			_ = svc.ds.ClearRecoveryLockRotation(ctx, host.UUID)
		}
		return ctxerr.Wrap(ctx, err, "enqueue recovery lock rotation command")
	}

	if err := svc.NewActivity(
		ctx,
		authz.UserFromContext(ctx),
		fleet.ActivityTypeRotatedHostRecoveryLockPassword{
			HostID:          host.ID,
			HostDisplayName: host.DisplayName(),
		},
	); err != nil {
		return ctxerr.Wrap(ctx, err, "create activity for rotate recovery lock password")
	}
	return nil
}
