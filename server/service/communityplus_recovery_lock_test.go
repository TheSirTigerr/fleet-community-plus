package service

import (
	"context"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	activity_api "github.com/fleetdm/fleet/v4/server/activity/api"
	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
)

type recoveryLockCommanderStub struct {
	err       error
	hostUUIDs []string
	commandID string
	callCount int
}

func (c *recoveryLockCommanderStub) RotateRecoveryLock(_ context.Context, hostUUIDs []string, commandID string) error {
	c.callCount++
	c.hostUUIDs = append([]string(nil), hostUUIDs...)
	c.commandID = commandID
	return c.err
}

func recoveryLockAdminContext() context.Context {
	role := fleet.RoleAdmin
	return viewer.NewContext(context.Background(), viewer.Viewer{
		User: &fleet.User{ID: 1, Name: "Admin", Email: "admin@example.com", GlobalRole: &role},
	})
}

func newRecoveryLockTestService(t *testing.T, ds *mock.Store) *Service {
	t.Helper()
	svc := &Service{ds: ds, authz: authz.Must()}
	svc.SetActivityService(&mock.MockActivityService{
		NewActivityFunc: func(_ context.Context, _ *activity_api.User, _ activity_api.ActivityDetails) error {
			return nil
		},
	})
	return svc
}

func configureRecoveryLockSuccessState(ds *mock.Store) *fleet.Host {
	host := &fleet.Host{
		ID:       42,
		UUID:     "host-uuid",
		Hostname: "macbook",
		Platform: "darwin",
		CPUType:  "arm64",
	}
	ds.HostFunc = func(context.Context, uint) (*fleet.Host, error) {
		return host, nil
	}
	ds.IsHostConnectedToFleetMDMFunc = func(context.Context, *fleet.Host) (bool, error) {
		return true, nil
	}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{
			MDM: fleet.MDM{EnableRecoveryLockPassword: optjson.SetBool(true)},
		}, nil
	}
	verified := string(fleet.MDMDeliveryVerified)
	ds.GetRecoveryLockRotationStatusFunc = func(context.Context, string) (*fleet.HostRecoveryLockRotationStatus, error) {
		return &fleet.HostRecoveryLockRotationStatus{
			HostUUID:      host.UUID,
			HasPassword:   true,
			Status:        &verified,
			OperationType: string(fleet.MDMOperationTypeInstall),
		}, nil
	}
	return host
}

func TestCommunityPlusRotateRecoveryLockPassword(t *testing.T) {
	ds := new(mock.Store)
	host := configureRecoveryLockSuccessState(ds)
	var initiatedPassword, initiatedCommand string
	ds.InitiateRecoveryLockRotationFunc = func(_ context.Context, hostUUID, commandID, password string) error {
		if hostUUID != host.UUID {
			t.Fatalf("unexpected host UUID %q", hostUUID)
		}
		initiatedCommand = commandID
		initiatedPassword = password
		return nil
	}

	var activity activity_api.ActivityDetails
	svc := &Service{ds: ds, authz: authz.Must()}
	svc.SetActivityService(&mock.MockActivityService{
		NewActivityFunc: func(_ context.Context, _ *activity_api.User, value activity_api.ActivityDetails) error {
			activity = value
			return nil
		},
	})
	commander := &recoveryLockCommanderStub{}

	if err := svc.communityPlusRotateRecoveryLockPassword(recoveryLockAdminContext(), host.ID, commander); err != nil {
		t.Fatalf("rotate Recovery Lock password: %v", err)
	}
	if initiatedPassword == "" || initiatedCommand == "" {
		t.Fatal("expected pending rotation with generated password and command UUID")
	}
	if commander.callCount != 1 || len(commander.hostUUIDs) != 1 || commander.hostUUIDs[0] != host.UUID || commander.commandID != initiatedCommand {
		t.Fatalf("unexpected commander call: %#v", commander)
	}
	if _, ok := activity.(fleet.ActivityTypeRotatedHostRecoveryLockPassword); !ok {
		t.Fatalf("unexpected activity type %T", activity)
	}
}

func TestCommunityPlusRotateRecoveryLockClearsPendingOnEnqueueFailure(t *testing.T) {
	ds := new(mock.Store)
	host := configureRecoveryLockSuccessState(ds)
	ds.InitiateRecoveryLockRotationFunc = func(context.Context, string, string, string) error {
		return nil
	}
	cleared := false
	ds.ClearRecoveryLockRotationFunc = func(_ context.Context, hostUUID string) error {
		if hostUUID != host.UUID {
			t.Fatalf("unexpected host UUID %q", hostUUID)
		}
		cleared = true
		return nil
	}

	svc := newRecoveryLockTestService(t, ds)
	commander := &recoveryLockCommanderStub{err: errors.New("enqueue failed")}
	err := svc.communityPlusRotateRecoveryLockPassword(recoveryLockAdminContext(), host.ID, commander)
	if err == nil {
		t.Fatal("expected enqueue failure")
	}
	if !cleared {
		t.Fatal("expected pending rotation to be cleared after enqueue failure")
	}
}
