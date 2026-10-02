package servicecompat

import (
	"context"
	"strings"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	storemock "github.com/fleetdm/fleet/v4/server/mock"
	servicemock "github.com/fleetdm/fleet/v4/server/mock/service"
)

func TestRemoteLockRejectsPersonalAppleEnrollment(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	status := fleet.MDMEnrollmentStatusPersonal
	host := &fleet.Host{
		ID:       41,
		Platform: "ios",
		MDM: fleet.MDMHostData{
			EnrollmentStatus: &status,
		},
	}
	ds.HostFunc = func(context.Context, uint) (*fleet.Host, error) {
		return host, nil
	}

	svc := wrapRemoteLock(base, []any{fleet.Datastore(ds)})
	_, err := svc.LockHost(recoveryLockAdminContext(), host.ID, false)
	if err == nil {
		t.Fatal("expected personal Apple enrollment to be rejected")
	}
	if !strings.Contains(err.Error(), fleet.CantLockPersonalHostsMessage) {
		t.Fatalf("unexpected personal-enrollment error: %v", err)
	}
}

func TestRemoteLockRejectsPendingLock(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	host := &fleet.Host{ID: 42, Platform: "linux"}
	ds.HostFunc = func(context.Context, uint) (*fleet.Host, error) {
		return host, nil
	}
	ds.GetHostOrbitInfoFunc = func(context.Context, uint) (*fleet.HostOrbitInfo, error) {
		return &fleet.HostOrbitInfo{}, nil
	}
	ds.GetHostLockWipeStatusFunc = func(context.Context, *fleet.Host) (*fleet.HostLockWipeStatus, error) {
		return &fleet.HostLockWipeStatus{
			HostFleetPlatform: "linux",
			LockScript:        &fleet.HostScriptResult{},
		}, nil
	}

	svc := wrapRemoteLock(base, []any{fleet.Datastore(ds)})
	_, err := svc.LockHost(recoveryLockAdminContext(), host.ID, false)
	if err == nil {
		t.Fatal("expected pending lock to be rejected")
	}
	if !strings.Contains(err.Error(), "pending lock request") {
		t.Fatalf("unexpected pending-lock error: %v", err)
	}
	if ds.LockHostViaScriptFuncInvoked {
		t.Fatal("pending lock must not queue another lock script")
	}
}

func TestRemoteLockQueuesWindowsScriptAndActivity(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	host := &fleet.Host{ID: 43, Hostname: "workstation-43", Platform: "windows"}

	ds.HostFunc = func(context.Context, uint) (*fleet.Host, error) {
		return host, nil
	}
	ds.GetHostOrbitInfoFunc = func(context.Context, uint) (*fleet.HostOrbitInfo, error) {
		return &fleet.HostOrbitInfo{}, nil
	}
	ds.GetHostLockWipeStatusFunc = func(context.Context, *fleet.Host) (*fleet.HostLockWipeStatus, error) {
		return &fleet.HostLockWipeStatus{HostFleetPlatform: "windows"}, nil
	}
	base.VerifyMDMWindowsConfiguredFunc = func(context.Context) error {
		return nil
	}

	var request *fleet.HostScriptRequestPayload
	var platform string
	ds.LockHostViaScriptFunc = func(_ context.Context, value *fleet.HostScriptRequestPayload, fleetPlatform string) error {
		request = value
		platform = fleetPlatform
		return nil
	}
	var activity fleet.ActivityDetails
	base.NewActivityFunc = func(_ context.Context, _ *fleet.User, value fleet.ActivityDetails) error {
		activity = value
		return nil
	}

	svc := wrapRemoteLock(base, []any{fleet.Datastore(ds)})
	pin, err := svc.LockHost(recoveryLockAdminContext(), host.ID, false)
	if err != nil {
		t.Fatalf("lock Windows host: %v", err)
	}
	if pin != "" {
		t.Fatalf("Windows lock must not return a PIN, got %q", pin)
	}
	if request == nil {
		t.Fatal("expected Windows lock script to be queued")
	}
	if request.HostID != host.ID || request.SyncRequest {
		t.Fatalf("unexpected Windows lock request: %#v", request)
	}
	if request.UserID == nil || *request.UserID != 1 {
		t.Fatalf("expected admin user ID on script request: %#v", request.UserID)
	}
	if !strings.Contains(request.ScriptContents, "LockWorkStation") {
		t.Fatalf("expected Windows lock script, got: %s", request.ScriptContents)
	}
	if platform != "windows" {
		t.Fatalf("unexpected Fleet platform %q", platform)
	}
	if _, ok := activity.(fleet.ActivityTypeLockedHost); !ok {
		t.Fatalf("unexpected activity type %T", activity)
	}
}
