package servicecompat

import (
	"context"
	"strings"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	storemock "github.com/fleetdm/fleet/v4/server/mock"
	servicemock "github.com/fleetdm/fleet/v4/server/mock/service"
)

func TestRemoteWipeRejectsPersonalAppleEnrollment(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	status := fleet.MDMEnrollmentStatusPersonal
	host := &fleet.Host{
		ID:       51,
		Platform: "ios",
		MDM: fleet.MDMHostData{
			EnrollmentStatus: &status,
		},
	}
	ds.HostFunc = func(context.Context, uint) (*fleet.Host, error) {
		return host, nil
	}

	svc := wrapRemoteLock(base, []any{fleet.Datastore(ds)})
	err := svc.WipeHost(recoveryLockAdminContext(), host.ID, nil)
	if err == nil {
		t.Fatal("expected personal Apple enrollment to be rejected")
	}
	if !strings.Contains(err.Error(), fleet.CantWipePersonalHostsMessage) {
		t.Fatalf("unexpected personal-enrollment error: %v", err)
	}
}

func TestRemoteWipeQueuesWindowsMDMCommandAndActivity(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	host := &fleet.Host{ID: 52, Hostname: "windows-52", Platform: "windows"}

	ds.HostFunc = func(context.Context, uint) (*fleet.Host, error) {
		return host, nil
	}
	base.VerifyMDMWindowsConfiguredFunc = func(context.Context) error {
		return nil
	}
	ds.IsHostConnectedToFleetMDMFunc = func(context.Context, *fleet.Host) (bool, error) {
		return true, nil
	}
	ds.GetHostLockWipeStatusFunc = func(context.Context, *fleet.Host) (*fleet.HostLockWipeStatus, error) {
		return &fleet.HostLockWipeStatus{HostFleetPlatform: "windows"}, nil
	}

	var command *fleet.MDMWindowsCommand
	ds.WipeHostViaWindowsMDMFunc = func(_ context.Context, _ *fleet.Host, value *fleet.MDMWindowsCommand) error {
		command = value
		return nil
	}
	var activity fleet.ActivityDetails
	base.NewActivityFunc = func(_ context.Context, _ *fleet.User, value fleet.ActivityDetails) error {
		activity = value
		return nil
	}

	svc := wrapRemoteLock(base, []any{fleet.Datastore(ds)})
	if err := svc.WipeHost(recoveryLockAdminContext(), host.ID, nil); err != nil {
		t.Fatalf("wipe Windows host: %v", err)
	}
	if command == nil {
		t.Fatal("expected Windows MDM wipe command")
	}
	if command.CommandUUID == "" {
		t.Fatal("expected Windows wipe command UUID")
	}
	if !strings.Contains(command.TargetLocURI, "RemoteWipe/") || !strings.Contains(command.TargetLocURI, "Wipe") {
		t.Fatalf("unexpected Windows wipe target: %q", command.TargetLocURI)
	}
	if !strings.Contains(string(command.RawCommand), "<Exec>") || !strings.Contains(string(command.RawCommand), command.CommandUUID) {
		t.Fatalf("unexpected Windows wipe command: %s", string(command.RawCommand))
	}
	if _, ok := activity.(fleet.ActivityTypeWipedHost); !ok {
		t.Fatalf("unexpected activity type %T", activity)
	}
}

func TestRemoteWipeQueuesLinuxScriptAndActivity(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	host := &fleet.Host{ID: 53, Hostname: "linux-53", Platform: "linux"}

	ds.HostFunc = func(context.Context, uint) (*fleet.Host, error) {
		return host, nil
	}
	ds.GetHostOrbitInfoFunc = func(context.Context, uint) (*fleet.HostOrbitInfo, error) {
		return &fleet.HostOrbitInfo{}, nil
	}
	ds.GetHostLockWipeStatusFunc = func(context.Context, *fleet.Host) (*fleet.HostLockWipeStatus, error) {
		return &fleet.HostLockWipeStatus{HostFleetPlatform: "linux"}, nil
	}

	var request *fleet.HostScriptRequestPayload
	var platform string
	ds.WipeHostViaScriptFunc = func(_ context.Context, value *fleet.HostScriptRequestPayload, fleetPlatform string) error {
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
	if err := svc.WipeHost(recoveryLockAdminContext(), host.ID, nil); err != nil {
		t.Fatalf("wipe Linux host: %v", err)
	}
	if request == nil {
		t.Fatal("expected Linux wipe script request")
	}
	if request.HostID != host.ID || request.SyncRequest {
		t.Fatalf("unexpected Linux wipe request: %#v", request)
	}
	if request.UserID == nil || *request.UserID != 1 {
		t.Fatalf("expected admin user ID on wipe script: %#v", request.UserID)
	}
	if !strings.Contains(request.ScriptContents, "fleet-communityplus-wipe") ||
		!strings.Contains(request.ScriptContents, "/proc/sysrq-trigger") {
		t.Fatalf("unexpected Linux wipe script: %s", request.ScriptContents)
	}
	if platform != "linux" {
		t.Fatalf("unexpected Fleet platform %q", platform)
	}
	if _, ok := activity.(fleet.ActivityTypeWipedHost); !ok {
		t.Fatalf("unexpected activity type %T", activity)
	}
}

func TestRemoteWipeDelegatesAndroidToCommunityCore(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	host := &fleet.Host{ID: 54, Platform: "android"}
	ds.HostFunc = func(context.Context, uint) (*fleet.Host, error) {
		return host, nil
	}

	called := false
	base.WipeHostFunc = func(_ context.Context, hostID uint, metadata *fleet.MDMWipeMetadata) error {
		called = true
		if hostID != host.ID {
			t.Fatalf("unexpected Android host ID %d", hostID)
		}
		if metadata != nil {
			t.Fatalf("unexpected Android metadata %#v", metadata)
		}
		return nil
	}

	svc := wrapRemoteLock(base, []any{fleet.Datastore(ds)})
	if err := svc.WipeHost(recoveryLockAdminContext(), host.ID, nil); err != nil {
		t.Fatalf("delegate Android wipe: %v", err)
	}
	if !called {
		t.Fatal("expected Android wipe to delegate to Fleet Community core")
	}
}

func TestRemoteWipeRejectsPendingLock(t *testing.T) {
	ds := new(storemock.Store)
	base := new(servicemock.Service)
	host := &fleet.Host{ID: 55, Platform: "linux"}

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
	err := svc.WipeHost(recoveryLockAdminContext(), host.ID, nil)
	if err == nil {
		t.Fatal("expected pending lock to block wipe")
	}
	if !strings.Contains(err.Error(), "pending lock request") {
		t.Fatalf("unexpected pending-lock wipe error: %v", err)
	}
	if ds.WipeHostViaScriptFuncInvoked {
		t.Fatal("pending lock must not queue a wipe script")
	}
}
