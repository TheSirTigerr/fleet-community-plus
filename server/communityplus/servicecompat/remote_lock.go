package servicecompat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	common_mysql "github.com/fleetdm/fleet/v4/server/platform/mysql"
	"github.com/fleetdm/fleet/v4/server/mdm/android"
	"github.com/google/uuid"
)

const communityPlusWindowsLockScript = `$ErrorActionPreference = "Stop"
$locked = $false
try {
    $sessions = & "$env:SystemRoot\System32\query.exe" session 2>$null
    foreach ($line in $sessions) {
        if ($line -match '^\s*>?(\S+)\s+(\S+)\s+(\d+)\s+Active\s*') {
            & "$env:SystemRoot\System32\tsdiscon.exe" $Matches[3] 2>$null
            if ($LASTEXITCODE -eq 0) { $locked = $true }
        }
    }
} catch {}
if (-not $locked) {
    & "$env:SystemRoot\System32\rundll32.exe" user32.dll,LockWorkStation
}
exit 0
`

const communityPlusWindowsUnlockScript = `$ErrorActionPreference = "SilentlyContinue"
$sessions = & "$env:SystemRoot\System32\query.exe" session 2>$null
foreach ($line in $sessions) {
    if ($line -match '^\s*>?(\S+)\s+(\S+)\s+(\d+)\s+Disc\s*') {
        & "$env:SystemRoot\System32\tscon.exe" $Matches[3] /dest:console 2>$null
        if ($LASTEXITCODE -eq 0) { exit 0 }
    }
}
exit 0
`

const communityPlusLinuxLockScript = `#!/bin/sh
set -eu
if command -v loginctl >/dev/null 2>&1; then
    loginctl lock-sessions >/dev/null 2>&1 || true
    loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}' | while read -r sid; do
        [ -n "$sid" ] && loginctl lock-session "$sid" >/dev/null 2>&1 || true
    done
fi
exit 0
`

const communityPlusLinuxUnlockScript = `#!/bin/sh
set -eu
if command -v loginctl >/dev/null 2>&1; then
    loginctl unlock-sessions >/dev/null 2>&1 || true
    loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}' | while read -r sid; do
        [ -n "$sid" ] && loginctl unlock-session "$sid" >/dev/null 2>&1 || true
    done
fi
exit 0
`

type remoteLockWrapper struct {
	fleet.Service
	ds         fleet.Datastore
	authorizer *authz.Authorizer
	apple      fleet.MDMAppleCommandIssuer
	android    android.Service
}

func wrapRemoteLock(base fleet.Service, options []any) fleet.Service {
	if base == nil {
		return nil
	}
	var ds fleet.Datastore
	var apple fleet.MDMAppleCommandIssuer
	var androidSvc android.Service
	for _, option := range options {
		switch value := option.(type) {
		case fleet.Datastore:
			ds = value
		case fleet.MDMAppleCommandIssuer:
			apple = value
		case android.Service:
			androidSvc = value
		}
	}
	if ds == nil {
		return base
	}
	return &remoteLockWrapper{
		Service:    base,
		ds:         ds,
		authorizer: authz.Must(),
		apple:      apple,
		android:    androidSvc,
	}
}

func (s *remoteLockWrapper) LockHost(ctx context.Context, hostID uint, viewPIN bool) (string, error) {
	host, err := s.authorizedHost(ctx, hostID)
	if err != nil {
		return "", err
	}
	platform := host.FleetPlatform()

	switch platform {
	case "darwin", "ios", "ipados":
		if host.MDM.EnrollmentStatus != nil && *host.MDM.EnrollmentStatus == fleet.MDMEnrollmentStatusPersonal {
			return "", &fleet.BadRequestError{Message: fleet.CantLockPersonalHostsMessage}
		}
		if host.MDM.EnrollmentStatus != nil && *host.MDM.EnrollmentStatus == fleet.MDMEnrollmentStatusManual &&
			(platform == "ios" || platform == "ipados") {
			return "", &fleet.BadRequestError{Message: fleet.CantLockManualIOSIpadOSHostsMessage}
		}
		if err := s.VerifyMDMAppleConfigured(ctx); err != nil {
			if errors.Is(err, fleet.ErrMDMNotConfigured) {
				err = fleet.NewInvalidArgumentError("host_id", fleet.AppleMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
			}
			return "", ctxerr.Wrap(ctx, err, "check Apple MDM enabled")
		}
		if s.apple == nil {
			return "", errors.New("Community+ remote lock: Apple MDM commander is unavailable")
		}
		connected, err := s.ds.IsHostConnectedToFleetMDM(ctx, host)
		if err != nil {
			return "", ctxerr.Wrap(ctx, err, "check Apple MDM enrollment")
		}
		if !connected {
			return "", fleet.NewInvalidArgumentError("host_id", "Can't lock the host because it doesn't have MDM turned on.")
		}
	case "windows", "linux":
		if platform == "windows" {
			if err := s.VerifyMDMWindowsConfigured(ctx); err != nil {
				if errors.Is(err, fleet.ErrMDMNotConfigured) {
					err = fleet.NewInvalidArgumentError("host_id", fleet.WindowsMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
				}
				return "", ctxerr.Wrap(ctx, err, "check Windows MDM enabled")
			}
		}
		if err := s.requireScripts(ctx, host, "lock"); err != nil {
			return "", err
		}
	case "android":
		if err := s.VerifyMDMAndroidConfigured(ctx); err != nil {
			if errors.Is(err, fleet.ErrMDMNotConfigured) {
				err = fleet.NewInvalidArgumentError("host_id", fleet.AndroidMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
			}
			return "", ctxerr.Wrap(ctx, err, "check Android MDM enabled")
		}
		if s.android == nil {
			return "", errors.New("Community+ remote lock: Android MDM service is unavailable")
		}
		connected, err := s.ds.IsHostConnectedToFleetMDM(ctx, host)
		if err != nil {
			return "", ctxerr.Wrap(ctx, err, "check Android MDM enrollment")
		}
		if !connected {
			return "", fleet.NewInvalidArgumentError("host_id", "Can't lock the host because it doesn't have MDM turned on.")
		}
	default:
		return "", fleet.NewInvalidArgumentError("host_id", fmt.Sprintf("Unsupported host platform: %s", host.Platform))
	}

	status, err := s.ds.GetHostLockWipeStatus(ctx, host)
	if err != nil {
		return "", ctxerr.Wrap(ctx, err, "get host lock/wipe status")
	}
	switch {
	case status.IsPendingLock():
		return "", fleet.NewInvalidArgumentError("host_id", "Host has pending lock request. Host cannot be locked again until lock is complete.")
	case status.IsPendingUnlock():
		return "", fleet.NewInvalidArgumentError("host_id", "Host has pending unlock request. Host cannot be locked again until unlock is complete.")
	case status.IsPendingWipe():
		return "", fleet.NewInvalidArgumentError("host_id", "Host has pending wipe request. Cannot process lock requests once host is wiped.")
	case status.IsWiped():
		return "", fleet.NewInvalidArgumentError("host_id", "Host is wiped. Cannot process lock requests once host is wiped.")
	case status.IsLocked():
		return "", fleet.NewInvalidArgumentError("host_id", "Host is already locked.").WithStatus(http.StatusConflict)
	}

	user := authz.UserFromContext(ctx)
	if user == nil {
		return "", fleet.ErrNoContext
	}

	var pin string
	switch platform {
	case "darwin":
		pin, err = s.apple.DeviceLock(ctx, host, uuid.NewString())
	case "ios", "ipados":
		appCfg, cfgErr := s.ds.AppConfig(ctx)
		if cfgErr != nil {
			return "", ctxerr.Wrap(ctx, cfgErr, "get app config")
		}
		err = s.apple.EnableLostMode(ctx, host, uuid.NewString(), appCfg.OrgInfo.OrgName)
	case "windows":
		err = s.ds.LockHostViaScript(ctx, &fleet.HostScriptRequestPayload{
			HostID: host.ID, ScriptContents: communityPlusWindowsLockScript, UserID: &user.ID, SyncRequest: false,
		}, platform)
	case "linux":
		err = s.ds.LockHostViaScript(ctx, &fleet.HostScriptRequestPayload{
			HostID: host.ID, ScriptContents: communityPlusLinuxLockScript, UserID: &user.ID, SyncRequest: false,
		}, platform)
	case "android":
		err = s.android.LockAndroidHost(ctx, host.ID)
	}
	if err != nil {
		return "", ctxerr.Wrap(ctx, err, "queue remote lock")
	}

	if err := s.NewActivity(ctx, user, fleet.ActivityTypeLockedHost{
		HostID: host.ID, HostDisplayName: host.DisplayName(), ViewPIN: viewPIN && platform == "darwin",
	}); err != nil {
		return "", ctxerr.Wrap(ctx, err, "record remote lock activity")
	}
	return pin, nil
}

func (s *remoteLockWrapper) UnlockHost(ctx context.Context, hostID uint) (string, error) {
	host, err := s.authorizedHost(ctx, hostID)
	if err != nil {
		return "", err
	}
	platform := host.FleetPlatform()
	switch platform {
	case "darwin", "ios", "ipados":
		if s.apple == nil {
			return "", errors.New("Community+ remote lock: Apple MDM commander is unavailable")
		}
	case "windows", "linux":
		if platform == "windows" {
			if err := s.VerifyMDMWindowsConfigured(ctx); err != nil {
				if errors.Is(err, fleet.ErrMDMNotConfigured) {
					err = fleet.NewInvalidArgumentError("host_id", fleet.WindowsMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
				}
				return "", ctxerr.Wrap(ctx, err, "check Windows MDM enabled")
			}
		}
		if err := s.requireScripts(ctx, host, "unlock"); err != nil {
			return "", err
		}
	default:
		return "", fleet.NewInvalidArgumentError("host_id", fmt.Sprintf("Unsupported host platform: %s", host.Platform))
	}

	status, err := s.ds.GetHostLockWipeStatus(ctx, host)
	if err != nil {
		return "", ctxerr.Wrap(ctx, err, "get host lock/wipe status")
	}
	switch {
	case status.IsPendingLock():
		return "", fleet.NewInvalidArgumentError("host_id", "Host has pending lock request. Host cannot be unlocked until lock is complete.")
	case status.IsPendingUnlock() && platform != "darwin":
		return "", fleet.NewInvalidArgumentError("host_id", "Host has pending unlock request. The host will unlock when it comes online.")
	case status.IsPendingWipe():
		return "", fleet.NewInvalidArgumentError("host_id", "Host has pending wipe request. Cannot process unlock requests once host is wiped.")
	case status.IsWiped():
		return "", fleet.NewInvalidArgumentError("host_id", "Host is wiped. Cannot process unlock requests once host is wiped.")
	case status.IsUnlocked():
		return "", fleet.NewInvalidArgumentError("host_id", "Host is already unlocked.").WithStatus(http.StatusConflict)
	}

	user := authz.UserFromContext(ctx)
	if user == nil {
		return "", fleet.ErrNoContext
	}
	var pin string
	switch platform {
	case "darwin":
		if status.UnlockRequestedAt.IsZero() {
			if err := s.ds.UnlockHostManually(ctx, host.ID, platform, time.Now().UTC()); err != nil {
				return "", err
			}
		}
		pin = status.UnlockPIN
	case "ios", "ipados":
		if err := s.apple.DisableLostMode(ctx, host, uuid.NewString()); err != nil {
			return "", ctxerr.Wrap(ctx, err, "disable Apple lost mode")
		}
	case "windows":
		if err := s.ds.UnlockHostViaScript(ctx, &fleet.HostScriptRequestPayload{
			HostID: host.ID, ScriptContents: communityPlusWindowsUnlockScript, UserID: &user.ID, SyncRequest: false,
		}, platform); err != nil {
			return "", err
		}
	case "linux":
		if err := s.ds.UnlockHostViaScript(ctx, &fleet.HostScriptRequestPayload{
			HostID: host.ID, ScriptContents: communityPlusLinuxUnlockScript, UserID: &user.ID, SyncRequest: false,
		}, platform); err != nil {
			return "", err
		}
	}
	if err := s.NewActivity(ctx, user, fleet.ActivityTypeUnlockedHost{
		HostID: host.ID, HostDisplayName: host.DisplayName(), HostPlatform: host.Platform,
	}); err != nil {
		return "", ctxerr.Wrap(ctx, err, "record remote unlock activity")
	}
	return pin, nil
}

func (s *remoteLockWrapper) authorizedHost(ctx context.Context, hostID uint) (*fleet.Host, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.Host{}, fleet.ActionList); err != nil {
		return nil, err
	}
	host, err := s.ds.Host(ctx, hostID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get host")
	}
	notFoundErr := ctxerr.Wrap(ctx, common_mysql.NotFound("Host").WithID(hostID), "remote host action")
	if err := s.authorizer.AuthorizeOrNotFound(ctx, fleet.MDMCommandAuthz{TeamID: host.TeamID}, fleet.ActionWrite, notFoundErr); err != nil {
		return nil, err
	}
	return host, nil
}

func (s *remoteLockWrapper) requireScripts(ctx context.Context, host *fleet.Host, action string) error {
	info, err := s.ds.GetHostOrbitInfo(ctx, host.ID)
	if err != nil {
		if fleet.IsNotFound(err) {
			return nil
		}
		return ctxerr.Wrap(ctx, err, "get host orbit info")
	}
	if info.ScriptsEnabled != nil && !*info.ScriptsEnabled {
		return fleet.NewInvalidArgumentError(
			"host_id",
			fmt.Sprintf("Couldn't %s host. To %s, deploy the fleetd agent with --enable-scripts and refetch host vitals.", action, action),
		)
	}
	return nil
}
