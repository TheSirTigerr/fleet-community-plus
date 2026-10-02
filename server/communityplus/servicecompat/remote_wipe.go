package servicecompat

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/google/uuid"
)

const communityPlusWindowsWipeCommand = `
<Exec>
	<CmdID>%s</CmdID>
	<Item>
		<Target>
			<LocURI>./Device/Vendor/MSFT/RemoteWipe/%s</LocURI>
		</Target>
		<Meta>
			<Format xmlns="syncml:metinf">chr</Format>
			<Type>text/plain</Type>
		</Meta>
		<Data></Data>
	</Item>
</Exec>`

// communityPlusLinuxWipeScript stages itself in /run (normally tmpfs), blocks
// new logins, detaches network filesystems, and then removes data from every
// local filesystem currently mounted on the host. The final power-off uses
// sysrq so it remains available after userspace files have been deleted.
const communityPlusLinuxWipeScript = `#!/bin/sh
set -eu

STAGED=/run/fleet-communityplus-wipe.sh
MODE=${1:-stage}

if [ "$MODE" != "execute" ]; then
    cp "$0" "$STAGED"
    chmod 700 "$STAGED"

    if command -v systemd-run >/dev/null 2>&1; then
        systemd-run --unit=fleet-communityplus-wipe --collect /bin/sh "$STAGED" execute >/dev/null 2>&1
    else
        (/usr/bin/nohup /bin/sh "$STAGED" execute >/dev/null 2>&1 </dev/null) &
    fi
    exit 0
fi

printf '%s\n' 'Fleet Community+ remote wipe in progress.' > /etc/nologin 2>/dev/null || true
printf '%s\n' 'Fleet Community+ remote wipe in progress.' > /run/nologin 2>/dev/null || true

if command -v loginctl >/dev/null 2>&1; then
    loginctl terminate-user root >/dev/null 2>&1 || true
    loginctl list-users --no-legend 2>/dev/null | awk '{print $1}' | while read -r uid; do
        [ -n "$uid" ] && [ "$uid" != "0" ] && loginctl terminate-user "$uid" >/dev/null 2>&1 || true
    done
fi

# Network-backed data must never be traversed by a destructive local wipe.
if [ -r /proc/mounts ]; then
    awk '$3 ~ /^(nfs|nfs4|cifs|smbfs|fuse\.sshfs|afs|9p)$/ {print $2}' /proc/mounts |
        sort -r |
        while read -r encoded; do
            mountpoint=$(printf '%b' "$encoded")
            umount -f -l "$mountpoint" >/dev/null 2>&1 || true
        done
fi

# Capture all local mount roots before deleting userspace. Supplying every
# mount as a separate find root also covers dedicated /home, /var or /boot
# partitions while -xdev prevents crossing into pseudo/network filesystems.
set --
if [ -r /proc/mounts ]; then
    while IFS=' ' read -r _device encoded fstype _rest; do
        case "$fstype" in
            proc|procfs|sysfs|devtmpfs|devpts|tmpfs|securityfs|cgroup|cgroup2|pstore|debugfs|tracefs|configfs|fusectl|mqueue|hugetlbfs|rpc_pipefs|nfs|nfs4|cifs|smbfs|fuse.sshfs|afs|9p)
                continue
                ;;
        esac
        mountpoint=$(printf '%b' "$encoded")
        set -- "$@" "$mountpoint"
    done < /proc/mounts
fi

# Enable emergency power-off before deleting /etc and /usr.
if [ -w /proc/sys/kernel/sysrq ]; then
    printf '1\n' > /proc/sys/kernel/sysrq || true
fi

sync || true
if [ "$#" -gt 0 ]; then
    find "$@" -xdev -mindepth 1 -delete 2>/dev/null || true
else
    # A missing mount table is unexpected; fail closed instead of deleting an
    # unknown namespace.
    exit 1
fi

# /proc is a separate pseudo filesystem and remains mounted. The shell and this
# staged script live in /run, so the builtin redirection still works after the
# local filesystems have been erased.
printf 'o\n' > /proc/sysrq-trigger 2>/dev/null || true
exit 0
`

func (s *remoteLockWrapper) WipeHost(ctx context.Context, hostID uint, metadata *fleet.MDMWipeMetadata) error {
	host, err := s.authorizedHost(ctx, hostID)
	if err != nil {
		return err
	}
	platform := host.FleetPlatform()
	if platform == "android" {
		// Android wipe is already part of Fleet Community. Keep that implementation
		// authoritative instead of duplicating its COBO/BYO validation and activity flow.
		return s.Service.WipeHost(ctx, hostID, metadata)
	}

	requireMDM := false
	switch platform {
	case "darwin", "ios", "ipados":
		if host.MDM.EnrollmentStatus != nil && *host.MDM.EnrollmentStatus == fleet.MDMEnrollmentStatusPersonal {
			return &fleet.BadRequestError{Message: fleet.CantWipePersonalHostsMessage}
		}
		if err := s.VerifyMDMAppleConfigured(ctx); err != nil {
			if errors.Is(err, fleet.ErrMDMNotConfigured) {
				err = fleet.NewInvalidArgumentError("host_id", fleet.AppleMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
			}
			return ctxerr.Wrap(ctx, err, "check Apple MDM enabled")
		}
		if s.apple == nil {
			return errors.New("Community+ remote wipe: Apple MDM commander is unavailable")
		}
		requireMDM = true

	case "windows":
		if err := s.VerifyMDMWindowsConfigured(ctx); err != nil {
			if errors.Is(err, fleet.ErrMDMNotConfigured) {
				err = fleet.NewInvalidArgumentError("host_id", fleet.WindowsMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
			}
			return ctxerr.Wrap(ctx, err, "check Windows MDM enabled")
		}
		requireMDM = true

	case "linux":
		if err := s.requireScripts(ctx, host, "wipe"); err != nil {
			return err
		}

	default:
		return fleet.NewInvalidArgumentError("host_id", fmt.Sprintf("Unsupported host platform: %s", host.Platform))
	}

	if requireMDM {
		connected, err := s.ds.IsHostConnectedToFleetMDM(ctx, host)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "check MDM enrollment")
		}
		if !connected {
			return fleet.NewInvalidArgumentError("host_id", "Can't wipe the host because it doesn't have MDM turned on.")
		}
	}

	status, err := s.ds.GetHostLockWipeStatus(ctx, host)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "get host lock/wipe status")
	}
	switch {
	case status.IsPendingLock():
		return fleet.NewInvalidArgumentError("host_id", "Host has pending lock request. Host cannot be wiped until lock is complete.")
	case status.IsPendingUnlock():
		return fleet.NewInvalidArgumentError("host_id", "Host has pending unlock request. Host cannot be wiped until unlock is complete.")
	case status.IsPendingWipe():
		return fleet.NewInvalidArgumentError("host_id", "Host has pending wipe request. The host will be wiped when it comes online.")
	case status.IsLocked():
		return fleet.NewInvalidArgumentError("host_id", "Host is locked. Host cannot be wiped until it is unlocked.")
	case status.IsWiped():
		return fleet.NewInvalidArgumentError("host_id", "Host is already wiped.").WithStatus(http.StatusConflict)
	}

	user := authz.UserFromContext(ctx)
	if user == nil {
		return fleet.ErrNoContext
	}

	switch platform {
	case "darwin", "ios", "ipados":
		if err := s.apple.EraseDevice(ctx, host, uuid.NewString()); err != nil {
			return ctxerr.Wrap(ctx, err, "queue Apple wipe")
		}

	case "windows":
		wipeType := fleet.MDMWindowsWipeTypeDoWipeProtected
		if metadata != nil && metadata.Windows != nil {
			wipeType = metadata.Windows.WipeType
		}
		commandUUID := uuid.NewString()
		command := &fleet.MDMWindowsCommand{
			CommandUUID:  commandUUID,
			RawCommand:   []byte(fmt.Sprintf(communityPlusWindowsWipeCommand, commandUUID, wipeType.String())),
			TargetLocURI: fmt.Sprintf("./Device/Vendor/MSFT/RemoteWipe/%s", wipeType.String()),
		}
		if err := s.ds.WipeHostViaWindowsMDM(ctx, host, command); err != nil {
			return ctxerr.Wrap(ctx, err, "queue Windows wipe")
		}

	case "linux":
		if err := s.ds.WipeHostViaScript(ctx, &fleet.HostScriptRequestPayload{
			HostID:         host.ID,
			ScriptContents: communityPlusLinuxWipeScript,
			UserID:         &user.ID,
			SyncRequest:    false,
		}, platform); err != nil {
			return ctxerr.Wrap(ctx, err, "queue Linux wipe")
		}

	}

	if err := s.NewActivity(ctx, user, fleet.ActivityTypeWipedHost{
		HostID:          host.ID,
		HostDisplayName: host.DisplayName(),
		HostPlatform:    platform,
	}); err != nil {
		return ctxerr.Wrap(ctx, err, "record remote wipe activity")
	}
	return nil
}
