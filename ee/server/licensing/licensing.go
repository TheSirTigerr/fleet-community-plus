// Package licensing is a compatibility facade for Community+'s edition
// identity. No Enterprise license validation implementation is included.
package licensing

import (
	communitylicensing "github.com/fleetdm/fleet/v4/server/communityplus/licensing"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

func LoadLicense(key string) (*fleet.LicenseInfo, error) {
	return communitylicensing.Load(key)
}
