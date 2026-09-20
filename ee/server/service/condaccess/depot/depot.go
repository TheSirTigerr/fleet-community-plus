// Package depot provides the legacy construction boundary used by Fleet's
// MySQL datastore.
package depot

import (
	communityplusscep "github.com/fleetdm/fleet/v4/server/communityplus/scep"
	scepdepot "github.com/fleetdm/fleet/v4/server/mdm/scep/depot"
)

// NewConditionalAccessSCEPDepot returns a fail-closed depot until the
// Community+ conditional-access issuer is enabled.
func NewConditionalAccessSCEPDepot(_ any, _ any, _ any, _ any) (scepdepot.Depot, error) {
	return communityplusscep.DisabledDepot{}, nil
}
