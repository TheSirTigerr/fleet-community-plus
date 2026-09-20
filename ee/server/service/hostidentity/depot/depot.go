// Package depot provides the legacy construction boundary used by Fleet's
// MySQL datastore.
package depot

import (
	communityplusscep "github.com/fleetdm/fleet/v4/server/communityplus/scep"
	scepdepot "github.com/fleetdm/fleet/v4/server/mdm/scep/depot"
)

// NewHostIdentitySCEPDepot returns a fail-closed depot until the Community+
// host-identity certificate issuer is enabled.
func NewHostIdentitySCEPDepot(_ any, _ any, _ any, _ any) (scepdepot.Depot, error) {
	return communityplusscep.DisabledDepot{}, nil
}
