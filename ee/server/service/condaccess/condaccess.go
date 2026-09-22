// Package condaccess is a compatibility facade for Community+ conditional access.
package condaccess

import communitycondaccess "github.com/fleetdm/fleet/v4/server/communityplus/condaccess"

func RegisterSCEP(a, b, c, d, e, f any) error {
	return communitycondaccess.RegisterSCEP(a, b, c, d, e, f)
}

func RegisterIdP(a, b, c, d, e any) error {
	return communitycondaccess.RegisterIdP(a, b, c, d, e)
}
