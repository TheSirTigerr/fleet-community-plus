// Package hostidentity is a compatibility facade for Community+ host identity.
package hostidentity

import communityhostidentity "github.com/fleetdm/fleet/v4/server/communityplus/hostidentity"

func RegisterSCEP(a, b, c, d, e any) error {
	return communityhostidentity.RegisterSCEP(a, b, c, d, e)
}
