// Package types is a compatibility facade for the independently implemented
// Community+ host identity model.
package types

import (
	"crypto/ecdsa"

	communitytypes "github.com/fleetdm/fleet/v4/server/communityplus/hostidentity/types"
)

type HostIdentityCertificate = communitytypes.HostIdentityCertificate

func CreateECDSAPublicKeyRaw(key *ecdsa.PublicKey) ([]byte, error) {
	return communitytypes.CreateECDSAPublicKeyRaw(key)
}
