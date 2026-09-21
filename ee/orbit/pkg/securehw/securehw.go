// Package securehw is a compatibility facade for the Community+ Orbit secure
// hardware boundary.
package securehw

import (
	communitysecurehw "github.com/fleetdm/fleet/v4/orbit/pkg/communityplus/securehw"
	"github.com/rs/zerolog"
)

var ErrUnavailable = communitysecurehw.ErrUnavailable

type ErrKeyNotFound = communitysecurehw.ErrKeyNotFound
type ErrSecureHWUnavailable = communitysecurehw.ErrSecureHWUnavailable
type ECCAlgorithm = communitysecurehw.ECCAlgorithm

const (
	ECCAlgorithmP256 = communitysecurehw.ECCAlgorithmP256
	ECCAlgorithmP384 = communitysecurehw.ECCAlgorithmP384
)

type HTTPSigner = communitysecurehw.HTTPSigner
type Key = communitysecurehw.Key
type SecureHW = communitysecurehw.SecureHW

func New(rootDir string, logger zerolog.Logger) (SecureHW, error) {
	return communitysecurehw.New(rootDir, logger)
}
