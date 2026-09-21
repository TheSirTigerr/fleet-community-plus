// Package hostidentity is a compatibility facade for the Community+ Orbit host
// identity boundary.
package hostidentity

import (
	"context"

	communityhostidentity "github.com/fleetdm/fleet/v4/orbit/pkg/communityplus/hostidentity"
	"github.com/rs/zerolog"
)

var ErrUnavailable = communityhostidentity.ErrUnavailable

type Credentials = communityhostidentity.Credentials

func Setup(ctx context.Context, rootDir, fleetURL, enrollSecret, certPath, keyPath string, insecure bool, logger zerolog.Logger, status func(string)) (*Credentials, error) {
	return communityhostidentity.Setup(ctx, rootDir, fleetURL, enrollSecret, certPath, keyPath, insecure, logger, status)
}
