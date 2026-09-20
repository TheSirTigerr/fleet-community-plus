// Package homebrew is the Community+ Homebrew ingestion boundary.
package homebrew

import (
	"context"
	"errors"
	"log/slog"

	maintainedapps "github.com/fleetdm/fleet/v4/ee/maintained-apps"
)

var ErrUnavailable = errors.New("Community+ Homebrew manifest ingestion is unavailable")

func IngestApps(context.Context, *slog.Logger, string, string) ([]*maintainedapps.FMAManifestApp, error) {
	return nil, ErrUnavailable
}
