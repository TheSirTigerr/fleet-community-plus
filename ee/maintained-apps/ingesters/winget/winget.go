// Package winget is the Community+ WinGet ingestion boundary.
package winget

import (
	"context"
	"errors"
	"log/slog"

	maintainedapps "github.com/fleetdm/fleet/v4/ee/maintained-apps"
)

var ErrUnavailable = errors.New("Community+ WinGet manifest ingestion is unavailable")

func IngestApps(context.Context, *slog.Logger, string, string) ([]*maintainedapps.FMAManifestApp, error) {
	return nil, ErrUnavailable
}
