// Package winget is the Community+ WinGet ingestion boundary.
package winget

import (
	"context"
	"log/slog"

	maintainedapps "github.com/fleetdm/fleet/v4/ee/maintained-apps"
	"github.com/fleetdm/fleet/v4/ee/maintained-apps/ingesters/source"
)

// IngestApps imports locally maintained Windows catalog entries. The catalog
// format is shared with Homebrew to keep catalog review and signing uniform.
func IngestApps(ctx context.Context, logger *slog.Logger, inputDir, slug string) ([]*maintainedapps.FMAManifestApp, error) {
	return source.Ingest(ctx, logger, inputDir, slug)
}
