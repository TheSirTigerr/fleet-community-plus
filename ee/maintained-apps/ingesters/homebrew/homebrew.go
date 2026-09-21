// Package homebrew is the Community+ Homebrew ingestion boundary.
package homebrew

import (
	"context"
	"log/slog"

	maintainedapps "github.com/fleetdm/fleet/v4/ee/maintained-apps"
	"github.com/fleetdm/fleet/v4/ee/maintained-apps/ingesters/source"
)

// IngestApps imports locally maintained macOS catalog entries. The catalog
// format is shared with WinGet to keep catalog review and signing uniform.
func IngestApps(ctx context.Context, logger *slog.Logger, inputDir, slug string) ([]*maintainedapps.FMAManifestApp, error) {
	return source.Ingest(ctx, logger, inputDir, slug)
}
