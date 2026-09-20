// Package maintained_apps is a compatibility facade for the independently
// implemented Community+ maintained-app manifest schema.
package maintained_apps

import (
	"context"
	"log/slog"

	communityapps "github.com/fleetdm/fleet/v4/server/communityplus/maintainedapps"
)

type FMAManifestFile = communityapps.ManifestFile
type FMAManifestApp = communityapps.ManifestApp
type FMAQueries = communityapps.Queries

type Ingester func(context.Context, *slog.Logger, string, string) ([]*FMAManifestApp, error)

const OutputPath = "ee/maintained-apps/outputs"

type FMAListFile struct {
	Apps []FMAListFileApp `json:"apps"`
}

type FMAListFileApp struct {
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	Platform         string `json:"platform"`
	UniqueIdentifier string `json:"unique_identifier,omitempty"`
}
