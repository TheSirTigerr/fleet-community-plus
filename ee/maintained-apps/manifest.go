// Package maintained_apps is a compatibility facade for the independently
// implemented Community+ maintained-app manifest schema.
package maintained_apps

import communityapps "github.com/fleetdm/fleet/v4/server/communityplus/maintainedapps"

type FMAManifestFile = communityapps.ManifestFile
type FMAManifestApp = communityapps.ManifestApp
type FMAQueries = communityapps.Queries
