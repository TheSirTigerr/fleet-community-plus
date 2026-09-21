// Package maintained_apps is a compatibility facade for the independently
// implemented Community+ maintained-app catalog types.
package maintained_apps

import communityapps "github.com/fleetdm/fleet/v4/server/communityplus/maintainedapps"

type FMAManifestFile = communityapps.FMAManifestFile
type FMAManifestApp = communityapps.FMAManifestApp
type FMAQueries = communityapps.FMAQueries
type Ingester = communityapps.Ingester

const OutputPath = communityapps.OutputPath

type FMAListFile = communityapps.FMAListFile
type FMAListFileApp = communityapps.FMAListFileApp
