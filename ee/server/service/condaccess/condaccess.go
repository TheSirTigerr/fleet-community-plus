// Package condaccess is a compatibility facade for Community+ conditional access.
package condaccess

import (
	"context"
	"log/slog"
	"net/http"

	communitycondaccess "github.com/fleetdm/fleet/v4/server/communityplus/condaccess"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
	scepdepot "github.com/fleetdm/fleet/v4/server/mdm/scep/depot"
)

func RegisterSCEP(ctx context.Context, mux *http.ServeMux, storage scepdepot.Depot, ds fleet.Datastore, logger *slog.Logger, cfg *config.FleetConfig) error {
	return communitycondaccess.RegisterSCEP(ctx, mux, storage, ds, logger, cfg)
}

func RegisterIdP(a, b, c, d, e any) error {
	return communitycondaccess.RegisterIdP(a, b, c, d, e)
}
