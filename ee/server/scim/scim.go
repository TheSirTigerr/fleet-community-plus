// Package scim is a compatibility facade for the Community+ SCIM provider.
package scim

import (
	"log/slog"
	"net/http"

	communityscim "github.com/fleetdm/fleet/v4/server/communityplus/scim"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

func RegisterSCIM(root *http.ServeMux, ds fleet.Datastore, svc fleet.Service, logger *slog.Logger, cfg *config.FleetConfig) error {
	return communityscim.RegisterSCIM(root, ds, svc, logger, cfg)
}

func RegisterValidationRoutes(r *mux.Router, opts []kithttp.ServerOption) {
	communityscim.RegisterValidationRoutes(r, opts)
}
