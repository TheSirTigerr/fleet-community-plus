// Package scim is a compatibility facade for the Community+ SCIM boundary.
package scim

import (
	communityscim "github.com/fleetdm/fleet/v4/server/communityplus/scim"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

func RegisterSCIM(a, b, c, d, e any) error {
	return communityscim.RegisterSCIM(a, b, c, d, e)
}

func RegisterValidationRoutes(r *mux.Router, opts []kithttp.ServerOption) {
	communityscim.RegisterValidationRoutes(r, opts)
}
