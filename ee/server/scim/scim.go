// Package scim provides the legacy route-registration boundary.
package scim

import (
	"net/http"

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

// RegisterSCIM leaves the premium route mount absent. Community+ SCIM will be
// registered through its own capability when implemented.
func RegisterSCIM(_ any, _ any, _ any, _ any, _ any) error { return nil }

// RegisterValidationRoutes declares the SCIM surface for endpoint-catalog
// validation without exposing live handlers.
func RegisterValidationRoutes(r *mux.Router, _ []kithttp.ServerOption) {
	register := func(method, path string) { r.HandleFunc(path, http.NotFound).Methods(method) }
	register(http.MethodGet, "/api/v1/fleet/scim/details")
	for _, resource := range []string{"Users", "Groups"} {
		base := "/api/v1/fleet/scim/" + resource
		register(http.MethodGet, base)
		register(http.MethodPost, base)
		register(http.MethodGet, base+"/{id}")
		register(http.MethodPut, base+"/{id}")
		register(http.MethodPatch, base+"/{id}")
		register(http.MethodDelete, base+"/{id}")
	}
	register(http.MethodGet, "/api/v1/fleet/scim/Schemas")
	register(http.MethodGet, "/api/v1/fleet/scim/ServiceProviderConfig")
	register(http.MethodGet, "/api/v1/fleet/scim/ResourceTypes")
}
