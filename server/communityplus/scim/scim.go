// Package scim implements Community+'s SCIM 2.0 provisioning surface.
package scim

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"

	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/service/middleware/auth"
)

type provider struct {
	ds     fleet.Datastore
	logger *slog.Logger
}

// RegisterSCIM mounts the Community+ SCIM provider for both supported Fleet API
// aliases. Authentication uses normal Fleet API bearer tokens and provisioning
// is restricted to global administrators.
func RegisterSCIM(
	root *http.ServeMux,
	ds fleet.Datastore,
	svc fleet.Service,
	logger *slog.Logger,
	fleetConfig *config.FleetConfig,
) error {
	if root == nil {
		return errors.New("scim: nil HTTP mux")
	}
	if ds == nil {
		return errors.New("scim: nil datastore")
	}
	if svc == nil {
		return errors.New("scim: nil service")
	}
	if fleetConfig == nil {
		return errors.New("scim: nil Fleet config")
	}
	if logger == nil {
		logger = slog.Default()
	}

	p := &provider{ds: ds, logger: logger}
	var handler http.Handler = http.HandlerFunc(p.serveHTTP)
	handler = requireGlobalAdmin(svc, handler)
	handler = p.recordLastRequest(handler)

	root.Handle("/api/v1/fleet/scim/", handler)
	root.Handle("/api/latest/fleet/scim/", handler)
	return nil
}

func requireGlobalAdmin(svc fleet.Service, next http.Handler) http.Handler {
	adminOnly := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := viewer.FromContext(r.Context())
		if !ok || v.User == nil || v.User.GlobalRole == nil || *v.User.GlobalRole != fleet.RoleAdmin {
			writeSCIMError(w, http.StatusForbidden, "global administrator privileges are required", "")
			return
		}
		next.ServeHTTP(w, r)
	})

	authenticated := auth.AuthenticatedUserMiddleware(svc, func(w http.ResponseWriter, detail string, status int) {
		writeSCIMError(w, status, detail, "")
	}, adminOnly)
	return auth.SetRequestsContextMiddleware(svc, authenticated)
}

func (p *provider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/scim/")
	if path == r.URL.Path {
		path = strings.TrimPrefix(r.URL.Path, "/api/latest/fleet/scim/")
	}
	path = strings.Trim(path, "/")

	switch {
	case path == "Users" || strings.HasPrefix(path, "Users/"):
		p.handleUsers(w, r, strings.TrimPrefix(path, "Users"))
	case path == "Groups" || strings.HasPrefix(path, "Groups/"):
		p.handleGroups(w, r, strings.TrimPrefix(path, "Groups"))
	case path == "ServiceProviderConfig" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, serviceProviderConfig())
	case path == "Schemas" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, schemasResponse())
	case path == "ResourceTypes" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, resourceTypesResponse())
	default:
		writeSCIMError(w, http.StatusNotFound, "SCIM resource not found", "")
	}
}

func (p *provider) recordLastRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		status := "success"
		if rw.status >= http.StatusBadRequest {
			status = "error"
		}
		details := fmt.Sprintf("%s %s -> %d", r.Method, r.URL.Path, rw.status)
		if len(details) > fleet.SCIMMaxFieldLength {
			details = details[:fleet.SCIMMaxFieldLength]
		}
		if err := p.ds.UpdateScimLastRequest(r.Context(), &fleet.ScimLastRequest{Status: status, Details: details}); err != nil {
			p.logger.ErrorContext(r.Context(), "Community+ SCIM: update last request", "err", err)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// RegisterValidationRoutes declares the SCIM surface for endpoint-catalog
// validation. Live requests are prefix-mounted on the root HTTP mux and are not
// otherwise visible to gorilla/mux route introspection.
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
