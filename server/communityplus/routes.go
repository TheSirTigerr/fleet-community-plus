package communityplus

import (
	"context"
	"net/http"
	"strconv"

	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/platform/endpointer"
	"github.com/fleetdm/fleet/v4/server/service/middleware/auth"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

// ViewerAccess adapts Fleet's authenticated user context to the independent
// Community+ permission model. Fleet role assignments are translated into
// Community+ scoped roles and evaluated by the same Authorizer used elsewhere.
type ViewerAccess struct{}

func (ViewerAccess) Authorize(ctx context.Context, request Request) (string, error) {
	v, ok := viewer.FromContext(ctx)
	if !ok || v.User == nil {
		return "", ErrUnauthenticated
	}
	actor := strconv.FormatUint(uint64(v.User.ID), 10)
	if fleetUserAllowed(v.User, request) {
		return actor, nil
	}
	return "", ErrForbidden
}

// GetRoutes exposes Community+ APIs through Fleet's normal user authentication
// middleware. The implementation is deliberately separate from Fleet's premium
// service methods and has no license dependency.
func GetRoutes(fleetSvc fleet.Service, store *SQLStore) endpointer.HandlerRoutesFunc {
	return func(r *mux.Router, _ []kithttp.ServerOption) {
		engine, err := NewAutomationEngine(&noopAutomationExecutor{})
		if err != nil {
			panic(err)
		}
		if err := RestoreAutomationRules(context.Background(), store, engine); err != nil {
			panic(err)
		}
		registry := newRuntimeRegistry()
		catalogStore := newPatchingCatalogStore(store)
		api, err := NewHTTPAPI(registry, engine, store, store, ViewerAccess{}, catalogStore)
		if err != nil {
			panic(err)
		}
		oidcSettingsAPI, err := NewOIDCSettingsAPI(store, ViewerAccess{}, store)
		if err != nil {
			panic(err)
		}

		authError := func(w http.ResponseWriter, detail string, status int) {
			writeJSON(w, status, map[string]string{"error": detail})
		}
		oidcSettingsHandler := auth.AuthenticatedUserMiddleware(fleetSvc, authError, oidcSettingsAPI.Handler())
		for _, version := range []string{"v1", "2022-04", "latest"} {
			r.Handle("/api/"+version+"/fleet/communityplus/sso/oidc", oidcSettingsHandler).
				Methods(http.MethodGet, http.MethodPut)
		}

		communityPlusHandler := api.WithHomebrew(api.Handler())
		handler := auth.AuthenticatedUserMiddleware(fleetSvc, authError, communityPlusHandler)
		r.PathPrefix("/api/").Handler(handler).Methods(http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete)
	}
}

type noopAutomationExecutor struct{}

func (noopAutomationExecutor) ExecuteAutomation(context.Context, AutomationRule, AutomationEvent) error {
	return nil
}
