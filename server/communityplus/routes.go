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
// Community+ permission model. A global Fleet admin administers the catalog;
// a team admin can read and deploy packages only for that team.
type ViewerAccess struct{}

func (ViewerAccess) Authorize(ctx context.Context, request Request) (string, error) {
	v, ok := viewer.FromContext(ctx)
	if !ok || v.User == nil {
		return "", ErrUnauthenticated
	}
	actor := strconv.FormatUint(uint64(v.User.ID), 10)
	if v.User.GlobalRole != nil && *v.User.GlobalRole == fleet.RoleAdmin {
		return actor, nil
	}
	if request.Scope.Kind != ScopeFleet {
		return "", ErrForbidden
	}
	for _, team := range v.User.Teams {
		if team.ID == request.Scope.FleetID && team.IsAdmin() {
			return actor, nil
		}
	}
	return "", ErrForbidden
}

// GetRoutes exposes Community+ catalog APIs through Fleet's normal user
// authentication middleware. The implementation is deliberately separate
// from Fleet's premium service methods and has no license dependency.
func GetRoutes(fleetSvc fleet.Service, store *SQLStore) endpointer.HandlerRoutesFunc {
	return func(r *mux.Router, _ []kithttp.ServerOption) {
		engine, err := NewAutomationEngine(&noopAutomationExecutor{})
		if err != nil {
			panic(err)
		}
		registry := NewRegistry()
		_ = registry.SetStatus(FeatureSoftwareAutomation, StatusExperimental)
		_ = registry.SetStatus(FeaturePatchPolicies, StatusExperimental)
		catalogStore := newPatchingCatalogStore(store)
		api, err := NewHTTPAPI(registry, engine, store, store, ViewerAccess{}, catalogStore)
		if err != nil {
			panic(err)
		}
		handler := auth.AuthenticatedUserMiddleware(fleetSvc, func(w http.ResponseWriter, detail string, status int) {
			writeJSON(w, status, map[string]string{"error": detail})
		}, api.Handler())
		r.PathPrefix("/api/").Handler(handler).Methods(http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete)
	}
}

type noopAutomationExecutor struct{}

func (noopAutomationExecutor) ExecuteAutomation(context.Context, AutomationRule, AutomationEvent) error {
	return nil
}
