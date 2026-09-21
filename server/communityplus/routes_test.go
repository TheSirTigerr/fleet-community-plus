package communityplus

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestViewerAccessRequiresAuthenticatedUser(t *testing.T) {
	_, err := (ViewerAccess{}).Authorize(context.Background(), Request{Scope: GlobalScope()})
	if err != ErrUnauthenticated {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestViewerAccessAllowsGlobalAdmin(t *testing.T) {
	role := fleet.RoleAdmin
	ctx := viewer.NewContext(context.Background(), viewer.Viewer{User: &fleet.User{ID: 42, GlobalRole: &role}})

	actor, err := (ViewerAccess{}).Authorize(ctx, Request{Resource: ResourceSoftware, Action: ActionAdmin, Scope: GlobalScope()})
	if err != nil {
		t.Fatalf("expected global admin to be allowed: %v", err)
	}
	if actor != "42" {
		t.Fatalf("expected actor 42, got %q", actor)
	}
}

func TestViewerAccessScopesTeamAdmin(t *testing.T) {
	ctx := viewer.NewContext(context.Background(), viewer.Viewer{User: &fleet.User{
		ID: 7,
		Teams: []fleet.UserTeam{{
			Team: fleet.Team{ID: 9},
			Role: fleet.RoleAdmin,
		}},
	}})

	actor, err := (ViewerAccess{}).Authorize(ctx, Request{Resource: ResourceSoftware, Action: ActionWrite, Scope: FleetScope(9)})
	if err != nil {
		t.Fatalf("expected team admin to be allowed for its fleet: %v", err)
	}
	if actor != "7" {
		t.Fatalf("expected actor 7, got %q", actor)
	}

	for _, req := range []Request{
		{Resource: ResourceSoftware, Action: ActionWrite, Scope: FleetScope(10)},
		{Resource: ResourceSoftware, Action: ActionWrite, Scope: GlobalScope()},
	} {
		if _, err := (ViewerAccess{}).Authorize(ctx, req); err != ErrForbidden {
			t.Fatalf("expected ErrForbidden for scope %+v, got %v", req.Scope, err)
		}
	}
}

func TestViewerAccessRejectsNonAdminTeamRole(t *testing.T) {
	ctx := viewer.NewContext(context.Background(), viewer.Viewer{User: &fleet.User{
		ID: 8,
		Teams: []fleet.UserTeam{{
			Team: fleet.Team{ID: 9},
			Role: fleet.RoleObserver,
		}},
	}})

	_, err := (ViewerAccess{}).Authorize(ctx, Request{Resource: ResourceSoftware, Action: ActionRead, Scope: FleetScope(9)})
	if err != ErrForbidden {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}
