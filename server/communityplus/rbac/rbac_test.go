package rbac

import (
	"errors"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func TestAllowedHonorsFleetScope(t *testing.T) {
	bindings := []Binding{{
		Role:  Role{Name: "helpdesk", Permissions: []Permission{PermissionRead, PermissionRunQuery}},
		Scope: FleetScope{FleetIDs: []uint{7, 9}},
	}}

	allowed, err := Allowed(bindings, DecisionRequest{Permission: PermissionRunQuery, FleetID: ptr(uint(7))})
	if err != nil || !allowed {
		t.Fatalf("expected fleet 7 to be allowed, allowed=%v err=%v", allowed, err)
	}
	allowed, err = Allowed(bindings, DecisionRequest{Permission: PermissionRunQuery, FleetID: ptr(uint(8))})
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("expected fleet 8 to be denied")
	}
}

func TestOrganizationWideRequestRequiresAllScope(t *testing.T) {
	bindings := []Binding{{
		Role:  Role{Name: "writer", Permissions: []Permission{PermissionWrite}},
		Scope: FleetScope{FleetIDs: []uint{1}},
	}}
	allowed, err := Allowed(bindings, DecisionRequest{Permission: PermissionWrite})
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("fleet-scoped binding must not authorize organization-wide request")
	}

	bindings[0].Scope = FleetScope{All: true}
	allowed, err = Allowed(bindings, DecisionRequest{Permission: PermissionWrite})
	if err != nil || !allowed {
		t.Fatalf("all-fleets scope should authorize organization-wide request, allowed=%v err=%v", allowed, err)
	}
}

func TestRejectsUnknownPermission(t *testing.T) {
	_, err := Allowed(nil, DecisionRequest{Permission: Permission("root_everything")})
	if !errors.Is(err, ErrUnknownPermission) {
		t.Fatalf("expected ErrUnknownPermission, got %v", err)
	}
}

func TestRejectsAmbiguousScope(t *testing.T) {
	err := (FleetScope{All: true, FleetIDs: []uint{1}}).Validate()
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope, got %v", err)
	}
}
