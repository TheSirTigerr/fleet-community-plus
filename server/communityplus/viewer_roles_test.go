package communityplus

import (
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestFleetUserRoleUnionPreservesFleetBoundaries(t *testing.T) {
	user := &fleet.User{
		Teams: []fleet.UserTeam{
			{Team: fleet.Team{ID: 12}, Role: fleet.RoleObserver},
			{Team: fleet.Team{ID: 13}, Role: fleet.RoleAdmin},
		},
	}

	checks := []struct {
		name    string
		request Request
		allowed bool
	}{
		{name: "observer reads own fleet", request: Request{Resource: ResourceSoftware, Action: ActionRead, Scope: FleetScope(12)}, allowed: true},
		{name: "observer cannot write own fleet", request: Request{Resource: ResourceSoftware, Action: ActionWrite, Scope: FleetScope(12)}, allowed: false},
		{name: "admin writes own fleet", request: Request{Resource: ResourceSoftware, Action: ActionWrite, Scope: FleetScope(13)}, allowed: true},
		{name: "admin role does not elevate observer fleet", request: Request{Resource: ResourceSoftware, Action: ActionWrite, Scope: FleetScope(12)}, allowed: false},
		{name: "team roles cannot read global users", request: Request{Resource: ResourceUsers, Action: ActionRead, Scope: GlobalScope()}, allowed: false},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if got := fleetUserAllowed(user, check.request); got != check.allowed {
				t.Fatalf("allowed=%v, want %v for %#v", got, check.allowed, check.request)
			}
		})
	}
}
