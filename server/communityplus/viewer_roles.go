package communityplus

import "github.com/fleetdm/fleet/v4/server/fleet"

// rolesForFleetUser translates Fleet's authenticated role assignments into
// Community+ roles. Unknown Fleet roles deliberately grant nothing.
func rolesForFleetUser(user *fleet.User) []Role {
	if user == nil {
		return nil
	}
	roles := make([]Role, 0, 1+len(user.Teams))
	if user.GlobalRole != nil {
		switch *user.GlobalRole {
		case fleet.RoleAdmin:
			roles = append(roles, GlobalAdminRole())
		case fleet.RoleObserver:
			roles = append(roles, GlobalObserverRole())
		case fleet.RoleObserverPlus:
			roles = append(roles, GlobalObserverPlusRole())
		}
	}
	for _, team := range user.Teams {
		var (
			role Role
			err  error
		)
		switch team.Role {
		case fleet.RoleAdmin:
			role, err = FleetAdminRole(team.ID)
		case fleet.RoleObserver:
			role, err = ObserverRole(team.ID)
		case fleet.RoleObserverPlus:
			role, err = ObserverPlusRole(team.ID)
		default:
			continue
		}
		if err == nil {
			roles = append(roles, role)
		}
	}
	return roles
}

func fleetUserAllowed(user *fleet.User, request Request) bool {
	authorizer := Authorizer{}
	for _, role := range rolesForFleetUser(user) {
		if authorizer.Allowed(role, request) {
			return true
		}
	}
	return false
}
