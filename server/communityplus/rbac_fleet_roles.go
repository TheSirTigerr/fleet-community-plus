package communityplus

// The Fleet-facing roles below intentionally use Community+'s separate
// write/execute actions to preserve Fleet's distinction between changing
// configuration and performing an operation on a host.

var operationalReadResources = []Resource{
	ResourceHosts, ResourceFleets, ResourcePolicies, ResourceSoftware,
	ResourceScripts, ResourceMDM, ResourceVulnerabilities, ResourceReports,
	ResourceAudit, ResourceAutomations,
}

func GlobalMaintainerRole() Role {
	role := Role{Name: "global_maintainer"}
	role.Permissions = appendReadPermissions(role.Permissions, GlobalScope(), append(append([]Resource(nil), operationalReadResources...), ResourceUsers, ResourceSettings))
	role.Permissions = appendActionPermissions(role.Permissions, GlobalScope(), ActionWrite,
		ResourceHosts, ResourcePolicies, ResourceSoftware, ResourceScripts, ResourceAutomations)
	role.Permissions = appendActionPermissions(role.Permissions, GlobalScope(), ActionExecute, ResourceSoftware, ResourceScripts)
	return role
}

func MaintainerRole(fleetID uint) (Role, error) {
	scope := FleetScope(fleetID)
	if err := scope.Validate(); err != nil {
		return Role{}, err
	}
	role := Role{Name: "maintainer"}
	role.Permissions = appendReadPermissions(role.Permissions, scope, operationalReadResources)
	role.Permissions = append(role.Permissions, Permission{Resource: ResourceSettings, Action: ActionRead, Scope: GlobalScope()})
	role.Permissions = appendActionPermissions(role.Permissions, scope, ActionWrite,
		ResourceHosts, ResourcePolicies, ResourceSoftware, ResourceScripts, ResourceAutomations)
	role.Permissions = appendActionPermissions(role.Permissions, scope, ActionExecute, ResourceSoftware, ResourceScripts)
	return role, nil
}

func GlobalTechnicianRole() Role {
	role := Role{Name: "global_technician"}
	role.Permissions = appendReadPermissions(role.Permissions, GlobalScope(), append(append([]Resource(nil), operationalReadResources...), ResourceUsers, ResourceSettings))
	role.Permissions = appendActionPermissions(role.Permissions, GlobalScope(), ActionExecute, ResourceSoftware, ResourceScripts)
	return role
}

func TechnicianRole(fleetID uint) (Role, error) {
	scope := FleetScope(fleetID)
	if err := scope.Validate(); err != nil {
		return Role{}, err
	}
	role := Role{Name: "technician"}
	role.Permissions = appendReadPermissions(role.Permissions, scope, operationalReadResources)
	role.Permissions = append(role.Permissions, Permission{Resource: ResourceSettings, Action: ActionRead, Scope: GlobalScope()})
	role.Permissions = appendActionPermissions(role.Permissions, scope, ActionExecute, ResourceSoftware, ResourceScripts)
	return role, nil
}

func GlobalGitOpsRole() Role {
	role := Role{Name: "global_gitops"}
	resources := []Resource{ResourceFleets, ResourcePolicies, ResourceSoftware, ResourceScripts, ResourceAutomations, ResourceSettings}
	role.Permissions = appendReadPermissions(role.Permissions, GlobalScope(), resources)
	role.Permissions = appendActionPermissions(role.Permissions, GlobalScope(), ActionWrite, resources...)
	return role
}

func GitOpsRole(fleetID uint) (Role, error) {
	scope := FleetScope(fleetID)
	if err := scope.Validate(); err != nil {
		return Role{}, err
	}
	role := Role{Name: "gitops"}
	resources := []Resource{ResourceFleets, ResourcePolicies, ResourceSoftware, ResourceScripts, ResourceAutomations}
	role.Permissions = appendReadPermissions(role.Permissions, scope, resources)
	role.Permissions = appendActionPermissions(role.Permissions, scope, ActionWrite, resources...)
	role.Permissions = append(role.Permissions, Permission{Resource: ResourceSettings, Action: ActionRead, Scope: GlobalScope()})
	return role, nil
}

func appendReadPermissions(dst []Permission, scope Scope, resources []Resource) []Permission {
	return appendActionPermissions(dst, scope, ActionRead, resources...)
}

func appendActionPermissions(dst []Permission, scope Scope, action Action, resources ...Resource) []Permission {
	for _, resource := range resources {
		dst = append(dst, Permission{Resource: resource, Action: action, Scope: scope})
	}
	return dst
}
