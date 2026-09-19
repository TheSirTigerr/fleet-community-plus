package communityplus

import "fmt"

// ScopeKind determines whether a permission is global or restricted to one Fleet.
type ScopeKind string

const (
	ScopeGlobal ScopeKind = "global"
	ScopeFleet  ScopeKind = "fleet"
)

// Scope is the security boundary used by Community+ authorization.
type Scope struct {
	Kind    ScopeKind `json:"kind"`
	FleetID uint      `json:"fleet_id,omitempty"`
}

func GlobalScope() Scope { return Scope{Kind: ScopeGlobal} }

func FleetScope(fleetID uint) Scope { return Scope{Kind: ScopeFleet, FleetID: fleetID} }

// Validate rejects ambiguous or unsafe scopes.
func (s Scope) Validate() error {
	switch s.Kind {
	case ScopeGlobal:
		if s.FleetID != 0 {
			return fmt.Errorf("communityplus: global scope must not contain fleet_id")
		}
	case ScopeFleet:
		if s.FleetID == 0 {
			return fmt.Errorf("communityplus: fleet scope requires a non-zero fleet_id")
		}
	default:
		return fmt.Errorf("communityplus: invalid scope kind %q", s.Kind)
	}
	return nil
}

// Contains reports whether a permission granted at s may operate on target.
func (s Scope) Contains(target Scope) bool {
	if s.Validate() != nil || target.Validate() != nil {
		return false
	}
	if s.Kind == ScopeGlobal {
		return true
	}
	return target.Kind == ScopeFleet && s.FleetID == target.FleetID
}

// Action is an operation that can be authorized.
type Action string

const (
	ActionRead    Action = "read"
	ActionWrite   Action = "write"
	ActionExecute Action = "execute"
	ActionAdmin   Action = "admin"
)

// Resource is a protected Community+ resource family.
type Resource string

const (
	ResourceHosts           Resource = "hosts"
	ResourceFleets          Resource = "fleets"
	ResourcePolicies        Resource = "policies"
	ResourceSoftware        Resource = "software"
	ResourceScripts         Resource = "scripts"
	ResourceMDM             Resource = "mdm"
	ResourceVulnerabilities Resource = "vulnerabilities"
	ResourceUsers           Resource = "users"
	ResourceReports         Resource = "reports"
	ResourceAudit           Resource = "audit"
	ResourceSettings        Resource = "settings"
)

// Permission grants an action on a resource within a scope.
type Permission struct {
	Resource Resource `json:"resource"`
	Action   Action   `json:"action"`
	Scope    Scope    `json:"scope"`
}

// Role is a reusable set of permissions.
type Role struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}

// Request describes an authorization check.
type Request struct {
	Resource Resource
	Action   Action
	Scope    Scope
}

// Authorizer evaluates roles without relying on edition or license checks.
type Authorizer struct{}

// Allowed returns true when one permission explicitly covers the request.
// Admin implies all actions for the same resource and scope.
func (Authorizer) Allowed(role Role, req Request) bool {
	if req.Scope.Validate() != nil {
		return false
	}
	for _, permission := range role.Permissions {
		if permission.Scope.Validate() != nil || !permission.Scope.Contains(req.Scope) {
			continue
		}
		if permission.Resource != req.Resource {
			continue
		}
		if permission.Action == ActionAdmin || permission.Action == req.Action {
			return true
		}
	}
	return false
}

// GlobalAdminRole grants administrative access to every protected resource.
func GlobalAdminRole() Role {
	resources := []Resource{
		ResourceHosts, ResourceFleets, ResourcePolicies, ResourceSoftware,
		ResourceScripts, ResourceMDM, ResourceVulnerabilities, ResourceUsers,
		ResourceReports, ResourceAudit, ResourceSettings,
	}
	permissions := make([]Permission, 0, len(resources))
	for _, resource := range resources {
		permissions = append(permissions, Permission{Resource: resource, Action: ActionAdmin, Scope: GlobalScope()})
	}
	return Role{Name: "global_admin", Permissions: permissions}
}

// FleetAdminRole grants full operational control inside exactly one Fleet but
// intentionally excludes global users and global settings administration.
func FleetAdminRole(fleetID uint) (Role, error) {
	scope := FleetScope(fleetID)
	if err := scope.Validate(); err != nil {
		return Role{}, err
	}
	resources := []Resource{
		ResourceHosts, ResourceFleets, ResourcePolicies, ResourceSoftware,
		ResourceScripts, ResourceMDM, ResourceVulnerabilities, ResourceReports,
		ResourceAudit,
	}
	permissions := make([]Permission, 0, len(resources))
	for _, resource := range resources {
		permissions = append(permissions, Permission{Resource: resource, Action: ActionAdmin, Scope: scope})
	}
	return Role{Name: "fleet_admin", Permissions: permissions}, nil
}

// ObserverRole creates a read-only role for one Fleet.
func ObserverRole(fleetID uint) (Role, error) {
	scope := FleetScope(fleetID)
	if err := scope.Validate(); err != nil {
		return Role{}, err
	}
	resources := []Resource{
		ResourceHosts, ResourceFleets, ResourcePolicies, ResourceSoftware,
		ResourceMDM, ResourceVulnerabilities, ResourceReports, ResourceAudit,
	}
	permissions := make([]Permission, 0, len(resources))
	for _, resource := range resources {
		permissions = append(permissions, Permission{Resource: resource, Action: ActionRead, Scope: scope})
	}
	return Role{Name: "observer", Permissions: permissions}, nil
}
