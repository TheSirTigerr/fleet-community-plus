// Package rbac provides Community+ custom role bindings layered on top of
// Fleet's existing OPA authorization engine. It deliberately reuses Fleet's
// public action names so an adapter can feed decisions into the existing
// Authorizer without inventing a second vocabulary.
package rbac

import (
	"errors"
	"fmt"
	"sort"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type Permission string

const (
	PermissionRead          Permission = fleet.ActionRead
	PermissionList          Permission = fleet.ActionList
	PermissionWrite         Permission = fleet.ActionWrite
	PermissionCreate        Permission = fleet.ActionCreate
	PermissionRunQuery      Permission = fleet.ActionRun
	PermissionRunNewQuery   Permission = fleet.ActionRunNew
	PermissionTransferHost  Permission = fleet.ActionTransferHost
	PermissionReadSecrets   Permission = fleet.ActionReadSecrets
	PermissionManageMembers Permission = fleet.ActionWriteMembers
	PermissionResend        Permission = fleet.ActionResend
	PermissionClearPasscode Permission = fleet.ActionClearPasscode
)

var (
	ErrInvalidRole       = errors.New("invalid Community+ role")
	ErrInvalidScope      = errors.New("invalid Community+ fleet scope")
	ErrUnknownPermission = errors.New("unknown Community+ permission")
)

var knownPermissions = map[Permission]struct{}{
	PermissionRead:          {},
	PermissionList:          {},
	PermissionWrite:         {},
	PermissionCreate:        {},
	PermissionRunQuery:      {},
	PermissionRunNewQuery:   {},
	PermissionTransferHost:  {},
	PermissionReadSecrets:   {},
	PermissionManageMembers: {},
	PermissionResend:        {},
	PermissionClearPasscode: {},
}

// Role is a named set of permissions. It is intentionally separate from
// Fleet's built-in role strings so installations can define their own roles.
type Role struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}

func (r Role) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidRole)
	}
	seen := make(map[Permission]struct{}, len(r.Permissions))
	for _, permission := range r.Permissions {
		if _, ok := knownPermissions[permission]; !ok {
			return fmt.Errorf("%w: %s", ErrUnknownPermission, permission)
		}
		if _, ok := seen[permission]; ok {
			return fmt.Errorf("%w: duplicate permission %s", ErrInvalidRole, permission)
		}
		seen[permission] = struct{}{}
	}
	return nil
}

func (r Role) Allows(permission Permission) bool {
	for _, current := range r.Permissions {
		if current == permission {
			return true
		}
	}
	return false
}

// FleetScope limits a role binding to selected fleets. All=true means every
// fleet and is also required for organization-wide (FleetID=nil) operations.
type FleetScope struct {
	All      bool   `json:"all"`
	FleetIDs []uint `json:"fleet_ids,omitempty"`
}

func (s FleetScope) Validate() error {
	if s.All && len(s.FleetIDs) != 0 {
		return fmt.Errorf("%w: all and fleet_ids are mutually exclusive", ErrInvalidScope)
	}
	if !s.All && len(s.FleetIDs) == 0 {
		return fmt.Errorf("%w: at least one fleet_id is required", ErrInvalidScope)
	}
	seen := make(map[uint]struct{}, len(s.FleetIDs))
	for _, id := range s.FleetIDs {
		if id == 0 {
			return fmt.Errorf("%w: fleet_id must be greater than zero", ErrInvalidScope)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: duplicate fleet_id %d", ErrInvalidScope, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (s FleetScope) Contains(fleetID *uint) bool {
	if fleetID == nil {
		return s.All
	}
	if s.All {
		return true
	}
	for _, id := range s.FleetIDs {
		if id == *fleetID {
			return true
		}
	}
	return false
}

// Binding assigns a custom role to a fleet scope.
type Binding struct {
	Role  Role       `json:"role"`
	Scope FleetScope `json:"scope"`
}

func (b Binding) Validate() error {
	if err := b.Role.Validate(); err != nil {
		return err
	}
	return b.Scope.Validate()
}

// DecisionRequest is the minimal authorization input needed by this layer.
type DecisionRequest struct {
	Permission Permission `json:"permission"`
	FleetID    *uint      `json:"fleet_id,omitempty"`
}

// Allowed evaluates a collection of custom-role bindings. The existing Fleet
// OPA authorizer remains authoritative for built-in roles; this function is
// designed for an adapter that grants additional Community+ custom-role access.
func Allowed(bindings []Binding, request DecisionRequest) (bool, error) {
	if _, ok := knownPermissions[request.Permission]; !ok {
		return false, fmt.Errorf("%w: %s", ErrUnknownPermission, request.Permission)
	}
	for _, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return false, err
		}
		if binding.Scope.Contains(request.FleetID) && binding.Role.Allows(request.Permission) {
			return true, nil
		}
	}
	return false, nil
}

func KnownPermissions() []Permission {
	out := make([]Permission, 0, len(knownPermissions))
	for permission := range knownPermissions {
		out = append(out, permission)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
