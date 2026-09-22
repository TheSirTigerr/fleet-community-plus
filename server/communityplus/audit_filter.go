package communityplus

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AuditCursor is a stable cursor for descending (occurred_at, id) pagination.
type AuditCursor struct {
	Before   time.Time `json:"before"`
	BeforeID string    `json:"before_id"`
}

// AuditFilter bounds and filters audit-log reads. Empty string fields mean no
// filter. FleetID nil means all scopes and is only authorized for global users.
type AuditFilter struct {
	FleetID    *uint
	ActorID    string
	Action     string
	Resource   Resource
	ResourceID string
	From       *time.Time
	Until      *time.Time
	Before     *AuditCursor
	Limit      int
}

func (f AuditFilter) Validate() error {
	if f.FleetID != nil && *f.FleetID == 0 {
		return fmt.Errorf("communityplus: audit fleet_id must be greater than zero")
	}
	if f.Limit < 0 || f.Limit > 1000 {
		return fmt.Errorf("communityplus: audit limit must be between 1 and 1000")
	}
	if len(f.ActorID) > 255 || len(f.Action) > 255 || len(f.ResourceID) > 255 {
		return fmt.Errorf("communityplus: audit filter value is too long")
	}
	if f.Resource != "" && !validAuditResource(f.Resource) {
		return fmt.Errorf("communityplus: invalid audit resource %q", f.Resource)
	}
	if f.From != nil && f.From.IsZero() {
		return fmt.Errorf("communityplus: audit from timestamp is invalid")
	}
	if f.Until != nil && f.Until.IsZero() {
		return fmt.Errorf("communityplus: audit until timestamp is invalid")
	}
	if f.From != nil && f.Until != nil && f.From.After(*f.Until) {
		return fmt.Errorf("communityplus: audit from must not be after until")
	}
	if f.Before != nil {
		if f.Before.Before.IsZero() || strings.TrimSpace(f.Before.BeforeID) == "" {
			return fmt.Errorf("communityplus: audit cursor requires before and before_id")
		}
		if len(f.Before.BeforeID) > 128 {
			return fmt.Errorf("communityplus: audit before_id is too long")
		}
	}
	return nil
}

func (f AuditFilter) normalizedLimit() int {
	if f.Limit <= 0 {
		return 100
	}
	return f.Limit
}

// Matches applies the same filtering and cursor semantics used by SQLStore.
// It is primarily useful to keep test/local stores behavior-compatible.
func (f AuditFilter) Matches(event AuditEvent) bool {
	if f.FleetID != nil && (event.Scope.Kind != ScopeFleet || event.Scope.FleetID != *f.FleetID) {
		return false
	}
	if f.ActorID != "" && event.ActorID != f.ActorID {
		return false
	}
	if f.Action != "" && event.Action != f.Action {
		return false
	}
	if f.Resource != "" && event.Resource != f.Resource {
		return false
	}
	if f.ResourceID != "" && event.ResourceID != f.ResourceID {
		return false
	}
	if f.From != nil && event.OccurredAt.Before(*f.From) {
		return false
	}
	if f.Until != nil && event.OccurredAt.After(*f.Until) {
		return false
	}
	if f.Before != nil {
		if event.OccurredAt.After(f.Before.Before) {
			return false
		}
		if event.OccurredAt.Equal(f.Before.Before) && event.ID >= f.Before.BeforeID {
			return false
		}
	}
	return true
}

// ParseAuditFilter parses the public audit endpoint query while also returning
// the scope that must be authorized before the query is executed.
func ParseAuditFilter(values url.Values) (AuditFilter, Scope, error) {
	filter := AuditFilter{Limit: 100}
	scope := GlobalScope()

	if value := strings.TrimSpace(values.Get("fleet_id")); value != "" {
		fleetID, err := strconv.ParseUint(value, 10, 64)
		if err != nil || fleetID == 0 || uint64(uint(fleetID)) != fleetID {
			return AuditFilter{}, Scope{}, fmt.Errorf("communityplus: invalid fleet_id")
		}
		id := uint(fleetID)
		filter.FleetID = &id
		scope = FleetScope(id)
	}
	if value := strings.TrimSpace(values.Get("limit")); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit <= 0 || limit > 1000 {
			return AuditFilter{}, Scope{}, fmt.Errorf("communityplus: limit must be between 1 and 1000")
		}
		filter.Limit = limit
	}

	filter.ActorID = strings.TrimSpace(values.Get("actor_id"))
	filter.Action = strings.TrimSpace(values.Get("action"))
	filter.ResourceID = strings.TrimSpace(values.Get("resource_id"))
	if value := strings.TrimSpace(values.Get("resource")); value != "" {
		filter.Resource = Resource(value)
	}

	from, err := parseAuditTime(values.Get("from"), "from")
	if err != nil {
		return AuditFilter{}, Scope{}, err
	}
	until, err := parseAuditTime(values.Get("until"), "until")
	if err != nil {
		return AuditFilter{}, Scope{}, err
	}
	filter.From, filter.Until = from, until

	beforeRaw := strings.TrimSpace(values.Get("before"))
	beforeID := strings.TrimSpace(values.Get("before_id"))
	if (beforeRaw == "") != (beforeID == "") {
		return AuditFilter{}, Scope{}, fmt.Errorf("communityplus: before and before_id must be provided together")
	}
	if beforeRaw != "" {
		before, err := time.Parse(time.RFC3339Nano, beforeRaw)
		if err != nil {
			return AuditFilter{}, Scope{}, fmt.Errorf("communityplus: invalid before timestamp")
		}
		filter.Before = &AuditCursor{Before: before.UTC(), BeforeID: beforeID}
	}

	if err := filter.Validate(); err != nil {
		return AuditFilter{}, Scope{}, err
	}
	return filter, scope, nil
}

func NextAuditCursor(events []AuditEvent, limit int) *AuditCursor {
	limit = AuditFilter{Limit: limit}.normalizedLimit()
	if len(events) == 0 || len(events) < limit {
		return nil
	}
	last := events[len(events)-1]
	return &AuditCursor{Before: last.OccurredAt.UTC(), BeforeID: last.ID}
}

func parseAuditTime(raw, field string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil, fmt.Errorf("communityplus: invalid %s timestamp", field)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func validAuditResource(resource Resource) bool {
	switch resource {
	case ResourceHosts, ResourceFleets, ResourcePolicies, ResourceSoftware,
		ResourceScripts, ResourceMDM, ResourceVulnerabilities, ResourceUsers,
		ResourceReports, ResourceAudit, ResourceAutomations, ResourceSettings:
		return true
	default:
		return false
	}
}
