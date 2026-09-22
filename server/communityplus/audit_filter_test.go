package communityplus

import (
	"net/url"
	"testing"
	"time"
)

func TestParseAuditFilter(t *testing.T) {
	values := url.Values{
		"fleet_id":    {"7"},
		"limit":       {"25"},
		"actor_id":    {"user-42"},
		"action":      {"automation_rule.upsert"},
		"resource":    {string(ResourceAutomations)},
		"resource_id": {"rule-1"},
		"from":        {"2026-09-20T10:00:00Z"},
		"until":       {"2026-09-21T10:00:00Z"},
		"before":      {"2026-09-21T09:00:00.123456Z"},
		"before_id":   {"cp-audit-123-4"},
	}
	filter, scope, err := ParseAuditFilter(values)
	if err != nil {
		t.Fatalf("parse audit filter: %v", err)
	}
	if scope != FleetScope(7) || filter.FleetID == nil || *filter.FleetID != 7 || filter.Limit != 25 {
		t.Fatalf("unexpected scope/filter: scope=%#v filter=%#v", scope, filter)
	}
	if filter.ActorID != "user-42" || filter.Action != "automation_rule.upsert" || filter.Resource != ResourceAutomations || filter.ResourceID != "rule-1" {
		t.Fatalf("unexpected text filters: %#v", filter)
	}
	if filter.From == nil || filter.Until == nil || filter.Before == nil || filter.Before.BeforeID != "cp-audit-123-4" {
		t.Fatalf("expected time filters and cursor: %#v", filter)
	}
}

func TestParseAuditFilterRejectsUnsafeValues(t *testing.T) {
	for name, values := range map[string]url.Values{
		"bad fleet":       {"fleet_id": {"0"}},
		"bad limit":       {"limit": {"1001"}},
		"bad resource":    {"resource": {"not-a-resource"}},
		"bad from":        {"from": {"yesterday"}},
		"half cursor":     {"before": {"2026-09-21T09:00:00Z"}},
		"reverse window":  {"from": {"2026-09-22T10:00:00Z"}, "until": {"2026-09-21T10:00:00Z"}},
		"oversized actor": {"actor_id": {string(make([]byte, 256))}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseAuditFilter(values); err == nil {
				t.Fatal("expected invalid audit filter")
			}
		})
	}
}

func TestAuditFilterMatchesCursorAndFields(t *testing.T) {
	at := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	from := at.Add(-time.Hour)
	until := at.Add(time.Hour)
	filter := AuditFilter{
		ActorID: "user-1", Action: "software.install", Resource: ResourceSoftware,
		ResourceID: "pkg-1", From: &from, Until: &until,
		Before: &AuditCursor{Before: at, BeforeID: "event-z"},
	}
	matching := AuditEvent{ID: "event-a", OccurredAt: at, ActorID: "user-1", Action: "software.install", Resource: ResourceSoftware, ResourceID: "pkg-1", Scope: GlobalScope()}
	if !filter.Matches(matching) {
		t.Fatal("expected event to match")
	}
	matching.ID = "event-z"
	if filter.Matches(matching) {
		t.Fatal("cursor must exclude its boundary event")
	}
}

func TestNextAuditCursor(t *testing.T) {
	at := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	events := []AuditEvent{{ID: "a", OccurredAt: at}, {ID: "b", OccurredAt: at.Add(-time.Second)}}
	cursor := NextAuditCursor(events, 2)
	if cursor == nil || cursor.BeforeID != "b" || !cursor.Before.Equal(events[1].OccurredAt) {
		t.Fatalf("unexpected cursor: %#v", cursor)
	}
	if NextAuditCursor(events, 3) != nil {
		t.Fatal("short page must not return a cursor")
	}
}
