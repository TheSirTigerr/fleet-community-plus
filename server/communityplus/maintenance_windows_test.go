package communityplus

import (
	"testing"
	"time"
)

func TestMaintenanceWindowOpenAt(t *testing.T) {
	window := MaintenanceWindow{
		ID:              "sunday-night",
		Scope:           FleetScope(7),
		Timezone:        "Europe/Berlin",
		Weekdays:        []int{0},
		StartMinute:     23 * 60,
		DurationMinutes: 120,
		Enabled:         true,
		CreatedAt:       time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
		CreatedBy:       "admin",
	}

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"inside same day", time.Date(2026, time.October, 4, 21, 30, 0, 0, time.UTC), true},
		{"inside after midnight", time.Date(2026, time.October, 4, 22, 30, 0, 0, time.UTC), true},
		{"outside", time.Date(2026, time.October, 5, 2, 0, 0, 0, time.UTC), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := window.openAt(test.at)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("open=%v want=%v at=%s", got, test.want, test.at)
			}
		})
	}
}

func TestAutomaticChangesAllowedAt(t *testing.T) {
	now := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	disabled := MaintenanceWindow{
		ID: "disabled", Scope: FleetScope(7), Timezone: "UTC", Weekdays: []int{3},
		StartMinute: 0, DurationMinutes: 60, Enabled: false,
		CreatedAt: now, CreatedBy: "admin",
	}
	allowed, err := automaticChangesAllowedAt([]MaintenanceWindow{disabled}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("disabled windows must not restrict automatic changes")
	}

	closed := disabled
	closed.ID = "closed"
	closed.Enabled = true
	closed.StartMinute = 60
	allowed, err = automaticChangesAllowedAt([]MaintenanceWindow{closed}, now)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("enabled closed window must restrict automatic changes")
	}
}

func TestMaintenanceWindowValidation(t *testing.T) {
	now := time.Now().UTC()
	valid := MaintenanceWindow{
		ID: "mw", Scope: FleetScope(1), Timezone: "UTC", Weekdays: []int{1},
		StartMinute: 60, DurationMinutes: 30, Enabled: true, CreatedAt: now, CreatedBy: "admin",
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Timezone = "No/Such_Zone"
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected invalid timezone to fail")
	}
	invalid = valid
	invalid.Weekdays = []int{1, 1}
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected duplicate weekday to fail")
	}
}
