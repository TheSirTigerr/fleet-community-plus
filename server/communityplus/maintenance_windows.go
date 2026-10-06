package communityplus

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// MaintenanceWindow limits automatic Community+ endpoint changes to reviewed
// weekly windows. Weekdays use Go's time.Weekday numbering (Sunday=0).
type MaintenanceWindow struct {
	ID              string    `json:"id"`
	Scope           Scope     `json:"scope"`
	Timezone        string    `json:"timezone"`
	Weekdays        []int     `json:"weekdays"`
	StartMinute     int       `json:"start_minute"`
	DurationMinutes int       `json:"duration_minutes"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	CreatedBy       string    `json:"created_by"`
}

func (w MaintenanceWindow) Validate() error {
	if w.ID == "" {
		return fmt.Errorf("communityplus: maintenance window id is required")
	}
	if w.Scope.Kind != ScopeFleet {
		return fmt.Errorf("communityplus: maintenance windows must target a Fleet")
	}
	if err := w.Scope.Validate(); err != nil {
		return err
	}
	if w.Timezone == "" {
		return fmt.Errorf("communityplus: maintenance window timezone is required")
	}
	if _, err := time.LoadLocation(w.Timezone); err != nil {
		return fmt.Errorf("communityplus: invalid maintenance window timezone %q", w.Timezone)
	}
	if len(w.Weekdays) == 0 {
		return fmt.Errorf("communityplus: maintenance window requires at least one weekday")
	}
	seen := make(map[int]struct{}, len(w.Weekdays))
	for _, weekday := range w.Weekdays {
		if weekday < 0 || weekday > 6 {
			return fmt.Errorf("communityplus: maintenance window weekday %d is invalid", weekday)
		}
		if _, ok := seen[weekday]; ok {
			return fmt.Errorf("communityplus: maintenance window contains duplicate weekday %d", weekday)
		}
		seen[weekday] = struct{}{}
	}
	if w.StartMinute < 0 || w.StartMinute >= 24*60 {
		return fmt.Errorf("communityplus: maintenance window start_minute must be between 0 and 1439")
	}
	if w.DurationMinutes <= 0 || w.DurationMinutes > 24*60 {
		return fmt.Errorf("communityplus: maintenance window duration_minutes must be between 1 and 1440")
	}
	if w.CreatedAt.IsZero() || w.CreatedBy == "" {
		return fmt.Errorf("communityplus: maintenance window created_at and created_by are required")
	}
	return nil
}

func (w MaintenanceWindow) openAt(at time.Time) (bool, error) {
	if err := w.Validate(); err != nil {
		return false, err
	}
	if !w.Enabled {
		return false, nil
	}
	location, _ := time.LoadLocation(w.Timezone)
	local := at.In(location)
	weekdayEnabled := func(day time.Weekday) bool {
		for _, weekday := range w.Weekdays {
			if int(day) == weekday {
				return true
			}
		}
		return false
	}
	for offset := 0; offset <= 1; offset++ {
		base := local.AddDate(0, 0, -offset)
		if !weekdayEnabled(base.Weekday()) {
			continue
		}
		start := time.Date(base.Year(), base.Month(), base.Day(), 0, 0, 0, 0, location).
			Add(time.Duration(w.StartMinute) * time.Minute)
		end := start.Add(time.Duration(w.DurationMinutes) * time.Minute)
		if !local.Before(start) && local.Before(end) {
			return true, nil
		}
	}
	return false, nil
}

type MaintenanceWindowStore interface {
	UpsertMaintenanceWindow(context.Context, MaintenanceWindow) error
	DeleteMaintenanceWindow(context.Context, string) error
	GetMaintenanceWindow(context.Context, string) (MaintenanceWindow, error)
	ListMaintenanceWindows(context.Context, uint) ([]MaintenanceWindow, error)
}

func automaticChangesAllowedAt(windows []MaintenanceWindow, at time.Time) (bool, error) {
	enabled := false
	for _, window := range windows {
		if !window.Enabled {
			continue
		}
		enabled = true
		open, err := window.openAt(at)
		if err != nil {
			return false, err
		}
		if open {
			return true, nil
		}
	}
	return !enabled, nil
}

func sortMaintenanceWindows(windows []MaintenanceWindow) {
	sort.Slice(windows, func(i, j int) bool {
		if windows[i].StartMinute == windows[j].StartMinute {
			return windows[i].ID < windows[j].ID
		}
		return windows[i].StartMinute < windows[j].StartMinute
	})
}
