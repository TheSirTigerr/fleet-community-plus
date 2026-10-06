package communityplus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func (s *SQLStore) UpsertMaintenanceWindow(ctx context.Context, window MaintenanceWindow) error {
	if err := window.Validate(); err != nil {
		return err
	}
	weekdays, err := json.Marshal(window.Weekdays)
	if err != nil {
		return fmt.Errorf("communityplus: encode maintenance weekdays: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO communityplus_maintenance_windows
	(id, fleet_id, timezone, weekdays, start_minute, duration_minutes, enabled, created_at, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
	timezone = IF(fleet_id = VALUES(fleet_id), VALUES(timezone), timezone),
	weekdays = IF(fleet_id = VALUES(fleet_id), VALUES(weekdays), weekdays),
	start_minute = IF(fleet_id = VALUES(fleet_id), VALUES(start_minute), start_minute),
	duration_minutes = IF(fleet_id = VALUES(fleet_id), VALUES(duration_minutes), duration_minutes),
	enabled = IF(fleet_id = VALUES(fleet_id), VALUES(enabled), enabled),
	created_at = IF(fleet_id = VALUES(fleet_id), VALUES(created_at), created_at),
	created_by = IF(fleet_id = VALUES(fleet_id), VALUES(created_by), created_by)`,
		window.ID, window.Scope.FleetID, window.Timezone, weekdays, window.StartMinute,
		window.DurationMinutes, window.Enabled, window.CreatedAt, window.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("communityplus: upsert maintenance window: %w", err)
	}
	var fleetID uint
	if err := s.db.QueryRowContext(ctx,
		`SELECT fleet_id FROM communityplus_maintenance_windows WHERE id = ?`, window.ID,
	).Scan(&fleetID); err != nil {
		return fmt.Errorf("communityplus: verify maintenance window scope: %w", err)
	}
	if fleetID != window.Scope.FleetID {
		return fmt.Errorf("%w: maintenance window %q", ErrScopeConflict, window.ID)
	}
	return nil
}

func (s *SQLStore) DeleteMaintenanceWindow(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("communityplus: maintenance window id is required")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM communityplus_maintenance_windows WHERE id = ?`, id); err != nil {
		return fmt.Errorf("communityplus: delete maintenance window: %w", err)
	}
	return nil
}

func (s *SQLStore) GetMaintenanceWindow(ctx context.Context, id string) (MaintenanceWindow, error) {
	var window MaintenanceWindow
	var weekdays []byte
	var fleetID uint
	err := s.db.QueryRowContext(ctx, `
SELECT id, fleet_id, timezone, weekdays, start_minute, duration_minutes, enabled, created_at, created_by
FROM communityplus_maintenance_windows
WHERE id = ?`, id).Scan(
		&window.ID, &fleetID, &window.Timezone, &weekdays, &window.StartMinute,
		&window.DurationMinutes, &window.Enabled, &window.CreatedAt, &window.CreatedBy,
	)
	if err != nil {
		return MaintenanceWindow{}, fmt.Errorf("communityplus: get maintenance window: %w", err)
	}
	window.Scope = FleetScope(fleetID)
	if err := json.Unmarshal(weekdays, &window.Weekdays); err != nil {
		return MaintenanceWindow{}, fmt.Errorf("communityplus: decode maintenance weekdays: %w", err)
	}
	if err := window.Validate(); err != nil {
		return MaintenanceWindow{}, fmt.Errorf("communityplus: validate stored maintenance window: %w", err)
	}
	return window, nil
}

func (s *SQLStore) ListMaintenanceWindows(ctx context.Context, fleetID uint) ([]MaintenanceWindow, error) {
	if fleetID == 0 {
		return nil, fmt.Errorf("communityplus: maintenance window Fleet id is required")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, fleet_id, timezone, weekdays, start_minute, duration_minutes, enabled, created_at, created_by
FROM communityplus_maintenance_windows
WHERE fleet_id = ?
ORDER BY start_minute, id`, fleetID)
	if err != nil {
		return nil, fmt.Errorf("communityplus: list maintenance windows: %w", err)
	}
	defer rows.Close()

	var result []MaintenanceWindow
	for rows.Next() {
		var window MaintenanceWindow
		var weekdays []byte
		var storedFleetID uint
		if err := rows.Scan(
			&window.ID, &storedFleetID, &window.Timezone, &weekdays, &window.StartMinute,
			&window.DurationMinutes, &window.Enabled, &window.CreatedAt, &window.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("communityplus: scan maintenance window: %w", err)
		}
		window.Scope = FleetScope(storedFleetID)
		if err := json.Unmarshal(weekdays, &window.Weekdays); err != nil {
			return nil, fmt.Errorf("communityplus: decode maintenance weekdays: %w", err)
		}
		if err := window.Validate(); err != nil {
			return nil, fmt.Errorf("communityplus: validate stored maintenance window: %w", err)
		}
		result = append(result, window)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("communityplus: iterate maintenance windows: %w", err)
	}
	sortMaintenanceWindows(result)
	return result, nil
}

func (s *SQLStore) AutomaticDeploymentsAllowed(ctx context.Context, fleetID uint, at time.Time) (bool, error) {
	windows, err := s.ListMaintenanceWindows(ctx, fleetID)
	if err != nil {
		return false, err
	}
	return automaticChangesAllowedAt(windows, at)
}
