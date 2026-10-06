package communityplus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLStoreMaintenanceWindowRoundTrip(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.October, 7, 0, 0, 0, 0, time.UTC)
	window := MaintenanceWindow{
		ID:              "night",
		Scope:           FleetScope(7),
		Timezone:        "Europe/Berlin",
		Weekdays:        []int{1, 3, 5},
		StartMinute:     120,
		DurationMinutes: 90,
		Enabled:         true,
		CreatedAt:       createdAt,
		CreatedBy:       "admin",
	}

	mock.ExpectExec("INSERT INTO communityplus_maintenance_windows").
		WithArgs(
			window.ID, uint(7), window.Timezone, sqlmock.AnyArg(), window.StartMinute,
			window.DurationMinutes, true, createdAt, window.CreatedBy,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT fleet_id FROM communityplus_maintenance_windows").
		WithArgs(window.ID).
		WillReturnRows(sqlmock.NewRows([]string{"fleet_id"}).AddRow(7))

	if err := store.UpsertMaintenanceWindow(context.Background(), window); err != nil {
		t.Fatalf("upsert maintenance window: %v", err)
	}

	mock.ExpectQuery("SELECT id, fleet_id, timezone, weekdays").
		WithArgs(uint(7)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "fleet_id", "timezone", "weekdays", "start_minute", "duration_minutes", "enabled", "created_at", "created_by",
		}).AddRow(
			window.ID, 7, window.Timezone, []byte(`[1,3,5]`), window.StartMinute,
			window.DurationMinutes, true, createdAt, window.CreatedBy,
		))

	windows, err := store.ListMaintenanceWindows(context.Background(), 7)
	if err != nil {
		t.Fatalf("list maintenance windows: %v", err)
	}
	if len(windows) != 1 || windows[0].ID != window.ID || windows[0].Scope != FleetScope(7) {
		t.Fatalf("unexpected maintenance windows: %#v", windows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreMaintenanceWindowScopeConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	window := MaintenanceWindow{
		ID: "shared", Scope: FleetScope(7), Timezone: "UTC", Weekdays: []int{3},
		StartMinute: 60, DurationMinutes: 30, Enabled: true,
		CreatedAt: time.Date(2026, time.October, 7, 0, 0, 0, 0, time.UTC), CreatedBy: "admin",
	}

	mock.ExpectExec("INSERT INTO communityplus_maintenance_windows").
		WithArgs(
			window.ID, uint(7), window.Timezone, sqlmock.AnyArg(), window.StartMinute,
			window.DurationMinutes, true, window.CreatedAt, window.CreatedBy,
		).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT fleet_id FROM communityplus_maintenance_windows").
		WithArgs(window.ID).
		WillReturnRows(sqlmock.NewRows([]string{"fleet_id"}).AddRow(8))

	if err := store.UpsertMaintenanceWindow(context.Background(), window); !errors.Is(err, ErrScopeConflict) {
		t.Fatalf("expected ErrScopeConflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreAutomaticDeploymentsAllowed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.October, 7, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT id, fleet_id, timezone, weekdays").
		WithArgs(uint(7)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "fleet_id", "timezone", "weekdays", "start_minute", "duration_minutes", "enabled", "created_at", "created_by",
		}).AddRow(
			"night", 7, "UTC", []byte(`[3]`), 60, 30, true, createdAt, "admin",
		))

	allowed, err := store.AutomaticDeploymentsAllowed(
		context.Background(),
		7,
		time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("automatic deployments should be blocked outside the maintenance window")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
