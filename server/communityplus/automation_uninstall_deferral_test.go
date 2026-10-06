package communityplus

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLStoreDeferredSoftwareUninstallLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	req := DeferredSoftwareUninstallAutomation{
		RuleID: "remove-app", HostID: 42, FleetID: 7, InstallerID: 9,
		RequestedAt: time.Date(2026, time.October, 7, 1, 20, 0, 0, time.UTC),
	}
	mock.ExpectExec("INSERT INTO communityplus_automation_uninstall_requests").
		WithArgs(req.RuleID, req.HostID, req.FleetID, req.InstallerID, req.RequestedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.QueueDeferredSoftwareUninstallAutomation(context.Background(), req); err != nil {
		t.Fatalf("queue deferred uninstall: %v", err)
	}

	mock.ExpectQuery("SELECT rule_id, host_id, fleet_id, installer_id, requested_at").
		WithArgs(uint(42)).
		WillReturnRows(sqlmock.NewRows([]string{
			"rule_id", "host_id", "fleet_id", "installer_id", "requested_at",
		}).AddRow(req.RuleID, req.HostID, req.FleetID, req.InstallerID, req.RequestedAt))
	got, err := store.ListDeferredSoftwareUninstallAutomationsForHost(context.Background(), 42)
	if err != nil {
		t.Fatalf("list deferred uninstall: %v", err)
	}
	if len(got) != 1 || got[0] != req {
		t.Fatalf("unexpected deferred uninstall requests: %#v", got)
	}

	mock.ExpectExec("DELETE FROM communityplus_automation_uninstall_requests").
		WithArgs(req.RuleID, req.HostID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.DeleteDeferredSoftwareUninstallAutomation(context.Background(), req.RuleID, req.HostID); err != nil {
		t.Fatalf("delete deferred uninstall: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreDetectsPendingSoftwareUninstall(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT \\(").
		WithArgs(uint(42), uint(9), uint(42), uint(9)).
		WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(true))
	pending, err := store.IsSoftwareUninstallPending(context.Background(), 42, 9)
	if err != nil {
		t.Fatalf("check pending uninstall: %v", err)
	}
	if !pending {
		t.Fatal("expected pending uninstall")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
