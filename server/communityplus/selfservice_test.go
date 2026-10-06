package communityplus

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestListSelfServiceItemsForHost(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}

	requestedAt := time.Now().UTC()
	mock.ExpectQuery("SELECT ss.id, d.id, e.id").
		WithArgs(uint(42), uint(42), uint(7), CatalogProviderWinget, "%%", "%%").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "deployment_id", "catalog_entry_id", "name", "package_identifier",
			"version", "provider", "installer_type", "exit_code", "requested_at",
		}).AddRow(101, "deployment-1", "entry-1", "Example", "Vendor.Example", "1.2.3", CatalogProviderWinget, "msi", nil, requestedAt))

	items, err := store.ListSelfServiceItemsForHost(context.Background(), 42, 7, CatalogProviderWinget, "")
	if err != nil {
		t.Fatalf("list self-service items: %v", err)
	}
	if len(items) != 1 || items[0].TitleID != 101 || items[0].DeploymentID != "deployment-1" {
		t.Fatalf("unexpected items: %#v", items)
	}
	if items[0].Status == nil || *items[0].Status != fleet.SoftwareInstallPending {
		t.Fatalf("status = %#v, want pending_install", items[0].Status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestSelfServiceDeployment(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT d.id").
		WithArgs(uint(101), uint(7), CatalogProviderWinget).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("deployment-1"))
	mock.ExpectExec("INSERT INTO communityplus_self_service_requests").
		WithArgs("deployment-1", uint(42)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM communityplus_deployment_results").
		WithArgs("deployment-1", uint(42)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	deploymentID, err := store.RequestSelfServiceDeployment(context.Background(), 42, 7, 101, CatalogProviderWinget)
	if err != nil {
		t.Fatalf("request self-service deployment: %v", err)
	}
	if deploymentID != "deployment-1" {
		t.Fatalf("deployment id = %q", deploymentID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
