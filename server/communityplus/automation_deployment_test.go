package communityplus

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestQueueAutomationDeployment(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT d.fleet_id, e.provider, h.platform, h.team_id").
		WithArgs(uint(42), "deployment-1").
		WillReturnRows(sqlmock.NewRows([]string{"fleet_id", "provider", "platform", "team_id"}).
			AddRow(7, CatalogProviderWinget, "windows", 7))
	mock.ExpectExec("INSERT INTO communityplus_automation_deployment_requests").
		WithArgs("deployment-1", uint(42)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM communityplus_deployment_results").
		WithArgs("deployment-1", uint(42)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.QueueAutomationDeployment(context.Background(), "deployment-1", 42); err != nil {
		t.Fatalf("queue automation deployment: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
