package communityplus

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func patchCandidate(provider CatalogProvider) CatalogEntry {
	entry := validCatalogEntry()
	entry.ID = "entry-new"
	entry.Version = "1.2.4"
	entry.ImportedAt = time.Now().UTC()
	switch provider {
	case CatalogProviderHomebrew:
		entry.Provider = CatalogProviderHomebrew
		entry.PackageIdentifier = "example"
		entry.Name = "Example"
		entry.InstallerType = "pkg"
		entry.InstallerURL = "https://example.invalid/example.pkg"
		entry.ProductCode = ""
	}
	return entry
}

func TestPromotePatchDeploymentsUpdatesDeploymentAndResetsResults(t *testing.T) {
	for _, provider := range []CatalogProvider{CatalogProviderWinget, CatalogProviderHomebrew} {
		t.Run(string(provider), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			store, err := NewSQLStore(db)
			if err != nil {
				t.Fatal(err)
			}
			candidate := patchCandidate(provider)
			currentPackageID := candidate.PackageIdentifier
			currentInstallerType := candidate.InstallerType

			mock.ExpectQuery("SELECT d.id, e.id, e.provider").
				WithArgs(provider, currentPackageID).
				WillReturnRows(sqlmock.NewRows([]string{
					"deployment_id", "entry_id", "provider", "package_identifier", "version", "installer_type",
				}).AddRow("deployment-1", "entry-old", provider, currentPackageID, "1.2.3", currentInstallerType))
			mock.ExpectExec("UPDATE communityplus_catalog_deployments").
				WithArgs(candidate.ID, "deployment-1", "entry-old").
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec("DELETE FROM communityplus_deployment_results").
				WithArgs("deployment-1").
				WillReturnResult(sqlmock.NewResult(0, 2))

			if err := store.PromotePatchDeployments(context.Background(), candidate); err != nil {
				t.Fatalf("promote patch deployment: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPromotePatchDeploymentsRejectsDowngrade(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	candidate := patchCandidate(CatalogProviderWinget)
	candidate.Version = "1.2.2"

	mock.ExpectQuery("SELECT d.id, e.id, e.provider").
		WithArgs(candidate.Provider, candidate.PackageIdentifier).
		WillReturnRows(sqlmock.NewRows([]string{
			"deployment_id", "entry_id", "provider", "package_identifier", "version", "installer_type",
		}).AddRow("deployment-1", "entry-old", candidate.Provider, candidate.PackageIdentifier, "1.2.3", candidate.InstallerType))

	if err := store.PromotePatchDeployments(context.Background(), candidate); err != nil {
		t.Fatalf("promote patch deployment: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
