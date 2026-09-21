package communityplus

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type memoryCatalogStore struct {
	entries     []CatalogEntry
	deployments []Deployment
}

func (s *memoryCatalogStore) UpsertCatalogEntry(_ context.Context, e CatalogEntry) error {
	s.entries = append(s.entries, e)
	return nil
}
func (s *memoryCatalogStore) GetCatalogEntry(_ context.Context, id string) (CatalogEntry, error) {
	for _, e := range s.entries {
		if e.ID == id {
			return e, nil
		}
	}
	return CatalogEntry{}, ErrForbidden
}
func (s *memoryCatalogStore) SearchCatalogEntries(_ context.Context, _ CatalogProvider, _ string, _ int) ([]CatalogEntry, error) {
	return append([]CatalogEntry(nil), s.entries...), nil
}
func (s *memoryCatalogStore) UpsertDeployment(_ context.Context, d Deployment) error {
	s.deployments = append(s.deployments, d)
	return nil
}
func (s *memoryCatalogStore) GetDeployment(_ context.Context, id string) (Deployment, error) {
	for _, d := range s.deployments {
		if d.ID == id {
			return d, nil
		}
	}
	return Deployment{}, fmt.Errorf("not found")
}
func (s *memoryCatalogStore) ListDeploymentResults(_ context.Context, _ string) ([]DeploymentResult, error) {
	return nil, nil
}

func (s *memoryCatalogStore) ListDeployments(_ context.Context, scope Scope) ([]Deployment, error) {
	var result []Deployment
	for _, d := range s.deployments {
		if d.Scope == scope {
			result = append(result, d)
		}
	}
	return result, nil
}

func validCatalogEntry() CatalogEntry {
	return CatalogEntry{ID: "entry-1", Provider: CatalogProviderWinget, PackageIdentifier: "Microsoft.PowerToys", Name: "PowerToys", Version: "0.99.0", InstallerType: "msi", InstallerURL: "https://example.invalid/PowerToys.msi", InstallerSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SourceURL: "https://example.invalid/PowerToys.installer.yaml", SourceSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ImportedAt: time.Now().UTC(), ImportedBy: "admin"}
}

func TestCatalogEntryAndDeploymentValidation(t *testing.T) {
	e := validCatalogEntry()
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.InstallerType = "exe"
	if err := e.Validate(); err == nil {
		t.Fatal("expected exe to require a reviewed manual installer policy")
	}

	d := Deployment{ID: "deployment-1", CatalogEntryID: "entry-1", Scope: FleetScope(7), Automatic: true, Patch: true, CreatedAt: time.Now().UTC(), CreatedBy: "admin"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.Scope = GlobalScope()
	if err := d.Validate(); err == nil {
		t.Fatal("expected global deployment to be rejected")
	}
}

func TestSearchCatalogEntriesValidatesAndSorts(t *testing.T) {
	store := &memoryCatalogStore{entries: []CatalogEntry{{Name: "Zulu", PackageIdentifier: "z"}, {Name: "Alpha", PackageIdentifier: "a"}}}
	entries, err := SearchCatalogEntries(context.Background(), store, CatalogProviderWinget, "power", 25)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Name != "Alpha" {
		t.Fatalf("unexpected order: %#v", entries)
	}
	if _, err := SearchCatalogEntries(context.Background(), store, CatalogProviderWinget, "x", 25); err == nil {
		t.Fatal("expected short query to fail")
	}
}
