package communityplus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CatalogProvider identifies an upstream package catalog. Community+ keeps the
// provider explicit so a deployment cannot accidentally switch sources.
type CatalogProvider string

const (
	CatalogProviderWinget   CatalogProvider = "winget"
	CatalogProviderHomebrew CatalogProvider = "homebrew"
)

func supportedCatalogProvider(provider CatalogProvider) bool {
	return provider == CatalogProviderWinget || provider == CatalogProviderHomebrew
}

// CatalogEntry is an approved package version. It intentionally stores the
// immutable installer URL and SHA-256 instead of a "latest" package reference.
// The endpoint agent can therefore verify exactly what an administrator reviewed.
type CatalogEntry struct {
	ID                string          `json:"id"`
	Provider          CatalogProvider `json:"provider"`
	PackageIdentifier string          `json:"package_identifier"`
	Name              string          `json:"name"`
	Version           string          `json:"version"`
	InstallerType     string          `json:"installer_type"`
	InstallerURL      string          `json:"installer_url"`
	InstallerSHA256   string          `json:"installer_sha256"`
	ProductCode       string          `json:"product_code,omitempty"`
	SourceURL         string          `json:"source_url"`
	SourceSHA256      string          `json:"source_sha256"`
	ImportedAt        time.Time       `json:"imported_at"`
	ImportedBy        string          `json:"imported_by"`
}

func (e CatalogEntry) Validate() error {
	if e.ID == "" || !supportedCatalogProvider(e.Provider) || e.PackageIdentifier == "" || e.Name == "" || e.Version == "" {
		return fmt.Errorf("communityplus: catalog entry id, supported provider, package_identifier, name and version are required")
	}
	switch e.Provider {
	case CatalogProviderWinget:
		if e.InstallerType != "msi" && e.InstallerType != "msix" && e.InstallerType != "msixbundle" {
			return fmt.Errorf("communityplus: installer type %q is not supported for WinGet automatic deployment", e.InstallerType)
		}
	case CatalogProviderHomebrew:
		if e.InstallerType != "pkg" {
			return fmt.Errorf("communityplus: installer type %q is not supported for Homebrew automatic deployment", e.InstallerType)
		}
	}
	if !strings.HasPrefix(e.InstallerURL, "https://") || !strings.HasPrefix(e.SourceURL, "https://") {
		return fmt.Errorf("communityplus: installer_url and source_url must use HTTPS")
	}
	if !validSHA256(e.InstallerSHA256) || !validSHA256(e.SourceSHA256) {
		return fmt.Errorf("communityplus: installer_sha256 and source_sha256 must be SHA-256 values")
	}
	if e.ImportedAt.IsZero() || e.ImportedBy == "" {
		return fmt.Errorf("communityplus: imported_at and imported_by are required")
	}
	return nil
}

func validSHA256(v string) bool {
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == sha256.Size
}

// Deployment is a team-scoped intent to make a reviewed catalog package
// available. The execution layer consumes these records; catalog import itself
// never causes a change on an endpoint.
type Deployment struct {
	ID             string    `json:"id"`
	CatalogEntryID string    `json:"catalog_entry_id"`
	Scope          Scope     `json:"scope"`
	SelfService    bool      `json:"self_service"`
	Automatic      bool      `json:"automatic"`
	Patch          bool      `json:"patch"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
}

func (d Deployment) Validate() error {
	if d.ID == "" || d.CatalogEntryID == "" || d.CreatedBy == "" || d.CreatedAt.IsZero() {
		return fmt.Errorf("communityplus: deployment id, catalog_entry_id, created_at and created_by are required")
	}
	if d.Scope.Kind != ScopeFleet {
		return fmt.Errorf("communityplus: deployments must target a Fleet")
	}
	if err := d.Scope.Validate(); err != nil {
		return err
	}
	if !d.SelfService && !d.Automatic {
		return fmt.Errorf("communityplus: deployment must enable self_service or automatic installation")
	}
	return nil
}

type CatalogStore interface {
	UpsertCatalogEntry(context.Context, CatalogEntry) error
	SearchCatalogEntries(context.Context, CatalogProvider, string, int) ([]CatalogEntry, error)
	GetCatalogEntry(context.Context, string) (CatalogEntry, error)
	GetDeployment(context.Context, string) (Deployment, error)
	UpsertDeployment(context.Context, Deployment) error
	ListDeployments(context.Context, Scope) ([]Deployment, error)
	ListDeploymentResults(context.Context, string) ([]DeploymentResult, error)
}

// SearchCatalogEntries sorts entries by name then package id so the UI has a
// deterministic result order even when its backing store does not specify one.
func SearchCatalogEntries(ctx context.Context, store CatalogStore, provider CatalogProvider, query string, limit int) ([]CatalogEntry, error) {
	if store == nil || !supportedCatalogProvider(provider) {
		return nil, fmt.Errorf("communityplus: supported catalog provider is required")
	}
	query = strings.TrimSpace(query)
	if len(query) < 2 || len(query) > 120 {
		return nil, fmt.Errorf("communityplus: search query must contain 2 to 120 characters")
	}
	if limit <= 0 || limit > 100 {
		return nil, fmt.Errorf("communityplus: search limit must be between 1 and 100")
	}
	entries, err := store.SearchCatalogEntries(ctx, provider, query, limit)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].PackageIdentifier < entries[j].PackageIdentifier
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// DeploymentResult is the latest outcome recorded by one host.
type DeploymentResult struct {
	DeploymentID string    `json:"deployment_id"`
	HostID       uint      `json:"host_id"`
	Hostname     string    `json:"hostname"`
	ExitCode     int       `json:"exit_code"`
	Output       string    `json:"output,omitempty"`
	AttemptCount int       `json:"attempt_count"`
	UpdatedAt    time.Time `json:"updated_at"`
}
