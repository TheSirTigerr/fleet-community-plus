// Package winget is the Community+ WinGet ingestion boundary.
package winget

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	maintainedapps "github.com/fleetdm/fleet/v4/server/communityplus/maintainedapps"
	"github.com/fleetdm/fleet/v4/server/communityplus/maintainedapps/ingesters/source"
)

// IngestApps imports locally maintained Windows catalog entries. The catalog
// format is shared with Homebrew to keep catalog review and signing uniform.
func IngestApps(ctx context.Context, logger *slog.Logger, inputDir, slug string) ([]*maintainedapps.FMAManifestApp, error) {
	apps, err := source.Ingest(ctx, logger, inputDir, slug)
	if err != nil {
		return nil, err
	}
	native, err := ingestNative(ctx, logger, inputDir, slug)
	if err != nil {
		return nil, err
	}
	return combine(apps, native)
}

// Native WinGet inputs use a downloaded public installer manifest named
// <name>.winget.yaml and a reviewed Community+ sidecar named
// <name>.winget.json. The sidecar is a normal source.App but may omit version,
// installer_url and sha256; those values are always replaced from the YAML.
func ingestNative(ctx context.Context, logger *slog.Logger, inputDir, slug string) ([]*maintainedapps.FMAManifestApp, error) {
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return nil, err
	}
	var definitions []source.App
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".winget.yaml") && !strings.HasSuffix(entry.Name(), ".winget.yml")) {
			continue
		}
		manifestPath := filepath.Join(inputDir, entry.Name())
		manifest, err := os.ReadFile(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("read WinGet manifest %q: %w", manifestPath, err)
		}
		metadata, err := ParseInstallerManifest(manifest, "x64")
		if err != nil {
			return nil, fmt.Errorf("parse WinGet manifest %q: %w", manifestPath, err)
		}
		sidecarPath := strings.TrimSuffix(manifestPath, filepath.Ext(manifestPath)) + ".json"
		sidecar, err := os.ReadFile(sidecarPath)
		if err != nil {
			return nil, fmt.Errorf("read Community+ WinGet sidecar %q: %w", sidecarPath, err)
		}
		var app source.App
		if err := json.Unmarshal(sidecar, &app); err != nil {
			return nil, fmt.Errorf("parse Community+ WinGet sidecar %q: %w", sidecarPath, err)
		}
		if app.Name == "" {
			app.Name = metadata.PackageIdentifier
		}
		app.Version = metadata.PackageVersion
		app.InstallerURL = metadata.InstallerURL
		app.SHA256 = metadata.SHA256
		if app.UpgradeCode == "" {
			app.UpgradeCode = metadata.ProductCode
		}
		definitions = append(definitions, app)
	}
	return source.Build(ctx, logger, definitions, slug)
}

func combine(first, second []*maintainedapps.FMAManifestApp) ([]*maintainedapps.FMAManifestApp, error) {
	seen := make(map[string]struct{}, len(first)+len(second))
	for _, app := range append(first, second...) {
		if _, exists := seen[app.Slug]; exists {
			return nil, fmt.Errorf("duplicate Community+ WinGet catalog slug %q", app.Slug)
		}
		seen[app.Slug] = struct{}{}
	}
	return append(first, second...), nil
}
