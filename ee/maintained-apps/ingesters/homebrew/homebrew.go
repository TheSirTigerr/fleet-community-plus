// Package homebrew is the Community+ Homebrew ingestion boundary.
package homebrew

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	maintainedapps "github.com/fleetdm/fleet/v4/ee/maintained-apps"
	"github.com/fleetdm/fleet/v4/ee/maintained-apps/ingesters/source"
)

// IngestApps imports locally maintained macOS catalog entries. The catalog
// format is shared with WinGet to keep catalog review and signing uniform.
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

// Native Homebrew inputs use a downloaded public Cask named <name>.cask.rb
// and a reviewed Community+ sidecar named <name>.cask.json. Variable Casks
// and Casks without a fixed SHA-256 are rejected by ParseCask.
func ingestNative(ctx context.Context, logger *slog.Logger, inputDir, slug string) ([]*maintainedapps.FMAManifestApp, error) {
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return nil, err
	}
	var definitions []source.App
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cask.rb") {
			continue
		}
		caskPath := filepath.Join(inputDir, entry.Name())
		cask, err := os.ReadFile(caskPath)
		if err != nil {
			return nil, fmt.Errorf("read Homebrew Cask %q: %w", caskPath, err)
		}
		metadata, err := ParseCask(cask)
		if err != nil {
			return nil, fmt.Errorf("parse Homebrew Cask %q: %w", caskPath, err)
		}
		sidecarPath := strings.TrimSuffix(caskPath, ".rb") + ".json"
		sidecar, err := os.ReadFile(sidecarPath)
		if err != nil {
			return nil, fmt.Errorf("read Community+ Homebrew sidecar %q: %w", sidecarPath, err)
		}
		var app source.App
		if err := json.Unmarshal(sidecar, &app); err != nil {
			return nil, fmt.Errorf("parse Community+ Homebrew sidecar %q: %w", sidecarPath, err)
		}
		if app.Name == "" {
			app.Name = metadata.Name
		}
		app.Version = metadata.Version
		app.InstallerURL = metadata.InstallerURL
		app.SHA256 = metadata.SHA256
		definitions = append(definitions, app)
	}
	return source.Build(ctx, logger, definitions, slug)
}

func combine(first, second []*maintainedapps.FMAManifestApp) ([]*maintainedapps.FMAManifestApp, error) {
	seen := make(map[string]struct{}, len(first)+len(second))
	for _, app := range append(first, second...) {
		if _, exists := seen[app.Slug]; exists {
			return nil, fmt.Errorf("duplicate Community+ Homebrew catalog slug %q", app.Slug)
		}
		seen[app.Slug] = struct{}{}
	}
	return append(first, second...), nil
}
