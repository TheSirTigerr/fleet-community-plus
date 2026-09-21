// Package source imports Community+-maintained app definitions from local JSON
// files. It intentionally uses a small, documented schema so deployments can
// maintain their own catalog without relying on Fleet's hosted catalog.
package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	maintainedapps "github.com/fleetdm/fleet/v4/ee/maintained-apps"
)

const (
	installScriptRef   = "communityplus_install"
	uninstallScriptRef = "communityplus_uninstall"
)

// App is the portable Community+ catalog format. One .json file can contain
// either a single App object or {"apps": [ ... ]}. SHA256 is the hash of the
// installer at InstallerURL and is checked again by Fleet before installation.
type App struct {
	Slug              string                    `json:"slug"`
	Name              string                    `json:"name"`
	Version           string                    `json:"version"`
	InstallerURL      string                    `json:"installer_url"`
	SHA256            string                    `json:"sha256"`
	InstallScript     string                    `json:"install_script"`
	UninstallScript   string                    `json:"uninstall_script"`
	Queries           maintainedapps.FMAQueries `json:"queries"`
	DefaultCategories []string                  `json:"default_categories"`
	UpgradeCode       string                    `json:"upgrade_code,omitempty"`
	UniqueIdentifier  string                    `json:"unique_identifier,omitempty"`
	Frozen            bool                      `json:"frozen,omitempty"`
}

type list struct {
	Apps []App `json:"apps"`
}

// Ingest reads all JSON source files below inputDir. slugFilter may be empty
// or match one exact app slug. The returned order is deterministic.
func Ingest(ctx context.Context, logger *slog.Logger, inputDir, slugFilter string) ([]*maintainedapps.FMAManifestApp, error) {
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return nil, fmt.Errorf("read Community+ catalog %q: %w", inputDir, err)
	}

	var apps []App
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fileApps, err := readFile(filepath.Join(inputDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		apps = append(apps, fileApps...)
	}

	sort.Slice(apps, func(i, j int) bool { return apps[i].Slug < apps[j].Slug })
	seen := make(map[string]struct{}, len(apps))
	output := make([]*maintainedapps.FMAManifestApp, 0, len(apps))
	for _, app := range apps {
		if slugFilter != "" && app.Slug != slugFilter {
			continue
		}
		if _, exists := seen[app.Slug]; exists {
			return nil, fmt.Errorf("duplicate Community+ catalog slug %q", app.Slug)
		}
		seen[app.Slug] = struct{}{}
		if err := validate(app); err != nil {
			return nil, err
		}
		logger.InfoContext(ctx, "imported Community+ maintained app", "slug", app.Slug, "version", app.Version)
		output = append(output, &maintainedapps.FMAManifestApp{
			Slug:               app.Slug,
			Name:               app.Name,
			Version:            app.Version,
			InstallerURL:       app.InstallerURL,
			SHA256:             strings.ToLower(app.SHA256),
			InstallScriptRef:   installScriptRef,
			InstallScript:      app.InstallScript,
			UninstallScriptRef: uninstallScriptRef,
			UninstallScript:    app.UninstallScript,
			Queries:            app.Queries,
			DefaultCategories:  app.DefaultCategories,
			UpgradeCode:        app.UpgradeCode,
			UniqueIdentifier:   app.UniqueIdentifier,
			Frozen:             app.Frozen,
		})
	}
	return output, nil
}

func readFile(path string) ([]App, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Community+ catalog file %q: %w", path, err)
	}
	var wrapped list
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Apps != nil {
		return wrapped.Apps, nil
	}
	var app App
	if err := json.Unmarshal(data, &app); err != nil {
		return nil, fmt.Errorf("parse Community+ catalog file %q: %w", path, err)
	}
	return []App{app}, nil
}

func validate(app App) error {
	if app.Slug == "" || app.Name == "" || app.Version == "" {
		return fmt.Errorf("Community+ catalog app requires slug, name, and version")
	}
	if app.Platform() == "" {
		return fmt.Errorf("Community+ catalog app %q has an invalid platform suffix", app.Slug)
	}
	u, err := url.ParseRequestURI(app.InstallerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("Community+ catalog app %q requires an HTTPS installer_url", app.Slug)
	}
	decodedHash, err := hex.DecodeString(app.SHA256)
	if err != nil || len(decodedHash) != sha256.Size {
		return fmt.Errorf("Community+ catalog app %q requires a SHA-256 installer hash", app.Slug)
	}
	if strings.TrimSpace(app.InstallScript) == "" || strings.TrimSpace(app.UninstallScript) == "" {
		return fmt.Errorf("Community+ catalog app %q requires install and uninstall scripts", app.Slug)
	}
	if strings.TrimSpace(app.Queries.Exists) == "" {
		return fmt.Errorf("Community+ catalog app %q requires queries.exists", app.Slug)
	}
	return nil
}

func (app App) Platform() string {
	parts := strings.Split(app.Slug, "/")
	if len(parts) < 2 {
		return ""
	}
	switch parts[len(parts)-1] {
	case "darwin", "windows", "linux":
		return parts[len(parts)-1]
	default:
		return ""
	}
}
