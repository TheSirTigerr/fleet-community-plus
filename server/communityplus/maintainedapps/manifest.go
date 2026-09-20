// Package maintainedapps defines the public manifest schema consumed by the
// Community maintained-app synchronization code.
package maintainedapps

import "strings"

type ManifestFile struct {
	Refs     map[string]string `json:"refs"`
	Versions []*ManifestApp    `json:"versions"`
}

type Queries struct {
	Exists  string `json:"exists"`
	Patched string `json:"patched"`
	Open    string `json:"open"`
}

type ManifestApp struct {
	Slug               string   `json:"slug,omitempty"`
	Name               string   `json:"name,omitempty"`
	Version            string   `json:"version"`
	InstallerURL       string   `json:"installer_url"`
	SHA256             string   `json:"sha256"`
	InstallScriptRef   string   `json:"install_script_ref"`
	InstallScript      string   `json:"-"`
	UninstallScriptRef string   `json:"uninstall_script_ref"`
	UninstallScript    string   `json:"-"`
	Queries            Queries  `json:"queries"`
	DefaultCategories  []string `json:"default_categories"`
	UpgradeCode        string   `json:"upgrade_code,omitempty"`
	UniqueIdentifier   string   `json:"unique_identifier,omitempty"`
	Frozen             bool     `json:"frozen,omitempty"`
}

func (app ManifestApp) IsEmpty() bool { return app.Slug == "" || app.Version == "" }

func (app ManifestApp) SlugAppName() string {
	parts := strings.Split(app.Slug, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// Platform returns the platform component of a manifest slug such as
// "google-chrome/darwin". Unknown or malformed slugs produce an empty value so
// callers never persist arbitrary path data as a platform.
func (app ManifestApp) Platform() string {
	parts := strings.Split(app.Slug, "/")
	if len(parts) < 2 {
		return ""
	}
	platform := parts[len(parts)-1]
	switch platform {
	case "darwin", "windows", "linux":
		return platform
	default:
		return ""
	}
}
