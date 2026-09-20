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
	Version            string   `json:"version"`
	InstallerURL       string   `json:"installer_url"`
	SHA256             string   `json:"sha256"`
	InstallScriptRef   string   `json:"install_script_ref"`
	UninstallScriptRef string   `json:"uninstall_script_ref"`
	Queries            Queries  `json:"queries"`
	DefaultCategories  []string `json:"default_categories"`
	UpgradeCode        string   `json:"upgrade_code,omitempty"`
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
