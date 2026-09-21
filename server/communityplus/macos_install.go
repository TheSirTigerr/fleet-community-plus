package communityplus

import "fmt"

// MacOSInstallPlan is an immutable direct-PKG contract derived from a reviewed
// Homebrew cask. Community+ never executes Homebrew Ruby or arbitrary scripts.
type MacOSInstallPlan struct {
	DeploymentID  string
	PackageID     string
	Version       string
	InstallerURL  string
	SHA256        string
	InstallerType string
}

func NewMacOSInstallPlan(deployment Deployment, entry CatalogEntry) (MacOSInstallPlan, error) {
	if err := deployment.Validate(); err != nil {
		return MacOSInstallPlan{}, err
	}
	if err := entry.Validate(); err != nil {
		return MacOSInstallPlan{}, err
	}
	if deployment.CatalogEntryID != entry.ID {
		return MacOSInstallPlan{}, fmt.Errorf("communityplus: deployment does not reference catalog entry")
	}
	if entry.Provider != CatalogProviderHomebrew || entry.InstallerType != "pkg" {
		return MacOSInstallPlan{}, fmt.Errorf("communityplus: unsupported macOS catalog entry")
	}
	return MacOSInstallPlan{
		DeploymentID:  deployment.ID,
		PackageID:     entry.PackageIdentifier,
		Version:       entry.Version,
		InstallerURL:  entry.InstallerURL,
		SHA256:        entry.InstallerSHA256,
		InstallerType: entry.InstallerType,
	}, nil
}
