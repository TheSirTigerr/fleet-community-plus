package winget

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// ManifestMetadata is the verified download metadata extracted from a public
// WinGet installer manifest. It deliberately contains no install or uninstall
// commands; those are endpoint-impacting policy decisions and stay in the
// reviewed Community+ catalog entry.
type ManifestMetadata struct {
	PackageIdentifier string
	PackageVersion    string
	InstallerType     string
	InstallerURL      string
	SHA256            string
	ProductCode       string
}

type installerManifest struct {
	PackageIdentifier string `yaml:"PackageIdentifier"`
	PackageVersion    string `yaml:"PackageVersion"`
	Installers        []struct {
		Architecture           string `yaml:"Architecture"`
		InstallerType          string `yaml:"InstallerType"`
		InstallerURL           string `yaml:"InstallerUrl"`
		InstallerSHA256        string `yaml:"InstallerSha256"`
		ProductCode            string `yaml:"ProductCode"`
		AppsAndFeaturesEntries []struct {
			ProductCode string `yaml:"ProductCode"`
		} `yaml:"AppsAndFeaturesEntries"`
	} `yaml:"Installers"`
}

// ParseInstallerManifest extracts one installer from a public WinGet YAML
// manifest. architecture is normally x64; a neutral installer is used when an
// exact architecture is not present. The caller must still define the scripts
// and osquery queries used on managed endpoints.
func ParseInstallerManifest(data []byte, architecture string) (*ManifestMetadata, error) {
	var manifest installerManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse WinGet installer manifest: %w", err)
	}
	if manifest.PackageIdentifier == "" || manifest.PackageVersion == "" {
		return nil, fmt.Errorf("WinGet installer manifest requires PackageIdentifier and PackageVersion")
	}

	var selected *struct {
		Architecture           string `yaml:"Architecture"`
		InstallerType          string `yaml:"InstallerType"`
		InstallerURL           string `yaml:"InstallerUrl"`
		InstallerSHA256        string `yaml:"InstallerSha256"`
		ProductCode            string `yaml:"ProductCode"`
		AppsAndFeaturesEntries []struct {
			ProductCode string `yaml:"ProductCode"`
		} `yaml:"AppsAndFeaturesEntries"`
	}
	for i := range manifest.Installers {
		installer := &manifest.Installers[i]
		if strings.EqualFold(installer.Architecture, architecture) {
			selected = installer
			break
		}
		if selected == nil && strings.EqualFold(installer.Architecture, "neutral") {
			selected = installer
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("WinGet package %q has no %s or neutral installer", manifest.PackageIdentifier, architecture)
	}
	if err := validateDownload(selected.InstallerURL, selected.InstallerSHA256); err != nil {
		return nil, fmt.Errorf("WinGet package %q: %w", manifest.PackageIdentifier, err)
	}
	productCode := selected.ProductCode
	if productCode == "" && len(selected.AppsAndFeaturesEntries) == 1 {
		productCode = selected.AppsAndFeaturesEntries[0].ProductCode
	}
	return &ManifestMetadata{
		PackageIdentifier: manifest.PackageIdentifier,
		PackageVersion:    manifest.PackageVersion,
		InstallerType:     strings.ToLower(selected.InstallerType),
		InstallerURL:      selected.InstallerURL,
		SHA256:            strings.ToLower(selected.InstallerSHA256),
		ProductCode:       productCode,
	}, nil
}

func validateDownload(installerURL, hash string) error {
	u, err := url.ParseRequestURI(installerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("requires an HTTPS InstallerUrl")
	}
	decoded, err := hex.DecodeString(hash)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("requires a SHA-256 InstallerSha256")
	}
	return nil
}
