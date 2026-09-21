package communityplus

import (
	"fmt"
	"strings"
)

// WindowsInstallPlan is the immutable execution contract consumed by the
// Community+ Windows worker. It contains only reviewed metadata from a
// catalog entry; no caller-provided script is ever executed.
type WindowsInstallPlan struct {
	DeploymentID  string `json:"deployment_id"`
	PackageID     string `json:"package_identifier"`
	Version       string `json:"version"`
	InstallerURL  string `json:"installer_url"`
	SHA256        string `json:"sha256"`
	InstallerType string `json:"installer_type"`
	ProductCode   string `json:"product_code,omitempty"`
}

func NewWindowsInstallPlan(deployment Deployment, entry CatalogEntry) (WindowsInstallPlan, error) {
	if err := deployment.Validate(); err != nil {
		return WindowsInstallPlan{}, err
	}
	if err := entry.Validate(); err != nil {
		return WindowsInstallPlan{}, err
	}
	if deployment.CatalogEntryID != entry.ID {
		return WindowsInstallPlan{}, fmt.Errorf("communityplus: deployment does not reference catalog entry")
	}
	if entry.InstallerType != "msi" && entry.InstallerType != "msix" && entry.InstallerType != "msixbundle" {
		return WindowsInstallPlan{}, fmt.Errorf("communityplus: unsupported Windows installer type %q", entry.InstallerType)
	}
	return WindowsInstallPlan{DeploymentID: deployment.ID, PackageID: entry.PackageIdentifier, Version: entry.Version, InstallerURL: entry.InstallerURL, SHA256: entry.InstallerSHA256, InstallerType: entry.InstallerType, ProductCode: entry.ProductCode}, nil
}

// PowerShell returns a fixed installer routine for an already verified plan.
// The worker downloads the exact immutable URL and verifies its SHA-256 before
// invoking Windows Installer or Add-AppxPackage. MSI product-code detection
// makes repeated runs idempotent at the installed target version.
func (p WindowsInstallPlan) PowerShell() (string, error) {
	if p.DeploymentID == "" || p.PackageID == "" || p.Version == "" || !validSHA256(p.SHA256) || !strings.HasPrefix(p.InstallerURL, "https://") {
		return "", fmt.Errorf("communityplus: invalid Windows install plan")
	}
	if p.InstallerType != "msi" && p.InstallerType != "msix" && p.InstallerType != "msixbundle" {
		return "", fmt.Errorf("communityplus: unsupported Windows installer type")
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$url = '%s'
$expectedHash = '%s'
$type = '%s'
$file = Join-Path $env:TEMP ('communityplus-' + '%s' + '-' + '%s')
Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing
if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'Installer SHA-256 mismatch' }
if ($type -eq 'msi') {
  $existing = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq '%s' }
  if ($existing -and $existing.DisplayVersion -eq '%s') { exit 0 }
  Start-Process msiexec.exe -ArgumentList @('/i', $file, '/qn', '/norestart') -Wait -NoNewWindow
} else {
  Add-AppxPackage -Path $file -ForceApplicationShutdown
}
`, p.InstallerURL, strings.ToLower(p.SHA256), p.InstallerType, p.DeploymentID, p.InstallerType, p.ProductCode, p.Version), nil
}
