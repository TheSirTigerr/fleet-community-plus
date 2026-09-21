package winget

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseInstallerManifest(t *testing.T) {
	data := []byte(`PackageIdentifier: Example.App
PackageVersion: 1.2.3
Installers:
  - Architecture: x64
    InstallerType: msi
    InstallerUrl: https://downloads.example.test/example-x64.msi
    InstallerSha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    ProductCode: '{EXAMPLE}'
  - Architecture: arm64
    InstallerType: msi
    InstallerUrl: https://downloads.example.test/example-arm64.msi
    InstallerSha256: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
`)

	metadata, err := ParseInstallerManifest(data, "x64")
	require.NoError(t, err)
	require.Equal(t, "Example.App", metadata.PackageIdentifier)
	require.Equal(t, "1.2.3", metadata.PackageVersion)
	require.Equal(t, "msi", metadata.InstallerType)
	require.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", metadata.SHA256)
}

func TestIngestAppsMergesNativeManifestAndSidecar(t *testing.T) {
	dir := t.TempDir()
	manifest := `PackageIdentifier: Example.App
PackageVersion: 1.2.3
Installers:
  - Architecture: x64
    InstallerType: msi
    InstallerUrl: https://downloads.example.test/example.msi
    InstallerSha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    ProductCode: '{EXAMPLE}'
`
	sidecar := `{"slug":"example/windows","name":"Example","install_script":"msiexec /i $INSTALLER_PATH /qn","uninstall_script":"msiexec /x {EXAMPLE} /qn","queries":{"exists":"SELECT 1;"}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.winget.yaml"), []byte(manifest), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.winget.json"), []byte(sidecar), 0o600))

	apps, err := IngestApps(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, nil)), dir, "")
	require.NoError(t, err)
	require.Len(t, apps, 1)
	require.Equal(t, "1.2.3", apps[0].Version)
	require.Equal(t, "https://downloads.example.test/example.msi", apps[0].InstallerURL)
	require.Equal(t, "{EXAMPLE}", apps[0].UpgradeCode)
}

func TestParseInstallerManifestRejectsUnverifiedDownload(t *testing.T) {
	data := []byte(`PackageIdentifier: Example.App
PackageVersion: 1.2.3
Installers:
  - Architecture: x64
    InstallerType: exe
    InstallerUrl: http://downloads.example.test/example.exe
    InstallerSha256: bad
`)
	_, err := ParseInstallerManifest(data, "x64")
	require.ErrorContains(t, err, "HTTPS InstallerUrl")
}
