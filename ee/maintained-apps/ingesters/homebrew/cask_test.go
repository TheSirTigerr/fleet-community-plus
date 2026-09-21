package homebrew

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCask(t *testing.T) {
	data := []byte(`cask "example" do
  version "1.2.3"
  sha256 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  url "https://downloads.example.test/example-#{version}.dmg"
  name "Example App"
end`)

	metadata, err := ParseCask(data)
	require.NoError(t, err)
	require.Equal(t, "Example App", metadata.Name)
	require.Equal(t, "1.2.3", metadata.Version)
	require.Equal(t, "https://downloads.example.test/example-1.2.3.dmg", metadata.InstallerURL)
}

func TestIngestAppsMergesNativeCaskAndSidecar(t *testing.T) {
	dir := t.TempDir()
	cask := `cask "example" do
  version "1.2.3"
  sha256 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  url "https://downloads.example.test/example-#{version}.dmg"
  name "Example App"
end`
	sidecar := `{"slug":"example/darwin","install_script":"hdiutil attach $INSTALLER_PATH","uninstall_script":"rm -rf /Applications/Example.app","queries":{"exists":"SELECT 1;"}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.cask.rb"), []byte(cask), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.cask.json"), []byte(sidecar), 0o600))

	apps, err := IngestApps(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, nil)), dir, "")
	require.NoError(t, err)
	require.Len(t, apps, 1)
	require.Equal(t, "Example App", apps[0].Name)
	require.Equal(t, "https://downloads.example.test/example-1.2.3.dmg", apps[0].InstallerURL)
}

func TestParseCaskRejectsNoCheckOrDynamicURL(t *testing.T) {
	data := []byte(`cask "example" do
  version "1.2.3"
  sha256 :no_check
  url "https://downloads.example.test/#{arch}/example.dmg"
  name "Example App"
end`)
	_, err := ParseCask(data)
	require.ErrorContains(t, err, "literal name, version, sha256, and url")
}
