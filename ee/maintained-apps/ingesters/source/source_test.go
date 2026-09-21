package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"log/slog"

	"github.com/stretchr/testify/require"
)

const validApp = `{
  "slug": "example/windows",
  "name": "Example",
  "version": "1.2.3",
  "installer_url": "https://downloads.example.test/example.msi",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "install_script": "msiexec /i example.msi /qn",
  "uninstall_script": "msiexec /x example.msi /qn",
  "queries": {"exists": "SELECT 1;"},
  "default_categories": ["Utilities"]
}`

func TestIngest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.json"), []byte(validApp), 0o600))

	apps, err := Ingest(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, nil)), dir, "")
	require.NoError(t, err)
	require.Len(t, apps, 1)
	require.Equal(t, "example/windows", apps[0].Slug)
	require.Equal(t, installScriptRef, apps[0].InstallScriptRef)
	require.Equal(t, "windows", apps[0].Platform())
}

func TestIngestRejectsUnsafeCatalogEntry(t *testing.T) {
	dir := t.TempDir()
	invalid := `{"slug":"example/windows","name":"Example","version":"1","installer_url":"http://example.test/app.msi","sha256":"bad","install_script":"x","uninstall_script":"x","queries":{"exists":"SELECT 1;"}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "invalid.json"), []byte(invalid), 0o600))

	_, err := Ingest(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, nil)), dir, "")
	require.ErrorContains(t, err, "HTTPS installer_url")
}

func TestIngestFiltersSlug(t *testing.T) {
	dir := t.TempDir()
	wrapped := `{"apps":[` + validApp + `,{"slug":"other/darwin","name":"Other","version":"1","installer_url":"https://downloads.example.test/other.pkg","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","install_script":"installer","uninstall_script":"rm","queries":{"exists":"SELECT 1;"}}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "apps.json"), []byte(wrapped), 0o600))

	apps, err := Ingest(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, nil)), dir, "other/darwin")
	require.NoError(t, err)
	require.Len(t, apps, 1)
	require.Equal(t, "other/darwin", apps[0].Slug)
}
