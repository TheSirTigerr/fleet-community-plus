package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	maintained_apps "github.com/fleetdm/fleet/v4/ee/maintained-apps"
	"github.com/stretchr/testify/require"
)

func TestJSONEncoderPreservesHTML(t *testing.T) {
	testData := struct {
		Description string `json:"description"`
	}{
		Description: `Test with HTML: <a href="https://example.com">link</a> & special chars < >`,
	}

	// Test with SetEscapeHTML(false)
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(testData); err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	result := buf.String()

	// Verify HTML characters are preserved, not escaped
	if strings.Contains(result, `\u003c`) {
		t.Error("Found escaped '<' character (\\u003c) - HTML escaping is still enabled")
	}
	if strings.Contains(result, `\u003e`) {
		t.Error("Found escaped '>' character (\\u003e) - HTML escaping is still enabled")
	}
	if strings.Contains(result, `\u0026`) {
		t.Error("Found escaped '&' character (\\u0026) - HTML escaping is still enabled")
	}

	// Verify HTML characters are present (note: quotes inside JSON are still escaped)
	if !strings.Contains(result, `<a href=\"https://example.com\">`) {
		t.Error("HTML anchor tag was not preserved correctly")
	}
	if !strings.Contains(result, ` & `) {
		t.Error("Ampersand character was not preserved correctly")
	}

	t.Logf("Successfully preserved HTML in JSON output: %s", result)
}

func TestRunWritesValidatedCatalog(t *testing.T) {
	root := t.TempDir()
	for _, platform := range []string{"homebrew", "winget"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, platform), 0o755))
	}
	app := `{"slug":"example/windows","name":"Example","version":"1.0.0","installer_url":"https://downloads.example.test/example.msi","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","install_script":"msiexec /i example.msi /qn","uninstall_script":"msiexec /x example.msi /qn","queries":{"exists":"SELECT 1;"},"default_categories":["Utilities"],"unique_identifier":"Example"}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "winget", "example.json"), []byte(app), 0o600))
	outputDir := filepath.Join(root, "output")

	err := run(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, nil)), catalogOptions{InputRoot: root, OutputDir: outputDir})
	require.NoError(t, err)

	appsData, err := os.ReadFile(filepath.Join(outputDir, "apps.json"))
	require.NoError(t, err)
	var apps maintained_apps.FMAListFile
	require.NoError(t, json.Unmarshal(appsData, &apps))
	require.Equal(t, uint(2), apps.Version)
	require.Len(t, apps.Apps, 1)
	require.Equal(t, "example/windows", apps.Apps[0].Slug)

	manifestData, err := os.ReadFile(filepath.Join(outputDir, "example", "windows.json"))
	require.NoError(t, err)
	var manifest maintained_apps.FMAManifestFile
	require.NoError(t, json.Unmarshal(manifestData, &manifest))
	require.Len(t, manifest.Versions, 1)
	require.Empty(t, manifest.Versions[0].UniqueIdentifier)
}

func TestRunCheckDoesNotWriteFiles(t *testing.T) {
	root := t.TempDir()
	for _, platform := range []string{"homebrew", "winget"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, platform), 0o755))
	}
	outputDir := filepath.Join(root, "output")

	err := run(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, nil)), catalogOptions{InputRoot: root, OutputDir: outputDir, CheckOnly: true})
	require.NoError(t, err)
	_, err = os.Stat(outputDir)
	require.True(t, os.IsNotExist(err))
}
