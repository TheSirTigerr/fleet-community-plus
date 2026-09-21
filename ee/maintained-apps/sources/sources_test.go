package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFetcherSyncWritesVerifiedSource(t *testing.T) {
	body := []byte("PackageIdentifier: Example.App\n")
	sum := sha256.Sum256(body)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	root := t.TempDir()
	dir := filepath.Join(root, "winget")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "homebrew"), 0o755))
	declaration := `{"url":"` + server.URL + `","sha256":"` + hex.EncodeToString(sum[:]) + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.winget.source.json"), []byte(declaration), 0o600))

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	fetcher := &Fetcher{Client: server.Client(), AllowedHosts: map[string]struct{}{serverURL.Hostname(): {}}}
	require.NoError(t, fetcher.Sync(context.Background(), root))
	got, err := os.ReadFile(filepath.Join(dir, "example.winget.yaml"))
	require.NoError(t, err)
	require.Equal(t, body, got)
}

func TestFetcherRejectsHashMismatch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("different content"))
	}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	fetcher := &Fetcher{Client: server.Client(), AllowedHosts: map[string]struct{}{serverURL.Hostname(): {}}}
	_, err = fetcher.fetch(context.Background(), PinnedSource{URL: server.URL, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	require.ErrorContains(t, err, "does not match")
}
