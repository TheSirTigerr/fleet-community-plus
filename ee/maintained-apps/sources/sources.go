// Package sources downloads pinned public package manifests for the
// Community+ catalog. It accepts only explicitly listed, content-hashed files.
package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxSourceSize = 2 << 20 // 2 MiB

var allowedHosts = map[string]struct{}{"raw.githubusercontent.com": {}}

type PinnedSource struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Fetcher struct {
	Client       *http.Client
	AllowedHosts map[string]struct{}
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		Client: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
		AllowedHosts: allowedHosts,
	}
}

// Sync downloads all pinned source declarations directly below inputRoot's
// winget and homebrew directories. Declarations use the suffix
// .winget.source.json or .cask.source.json and are written to their matching
// .winget.yaml or .cask.rb file only after hash verification succeeds.
func Sync(ctx context.Context, inputRoot string) error {
	return NewFetcher().Sync(ctx, inputRoot)
}

func (f *Fetcher) Sync(ctx context.Context, inputRoot string) error {
	for _, sourceType := range []string{"winget", "homebrew"} {
		dir := filepath.Join(inputRoot, sourceType)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("read %s source directory: %w", sourceType, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !isDeclaration(sourceType, entry.Name()) {
				continue
			}
			declarationPath := filepath.Join(dir, entry.Name())
			if err := f.syncOne(ctx, declarationPath, sourceType); err != nil {
				return err
			}
		}
	}
	return nil
}

func isDeclaration(sourceType, name string) bool {
	suffix := ".winget.source.json"
	if sourceType == "homebrew" {
		suffix = ".cask.source.json"
	}
	return strings.HasSuffix(name, suffix)
}

func (f *Fetcher) syncOne(ctx context.Context, declarationPath, sourceType string) error {
	data, err := os.ReadFile(declarationPath)
	if err != nil {
		return fmt.Errorf("read source declaration %q: %w", declarationPath, err)
	}
	var source PinnedSource
	if err := json.Unmarshal(data, &source); err != nil {
		return fmt.Errorf("parse source declaration %q: %w", declarationPath, err)
	}
	body, err := f.fetch(ctx, source)
	if err != nil {
		return fmt.Errorf("fetch source declared by %q: %w", declarationPath, err)
	}
	target := strings.TrimSuffix(declarationPath, ".source.json")
	if sourceType == "winget" {
		target += ".yaml"
	} else {
		target += ".rb"
	}
	return writeAtomic(target, body)
}

func (f *Fetcher) fetch(ctx context.Context, source PinnedSource) ([]byte, error) {
	u, err := url.ParseRequestURI(source.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("source URL must be HTTPS")
	}
	if _, ok := f.AllowedHosts[strings.ToLower(u.Hostname())]; !ok {
		return nil, fmt.Errorf("source host %q is not allowed", u.Hostname())
	}
	expected, err := hex.DecodeString(source.SHA256)
	if err != nil || len(expected) != sha256.Size {
		return nil, fmt.Errorf("source requires a SHA-256 hash")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, err
	}
	response, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSourceSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSourceSize {
		return nil, fmt.Errorf("source exceeds %d byte limit", maxSourceSize)
	}
	actual := sha256.Sum256(body)
	if !strings.EqualFold(hex.EncodeToString(actual[:]), source.SHA256) {
		return nil, fmt.Errorf("source SHA-256 does not match declaration")
	}
	return body, nil
}

func writeAtomic(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".source-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
