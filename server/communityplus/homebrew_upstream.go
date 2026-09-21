package communityplus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	homebrewCaskListURL = "https://formulae.brew.sh/api/cask.json"
	homebrewMaxListSize = 32 << 20
	homebrewMaxCaskSize = 2 << 20
)

type HomebrewUpstreamEntry struct {
	Token       string `json:"token"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
	Version     string `json:"version"`
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
}

type homebrewCask struct {
	Token      string                     `json:"token"`
	Name       []string                   `json:"name"`
	Desc       string                     `json:"desc"`
	Homepage   string                     `json:"homepage"`
	URL        string                     `json:"url"`
	Version    string                     `json:"version"`
	SHA256     string                     `json:"sha256"`
	Deprecated bool                       `json:"deprecated"`
	Disabled   bool                       `json:"disabled"`
	Variations map[string]json.RawMessage `json:"variations"`
	Artifacts  []map[string]json.RawMessage `json:"artifacts"`
}

func homebrewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func fetchHomebrewJSON(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "formulae.brew.sh") || !strings.HasPrefix(u.Path, "/api/cask") {
		return nil, fmt.Errorf("communityplus: invalid Homebrew API URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("communityplus: create Homebrew request: %w", err)
	}
	res, err := homebrewHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("communityplus: fetch Homebrew metadata: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("communityplus: Homebrew API returned HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("communityplus: read Homebrew metadata: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("communityplus: Homebrew response exceeds size limit")
	}
	return data, nil
}

func homebrewDisplayName(c homebrewCask) string {
	for _, name := range c.Name {
		if strings.TrimSpace(name) != "" {
			return strings.TrimSpace(name)
		}
	}
	return c.Token
}

func homebrewDirectPKG(c homebrewCask) bool {
	if c.Disabled || c.Deprecated || c.Token == "" || c.Version == "" || !validSHA256(strings.ToLower(c.SHA256)) {
		return false
	}
	if len(c.Variations) != 0 {
		// Platform-specific overrides can point at a different architecture.
		// Do not guess which one is correct for a host.
		return false
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || !strings.HasSuffix(strings.ToLower(u.Path), ".pkg") {
		return false
	}
	for _, artifact := range c.Artifacts {
		if _, ok := artifact["pkg"]; ok {
			return true
		}
	}
	return false
}

func SearchHomebrewUpstream(ctx context.Context, query string, limit int) ([]HomebrewUpstreamEntry, error) {
	query = strings.ToLower(strings.TrimSpace(query))
	if len(query) < 2 || len(query) > 120 {
		return nil, fmt.Errorf("communityplus: Homebrew search query must contain 2 to 120 characters")
	}
	if limit <= 0 || limit > 50 {
		return nil, fmt.Errorf("communityplus: Homebrew search limit must be between 1 and 50")
	}
	data, err := fetchHomebrewJSON(ctx, homebrewCaskListURL, homebrewMaxListSize)
	if err != nil {
		return nil, err
	}
	var casks []homebrewCask
	if err := json.Unmarshal(data, &casks); err != nil {
		return nil, fmt.Errorf("communityplus: decode Homebrew cask list: %w", err)
	}
	matches := make([]HomebrewUpstreamEntry, 0, limit)
	for _, cask := range casks {
		if !homebrewDirectPKG(cask) {
			continue
		}
		name := homebrewDisplayName(cask)
		haystack := strings.ToLower(cask.Token + "\n" + name + "\n" + cask.Desc)
		if !strings.Contains(haystack, query) {
			continue
		}
		matches = append(matches, HomebrewUpstreamEntry{
			Token: cask.Token, Name: name, Description: cask.Desc, Homepage: cask.Homepage,
			Version: cask.Version, URL: cask.URL, SHA256: strings.ToLower(cask.SHA256),
		})
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Name == matches[j].Name {
			return matches[i].Token < matches[j].Token
		}
		return matches[i].Name < matches[j].Name
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches, nil
}

func FetchHomebrewCask(ctx context.Context, token, expectedVersion string) (CatalogEntry, error) {
	token = strings.TrimSpace(token)
	expectedVersion = strings.TrimSpace(expectedVersion)
	if token == "" || expectedVersion == "" || strings.ContainsAny(token, "/\\") {
		return CatalogEntry{}, fmt.Errorf("communityplus: Homebrew token and reviewed version are required")
	}
	sourceURL := "https://formulae.brew.sh/api/cask/" + url.PathEscape(token) + ".json"
	data, err := fetchHomebrewJSON(ctx, sourceURL, homebrewMaxCaskSize)
	if err != nil {
		return CatalogEntry{}, err
	}
	var cask homebrewCask
	if err := json.Unmarshal(data, &cask); err != nil {
		return CatalogEntry{}, fmt.Errorf("communityplus: decode Homebrew cask: %w", err)
	}
	if cask.Token != token || cask.Version != expectedVersion {
		return CatalogEntry{}, fmt.Errorf("communityplus: Homebrew cask changed since review; search again before importing")
	}
	if !homebrewDirectPKG(cask) {
		return CatalogEntry{}, fmt.Errorf("communityplus: Homebrew cask is not a deployable architecture-neutral direct PKG")
	}
	sourceHash := sha256.Sum256(data)
	installerHash := strings.ToLower(cask.SHA256)
	return CatalogEntry{
		ID:                homebrewCatalogEntryID(cask.Token, cask.Version, installerHash),
		Provider:          CatalogProviderHomebrew,
		PackageIdentifier: cask.Token,
		Name:              homebrewDisplayName(cask),
		Version:           cask.Version,
		InstallerType:     "pkg",
		InstallerURL:      cask.URL,
		InstallerSHA256:   installerHash,
		SourceURL:         sourceURL,
		SourceSHA256:      hex.EncodeToString(sourceHash[:]),
	}, nil
}

func homebrewCatalogEntryID(token, version, installerSHA string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(token) + "\x00" + version + "\x00" + strings.ToLower(installerSHA)))
	return "homebrew-" + hex.EncodeToString(sum[:16])
}
