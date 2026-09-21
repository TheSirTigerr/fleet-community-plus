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
	"os"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/communityplus/winget"
)

const wingetRepository = "microsoft/winget-pkgs"

type upstreamWingetCandidate struct {
	DisplayName   string `json:"display_name"`
	PackageID     string `json:"package_identifier"`
	Version       string `json:"version"`
	InstallerType string `json:"installer_type"`
	SourceURL     string `json:"source_url"`
	SourceSHA256  string `json:"source_sha256"`
}

type githubCodeSearchResponse struct {
	Items []struct {
		Path string `json:"path"`
	} `json:"items"`
}

// SearchWinGetUpstream queries the public manifest repository and then pins
// every candidate to the exact repository commit before returning it. GitHub's
// code search is rate-limited; administrators can configure GITHUB_TOKEN on
// the Fleet server for reliable production use.
func SearchWinGetUpstream(ctx context.Context, query string, limit int) ([]upstreamWingetCandidate, error) {
	query = strings.TrimSpace(query)
	if len(query) < 2 || len(query) > 80 {
		return nil, fmt.Errorf("communityplus: upstream search query must contain 2 to 80 characters")
	}
	if limit <= 0 || limit > 20 {
		return nil, fmt.Errorf("communityplus: upstream search limit must be between 1 and 20")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	commit, err := githubDefaultBranchCommit(ctx, client)
	if err != nil {
		return nil, err
	}
	apiURL := "https://api.github.com/search/code?q=" + url.QueryEscape(query+" repo:"+wingetRepository+" path:manifests extension:yaml") + "&per_page=" + fmt.Sprint(limit*3)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("communityplus: search WinGet source: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("communityplus: WinGet source search returned HTTP %d; configure GITHUB_TOKEN on the server when GitHub requires authentication", res.StatusCode)
	}
	var search githubCodeSearchResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, res.Body, 2<<20)).Decode(&search); err != nil {
		return nil, fmt.Errorf("communityplus: decode WinGet source search: %w", err)
	}
	result := make([]upstreamWingetCandidate, 0, limit)
	seen := map[string]bool{}
	for _, item := range search.Items {
		if len(result) == limit || !strings.HasSuffix(strings.ToLower(item.Path), ".installer.yaml") {
			continue
		}
		sourceURL := "https://raw.githubusercontent.com/" + wingetRepository + "/" + commit + "/" + item.Path
		data, err := downloadPinnedManifestWithoutHash(ctx, sourceURL)
		if err != nil {
			continue
		}
		manifest, err := winget.Parse(data)
		if err != nil || seen[manifest.PackageIdentifier] {
			continue
		}
		seen[manifest.PackageIdentifier] = true
		sum := sha256.Sum256(data)
		result = append(result, upstreamWingetCandidate{DisplayName: manifest.PackageIdentifier, PackageID: manifest.PackageIdentifier, Version: manifest.PackageVersion, InstallerType: manifest.InstallerType, SourceURL: sourceURL, SourceSHA256: hex.EncodeToString(sum[:])})
	}
	return result, nil
}

func githubDefaultBranchCommit(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+wingetRepository+"/commits/master", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("communityplus: resolve WinGet source revision: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("communityplus: WinGet source revision returned HTTP %d", res.StatusCode)
	}
	var response struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil || len(response.SHA) != 40 {
		return "", fmt.Errorf("communityplus: invalid WinGet source revision")
	}
	return response.SHA, nil
}

func downloadPinnedManifestWithoutHash(ctx context.Context, rawURL string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected source status %d", res.StatusCode)
	}
	// The upstream YAMLs are small. A strict Content-Length guard avoids an
	// unbounded read before the parser sees the document.
	if res.ContentLength > 2<<20 {
		return nil, fmt.Errorf("source manifest exceeds 2 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return nil, fmt.Errorf("invalid source manifest size")
	}
	return data, nil
}
