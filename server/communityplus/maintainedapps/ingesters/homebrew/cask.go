package homebrew

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// CaskMetadata is the fixed, verifiable subset of a public Homebrew Cask. The
// parser intentionally rejects dynamic Ruby expressions and :no_check hashes.
// A reviewed Community+ entry supplies all endpoint commands separately.
type CaskMetadata struct {
	Name         string
	Version      string
	InstallerURL string
	SHA256       string
}

var (
	versionPattern = regexp.MustCompile(`(?m)^\s*version\s+["']([^"']+)["']\s*$`)
	shaPattern     = regexp.MustCompile(`(?m)^\s*sha256\s+["']([A-Fa-f0-9]{64})["']\s*$`)
	urlPattern     = regexp.MustCompile(`(?m)^\s*url\s+["']([^"']+)["']`)
	namePattern    = regexp.MustCompile(`(?m)^\s*name\s+["']([^"']+)["']`)
)

// ParseCask extracts a Cask only when its version, download URL, and SHA-256
// are literal values. A URL may interpolate only #{version}, which is replaced
// with the literal version before HTTPS validation.
func ParseCask(data []byte) (*CaskMetadata, error) {
	contents := string(data)
	version := capture(versionPattern, contents)
	hash := capture(shaPattern, contents)
	installerURL := capture(urlPattern, contents)
	name := capture(namePattern, contents)
	if version == "" || hash == "" || installerURL == "" || name == "" {
		return nil, fmt.Errorf("Homebrew Cask requires literal name, version, sha256, and url")
	}
	if strings.Contains(installerURL, "#{") && !strings.Contains(installerURL, "#{version}") {
		return nil, fmt.Errorf("Homebrew Cask URL contains unsupported Ruby interpolation")
	}
	installerURL = strings.ReplaceAll(installerURL, "#{version}", version)
	if strings.Contains(installerURL, "#{") {
		return nil, fmt.Errorf("Homebrew Cask URL contains unresolved interpolation")
	}
	u, err := url.ParseRequestURI(installerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("Homebrew Cask requires an HTTPS url")
	}
	decoded, err := hex.DecodeString(hash)
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("Homebrew Cask requires a SHA-256 sha256 value")
	}
	return &CaskMetadata{Name: name, Version: version, InstallerURL: installerURL, SHA256: strings.ToLower(hash)}, nil
}

func capture(pattern *regexp.Regexp, content string) string {
	match := pattern.FindStringSubmatch(content)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}
