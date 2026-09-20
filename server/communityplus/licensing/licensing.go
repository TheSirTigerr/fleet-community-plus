// Package licensing provides Community+'s edition identity. It deliberately
// does not parse, mint, or bypass Fleet Enterprise license tokens.
package licensing

import (
	"errors"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

var ErrExternalLicenseUnsupported = errors.New("Fleet Enterprise license verification is not available in Community+")

// Load returns Fleet's free-license identity when no external license token is
// configured. Community+ capabilities are controlled by the separate feature
// registry, not by pretending to hold a Fleet Premium license.
func Load(key string) (*fleet.LicenseInfo, error) {
	if strings.TrimSpace(key) != "" {
		return nil, ErrExternalLicenseUnsupported
	}
	return &fleet.LicenseInfo{Tier: fleet.TierFree}, nil
}
