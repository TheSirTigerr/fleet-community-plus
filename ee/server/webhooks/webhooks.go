// Package webhooks provides the legacy mapper construction boundary.
package webhooks

import communitywebhooks "github.com/fleetdm/fleet/v4/server/webhooks"

// NewMapper uses the Community mapper until Community+ supplies additional
// vulnerability metadata through its own capability.
func NewMapper() communitywebhooks.VulnMapper { return communitywebhooks.NewMapper() }
