package fleetctl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type communityPlusCapabilityDoer interface {
	AuthenticatedDo(verb, path, rawQuery string, params interface{}) (*http.Response, error)
}

type communityPlusCapability struct {
	Feature string `json:"feature"`
	Status  string `json:"status"`
}

type communityPlusCapabilitiesResponse struct {
	Capabilities []communityPlusCapability `json:"capabilities"`
}

// communityPlusFeatureEnabled asks a Community+ server for one independently
// implemented capability. A 404 means the target is a regular Fleet server (or
// an older Community+ server) and is intentionally treated as unsupported.
func communityPlusFeatureEnabled(client communityPlusCapabilityDoer, feature string) (bool, error) {
	resp, err := client.AuthenticatedDo(http.MethodGet, "/api/v1/fleet/communityplus/capabilities", "", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("Community+ capabilities returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var payload communityPlusCapabilitiesResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, fmt.Errorf("decode Community+ capabilities: %w", err)
	}
	for _, capability := range payload.Capabilities {
		if capability.Feature == feature {
			return capability.Status == "available" || capability.Status == "experimental", nil
		}
	}
	return false, nil
}

// fleetGitOpsSupported preserves Fleet Premium behavior while allowing a
// Community+ server that independently implements fleets to accept fleet-scoped
// GitOps files. It does not turn the Fleet license into Premium, so unrelated
// Premium-only GitOps keys keep their existing validation and gating.
func fleetGitOpsSupported(license *fleet.LicenseInfo, client communityPlusCapabilityDoer) (bool, error) {
	if license != nil && license.IsPremium() {
		return true, nil
	}
	return communityPlusFeatureEnabled(client, "fleets")
}
