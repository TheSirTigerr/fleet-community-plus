package fleetctl

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type fakeCommunityPlusCapabilityClient struct {
	status int
	body   string
}

func (f fakeCommunityPlusCapabilityClient) AuthenticatedDo(_, _, _ string, _ interface{}) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
	}, nil
}

func TestCommunityPlusFeatureEnabled(t *testing.T) {
	client := fakeCommunityPlusCapabilityClient{
		status: http.StatusOK,
		body: `{"capabilities":[
			{"feature":"fleets","status":"available"},
			{"feature":"gitops","status":"planned"},
			{"feature":"software_automation","status":"experimental"}
		]}`,
	}

	enabled, err := communityPlusFeatureEnabled(client, "fleets")
	if err != nil || !enabled {
		t.Fatalf("fleets enabled=%v err=%v", enabled, err)
	}
	enabled, err = communityPlusFeatureEnabled(client, "gitops")
	if err != nil || enabled {
		t.Fatalf("planned gitops enabled=%v err=%v", enabled, err)
	}
	enabled, err = communityPlusFeatureEnabled(client, "software_automation")
	if err != nil || !enabled {
		t.Fatalf("experimental software enabled=%v err=%v", enabled, err)
	}
}

func TestCommunityPlusFeatureEnabledTreatsMissingEndpointAsUnsupported(t *testing.T) {
	enabled, err := communityPlusFeatureEnabled(fakeCommunityPlusCapabilityClient{status: http.StatusNotFound}, "fleets")
	if err != nil || enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
}

func TestFleetGitOpsSupported(t *testing.T) {
	communityPlus := fakeCommunityPlusCapabilityClient{
		status: http.StatusOK,
		body:   `{"capabilities":[{"feature":"fleets","status":"available"}]}`,
	}
	enabled, err := fleetGitOpsSupported(&fleet.LicenseInfo{Tier: fleet.TierFree}, communityPlus)
	if err != nil || !enabled {
		t.Fatalf("Community+ fleet GitOps enabled=%v err=%v", enabled, err)
	}

	missing := fakeCommunityPlusCapabilityClient{status: http.StatusNotFound}
	enabled, err = fleetGitOpsSupported(&fleet.LicenseInfo{Tier: fleet.TierFree}, missing)
	if err != nil || enabled {
		t.Fatalf("regular free Fleet GitOps enabled=%v err=%v", enabled, err)
	}

	enabled, err = fleetGitOpsSupported(&fleet.LicenseInfo{Tier: fleet.TierPremium}, fakeCommunityPlusCapabilityClient{status: http.StatusInternalServerError})
	if err != nil || !enabled {
		t.Fatalf("Premium Fleet GitOps enabled=%v err=%v", enabled, err)
	}
}
