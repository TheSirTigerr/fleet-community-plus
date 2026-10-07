package servicecompat

import (
	"context"
	"slices"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	servicemock "github.com/fleetdm/fleet/v4/server/mock/service"
)

func TestVulnerabilityEnrichmentWrapperListsEnrichedMetadata(t *testing.T) {
	base := new(servicemock.Service)
	var got fleet.VulnListOptions
	base.ListVulnerabilitiesFunc = func(_ context.Context, opt fleet.VulnListOptions) ([]fleet.VulnerabilityWithMetadata, *fleet.PaginationMetadata, error) {
		got = opt
		return []fleet.VulnerabilityWithMetadata{{CVE: fleet.CVE{CVE: "CVE-2026-1234"}}}, nil, nil
	}

	svc := wrapVulnerabilityEnrichment(base)
	teamID := uint(7)
	vulns, _, err := svc.ListVulnerabilities(context.Background(), fleet.VulnListOptions{
		TeamID:       &teamID,
		KnownExploit: true,
	})
	if err != nil {
		t.Fatalf("list enriched vulnerabilities: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("unexpected vulnerabilities: %#v", vulns)
	}
	if !got.IsEE || !got.KnownExploit || got.TeamID == nil || *got.TeamID != teamID {
		t.Fatalf("enrichment options not preserved/enabled: %#v", got)
	}
	for _, key := range []string{"cvss_score", "epss_probability", "cisa_known_exploit", "cve_published"} {
		if !slices.Contains(got.ValidSortColumns, key) {
			t.Fatalf("missing enriched sort column %q: %#v", key, got.ValidSortColumns)
		}
	}
}

func TestVulnerabilityEnrichmentWrapperGetsEnrichedDetail(t *testing.T) {
	base := new(servicemock.Service)
	var (
		gotCVE       string
		gotTeamID    *uint
		gotUseScores bool
	)
	base.VulnerabilityFunc = func(_ context.Context, cve string, teamID *uint, useScores bool) (*fleet.VulnerabilityWithMetadata, bool, error) {
		gotCVE, gotTeamID, gotUseScores = cve, teamID, useScores
		return &fleet.VulnerabilityWithMetadata{CVE: fleet.CVE{CVE: cve}}, true, nil
	}

	svc := wrapVulnerabilityEnrichment(base)
	teamID := uint(9)
	vuln, known, err := svc.Vulnerability(context.Background(), "CVE-2026-5678", &teamID, false)
	if err != nil {
		t.Fatalf("get enriched vulnerability: %v", err)
	}
	if vuln == nil || !known {
		t.Fatalf("unexpected vulnerability result: %#v known=%v", vuln, known)
	}
	if gotCVE != "CVE-2026-5678" || gotTeamID == nil || *gotTeamID != teamID || !gotUseScores {
		t.Fatalf("enrichment detail options not applied: cve=%q team=%v scores=%v", gotCVE, gotTeamID, gotUseScores)
	}
}
