package servicecompat

import (
	"context"
	"slices"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
	servicemock "github.com/fleetdm/fleet/v4/server/mock/service"
	"github.com/fleetdm/fleet/v4/server/test"
)

func TestVulnerabilityEnrichmentWrapperListsEnrichedMetadata(t *testing.T) {
	base := new(servicemock.Service)
	var got fleet.VulnListOptions
	base.ListVulnerabilitiesFunc = func(_ context.Context, opt fleet.VulnListOptions) ([]fleet.VulnerabilityWithMetadata, *fleet.PaginationMetadata, error) {
		got = opt
		return []fleet.VulnerabilityWithMetadata{{CVE: fleet.CVE{CVE: "CVE-2026-1234"}}}, nil, nil
	}

	svc := wrapVulnerabilityEnrichment(base, nil)
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

	svc := wrapVulnerabilityEnrichment(base, nil)
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

func TestVulnerabilityEnrichmentWrapperUnlocksSoftwareCVSSAndKEVFilters(t *testing.T) {
	base := new(servicemock.Service)
	ds := new(mock.Store)
	var gotList, gotCount fleet.SoftwareListOptions
	ds.ListSoftwareFunc = func(_ context.Context, opt fleet.SoftwareListOptions) ([]fleet.Software, *fleet.PaginationMetadata, error) {
		gotList = opt
		return []fleet.Software{{Name: "Example"}}, nil, nil
	}
	ds.CountSoftwareFunc = func(_ context.Context, opt fleet.SoftwareListOptions) (int, error) {
		gotCount = opt
		return 1, nil
	}

	svc := wrapVulnerabilityEnrichment(base, []any{ds})
	role := fleet.RoleAdmin
	ctx := test.UserContext(context.Background(), &fleet.User{GlobalRole: &role})
	teamID := uint(7)
	opt := fleet.SoftwareListOptions{
		TeamID:       &teamID,
		MinimumCVSS:  7,
		MaximumCVSS:  10,
		KnownExploit: true,
	}

	software, _, err := svc.ListSoftware(ctx, opt)
	if err != nil {
		t.Fatalf("list software with vulnerability filters: %v", err)
	}
	if len(software) != 1 {
		t.Fatalf("unexpected software: %#v", software)
	}
	if !gotList.IncludeCVEScores || !gotList.WithHostCounts || !gotList.KnownExploit ||
		gotList.MinimumCVSS != 7 || gotList.MaximumCVSS != 10 ||
		gotList.ListOptions.OrderKey != "hosts_count" ||
		gotList.ListOptions.OrderDirection != fleet.OrderDescending {
		t.Fatalf("vulnerability software list options not enabled: %#v", gotList)
	}

	count, err := svc.CountSoftware(ctx, opt)
	if err != nil {
		t.Fatalf("count software with vulnerability filters: %v", err)
	}
	if count != 1 || !gotCount.IncludeCVEScores || !gotCount.KnownExploit ||
		gotCount.MinimumCVSS != 7 || gotCount.MaximumCVSS != 10 {
		t.Fatalf("vulnerability software count options not enabled: count=%d opts=%#v", count, gotCount)
	}
}

func TestVulnerabilityEnrichmentWrapperKeepsNormalSoftwarePath(t *testing.T) {
	base := new(servicemock.Service)
	called := false
	base.ListSoftwareFunc = func(_ context.Context, opt fleet.SoftwareListOptions) ([]fleet.Software, *fleet.PaginationMetadata, error) {
		called = true
		return nil, nil, nil
	}

	svc := wrapVulnerabilityEnrichment(base, nil)
	if _, _, err := svc.ListSoftware(context.Background(), fleet.SoftwareListOptions{}); err != nil {
		t.Fatalf("normal software path: %v", err)
	}
	if !called {
		t.Fatal("normal software request did not delegate to base service")
	}
}
