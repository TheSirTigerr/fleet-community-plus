package fleetctl

import (
	"strings"
	"testing"

	"github.com/fleetdm/fleet/v4/pkg/spec"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestValidateCommunityPlusFleetNames(t *testing.T) {
	nameA := "Café"
	nameB := "CAFE\u0301"
	configs := []ConfigFile{
		{Filename: "a.yml", Config: &spec.GitOps{TeamName: &nameA}},
		{Filename: "b.yml", Config: &spec.GitOps{TeamName: &nameB}},
	}
	if err := validateCommunityPlusFleetNames(configs); err == nil || !strings.Contains(err.Error(), "duplicate fleet names") {
		t.Fatalf("expected normalized duplicate fleet name error, got %v", err)
	}
}

func TestContainsNormalizedFleetName(t *testing.T) {
	if !containsNormalizedFleetName([]string{"Café"}, "CAFE\u0301") {
		t.Fatal("expected Unicode-normalized fleet name match")
	}
	if containsNormalizedFleetName([]string{"Fleet A"}, "Fleet B") {
		t.Fatal("unexpected fleet name match")
	}
}

func TestContainsNoTeamConfig(t *testing.T) {
	name := fleet.TeamNameNoTeam
	configs := []ConfigFile{{Filename: "unassigned.yml", Config: &spec.GitOps{TeamName: &name}}}
	if !containsNoTeamConfig(configs) {
		t.Fatal("expected unassigned config to be detected")
	}
}

func TestValidateCommunityPlusGitOpsConfigAcceptsCommunityConfig(t *testing.T) {
	if err := validateCommunityPlusGitOpsConfig(&spec.GitOps{}, "fleet.yml"); err != nil {
		t.Fatalf("unexpected Community+ GitOps validation error: %v", err)
	}
}
