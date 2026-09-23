package communityplus

import "testing"

func TestRuntimeRegistryPublishesOnlyWiredCapabilities(t *testing.T) {
	registry := newRuntimeRegistry()
	checks := map[Feature]FeatureStatus{
		FeatureFleets:               StatusAvailable,
		FeatureRBAC:                 StatusAvailable,
		FeatureAuditLog:             StatusAvailable,
		FeatureFleetPoliciesQueries: StatusAvailable,
		FeatureReports:              StatusAvailable,
		FeatureCustomTables:         StatusAvailable,
		FeatureGitOps:               StatusAvailable,
		FeatureSSO:                  StatusAvailable,
		FeatureSCIM:                 StatusAvailable,
		FeatureConditionalAccess:    StatusAvailable,
		FeatureAccountPasswordSync:  StatusAvailable,
		FeatureSoftwareAutomation:   StatusExperimental,
		FeaturePatchPolicies:        StatusExperimental,
	}
	for feature, want := range checks {
		got, ok := registry.Status(feature)
		if !ok || got != want {
			t.Fatalf("feature %s status=%q ok=%v, want %q", feature, got, ok, want)
		}
	}
}
