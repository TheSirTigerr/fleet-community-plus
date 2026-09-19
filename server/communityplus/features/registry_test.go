package features

import (
	"errors"
	"reflect"
	"testing"
)

func TestEnableAddsDependencies(t *testing.T) {
	r := NewRegistry()
	if err := r.Enable(FeaturePatchManagement); err != nil {
		t.Fatal(err)
	}

	for _, feature := range []Feature{
		FeatureFleets,
		FeatureAuditLog,
		FeaturePolicyAutomation,
		FeatureSoftwareAutomation,
		FeaturePatchManagement,
	} {
		if !r.Enabled(feature) {
			t.Fatalf("expected %s to be enabled", feature)
		}
	}
}

func TestDisableProtectsDependencies(t *testing.T) {
	r := NewRegistry()
	if err := r.Enable(FeatureConditionalAccess); err != nil {
		t.Fatal(err)
	}
	if err := r.Disable(FeatureMDM); !errors.Is(err, ErrDependencyInUse) {
		t.Fatalf("expected ErrDependencyInUse, got %v", err)
	}
}

func TestRequire(t *testing.T) {
	r := NewRegistry()
	if err := r.Require(FeatureGitOps); !errors.Is(err, ErrFeatureDisabled) {
		t.Fatalf("expected ErrFeatureDisabled, got %v", err)
	}
	if err := r.Enable(FeatureGitOps); err != nil {
		t.Fatal(err)
	}
	if err := r.Require(FeatureGitOps); err != nil {
		t.Fatalf("expected enabled feature, got %v", err)
	}
}

func TestListIsStable(t *testing.T) {
	r := NewRegistry()
	if err := r.Enable(FeatureAdvancedRBAC); err != nil {
		t.Fatal(err)
	}
	if err := r.Enable(FeatureAuditLog); err != nil {
		t.Fatal(err)
	}

	want := []Feature{FeatureAdvancedRBAC, FeatureAuditLog, FeatureFleets}
	if got := r.List(); !reflect.DeepEqual(got, want) {
		t.Fatalf("List() = %v, want %v", got, want)
	}
}

func TestUnknownFeature(t *testing.T) {
	r := NewRegistry()
	if err := r.Enable(Feature("not-real")); !errors.Is(err, ErrUnknownFeature) {
		t.Fatalf("expected ErrUnknownFeature, got %v", err)
	}
}
