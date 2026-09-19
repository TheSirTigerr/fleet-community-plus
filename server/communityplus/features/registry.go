package features

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Feature identifies an independently implementable Community+ capability.
type Feature string

const (
	FeatureFleets                  Feature = "fleets"
	FeatureAdvancedRBAC            Feature = "advanced_rbac"
	FeatureAuditLog                Feature = "audit_log"
	FeaturePolicyAutomation        Feature = "policy_automation"
	FeatureSoftwareAutomation      Feature = "software_automation"
	FeaturePatchManagement         Feature = "patch_management"
	FeatureMDM                     Feature = "mdm"
	FeatureIdentityProvisioning    Feature = "identity_provisioning"
	FeatureConditionalAccess       Feature = "conditional_access"
	FeatureVulnerabilityEnrichment Feature = "vulnerability_enrichment"
	FeatureGitOps                  Feature = "gitops"
)

var (
	ErrUnknownFeature  = errors.New("unknown Community+ feature")
	ErrFeatureDisabled = errors.New("Community+ feature is disabled")
	ErrDependencyInUse = errors.New("Community+ feature is required by another enabled feature")
)

var dependencies = map[Feature][]Feature{
	FeatureAdvancedRBAC:       {FeatureFleets},
	FeaturePolicyAutomation:   {FeatureFleets, FeatureAuditLog},
	FeatureSoftwareAutomation: {FeaturePolicyAutomation},
	FeaturePatchManagement:    {FeatureSoftwareAutomation},
	FeatureMDM:                {FeatureFleets},
	FeatureIdentityProvisioning: {
		FeatureAdvancedRBAC,
	},
	FeatureConditionalAccess: {
		FeatureIdentityProvisioning,
		FeatureMDM,
	},
	FeatureGitOps: {FeatureFleets},
}

var knownFeatures = map[Feature]struct{}{
	FeatureFleets:                  {},
	FeatureAdvancedRBAC:            {},
	FeatureAuditLog:                {},
	FeaturePolicyAutomation:        {},
	FeatureSoftwareAutomation:      {},
	FeaturePatchManagement:         {},
	FeatureMDM:                     {},
	FeatureIdentityProvisioning:    {},
	FeatureConditionalAccess:       {},
	FeatureVulnerabilityEnrichment: {},
	FeatureGitOps:                  {},
}

// Registry tracks Community+ capabilities independently from Fleet's
// commercial licensing. A feature is only enabled after its implementation is
// deliberately registered by Community+ startup code.
type Registry struct {
	mu      sync.RWMutex
	enabled map[Feature]struct{}
}

func NewRegistry() *Registry {
	return &Registry{enabled: make(map[Feature]struct{})}
}

// Known returns all feature identifiers understood by this build.
func Known() []Feature {
	out := make([]Feature, 0, len(knownFeatures))
	for feature := range knownFeatures {
		out = append(out, feature)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Enable enables feature and all of its declared dependencies.
func (r *Registry) Enable(feature Feature) error {
	if !isKnown(feature) {
		return fmt.Errorf("%w: %s", ErrUnknownFeature, feature)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enableLocked(feature, make(map[Feature]bool))
}

func (r *Registry) enableLocked(feature Feature, visiting map[Feature]bool) error {
	if _, ok := r.enabled[feature]; ok {
		return nil
	}
	if visiting[feature] {
		return fmt.Errorf("feature dependency cycle at %s", feature)
	}
	visiting[feature] = true
	defer delete(visiting, feature)

	for _, dependency := range dependencies[feature] {
		if !isKnown(dependency) {
			return fmt.Errorf("%w: dependency %s of %s", ErrUnknownFeature, dependency, feature)
		}
		if err := r.enableLocked(dependency, visiting); err != nil {
			return err
		}
	}
	r.enabled[feature] = struct{}{}
	return nil
}

// Disable disables feature if no currently enabled feature depends on it.
func (r *Registry) Disable(feature Feature) error {
	if !isKnown(feature) {
		return fmt.Errorf("%w: %s", ErrUnknownFeature, feature)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for enabled := range r.enabled {
		if enabled != feature && dependsOn(enabled, feature, make(map[Feature]bool)) {
			return fmt.Errorf("%w: %s requires %s", ErrDependencyInUse, enabled, feature)
		}
	}
	delete(r.enabled, feature)
	return nil
}

// Enabled reports whether feature is currently enabled.
func (r *Registry) Enabled(feature Feature) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.enabled[feature]
	return ok
}

// Require returns an error when feature is not enabled.
func (r *Registry) Require(feature Feature) error {
	if !isKnown(feature) {
		return fmt.Errorf("%w: %s", ErrUnknownFeature, feature)
	}
	if !r.Enabled(feature) {
		return fmt.Errorf("%w: %s", ErrFeatureDisabled, feature)
	}
	return nil
}

// List returns the currently enabled features in stable order.
func (r *Registry) List() []Feature {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Feature, 0, len(r.enabled))
	for feature := range r.enabled {
		out = append(out, feature)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func isKnown(feature Feature) bool {
	_, ok := knownFeatures[feature]
	return ok
}

func dependsOn(feature, dependency Feature, visited map[Feature]bool) bool {
	if visited[feature] {
		return false
	}
	visited[feature] = true
	for _, current := range dependencies[feature] {
		if current == dependency || dependsOn(current, dependency, visited) {
			return true
		}
	}
	return false
}
