// Package communityplus contains independently implemented Community+ capabilities.
//
// Code in this package must not depend on Fleet's restricted Enterprise Edition
// implementation. Public API contracts and Community interfaces may be used as
// integration specifications.
package communityplus

import (
	"fmt"
	"sort"
	"sync"
)

// Feature identifies a Community+ capability.
type Feature string

const (
	FeatureFleets                  Feature = "fleets"
	FeatureRBAC                    Feature = "rbac"
	FeatureAuditLog                Feature = "audit_log"
	FeaturePolicyAutomation        Feature = "policy_automation"
	FeatureFleetPoliciesQueries    Feature = "fleet_policies_queries"
	FeatureSoftwareAutomation      Feature = "software_automation"
	FeaturePatchPolicies           Feature = "patch_policies"
	FeatureAdvancedMDM             Feature = "advanced_mdm"
	FeatureZeroTouch               Feature = "zero_touch"
	FeatureSSO                     Feature = "sso"
	FeatureSCIM                    Feature = "scim"
	FeatureConditionalAccess       Feature = "conditional_access"
	FeatureVulnerabilityEnrichment Feature = "vulnerability_enrichment"
	FeatureGitOps                  Feature = "gitops"
	FeatureDiskEncryption          Feature = "disk_encryption"
	FeatureRemoteActions           Feature = "remote_actions"
	FeatureReports                 Feature = "reports"
	FeatureCustomTables            Feature = "custom_tables"
	FeatureCertificates            Feature = "certificates"
	FeatureAgentControls           Feature = "agent_controls"
)

// FeatureStatus describes implementation maturity. It intentionally replaces
// a license-gated boolean so unfinished functionality cannot be presented as
// available merely because a license check was bypassed.
type FeatureStatus string

const (
	StatusPlanned      FeatureStatus = "planned"
	StatusExperimental FeatureStatus = "experimental"
	StatusAvailable    FeatureStatus = "available"
)

var knownFeatures = []Feature{
	FeatureFleets,
	FeatureRBAC,
	FeatureAuditLog,
	FeaturePolicyAutomation,
	FeatureFleetPoliciesQueries,
	FeatureSoftwareAutomation,
	FeaturePatchPolicies,
	FeatureAdvancedMDM,
	FeatureZeroTouch,
	FeatureSSO,
	FeatureSCIM,
	FeatureConditionalAccess,
	FeatureVulnerabilityEnrichment,
	FeatureGitOps,
	FeatureDiskEncryption,
	FeatureRemoteActions,
	FeatureReports,
	FeatureCustomTables,
	FeatureCertificates,
	FeatureAgentControls,
}

// Capability describes a feature and its current implementation status.
type Capability struct {
	Feature Feature       `json:"feature"`
	Status  FeatureStatus `json:"status"`
}

// Registry tracks Community+ implementation maturity at runtime.
type Registry struct {
	mu       sync.RWMutex
	statuses map[Feature]FeatureStatus
}

// NewRegistry returns a registry with all known features explicitly planned.
func NewRegistry() *Registry {
	statuses := make(map[Feature]FeatureStatus, len(knownFeatures))
	for _, feature := range knownFeatures {
		statuses[feature] = StatusPlanned
	}
	return &Registry{statuses: statuses}
}

func isKnownFeature(feature Feature) bool {
	for _, candidate := range knownFeatures {
		if candidate == feature {
			return true
		}
	}
	return false
}

func validFeatureStatus(status FeatureStatus) bool {
	switch status {
	case StatusPlanned, StatusExperimental, StatusAvailable:
		return true
	default:
		return false
	}
}

// SetStatus changes the implementation maturity for a known capability.
func (r *Registry) SetStatus(feature Feature, status FeatureStatus) error {
	if r == nil {
		return fmt.Errorf("communityplus: nil capability registry")
	}
	if !isKnownFeature(feature) {
		return fmt.Errorf("communityplus: unknown feature %q", feature)
	}
	if !validFeatureStatus(status) {
		return fmt.Errorf("communityplus: invalid feature status %q", status)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses[feature] = status
	return nil
}

// Status reports the current status of a feature.
func (r *Registry) Status(feature Feature) (FeatureStatus, bool) {
	if r == nil {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	status, ok := r.statuses[feature]
	return status, ok
}

// Enabled reports whether a feature can be served to users.
func (r *Registry) Enabled(feature Feature) bool {
	status, ok := r.Status(feature)
	return ok && (status == StatusExperimental || status == StatusAvailable)
}

// Capabilities returns a stable, sorted snapshot suitable for APIs and UI.
func (r *Registry) Capabilities() []Capability {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Capability, 0, len(r.statuses))
	for feature, status := range r.statuses {
		result = append(result, Capability{Feature: feature, Status: status})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Feature < result[j].Feature })
	return result
}
