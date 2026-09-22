package communityplus

// newRuntimeRegistry describes the maturity of capabilities wired into the
// production Fleet server. NewRegistry intentionally remains all-planned for
// callers that want an empty capability set.
func newRuntimeRegistry() *Registry {
	registry := NewRegistry()
	mustSetRuntimeStatus(registry, FeatureRBAC, StatusAvailable)
	mustSetRuntimeStatus(registry, FeatureAuditLog, StatusAvailable)
	mustSetRuntimeStatus(registry, FeatureSoftwareAutomation, StatusExperimental)
	mustSetRuntimeStatus(registry, FeaturePatchPolicies, StatusExperimental)
	return registry
}

func mustSetRuntimeStatus(registry *Registry, feature Feature, status FeatureStatus) {
	if err := registry.SetStatus(feature, status); err != nil {
		panic(err)
	}
}
