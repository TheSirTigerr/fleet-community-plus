package servicecompat

import (
	"context"

	"github.com/fleetdm/fleet/v4/server/authz"
	licensectx "github.com/fleetdm/fleet/v4/server/contexts/license"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

var communityPlusVulnerabilitySortColumns = []string{
	"cve",
	"cvss_score",
	"epss_probability",
	"cisa_known_exploit",
	"cve_published",
	"created_at",
	"host_count",
	"hosts_count",
	"host_count_updated_at",
	"hosts_count_updated_at",
}

// vulnerabilityEnrichmentWrapper enables the already-existing Fleet Community
// vulnerability metadata queries without changing authorization or scope rules.
type vulnerabilityEnrichmentWrapper struct {
	fleet.Service
	ds         fleet.Datastore
	authorizer *authz.Authorizer
}

func wrapVulnerabilityEnrichment(base fleet.Service, options []any) fleet.Service {
	if base == nil {
		return nil
	}
	var ds fleet.Datastore
	for _, option := range options {
		if value, ok := option.(fleet.Datastore); ok {
			ds = value
			break
		}
	}
	return &vulnerabilityEnrichmentWrapper{Service: base, ds: ds, authorizer: authz.Must()}
}

func (s *vulnerabilityEnrichmentWrapper) ListVulnerabilities(
	ctx context.Context,
	opt fleet.VulnListOptions,
) ([]fleet.VulnerabilityWithMetadata, *fleet.PaginationMetadata, error) {
	opt.IsEE = true
	if len(opt.ValidSortColumns) == 0 {
		opt.ValidSortColumns = append([]string(nil), communityPlusVulnerabilitySortColumns...)
	}
	return s.Service.ListVulnerabilities(ctx, opt)
}

func (s *vulnerabilityEnrichmentWrapper) Vulnerability(
	ctx context.Context,
	cve string,
	teamID *uint,
	_ bool,
) (*fleet.VulnerabilityWithMetadata, bool, error) {
	return s.Service.Vulnerability(ctx, cve, teamID, true)
}

var _ fleet.Service = (*vulnerabilityEnrichmentWrapper)(nil)

func hasCommunityPlusVulnerabilitySoftwareFilter(opt fleet.SoftwareListOptions) bool {
	return opt.MaximumCVSS > 0 || opt.MinimumCVSS > 0 || opt.KnownExploit
}

func (s *vulnerabilityEnrichmentWrapper) ListSoftware(
	ctx context.Context,
	opt fleet.SoftwareListOptions,
) ([]fleet.Software, *fleet.PaginationMetadata, error) {
	if !hasCommunityPlusVulnerabilitySoftwareFilter(opt) || s.ds == nil {
		return s.Service.ListSoftware(ctx, opt)
	}
	if err := s.authorizer.Authorize(ctx, &fleet.AuthzSoftwareInventory{TeamID: opt.TeamID}, fleet.ActionRead); err != nil {
		return nil, nil, err
	}

	opt.IncludeCVEScores = true
	if opt.ListOptions.OrderKey == "" {
		opt.ListOptions.OrderKey = "hosts_count"
		opt.ListOptions.OrderDirection = fleet.OrderDescending
	}
	opt.WithHostCounts = true
	return s.ds.ListSoftware(ctx, opt)
}

func (s *vulnerabilityEnrichmentWrapper) CountSoftware(
	ctx context.Context,
	opt fleet.SoftwareListOptions,
) (int, error) {
	if !hasCommunityPlusVulnerabilitySoftwareFilter(opt) || s.ds == nil {
		return s.Service.CountSoftware(ctx, opt)
	}
	if err := s.authorizer.Authorize(ctx, &fleet.AuthzSoftwareInventory{TeamID: opt.TeamID}, fleet.ActionRead); err != nil {
		return 0, err
	}

	opt.IncludeCVEScores = true
	return s.ds.CountSoftware(ctx, opt)
}

type communityPlusVulnerabilityLicense struct{}

func (communityPlusVulnerabilityLicense) IsPremium() bool               { return true }
func (communityPlusVulnerabilityLicense) IsAllowDisableTelemetry() bool { return false }
func (communityPlusVulnerabilityLicense) GetTier() string               { return "community-plus" }
func (communityPlusVulnerabilityLicense) GetOrganization() string       { return "" }
func (communityPlusVulnerabilityLicense) GetDeviceCount() int           { return 0 }

var _ licensectx.LicenseChecker = communityPlusVulnerabilityLicense{}

func hasCommunityPlusHostVulnerabilityFilter(opt fleet.HostSoftwareTitleListOptions) bool {
	return opt.MaximumCVSS > 0 || opt.MinimumCVSS > 0 || opt.KnownExploit
}

func (s *vulnerabilityEnrichmentWrapper) ListHostSoftware(
	ctx context.Context,
	hostID uint,
	opt fleet.HostSoftwareTitleListOptions,
) ([]*fleet.HostSoftwareWithInstaller, *fleet.PaginationMetadata, error) {
	if !hasCommunityPlusHostVulnerabilityFilter(opt) || licensectx.IsPremium(ctx) {
		return s.Service.ListHostSoftware(ctx, hostID, opt)
	}
	return s.Service.ListHostSoftware(
		licensectx.NewContext(ctx, communityPlusVulnerabilityLicense{}),
		hostID,
		opt,
	)
}
