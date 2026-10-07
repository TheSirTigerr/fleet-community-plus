package servicecompat

import (
	"context"

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
}

func wrapVulnerabilityEnrichment(base fleet.Service) fleet.Service {
	if base == nil {
		return nil
	}
	return &vulnerabilityEnrichmentWrapper{Service: base}
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
