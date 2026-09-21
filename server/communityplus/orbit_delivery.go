package communityplus

import (
	"context"
	"fmt"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

var OrbitDelivery *SQLStore

func providerForHost(host *fleet.Host) (CatalogProvider, bool) {
	if host == nil {
		return "", false
	}
	switch host.Platform {
	case "windows":
		return CatalogProviderWinget, true
	case "darwin":
		return CatalogProviderHomebrew, true
	default:
		return "", false
	}
}

func PendingOrbitDeployments(ctx context.Context, host *fleet.Host) ([]string, error) {
	provider, ok := providerForHost(host)
	if OrbitDelivery == nil || !ok || host.TeamID == nil {
		return nil, nil
	}
	return OrbitDelivery.PendingDeploymentIDsForProvider(ctx, host.ID, *host.TeamID, provider)
}

// OrbitWindowsPlan retains its original exported name for compatibility with
// the service endpoint, but now returns the reviewed plan for either supported
// endpoint platform.
func OrbitWindowsPlan(ctx context.Context, host *fleet.Host, id string) (*fleet.CommunityPlusInstallPlan, error) {
	provider, ok := providerForHost(host)
	if OrbitDelivery == nil || !ok || host.TeamID == nil {
		return nil, fmt.Errorf("Community+ deployment is unavailable for this host")
	}
	d, err := OrbitDelivery.GetDeployment(ctx, id)
	if err != nil {
		return nil, err
	}
	if !d.Automatic || d.Scope.FleetID != *host.TeamID {
		return nil, fmt.Errorf("Community+ deployment is not assigned to this host")
	}
	e, err := OrbitDelivery.GetCatalogEntry(ctx, d.CatalogEntryID)
	if err != nil {
		return nil, err
	}
	if e.Provider != provider {
		return nil, fmt.Errorf("Community+ deployment provider does not match host platform")
	}

	switch provider {
	case CatalogProviderWinget:
		p, err := NewWindowsInstallPlan(d, e)
		if err != nil {
			return nil, err
		}
		return &fleet.CommunityPlusInstallPlan{
			DeploymentID: p.DeploymentID, PackageID: p.PackageID, Version: p.Version,
			InstallerURL: p.InstallerURL, SHA256: p.SHA256, InstallerType: p.InstallerType,
			ProductCode: p.ProductCode, Platform: "windows",
		}, nil
	case CatalogProviderHomebrew:
		p, err := NewMacOSInstallPlan(d, e)
		if err != nil {
			return nil, err
		}
		return &fleet.CommunityPlusInstallPlan{
			DeploymentID: p.DeploymentID, PackageID: p.PackageID, Version: p.Version,
			InstallerURL: p.InstallerURL, SHA256: p.SHA256, InstallerType: p.InstallerType,
			Platform: "darwin",
		}, nil
	default:
		return nil, fmt.Errorf("Community+ deployment provider is unsupported")
	}
}

func RecordOrbitDeploymentResult(ctx context.Context, host *fleet.Host, result *fleet.CommunityPlusDeploymentResult) error {
	provider, ok := providerForHost(host)
	if OrbitDelivery == nil || !ok || result == nil {
		return fmt.Errorf("Community+ deployment result is unavailable")
	}
	d, err := OrbitDelivery.GetDeployment(ctx, result.DeploymentID)
	if err != nil {
		return err
	}
	if host.TeamID == nil || d.Scope.FleetID != *host.TeamID {
		return fmt.Errorf("Community+ deployment is not assigned to this host")
	}
	e, err := OrbitDelivery.GetCatalogEntry(ctx, d.CatalogEntryID)
	if err != nil {
		return err
	}
	if e.Provider != provider {
		return fmt.Errorf("Community+ deployment provider does not match host platform")
	}
	return OrbitDelivery.RecordDeploymentResult(ctx, host.ID, *result)
}
