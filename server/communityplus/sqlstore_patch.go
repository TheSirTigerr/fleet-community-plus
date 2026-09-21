package communityplus

import (
	"context"
	"fmt"
)

// patchingCatalogStore promotes patch-enabled deployments immediately after a
// reviewed catalog version is imported. Embedding keeps the normal CatalogStore
// behavior unchanged for every other operation.
type patchingCatalogStore struct {
	*SQLStore
}

func newPatchingCatalogStore(store *SQLStore) CatalogStore {
	return &patchingCatalogStore{SQLStore: store}
}

func (s *patchingCatalogStore) UpsertCatalogEntry(ctx context.Context, entry CatalogEntry) error {
	if err := s.SQLStore.UpsertCatalogEntry(ctx, entry); err != nil {
		return err
	}
	return s.SQLStore.PromotePatchDeployments(ctx, entry)
}

// PromotePatchDeployments moves patch-enabled deployments to a newer reviewed
// entry only when package identity and installer type are unchanged and the
// version ordering is unambiguous. Existing results are cleared so successful
// hosts receive the newly reviewed version and failed-attempt counters restart.
func (s *SQLStore) PromotePatchDeployments(ctx context.Context, candidate CatalogEntry) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT d.id, e.id, e.provider, e.package_identifier, e.version, e.installer_type
FROM communityplus_catalog_deployments d
JOIN communityplus_catalog_entries e ON e.id = d.catalog_entry_id
WHERE d.patch = 1 AND e.provider = ? AND e.package_identifier = ?`, candidate.Provider, candidate.PackageIdentifier)
	if err != nil {
		return fmt.Errorf("communityplus: list patch deployments: %w", err)
	}

	type promotion struct {
		deploymentID string
		entryID      string
	}
	var promotions []promotion
	for rows.Next() {
		var deploymentID string
		var current CatalogEntry
		if err := rows.Scan(&deploymentID, &current.ID, &current.Provider, &current.PackageIdentifier, &current.Version, &current.InstallerType); err != nil {
			rows.Close()
			return fmt.Errorf("communityplus: scan patch deployment: %w", err)
		}
		if safePatchUpgrade(current, candidate) {
			promotions = append(promotions, promotion{deploymentID: deploymentID, entryID: current.ID})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("communityplus: iterate patch deployments: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("communityplus: close patch deployment rows: %w", err)
	}

	for _, promotion := range promotions {
		result, err := s.db.ExecContext(ctx, `UPDATE communityplus_catalog_deployments SET catalog_entry_id = ? WHERE id = ? AND catalog_entry_id = ?`, candidate.ID, promotion.deploymentID, promotion.entryID)
		if err != nil {
			return fmt.Errorf("communityplus: promote patch deployment %q: %w", promotion.deploymentID, err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("communityplus: inspect patch deployment %q promotion: %w", promotion.deploymentID, err)
		}
		if changed == 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM communityplus_deployment_results WHERE deployment_id = ?`, promotion.deploymentID); err != nil {
			return fmt.Errorf("communityplus: reset patch deployment %q results: %w", promotion.deploymentID, err)
		}
	}
	return nil
}
