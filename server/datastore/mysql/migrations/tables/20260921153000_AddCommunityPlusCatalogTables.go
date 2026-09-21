package tables

import "database/sql"

func init() { MigrationClient.AddMigration(Up_20260921153000, Down_20260921153000) }

func Up_20260921153000(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE communityplus_catalog_entries (
    id                 VARCHAR(128) NOT NULL,
    provider           VARCHAR(32) NOT NULL,
    package_identifier VARCHAR(255) NOT NULL,
    name               VARCHAR(255) NOT NULL,
    version            VARCHAR(128) NOT NULL,
    installer_type     VARCHAR(32) NOT NULL,
    installer_url      TEXT NOT NULL,
    installer_sha256   CHAR(64) NOT NULL,
    product_code       VARCHAR(255) NULL,
    source_url         TEXT NOT NULL,
    source_sha256      CHAR(64) NOT NULL,
    imported_at        TIMESTAMP(6) NOT NULL,
    imported_by        VARCHAR(255) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_communityplus_catalog_package_version (provider, package_identifier, version, installer_sha256),
    KEY idx_communityplus_catalog_search (provider, name, package_identifier)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE communityplus_catalog_deployments (
    id               VARCHAR(128) NOT NULL,
    catalog_entry_id VARCHAR(128) NOT NULL,
    fleet_id         BIGINT UNSIGNED NOT NULL,
    self_service     TINYINT(1) NOT NULL DEFAULT 0,
    automatic_install TINYINT(1) NOT NULL DEFAULT 0,
    patch            TINYINT(1) NOT NULL DEFAULT 0,
    created_at       TIMESTAMP(6) NOT NULL,
    created_by       VARCHAR(255) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_communityplus_catalog_deployments_fleet (fleet_id, created_at),
    CONSTRAINT fk_communityplus_catalog_deployment_entry FOREIGN KEY (catalog_entry_id) REFERENCES communityplus_catalog_entries (id) ON DELETE RESTRICT,
    CONSTRAINT fk_communityplus_catalog_deployment_fleet FOREIGN KEY (fleet_id) REFERENCES teams (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`)
	return err
}

func Down_20260921153000(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE IF EXISTS communityplus_catalog_deployments; DROP TABLE IF EXISTS communityplus_catalog_entries;`)
	return err
}
