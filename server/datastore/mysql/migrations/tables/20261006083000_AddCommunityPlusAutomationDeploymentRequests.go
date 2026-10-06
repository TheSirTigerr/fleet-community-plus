package tables

import "database/sql"

func init() {
	MigrationClient.AddMigration(Up_20261006083000, Down_20261006083000)
}

func Up_20261006083000(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE communityplus_automation_deployment_requests (
    deployment_id VARCHAR(128) NOT NULL,
    host_id       BIGINT UNSIGNED NOT NULL,
    requested_at  TIMESTAMP(6) NOT NULL,
    PRIMARY KEY (deployment_id, host_id),
    KEY idx_communityplus_automation_requests_host (host_id, requested_at),
    CONSTRAINT fk_communityplus_automation_request_deployment
        FOREIGN KEY (deployment_id) REFERENCES communityplus_catalog_deployments (id) ON DELETE CASCADE,
    CONSTRAINT fk_communityplus_automation_request_host
        FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`)
	return err
}

func Down_20261006083000(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE IF EXISTS communityplus_automation_deployment_requests`)
	return err
}
