package tables

import "database/sql"

func init() { MigrationClient.AddMigration(Up_20261006090000, Down_20261006090000) }

func Up_20261006090000(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE communityplus_self_service_deployments (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    deployment_id VARCHAR(128) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_communityplus_self_service_deployment (deployment_id),
    CONSTRAINT fk_communityplus_self_service_deployment
        FOREIGN KEY (deployment_id) REFERENCES communityplus_catalog_deployments (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE communityplus_self_service_requests (
    deployment_id VARCHAR(128) NOT NULL,
    host_id       BIGINT UNSIGNED NOT NULL,
    requested_at  TIMESTAMP(6) NOT NULL,
    PRIMARY KEY (deployment_id, host_id),
    KEY idx_communityplus_self_service_requests_host (host_id, requested_at),
    CONSTRAINT fk_communityplus_self_service_request_deployment
        FOREIGN KEY (deployment_id) REFERENCES communityplus_self_service_deployments (deployment_id) ON DELETE CASCADE,
    CONSTRAINT fk_communityplus_self_service_request_host
        FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO communityplus_self_service_deployments (deployment_id)
SELECT id FROM communityplus_catalog_deployments WHERE self_service = 1;
`)
	return err
}

func Down_20261006090000(tx *sql.Tx) error {
	_, err := tx.Exec(`
DROP TABLE IF EXISTS communityplus_self_service_requests;
DROP TABLE IF EXISTS communityplus_self_service_deployments;
`)
	return err
}
