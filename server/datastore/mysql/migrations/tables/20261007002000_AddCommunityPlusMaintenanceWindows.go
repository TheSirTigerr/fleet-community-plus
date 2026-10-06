package tables

import "database/sql"

func init() {
	MigrationClient.AddMigration(Up_20261007002000, Down_20261007002000)
}

func Up_20261007002000(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE communityplus_maintenance_windows (
	id               VARCHAR(128) NOT NULL,
	fleet_id         BIGINT UNSIGNED NOT NULL,
	timezone         VARCHAR(128) NOT NULL,
	weekdays         JSON NOT NULL,
	start_minute     SMALLINT UNSIGNED NOT NULL,
	duration_minutes SMALLINT UNSIGNED NOT NULL,
	enabled          TINYINT(1) NOT NULL DEFAULT 1,
	created_at       TIMESTAMP(6) NOT NULL,
	created_by       VARCHAR(255) NOT NULL,
	PRIMARY KEY (id),
	KEY idx_communityplus_maintenance_fleet_enabled (fleet_id, enabled, start_minute),
	CONSTRAINT fk_communityplus_maintenance_fleet
		FOREIGN KEY (fleet_id) REFERENCES teams (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
`)
	return err
}

func Down_20261007002000(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE IF EXISTS communityplus_maintenance_windows`)
	return err
}
