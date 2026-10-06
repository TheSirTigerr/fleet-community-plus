package tables

import "database/sql"

func init() {
	MigrationClient.AddMigration(Up_20261007004000, Down_20261007004000)
}

func Up_20261007004000(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE communityplus_automation_script_requests (
	rule_id      VARCHAR(128) NOT NULL,
	host_id      BIGINT UNSIGNED NOT NULL,
	fleet_id     BIGINT UNSIGNED NOT NULL,
	script_id    BIGINT UNSIGNED NOT NULL,
	policy_id    BIGINT UNSIGNED NULL,
	requested_at TIMESTAMP(6) NOT NULL,
	PRIMARY KEY (rule_id, host_id),
	KEY idx_communityplus_deferred_scripts_host (host_id, requested_at),
	CONSTRAINT fk_communityplus_deferred_script_rule
		FOREIGN KEY (rule_id) REFERENCES communityplus_automation_rules (id) ON DELETE CASCADE,
	CONSTRAINT fk_communityplus_deferred_script_host
		FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
	CONSTRAINT fk_communityplus_deferred_script_fleet
		FOREIGN KEY (fleet_id) REFERENCES teams (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
`)
	return err
}

func Down_20261007004000(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE IF EXISTS communityplus_automation_script_requests`)
	return err
}
