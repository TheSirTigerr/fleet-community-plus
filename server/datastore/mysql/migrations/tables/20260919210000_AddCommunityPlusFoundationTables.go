package tables

import (
	"database/sql"
)

func init() {
	MigrationClient.AddMigration(Up_20260919210000, Down_20260919210000)
}

func Up_20260919210000(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE communityplus_audit_events (
    id             VARCHAR(128) NOT NULL,
    occurred_at    TIMESTAMP(6) NOT NULL,
    actor_id       VARCHAR(255) NOT NULL,
    action         VARCHAR(255) NOT NULL,
    resource       VARCHAR(64) NOT NULL,
    resource_id    VARCHAR(255) NULL,
    scope_kind     VARCHAR(16) NOT NULL,
    fleet_id       BIGINT UNSIGNED NULL,
    metadata       JSON NULL,
    PRIMARY KEY (id),
    INDEX idx_communityplus_audit_occurred_at (occurred_at),
    INDEX idx_communityplus_audit_fleet_occurred (fleet_id, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE communityplus_automation_rules (
    id             VARCHAR(128) NOT NULL,
    name           VARCHAR(255) NOT NULL,
    scope_kind     VARCHAR(16) NOT NULL,
    fleet_id       BIGINT UNSIGNED NULL,
    trigger_name   VARCHAR(64) NOT NULL,
    action_name    VARCHAR(64) NOT NULL,
    enabled        TINYINT(1) NOT NULL DEFAULT 0,
    conditions     JSON NULL,
    config         JSON NULL,
    created_at     TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    INDEX idx_communityplus_rules_fleet_trigger (fleet_id, trigger_name, enabled),
    CONSTRAINT fk_communityplus_rules_fleet
        FOREIGN KEY (fleet_id) REFERENCES teams (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`)
	return err
}

func Down_20260919210000(tx *sql.Tx) error {
	_, err := tx.Exec(`
DROP TABLE IF EXISTS communityplus_automation_rules;
DROP TABLE IF EXISTS communityplus_audit_events;
`)
	return err
}
