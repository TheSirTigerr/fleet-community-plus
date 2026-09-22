package tables

import "database/sql"

func init() {
	MigrationClient.AddMigration(Up_20260922113600, Down_20260922113600)
}

func Up_20260922113600(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS communityplus_oidc_settings (
    id TINYINT UNSIGNED NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    issuer_url VARCHAR(2048) NOT NULL DEFAULT '',
    client_id VARCHAR(512) NOT NULL DEFAULT '',
    client_secret MEDIUMTEXT NOT NULL,
    scopes JSON NOT NULL,
    idp_name VARCHAR(255) NOT NULL DEFAULT '',
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO communityplus_oidc_settings
    (id, enabled, issuer_url, client_id, client_secret, scopes, idp_name)
VALUES
    (1, 0, '', '', '', JSON_ARRAY('openid', 'email'), '')
ON DUPLICATE KEY UPDATE id = VALUES(id);
`)
	return err
}

func Down_20260922113600(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE IF EXISTS communityplus_oidc_settings;`)
	return err
}
