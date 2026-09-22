package tables

import "database/sql"

func init() {
	MigrationClient.AddMigration(Up_20260922115000, Down_20260922115000)
}

func Up_20260922115000(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS communityplus_oidc_flows (
    state_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    nonce VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    code_verifier VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    redirect_url VARCHAR(2048) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    consumed_at DATETIME(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (state_hash),
    INDEX idx_communityplus_oidc_flows_expiry (expires_at, consumed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`)
	return err
}

func Down_20260922115000(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP TABLE IF EXISTS communityplus_oidc_flows;`)
	return err
}
