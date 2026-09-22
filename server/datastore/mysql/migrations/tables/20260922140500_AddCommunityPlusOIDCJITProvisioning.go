package tables

import "database/sql"

func init() {
	MigrationClient.AddMigration(Up_20260922140500, Down_20260922140500)
}

func Up_20260922140500(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE communityplus_oidc_settings
    ADD COLUMN enable_jit_provisioning TINYINT(1) NOT NULL DEFAULT 0 AFTER enabled;
`)
	return err
}

func Down_20260922140500(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE communityplus_oidc_settings
    DROP COLUMN enable_jit_provisioning;
`)
	return err
}
