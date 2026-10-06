package tables

import "database/sql"

func init() {
	MigrationClient.AddMigration(Up_20261006103000, Down_20261006103000)
}

func Up_20261006103000(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE communityplus_automation_rules
ADD COLUMN continuous TINYINT(1) NOT NULL DEFAULT 0 AFTER enabled
`)
	return err
}

func Down_20261006103000(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE communityplus_automation_rules
DROP COLUMN continuous
`)
	return err
}
