package tables

import "database/sql"

func init() { MigrationClient.AddMigration(Up_20260921173000, Down_20260921173000) }
func Up_20260921173000(tx *sql.Tx) error { _, err := tx.Exec(`ALTER TABLE communityplus_deployment_results ADD COLUMN attempt_count INT NOT NULL DEFAULT 0 AFTER output`); return err }
func Down_20260921173000(tx *sql.Tx) error { _, err := tx.Exec(`ALTER TABLE communityplus_deployment_results DROP COLUMN attempt_count`); return err }
