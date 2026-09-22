package tables

import "database/sql"

func init() {
	MigrationClient.AddMigration(Up_20260922030500, Down_20260922030500)
}

func Up_20260922030500(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE communityplus_audit_events
    ADD INDEX idx_communityplus_audit_actor_occurred (actor_id, occurred_at),
    ADD INDEX idx_communityplus_audit_action_resource_occurred (action, resource, occurred_at),
    ADD INDEX idx_communityplus_audit_resource_id_occurred (resource_id, occurred_at);
`)
	return err
}

func Down_20260922030500(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE communityplus_audit_events
    DROP INDEX idx_communityplus_audit_actor_occurred,
    DROP INDEX idx_communityplus_audit_action_resource_occurred,
    DROP INDEX idx_communityplus_audit_resource_id_occurred;
`)
	return err
}
