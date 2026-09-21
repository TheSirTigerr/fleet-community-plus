package tables
import "database/sql"
func init(){MigrationClient.AddMigration(Up_20260921170000,Down_20260921170000)}
func Up_20260921170000(tx *sql.Tx)error{_,err:=tx.Exec(`CREATE TABLE communityplus_deployment_results (deployment_id VARCHAR(128) NOT NULL, host_id BIGINT UNSIGNED NOT NULL, exit_code INT NOT NULL, output TEXT NOT NULL, updated_at TIMESTAMP(6) NOT NULL, PRIMARY KEY (deployment_id, host_id), CONSTRAINT fk_communityplus_result_deployment FOREIGN KEY (deployment_id) REFERENCES communityplus_catalog_deployments (id) ON DELETE CASCADE, CONSTRAINT fk_communityplus_result_host FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`);return err}
func Down_20260921170000(tx *sql.Tx)error{_,err:=tx.Exec(`DROP TABLE IF EXISTS communityplus_deployment_results`);return err}
