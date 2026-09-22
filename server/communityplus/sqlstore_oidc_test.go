package communityplus

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLStoreOIDCSettings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT enabled, enable_jit_provisioning, issuer_url, client_id, client_secret, scopes, idp_name").
		WillReturnRows(sqlmock.NewRows([]string{
			"enabled", "enable_jit_provisioning", "issuer_url", "client_id", "client_secret", "scopes", "idp_name",
		}).AddRow(
			true,
			true,
			"https://idp.example",
			"fleet-client",
			"secret",
			[]byte(`["openid","email","profile"]`),
			"Example IdP",
		))
	settings, err := store.GetOIDCSettings(context.Background())
	if err != nil {
		t.Fatalf("get OIDC settings: %v", err)
	}
	if !settings.Enabled || !settings.EnableJITProvisioning || settings.ClientID != "fleet-client" || settings.ClientSecret != "secret" || len(settings.Scopes) != 3 {
		t.Fatalf("unexpected OIDC settings: %#v", settings)
	}

	settings.IDPName = "Updated IdP"
	mock.ExpectExec("INSERT INTO communityplus_oidc_settings").
		WithArgs(
			true,
			true,
			"https://idp.example",
			"fleet-client",
			"secret",
			sqlmock.AnyArg(),
			"Updated IdP",
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.UpsertOIDCSettings(context.Background(), settings); err != nil {
		t.Fatalf("upsert OIDC settings: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreOIDCSettingsDefaultsWhenRowMissing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT enabled, enable_jit_provisioning, issuer_url, client_id, client_secret, scopes, idp_name").
		WillReturnRows(sqlmock.NewRows([]string{
			"enabled", "enable_jit_provisioning", "issuer_url", "client_id", "client_secret", "scopes", "idp_name",
		}))
	settings, err := store.GetOIDCSettings(context.Background())
	if err != nil {
		t.Fatalf("get default OIDC settings: %v", err)
	}
	if settings.Enabled || settings.EnableJITProvisioning || len(settings.Scopes) != 2 || settings.Scopes[0] != "openid" || settings.Scopes[1] != "email" {
		t.Fatalf("unexpected defaults: %#v", settings)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
