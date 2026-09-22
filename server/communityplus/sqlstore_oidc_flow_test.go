package communityplus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLStoreOIDCFlowOneTimeConsumption(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}

	expires := time.Date(2026, time.September, 22, 12, 0, 0, 0, time.UTC)
	flow := OIDCFlow{
		State:        "browser-state",
		Nonce:        "nonce-value",
		CodeVerifier: "verifier-value",
		RedirectURL:  "/hosts",
		ExpiresAt:    expires,
	}
	stateHash := oidcStateHash(flow.State)
	if stateHash == flow.State {
		t.Fatal("OIDC state must be hashed before persistence")
	}

	mock.ExpectExec("INSERT INTO communityplus_oidc_flows").
		WithArgs(stateHash, flow.Nonce, flow.CodeVerifier, flow.RedirectURL, flow.ExpiresAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.SaveOIDCFlow(context.Background(), flow); err != nil {
		t.Fatalf("save OIDC flow: %v", err)
	}

	mock.ExpectExec("UPDATE communityplus_oidc_flows").
		WithArgs(stateHash).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT nonce, code_verifier, redirect_url, expires_at").
		WithArgs(stateHash).
		WillReturnRows(sqlmock.NewRows([]string{"nonce", "code_verifier", "redirect_url", "expires_at"}).AddRow(
			flow.Nonce, flow.CodeVerifier, flow.RedirectURL, flow.ExpiresAt,
		))
	consumed, err := store.ConsumeOIDCFlow(context.Background(), flow.State)
	if err != nil {
		t.Fatalf("consume OIDC flow: %v", err)
	}
	if consumed.State != flow.State || consumed.Nonce != flow.Nonce || consumed.CodeVerifier != flow.CodeVerifier || consumed.RedirectURL != flow.RedirectURL {
		t.Fatalf("unexpected consumed flow: %#v", consumed)
	}

	mock.ExpectExec("UPDATE communityplus_oidc_flows").
		WithArgs(stateHash).
		WillReturnResult(sqlmock.NewResult(0, 0))
	_, err = store.ConsumeOIDCFlow(context.Background(), flow.State)
	if !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
