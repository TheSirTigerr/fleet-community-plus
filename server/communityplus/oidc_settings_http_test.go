package communityplus

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type memoryOIDCSettingsStore struct {
	settings OIDCSettings
	writes   int
}

func newMemoryOIDCSettingsStore() *memoryOIDCSettingsStore {
	return &memoryOIDCSettingsStore{settings: DefaultOIDCSettings()}
}

func (s *memoryOIDCSettingsStore) GetOIDCSettings(context.Context) (OIDCSettings, error) {
	result := s.settings
	result.Scopes = append([]string(nil), s.settings.Scopes...)
	return result, nil
}

func (s *memoryOIDCSettingsStore) UpsertOIDCSettings(_ context.Context, settings OIDCSettings) error {
	s.settings = settings
	s.settings.Scopes = append([]string(nil), settings.Scopes...)
	s.writes++
	return nil
}

func TestOIDCSettingsAPIAdminLifecycle(t *testing.T) {
	store := newMemoryOIDCSettingsStore()
	sink := &MemoryAuditSink{}
	api, err := NewOIDCSettingsAPI(store, roleAccessController{actor: "admin-1", roles: []Role{GlobalAdminRole()}}, sink)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{
		"enabled":true,
		"issuer_url":"https://idp.example/",
		"client_id":"fleet-community-plus",
		"client_secret":"super-secret",
		"scopes":["profile","email","profile"],
		"idp_name":"Example IdP"
	}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/communityplus/sso/oidc", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("super-secret")) {
		t.Fatalf("OIDC secret leaked in response: %s", recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"client_secret_configured":true`)) {
		t.Fatalf("secret configured marker missing: %s", recorder.Body.String())
	}
	if store.settings.ClientSecret != "super-secret" || store.settings.IssuerURL != "https://idp.example" {
		t.Fatalf("unexpected stored settings: %#v", store.settings)
	}
	if got := store.settings.Scopes; len(got) != 3 || got[0] != "openid" || got[1] != "email" || got[2] != "profile" {
		t.Fatalf("unexpected normalized scopes: %#v", got)
	}
	if events := sink.Events(); len(events) != 1 || events[0].Action != "oidc_settings.update" || events[0].ActorID != "admin-1" {
		t.Fatalf("unexpected audit events: %#v", events)
	}

	// Omitting client_secret keeps the existing secret instead of accidentally
	// clearing a write-only value returned by no GET endpoint.
	body = []byte(`{
		"enabled":true,
		"issuer_url":"https://idp.example",
		"client_id":"fleet-community-plus",
		"scopes":["profile"],
		"idp_name":"Example IdP"
	}`)
	req = httptest.NewRequest(http.MethodPut, "/api/latest/fleet/communityplus/sso/oidc", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || store.settings.ClientSecret != "super-secret" {
		t.Fatalf("secret was not preserved: status=%d settings=%#v", recorder.Code, store.settings)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/2022-04/fleet/communityplus/sso/oidc", nil)
	recorder = httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || bytes.Contains(recorder.Body.Bytes(), []byte("super-secret")) {
		t.Fatalf("get status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestOIDCSettingsAPIRejectsInvalidIssuer(t *testing.T) {
	store := newMemoryOIDCSettingsStore()
	api, err := NewOIDCSettingsAPI(store, roleAccessController{actor: "admin", roles: []Role{GlobalAdminRole()}}, &MemoryAuditSink{})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"enabled":true,"issuer_url":"http://idp.example","client_id":"client","scopes":[]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/communityplus/sso/oidc", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.writes != 0 {
		t.Fatalf("invalid settings were persisted")
	}
}

func TestOIDCSettingsAPIObserverCannotWrite(t *testing.T) {
	role, err := ObserverRole(7)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryOIDCSettingsStore()
	api, err := NewOIDCSettingsAPI(store, roleAccessController{actor: "observer", roles: []Role{role}}, &MemoryAuditSink{})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"enabled":false,"issuer_url":"","client_id":"","scopes":[]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/communityplus/sso/oidc", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
