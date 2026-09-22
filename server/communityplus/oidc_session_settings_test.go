package communityplus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOIDCSessionSettingsAPIExposesOnlyPublicFields(t *testing.T) {
	store := newMemoryOIDCSettingsStore()
	store.settings = OIDCSettings{
		Enabled:      true,
		IssuerURL:    "https://idp.example",
		ClientID:     "fleet-client",
		ClientSecret: "must-not-leak",
		Scopes:       []string{"openid", "email"},
		IDPName:      "Example IdP",
	}
	api, err := NewOIDCSessionSettingsAPI(store)
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []string{"v1", "2022-04", "latest"} {
		req := httptest.NewRequest(http.MethodGet, "/api/"+version+oidcSessionSettingsSuffix, nil)
		recorder := httptest.NewRecorder()
		api.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("version %s status=%d body=%s", version, recorder.Code, recorder.Body.String())
		}
		body := recorder.Body.String()
		if !strings.Contains(body, `"idp_name":"Example IdP"`) || !strings.Contains(body, `"sso_enabled":true`) {
			t.Fatalf("version %s unexpected body=%s", version, body)
		}
		for _, forbidden := range []string{"must-not-leak", "fleet-client", "https://idp.example", "client_secret", "issuer_url"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("version %s leaked %q in body=%s", version, forbidden, body)
			}
		}
	}
}

func TestOIDCSessionSettingsAPIDisabled(t *testing.T) {
	store := newMemoryOIDCSettingsStore()
	store.settings = DefaultOIDCSettings()
	api, err := NewOIDCSessionSettingsAPI(store)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/latest"+oidcSessionSettingsSuffix, nil).WithContext(context.Background())
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"sso_enabled":false`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
