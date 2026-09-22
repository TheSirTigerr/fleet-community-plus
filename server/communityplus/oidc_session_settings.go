package communityplus

import (
	"fmt"
	"net/http"
)

const oidcSessionSettingsSuffix = "/fleet/communityplus/sso/oidc/session"

// OIDCSessionSettingsAPI exposes only the non-sensitive fields required to
// render the unauthenticated Fleet login page.
type OIDCSessionSettingsAPI struct {
	store OIDCSettingsStore
}

func NewOIDCSessionSettingsAPI(store OIDCSettingsStore) (*OIDCSessionSettingsAPI, error) {
	if store == nil {
		return nil, fmt.Errorf("communityplus: OIDC session settings store is required")
	}
	return &OIDCSessionSettingsAPI{store: store}, nil
}

func (a *OIDCSessionSettingsAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, version := range []string{"v1", "2022-04", "latest"} {
		mux.HandleFunc("GET /api/"+version+oidcSessionSettingsSuffix, a.get)
	}
	return mux
}

func (a *OIDCSessionSettingsAPI) get(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	settings, err := a.store.GetOIDCSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load SSO settings"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": map[string]any{
			"idp_name":    settings.IDPName,
			"sso_enabled": settings.Enabled,
		},
	})
}
