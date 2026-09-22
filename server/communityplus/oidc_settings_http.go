package communityplus

import (
	"fmt"
	"net/http"
	"strconv"
)

// OIDCSettingsAPI exposes the authenticated administration surface for
// Community+ OpenID Connect configuration. The client secret is write-only.
type OIDCSettingsAPI struct {
	store  OIDCSettingsStore
	access AccessController
	audit  *AuditRecorder
}

func NewOIDCSettingsAPI(store OIDCSettingsStore, access AccessController, sink AuditSink) (*OIDCSettingsAPI, error) {
	if store == nil || access == nil || sink == nil {
		return nil, fmt.Errorf("communityplus: OIDC settings API dependencies are required")
	}
	recorder, err := NewAuditRecorder(sink)
	if err != nil {
		return nil, err
	}
	return &OIDCSettingsAPI{store: store, access: access, audit: recorder}, nil
}

func (a *OIDCSettingsAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, version := range []string{"v1", "2022-04", "latest"} {
		path := "/api/" + version + "/fleet/communityplus/sso/oidc"
		mux.HandleFunc("GET "+path, a.get)
		mux.HandleFunc("PUT "+path, a.put)
	}
	return mux
}

type oidcSettingsUpdateRequest struct {
	Enabled      bool     `json:"enabled"`
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret *string  `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes"`
	IDPName      string   `json:"idp_name"`
}

func (a *OIDCSettingsAPI) get(w http.ResponseWriter, r *http.Request) {
	if _, err := a.access.Authorize(r.Context(), Request{
		Resource: ResourceSettings, Action: ActionRead, Scope: GlobalScope(),
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	settings, err := a.store.GetOIDCSettings(r.Context())
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"oidc": settings.View()})
}

func (a *OIDCSettingsAPI) put(w http.ResponseWriter, r *http.Request) {
	actorID, err := a.access.Authorize(r.Context(), Request{
		Resource: ResourceSettings, Action: ActionWrite, Scope: GlobalScope(),
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	var req oidcSettingsUpdateRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeAPIError(w, err)
		return
	}
	current, err := a.store.GetOIDCSettings(r.Context())
	if err != nil {
		writeAPIError(w, err)
		return
	}
	settings := OIDCSettings{
		Enabled:      req.Enabled,
		IssuerURL:    req.IssuerURL,
		ClientID:     req.ClientID,
		ClientSecret: current.ClientSecret,
		Scopes:       req.Scopes,
		IDPName:      req.IDPName,
	}
	if req.ClientSecret != nil {
		settings.ClientSecret = *req.ClientSecret
	}
	settings.Normalize()
	if err := settings.Validate(); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.store.UpsertOIDCSettings(r.Context(), settings); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.audit.Record(r.Context(), AuditEvent{
		ActorID:    actorID,
		Action:     "oidc_settings.update",
		Resource:   ResourceSettings,
		ResourceID: "oidc",
		Scope:      GlobalScope(),
		Metadata: map[string]string{
			"enabled": strconv.FormatBool(settings.Enabled),
			"issuer":  settings.IssuerURL,
		},
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"oidc": settings.View()})
}
