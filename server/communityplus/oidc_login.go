package communityplus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/communityplus/oidc"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

const (
	oidcAuthorizePath = "/api/v1/fleet/communityplus/sso/oidc/authorize"
	oidcCallbackPath  = "/api/v1/fleet/communityplus/sso/oidc/callback"
	oidcFlowTTL       = 10 * time.Minute
)

type oidcFleetService interface {
	AppConfigUrls(context.Context) (*fleet.AppConfigUrls, error)
	GetSSOUser(context.Context, fleet.Auth) (*fleet.User, error)
	LoginSSOUser(context.Context, *fleet.User, string) (*fleet.SSOSession, error)
	GetSessionDuration(context.Context) time.Duration
}

type oidcJITFleetService interface {
	CommunityPlusGetSSOUser(context.Context, fleet.Auth, bool) (*fleet.User, error)
}

type oidcProtocol interface {
	Begin(context.Context, OIDCSettings, string) (oidc.FlowState, string, error)
	Complete(context.Context, OIDCSettings, string, string, oidc.FlowState) (*oidc.Identity, error)
}

type defaultOIDCProtocol struct {
	client *http.Client
}

func (p defaultOIDCProtocol) Begin(ctx context.Context, settings OIDCSettings, redirectURI string) (oidc.FlowState, string, error) {
	discovery, err := oidc.Discover(ctx, p.client, protocolOIDCSettings(settings))
	if err != nil {
		return oidc.FlowState{}, "", err
	}
	flow, err := oidc.NewFlowState()
	if err != nil {
		return oidc.FlowState{}, "", err
	}
	authorizationURL, err := oidc.AuthorizationURL(protocolOIDCSettings(settings), discovery, redirectURI, flow)
	if err != nil {
		return oidc.FlowState{}, "", err
	}
	return flow, authorizationURL, nil
}

func (p defaultOIDCProtocol) Complete(ctx context.Context, settings OIDCSettings, redirectURI, code string, flow oidc.FlowState) (*oidc.Identity, error) {
	discovery, err := oidc.Discover(ctx, p.client, protocolOIDCSettings(settings))
	if err != nil {
		return nil, err
	}
	return oidc.ExchangeAndVerify(
		ctx,
		p.client,
		protocolOIDCSettings(settings),
		discovery,
		redirectURI,
		code,
		flow.Nonce,
		flow.CodeVerifier,
		time.Now().UTC(),
	)
}

func protocolOIDCSettings(settings OIDCSettings) oidc.Settings {
	return oidc.Settings{
		IssuerURL:    settings.IssuerURL,
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
		Scopes:       append([]string(nil), settings.Scopes...),
	}
}

// OIDCLoginAPI implements the unauthenticated browser entry and callback routes
// for Community+ OIDC. Authentication is established only after the provider
// response is cryptographically verified and the one-time state is consumed.
type OIDCLoginAPI struct {
	settingsStore OIDCSettingsStore
	flowStore     OIDCFlowStore
	fleetSvc      oidcFleetService
	protocol      oidcProtocol
	now           func() time.Time
}

func NewOIDCLoginAPI(settingsStore OIDCSettingsStore, flowStore OIDCFlowStore, fleetSvc oidcFleetService, protocol oidcProtocol) (*OIDCLoginAPI, error) {
	if settingsStore == nil || flowStore == nil || fleetSvc == nil {
		return nil, fmt.Errorf("communityplus: OIDC login API dependencies are required")
	}
	if protocol == nil {
		protocol = defaultOIDCProtocol{client: &http.Client{Timeout: 15 * time.Second}}
	}
	return &OIDCLoginAPI{
		settingsStore: settingsStore,
		flowStore:     flowStore,
		fleetSvc:      fleetSvc,
		protocol:      protocol,
		now:           time.Now,
	}, nil
}

func (a *OIDCLoginAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+oidcAuthorizePath, a.authorize)
	mux.HandleFunc("GET "+oidcCallbackPath, a.callback)
	return mux
}

func (a *OIDCLoginAPI) authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	settings, err := a.settingsStore.GetOIDCSettings(r.Context())
	if err != nil {
		writePublicOIDCError(w, http.StatusInternalServerError)
		return
	}
	if !settings.Enabled {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "OIDC login is not enabled"})
		return
	}
	redirectURL, err := safeOIDCInternalRedirect(r.URL.Query().Get("redirect_url"))
	if err != nil {
		writePublicOIDCError(w, http.StatusBadRequest)
		return
	}
	callbackURL, err := a.callbackURL(r.Context())
	if err != nil {
		writePublicOIDCError(w, http.StatusInternalServerError)
		return
	}
	flow, authorizationURL, err := a.protocol.Begin(r.Context(), settings, callbackURL)
	if err != nil {
		writePublicOIDCError(w, http.StatusBadGateway)
		return
	}
	if err := a.flowStore.SaveOIDCFlow(r.Context(), OIDCFlow{
		State:        flow.State,
		Nonce:        flow.Nonce,
		CodeVerifier: flow.CodeVerifier,
		RedirectURL:  redirectURL,
		ExpiresAt:    a.now().UTC().Add(oidcFlowTTL),
	}); err != nil {
		writePublicOIDCError(w, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func (a *OIDCLoginAPI) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("error") != "" {
		writePublicOIDCError(w, http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" || len(code) > 8192 || len(state) > 1024 {
		writePublicOIDCError(w, http.StatusBadRequest)
		return
	}
	storedFlow, err := a.flowStore.ConsumeOIDCFlow(r.Context(), state)
	if err != nil {
		writePublicOIDCError(w, http.StatusBadRequest)
		return
	}
	settings, err := a.settingsStore.GetOIDCSettings(r.Context())
	if err != nil || !settings.Enabled {
		writePublicOIDCError(w, http.StatusUnauthorized)
		return
	}
	callbackURL, err := a.callbackURL(r.Context())
	if err != nil {
		writePublicOIDCError(w, http.StatusInternalServerError)
		return
	}
	identity, err := a.protocol.Complete(r.Context(), settings, callbackURL, code, oidc.FlowState{
		State:        state,
		Nonce:        storedFlow.Nonce,
		CodeVerifier: storedFlow.CodeVerifier,
	})
	if err != nil {
		writePublicOIDCError(w, http.StatusUnauthorized)
		return
	}
	auth := oidcFleetAuth{identity: identity}
	var user *fleet.User
	if jitSvc, ok := a.fleetSvc.(oidcJITFleetService); ok {
		user, err = jitSvc.CommunityPlusGetSSOUser(r.Context(), auth, settings.EnableJITProvisioning)
	} else {
		user, err = a.fleetSvc.GetSSOUser(r.Context(), auth)
	}
	if err != nil {
		writePublicOIDCError(w, http.StatusUnauthorized)
		return
	}
	session, err := a.fleetSvc.LoginSSOUser(r.Context(), user, storedFlow.RedirectURL)
	if err != nil || session == nil || session.Token == "" {
		writePublicOIDCError(w, http.StatusUnauthorized)
		return
	}
	redirectURL, err := safeOIDCInternalRedirect(session.RedirectURL)
	if err != nil {
		writePublicOIDCError(w, http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     "__Host-token",
		Value:    session.Token,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if duration := a.fleetSvc.GetSessionDuration(r.Context()); duration > 0 {
		cookie.Expires = a.now().UTC().Add(duration)
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (a *OIDCLoginAPI) callbackURL(ctx context.Context) (string, error) {
	urls, err := a.fleetSvc.AppConfigUrls(ctx)
	if err != nil {
		return "", err
	}
	if urls == nil {
		return "", errors.New("communityplus: Fleet server URL is unavailable")
	}
	base, err := url.Parse(urls.ServerSettings.ServerURL)
	if err != nil {
		return "", fmt.Errorf("communityplus: parse Fleet server URL: %w", err)
	}
	if base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", errors.New("communityplus: Fleet server URL must be a canonical https URL")
	}
	base.Path = strings.TrimRight(base.Path, "/") + oidcCallbackPath
	base.RawPath = ""
	return base.String(), nil
}

func safeOIDCInternalRedirect(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	if len(raw) > 2048 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "", errors.New("communityplus: invalid OIDC redirect URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil {
		return "", errors.New("communityplus: invalid OIDC redirect URL")
	}
	return parsed.String(), nil
}

func writePublicOIDCError(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]string{"error": "OIDC login failed"})
}

type oidcFleetAuth struct {
	identity *oidc.Identity
}

func (a oidcFleetAuth) UserID() string {
	if a.identity == nil {
		return ""
	}
	return a.identity.Email
}

func (a oidcFleetAuth) UserDisplayName() string {
	if a.identity == nil {
		return ""
	}
	return a.identity.Email
}

func (a oidcFleetAuth) AssertionAttributes() []fleet.SAMLAttribute { return nil }
