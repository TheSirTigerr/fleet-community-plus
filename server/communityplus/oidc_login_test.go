package communityplus

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/communityplus/oidc"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type memoryOIDCFlowStore struct {
	flow     OIDCFlow
	consumed bool
}

func (s *memoryOIDCFlowStore) SaveOIDCFlow(_ context.Context, flow OIDCFlow) error {
	if err := flow.Validate(); err != nil {
		return err
	}
	s.flow = flow
	s.consumed = false
	return nil
}

func (s *memoryOIDCFlowStore) ConsumeOIDCFlow(_ context.Context, state string) (OIDCFlow, error) {
	if s.consumed || state == "" || state != s.flow.State {
		return OIDCFlow{}, ErrOIDCFlowInvalid
	}
	s.consumed = true
	return s.flow, nil
}

type fakeOIDCProtocol struct {
	beginFlow        oidc.FlowState
	beginURL         string
	identity         *oidc.Identity
	beginRedirectURI string
	completeCode     string
	completeFlow     oidc.FlowState
}

func (p *fakeOIDCProtocol) Begin(_ context.Context, _ OIDCSettings, redirectURI string) (oidc.FlowState, string, error) {
	p.beginRedirectURI = redirectURI
	return p.beginFlow, p.beginURL, nil
}

func (p *fakeOIDCProtocol) Complete(_ context.Context, _ OIDCSettings, _ string, code string, flow oidc.FlowState) (*oidc.Identity, error) {
	p.completeCode = code
	p.completeFlow = flow
	if p.identity == nil {
		return nil, errors.New("missing fake identity")
	}
	return p.identity, nil
}

type fakeOIDCFleetService struct {
	serverURL       string
	user            *fleet.User
	session         *fleet.SSOSession
	sessionDuration time.Duration
	userID          string
}

func (s *fakeOIDCFleetService) AppConfigUrls(context.Context) (*fleet.AppConfigUrls, error) {
	urls := &fleet.AppConfigUrls{}
	urls.ServerSettings.ServerURL = s.serverURL
	return urls, nil
}

func (s *fakeOIDCFleetService) GetSSOUser(_ context.Context, auth fleet.Auth) (*fleet.User, error) {
	s.userID = auth.UserID()
	if s.user == nil {
		return nil, errors.New("user not found")
	}
	return s.user, nil
}

func (s *fakeOIDCFleetService) LoginSSOUser(_ context.Context, _ *fleet.User, redirectURL string) (*fleet.SSOSession, error) {
	if s.session == nil {
		return nil, errors.New("session unavailable")
	}
	copy := *s.session
	copy.RedirectURL = redirectURL
	return &copy, nil
}

func (s *fakeOIDCFleetService) GetSessionDuration(context.Context) time.Duration {
	return s.sessionDuration
}

func TestOIDCLoginAPIAuthorizeAndCallback(t *testing.T) {
	settingsStore := newMemoryOIDCSettingsStore()
	settingsStore.settings = OIDCSettings{
		Enabled:   true,
		IssuerURL: "https://idp.example",
		ClientID:  "fleet-client",
		Scopes:    []string{"openid", "email"},
		IDPName:   "Example IdP",
	}
	flowStore := &memoryOIDCFlowStore{}
	protocol := &fakeOIDCProtocol{
		beginFlow: oidc.FlowState{State: "state-1", Nonce: "nonce-1", CodeVerifier: "verifier-1"},
		beginURL:  "https://idp.example/authorize?state=state-1",
		identity:  &oidc.Identity{Subject: "subject-1", Email: "user@example.com"},
	}
	fleetSvc := &fakeOIDCFleetService{
		serverURL:       "https://fleet.example/prefix",
		user:            &fleet.User{ID: 7, Email: "user@example.com", SSOEnabled: true},
		session:         &fleet.SSOSession{Token: "session-token"},
		sessionDuration: 8 * time.Hour,
	}
	api, err := NewOIDCLoginAPI(settingsStore, flowStore, fleetSvc, protocol)
	if err != nil {
		t.Fatal(err)
	}
	api.now = func() time.Time { return time.Date(2026, time.September, 22, 12, 0, 0, 0, time.UTC) }

	req := httptest.NewRequest(http.MethodGet, oidcAuthorizePath+"?redirect_url=%2Fhosts%3Ffleet_id%3D7", nil)
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != protocol.beginURL {
		t.Fatalf("authorize status=%d location=%q body=%s", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	wantCallback := "https://fleet.example/prefix" + oidcCallbackPath
	if protocol.beginRedirectURI != wantCallback {
		t.Fatalf("callback URL=%q want=%q", protocol.beginRedirectURI, wantCallback)
	}
	if flowStore.flow.State != "state-1" || flowStore.flow.RedirectURL != "/hosts?fleet_id=7" || flowStore.flow.ExpiresAt.Sub(api.now()) != oidcFlowTTL {
		t.Fatalf("unexpected saved flow: %#v", flowStore.flow)
	}

	req = httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?code=code-1&state=state-1", nil)
	recorder = httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/hosts?fleet_id=7" {
		t.Fatalf("callback status=%d location=%q body=%s", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	if fleetSvc.userID != "user@example.com" || protocol.completeCode != "code-1" || protocol.completeFlow.Nonce != "nonce-1" || protocol.completeFlow.CodeVerifier != "verifier-1" {
		t.Fatalf("callback did not use verified flow: user=%q code=%q flow=%#v", fleetSvc.userID, protocol.completeCode, protocol.completeFlow)
	}
	if cookie := recorder.Header().Get("Set-Cookie"); !strings.Contains(cookie, "__Host-token=session-token") || !strings.Contains(cookie, "Secure") {
		t.Fatalf("missing secure Fleet session cookie: %q", cookie)
	}

	// The same state cannot be replayed after the successful callback.
	req = httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?code=code-2&state=state-1", nil)
	recorder = httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected replay rejection, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestOIDCLoginAPIRejectsExternalRedirect(t *testing.T) {
	settingsStore := newMemoryOIDCSettingsStore()
	settingsStore.settings = OIDCSettings{Enabled: true, IssuerURL: "https://idp.example", ClientID: "client", Scopes: []string{"openid", "email"}}
	flowStore := &memoryOIDCFlowStore{}
	protocol := &fakeOIDCProtocol{beginFlow: oidc.FlowState{State: "state", Nonce: "nonce", CodeVerifier: "verifier"}, beginURL: "https://idp.example/authorize"}
	fleetSvc := &fakeOIDCFleetService{serverURL: "https://fleet.example"}
	api, err := NewOIDCLoginAPI(settingsStore, flowStore, fleetSvc, protocol)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, oidcAuthorizePath+"?redirect_url=https%3A%2F%2Fevil.example", nil)
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if flowStore.flow.State != "" {
		t.Fatalf("unsafe redirect unexpectedly started an OIDC flow")
	}
}
