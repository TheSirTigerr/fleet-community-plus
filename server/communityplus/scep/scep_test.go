package scep

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigServiceChallenges(t *testing.T) {
	t.Parallel()
	ndes := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `<HTML>The enrollment challenge password is: <B> challenge-123 </B></HTML>`)
	}))
	t.Cleanup(ndes.Close)
	service := NewConfigService(nil, nil)
	challenge, err := service.GetNDESChallenge(context.Background(), NDESConfig{AdminURL: ndes.URL, Username: "user", Password: "password"})
	if err != nil || challenge != "challenge-123" {
		t.Fatalf("challenge=%q err=%v", challenge, err)
	}
	_, err = service.GetNDESChallenge(context.Background(), NDESConfig{AdminURL: ndes.URL, Username: "user", Password: "wrong"})
	if err == nil || !IsTerminalNDESChallengeError(err) {
		t.Fatalf("expected terminal auth error, got %v", err)
	}

	step := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		user, password, _ := r.BasicAuth()
		if user != "step" || password != "secret" {
			t.Error("missing basic auth")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"webhookEvent":"SCEPChallenge"`) {
			t.Errorf("body=%s", body)
		}
		_, _ = io.WriteString(w, " dynamic-challenge \n")
	}))
	t.Cleanup(step.Close)
	challenge, err = service.GetSmallstepChallenge(context.Background(), SmallstepConfig{SCEPURL: "https://scep.example", ChallengeURL: step.URL, Username: "step", Password: "secret"})
	if err != nil || challenge != "dynamic-challenge" {
		t.Fatalf("challenge=%q err=%v", challenge, err)
	}
}

func TestNDESResponseClassification(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ body, detail string }{
		{"The password cache is full.", "cached passwords"},
		{"You do not have sufficient permission to enroll with SCEP.", "sufficient permissions"},
		{"unexpected", "update credentials"},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, tt.body) }))
		_, err := NewConfigService(nil, nil).GetNDESChallenge(context.Background(), NDESConfig{AdminURL: server.URL})
		server.Close()
		if err == nil || !IsTerminalNDESChallengeError(err) || !strings.Contains(NDESChallengeErrorToDetail(err), tt.detail) {
			t.Fatalf("body=%q err=%v detail=%q", tt.body, err, NDESChallengeErrorToDetail(err))
		}
	}
}

func TestValidateSCEPURL(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("operation") != "GetCACaps" {
			t.Errorf("operation=%q", r.URL.Query().Get("operation"))
		}
		_, _ = io.WriteString(w, "SCEPStandard")
	}))
	defer server.Close()
	if err := NewConfigService(nil, nil).ValidateSCEPURL(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
	if err := NewConfigService(nil, nil).ValidateSCEPURL(context.Background(), "file:///tmp/scep"); err == nil {
		t.Fatal("unsafe URL accepted")
	}
}

type memoryStore struct {
	grouped *GroupedCAs
	profile *CertificateProfile
	resent  bool
}

func (s *memoryStore) GroupedCertificateAuthorities(context.Context) (*GroupedCAs, error) {
	return s.grouped, nil
}
func (s *memoryStore) CertificateProfile(context.Context, string, string, string, string) (*CertificateProfile, error) {
	return s.profile, nil
}
func (s *memoryStore) ResendCertificateProfile(context.Context, string, string, string) error {
	s.resent = true
	return nil
}

func TestProxySecurityBoundary(t *testing.T) {
	t.Parallel()
	var operations []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := r.URL.Query().Get("operation")
		operations = append(operations, op)
		if op == "GetCACaps" {
			_, _ = io.WriteString(w, "SCEPStandard\nPOSTPKIOperation")
			return
		}
		if op == "PKIOperation" {
			body, _ := io.ReadAll(r.Body)
			if string(body) != "request" {
				t.Errorf("body=%q", body)
			}
			_, _ = io.WriteString(w, "response")
			return
		}
		http.Error(w, "bad operation", http.StatusBadRequest)
	}))
	defer remote.Close()
	status := "pending"
	store := &memoryStore{grouped: &GroupedCAs{Custom: []CA{{Name: "CUSTOM", URL: remote.URL, Type: "custom_scep_proxy"}}}, profile: &CertificateProfile{Status: &status, Type: "custom_scep_proxy", CAName: "CUSTOM"}}
	proxy := NewProxyService(store, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	data, err := proxy.PKIOperation(context.Background(), []byte("request"), "host,aprofile,CUSTOM")
	if err != nil || string(data) != "response" || strings.Join(operations, ",") != "GetCACaps,PKIOperation" {
		t.Fatalf("data=%q operations=%v err=%v", data, operations, err)
	}
	blocked := "verified"
	store.profile.Status = &blocked
	if _, err := proxy.PKIOperation(context.Background(), nil, "host,aprofile,CUSTOM"); err == nil || !strings.Contains(err.Error(), "profile status") {
		t.Fatalf("expected status rejection, got %v", err)
	}
}

func TestProxyExpiredChallengeQueuesResend(t *testing.T) {
	t.Parallel()
	status := "pending"
	retrieved := time.Now().Add(-NDESChallengeInvalidAfter)
	store := &memoryStore{grouped: &GroupedCAs{NDES: &CA{Name: "NDES", URL: "https://invalid", Type: "ndes"}}, profile: &CertificateProfile{Status: &status, ChallengeRetrievedAt: &retrieved, Type: "ndes", CAName: "NDES"}}
	_, err := NewProxyService(store, nil, nil).PKIOperation(context.Background(), nil, "host,aprofile")
	if err == nil || !strings.Contains(err.Error(), "challenge password") || !store.resent {
		t.Fatalf("err=%v resent=%v", err, store.resent)
	}
}

func TestProxyHidesUpstreamURL(t *testing.T) {
	t.Parallel()
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "failed", http.StatusGone) }))
	defer remote.Close()
	status := "pending"
	store := &memoryStore{grouped: &GroupedCAs{NDES: &CA{Name: "NDES", URL: remote.URL, Type: "ndes"}}, profile: &CertificateProfile{Status: &status, Type: "ndes", CAName: "NDES"}}
	_, err := NewProxyService(store, slog.New(slog.NewTextHandler(io.Discard, nil)), nil).GetCACaps(context.Background(), "host,aprofile")
	if err == nil || !strings.Contains(err.Error(), "Could not GetCACaps") || strings.Contains(err.Error(), remote.URL) {
		t.Fatalf("unsafe error: %v", err)
	}
}
