package est

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestNewServiceWithoutOptions(t *testing.T) {
	if svc := NewService(); svc == nil {
		t.Fatal("expected default EST service")
	}
}

func TestNewServiceAppliesOptions(t *testing.T) {
	svc := NewService(
		WithLogger(slog.Default()),
		WithTimeout(time.Second),
	)
	impl, ok := svc.(*Service)
	if !ok || impl == nil {
		t.Fatal("expected concrete EST service")
	}
	if impl.timeout != time.Second {
		t.Fatalf("timeout = %s, want 1s", impl.timeout)
	}
}

func TestValidateESTURL(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/est/cacerts" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
		_, _ = io.WriteString(w, "certificate-chain")
	}))
	defer server.Close()

	svc := NewService(WithTimeout(time.Second)).(*Service)
	svc.client = server.Client()
	if err := svc.ValidateESTURL(context.Background(), fleet.ESTProxyCA{URL: server.URL + "/est"}); err != nil {
		t.Fatalf("ValidateESTURL: %v", err)
	}
}

func TestValidateESTURLRejectsBadResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "not-pkcs7")
	}))
	defer server.Close()

	svc := NewService().(*Service)
	svc.client = server.Client()
	if err := svc.ValidateESTURL(context.Background(), fleet.ESTProxyCA{URL: server.URL}); err == nil {
		t.Fatal("expected content-type validation error")
	}
}

func TestGetCertificate(t *testing.T) {
	const csr = "BASE64-CSR"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/est/simpleenroll" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/pkcs10" {
			t.Fatalf("Content-Type = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/pkcs7-mime" {
			t.Fatalf("Accept = %q", got)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "client" || pass != "secret" {
			t.Fatalf("unexpected basic auth %q/%q ok=%v", user, pass, ok)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != csr {
			t.Fatalf("CSR = %q", body)
		}
		w.Header().Set("Content-Type", "application/pkcs7-mime")
		_, _ = io.WriteString(w, "PKCS7-DATA")
	}))
	defer server.Close()

	svc := NewService().(*Service)
	svc.client = server.Client()
	cert, err := svc.GetCertificate(context.Background(), fleet.ESTProxyCA{
		URL:      server.URL + "/est/",
		Username: "client",
		Password: "secret",
	}, csr)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got := string(cert.Certificate); got != "PKCS7-DATA" {
		t.Fatalf("certificate = %q", got)
	}
}

func TestGetCertificateDoesNotLeakCredentialsInURL(t *testing.T) {
	svc := NewService()
	_, err := svc.GetCertificate(context.Background(), fleet.ESTProxyCA{
		URL:      "https://user:pass@example.test",
		Username: "client",
		Password: "secret",
	}, "csr")
	if err == nil || !strings.Contains(err.Error(), "without credentials") {
		t.Fatalf("unexpected error: %v", err)
	}
}
