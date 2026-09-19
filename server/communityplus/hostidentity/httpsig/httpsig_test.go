package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/fleethttpsig"
	hostidentity "github.com/fleetdm/fleet/v4/server/communityplus/hostidentity/types"
	remitlyhttpsig "github.com/remitly-oss/httpsig-go"
)

type memoryCertificateStore struct {
	certificate *hostidentity.HostIdentityCertificate
}

func (s memoryCertificateStore) GetHostIdentityCertBySerialNumber(_ context.Context, serial uint64) (*hostidentity.HostIdentityCertificate, error) {
	if s.certificate == nil || s.certificate.SerialNumber != serial {
		return nil, fmt.Errorf("certificate not found")
	}
	return s.certificate, nil
}

func TestMiddlewareVerifiesSignedAgentRequest(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hostidentity.CreateECDSAPublicKeyRaw(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hostID := uint(42)
	certificate := &hostidentity.HostIdentityCertificate{
		SerialNumber: 0x1234, HostID: &hostID, NotValidAfter: time.Now().Add(time.Hour), PublicKeyRaw: raw,
	}
	signer, err := fleethttpsig.Signer("1234", privateKey, remitlyhttpsig.Algo_ECDSA_P256_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := Middleware(memoryCertificateStore{certificate: certificate}, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var contextCertificate hostidentity.HostIdentityCertificate
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextCertificate, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "https://fleet.example.com/osquery/enroll", strings.NewReader(`{"test":true}`))
	if err := signer.Sign(req); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if contextCertificate.SerialNumber != certificate.SerialNumber {
		t.Fatalf("verified certificate missing from context: %#v", contextCertificate)
	}
}

func TestMiddlewareRequiresSignatureOnlyForAgentEndpoints(t *testing.T) {
	middleware, err := Middleware(memoryCertificateStore{}, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, test := range []struct {
		path string
		want int
	}{
		{"/osquery/config", http.StatusUnauthorized},
		{"/api/v1/fleet/hosts", http.StatusNoContent},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != test.want {
			t.Fatalf("path=%s status=%d want=%d", test.path, recorder.Code, test.want)
		}
	}
}

func TestVerifyHostIdentity(t *testing.T) {
	hostID := uint(7)
	ctx := NewContext(context.Background(), hostidentity.HostIdentityCertificate{
		HostID: &hostID, NotValidAfter: time.Now().Add(time.Hour),
	})
	if err := VerifyHostIdentity(ctx, hostID); err != nil {
		t.Fatalf("verify matching host: %v", err)
	}
	if err := VerifyHostIdentity(ctx, 8); err == nil {
		t.Fatal("expected cross-host certificate to be rejected")
	}
}
