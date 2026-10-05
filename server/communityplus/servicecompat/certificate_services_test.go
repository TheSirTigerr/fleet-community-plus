package servicecompat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type certificateTestEST struct {
	validate func(context.Context, fleet.ESTProxyCA) error
	get      func(context.Context, fleet.ESTProxyCA, string) (*fleet.ESTCertificate, error)
}

func (s *certificateTestEST) ValidateESTURL(ctx context.Context, ca fleet.ESTProxyCA) error {
	if s.validate != nil {
		return s.validate(ctx, ca)
	}
	return nil
}

func (s *certificateTestEST) GetCertificate(ctx context.Context, ca fleet.ESTProxyCA, csr string) (*fleet.ESTCertificate, error) {
	if s.get != nil {
		return s.get(ctx, ca, csr)
	}
	return &fleet.ESTCertificate{Certificate: []byte("issued")}, nil
}

func TestCommunityPlusIssueHydrantCertificate(t *testing.T) {
	var gotCA fleet.ESTProxyCA
	est := &certificateTestEST{
		get: func(_ context.Context, ca fleet.ESTProxyCA, csr string) (*fleet.ESTCertificate, error) {
			gotCA = ca
			if csr == "" {
				t.Fatal("expected encoded CSR")
			}
			return &fleet.ESTCertificate{Certificate: []byte("pkcs7")}, nil
		},
	}
	name, rawURL, clientID, clientSecret := "hydrant", "https://ca.example/est", "client", "secret"
	svc := &certificateAuthorityWrapper{est: est}
	got, err := svc.issueCertificate(context.Background(), &fleet.CertificateAuthority{
		Type:         string(fleet.CATypeHydrant),
		Name:         &name,
		URL:          &rawURL,
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
	}, &x509.CertificateRequest{Raw: []byte{1, 2, 3}})
	if err != nil {
		t.Fatalf("issue Hydrant certificate: %v", err)
	}
	if string(got) != "pkcs7" {
		t.Fatalf("certificate = %q", got)
	}
	if gotCA.Username != clientID || gotCA.Password != clientSecret || gotCA.URL != rawURL {
		t.Fatalf("unexpected EST CA mapping: %#v", gotCA)
	}
}

func TestCommunityPlusPrepareHydrantPreservesMaskedSecret(t *testing.T) {
	name, rawURL, clientID, secret := "hydrant", "https://ca.example/est", "client", "stored-secret"
	existingCA := &fleet.CertificateAuthority{
		Type:         string(fleet.CATypeHydrant),
		Name:         &name,
		URL:          &rawURL,
		ClientID:     &clientID,
		ClientSecret: &secret,
	}
	existing := map[string]*fleet.CertificateAuthority{
		certificateAuthorityKey(existingCA): existingCA,
	}
	validated := false
	svc := &certificateAuthorityWrapper{
		est: &certificateTestEST{validate: func(_ context.Context, ca fleet.ESTProxyCA) error {
			validated = true
			if ca.Password != secret {
				t.Fatalf("validation secret = %q", ca.Password)
			}
			return nil
		}},
	}
	grouped := &fleet.GroupedCertificateAuthorities{Hydrant: []fleet.HydrantCA{{
		Name: name, URL: rawURL, ClientID: clientID, ClientSecret: fleet.MaskedPassword,
	}}}
	prepared, err := svc.prepareCertificateAuthorities(context.Background(), grouped, existing)
	if err != nil {
		t.Fatalf("prepare certificate authorities: %v", err)
	}
	if !validated {
		t.Fatal("expected EST validation")
	}
	got := prepared[certificateAuthorityKeyParts(string(fleet.CATypeHydrant), name)]
	if got == nil || got.ClientSecret == nil || *got.ClientSecret != secret {
		t.Fatalf("masked secret was not preserved: %#v", got)
	}
}

func TestCommunityPlusParseCertificateCSRChecksRealCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "device.example"},
		EmailAddresses: []string{"user@example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	value := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	csr, err := parseCertificateCSR(string(value))
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
}

func TestCertificateUPNMatchesEmail(t *testing.T) {
	for _, test := range []struct {
		email string
		upn   string
		want  bool
	}{
		{"Alice@example.com", "alice@example.com", true},
		{"alice@example.com", "ALICE", true},
		{"alice@example.com", "ali", false},
		{"alice@example.com", "", false},
	} {
		if got := certificateUPNMatchesEmail(test.email, test.upn); got != test.want {
			t.Fatalf("certificateUPNMatchesEmail(%q, %q) = %v, want %v", test.email, test.upn, got, test.want)
		}
	}
}
