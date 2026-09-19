package digicert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestService(t *testing.T) {
	t.Parallel()

	const token = "secret-token"
	var received certificateRequest
	notBefore := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	notAfter := time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, token, r.Header.Get("X-API-Key"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mpki/api/v2/profile/profile-id":
			require.Equal(t, http.MethodGet, r.Method)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
				"id": "profile-id", "status": "Active",
			}))
		case "/mpki/api/v1/certificate":
			require.Equal(t, http.MethodPost, r.Method)
			require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
			block, _ := pem.Decode([]byte(received.CSR))
			require.NotNil(t, block)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			require.NoError(t, err)
			require.NoError(t, csr.CheckSignature())

			caKey, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			template := &x509.Certificate{
				SerialNumber: big.NewInt(42),
				Subject:      csr.Subject,
				NotBefore:    notBefore,
				NotAfter:     notAfter,
				KeyUsage:     x509.KeyUsageDigitalSignature,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, caKey)
			require.NoError(t, err)
			certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			w.WriteHeader(http.StatusCreated)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
				"serial_number": "42", "delivery_format": "x509", "certificate": string(certificatePEM),
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	config := Config{
		URL:                   server.URL,
		APIToken:              token,
		ProfileID:             "profile-id",
		CertificateCommonName: "device.example.com",
		UserPrincipalNames:    []string{"person@example.com"},
		CertificateSeatID:     "seat-id",
	}
	service := NewService()
	require.NoError(t, service.VerifyProfileID(context.Background(), config))
	certificate, err := service.GetCertificate(context.Background(), config)
	require.NoError(t, err)

	privateKey, decoded, err := pkcs12.Decode(certificate.PFXData, certificate.Password)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.Equal(t, config.CertificateCommonName, decoded.Subject.CommonName)
	require.Equal(t, notBefore, certificate.NotValidBefore)
	require.Equal(t, notAfter, certificate.NotValidAfter)
	require.Equal(t, "42", certificate.SerialNumber)
	require.Equal(t, config.ProfileID, received.Profile["id"])
	require.Equal(t, config.CertificateSeatID, received.Seat["seat_id"])
	require.Equal(t, "x509", received.DeliveryFormat)
	require.Equal(t, config.CertificateCommonName, received.Attributes.Subject.CommonName)
	require.Equal(t, config.UserPrincipalNames, received.Attributes.Extensions.SAN.UserPrincipalNames)
}

func TestServiceReturnsDigiCertErrorMessage(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]string{{"code": "invalid", "message": "Expected Fail"}},
		}))
	}))
	t.Cleanup(server.Close)

	_, err := NewService().GetCertificate(context.Background(), Config{
		URL: server.URL, APIToken: "token", ProfileID: "profile", CertificateCommonName: "name", CertificateSeatID: "seat",
	})
	require.ErrorContains(t, err, "Expected Fail")
}

func TestVerifyProfileRejectsInactiveAndMismatchedProfiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		response map[string]string
		contains string
	}{
		{name: "inactive", response: map[string]string{"id": "profile", "status": "Disabled"}, contains: "not active"},
		{name: "wrong ID", response: map[string]string{"id": "different", "status": "Active"}, contains: "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewEncoder(w).Encode(tt.response))
			}))
			t.Cleanup(server.Close)
			err := NewService().VerifyProfileID(context.Background(), Config{URL: server.URL, ProfileID: "profile"})
			require.ErrorContains(t, err, tt.contains)
		})
	}
}

func TestEndpointURLValidation(t *testing.T) {
	t.Parallel()
	for _, rawURL := range []string{"", "ftp://example.com", "https://user@example.com", "https://example.com?token=secret"} {
		_, err := endpointURL(rawURL, "path")
		require.Error(t, err, rawURL)
	}
}

func TestServiceDoesNotForwardTokenOnRedirect(t *testing.T) {
	t.Parallel()
	var redirectedToken string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedToken = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	err := NewService().VerifyProfileID(context.Background(), Config{
		URL: redirect.URL, APIToken: "must-not-leak", ProfileID: "profile",
	})
	require.ErrorContains(t, err, "HTTP 302")
	require.Empty(t, redirectedToken)
}
