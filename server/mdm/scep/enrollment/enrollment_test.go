package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	scepserver "github.com/fleetdm/fleet/v4/server/mdm/scep/server"
	"github.com/smallstep/scep"
	"github.com/stretchr/testify/require"
)

func TestEnroll(t *testing.T) {
	caCert, caKey := testCA(t)

	signer := scepserver.CSRSignerContextFunc(func(_ context.Context, msg *scep.CSRReqMessage) (*x509.Certificate, error) {
		now := time.Now().UTC()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      msg.CSR.Subject,
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, msg.CSR.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(der)
	})

	service, err := scepserver.NewService(caCert, caKey, signer)
	require.NoError(t, err)

	caCerts, err := FetchCACerts(context.Background(), service)
	require.NoError(t, err)
	require.Len(t, caCerts, 1)
	require.Equal(t, caCert.Raw, caCerts[0].Raw)

	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device.example"},
	}, deviceKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	signerKey, signerCert, err := NewEphemeralSigner(csr.Subject)
	require.NoError(t, err)

	cert, err := Enroll(context.Background(), service, caCerts, Request{
		CSR:        csr,
		SignerKey:  signerKey,
		SignerCert: signerCert,
	})
	require.NoError(t, err)
	require.Equal(t, "device.example", cert.Subject.CommonName)

	wantKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	require.NoError(t, err)
	gotKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)
	require.Equal(t, wantKey, gotKey)
}

func TestNewEphemeralSigner(t *testing.T) {
	key, cert, err := NewEphemeralSigner(pkix.Name{CommonName: "device.example"})
	require.NoError(t, err)
	require.NotNil(t, key)
	require.NotNil(t, cert)
	require.Equal(t, "device.example", cert.Subject.CommonName)
	require.True(t, cert.NotAfter.After(cert.NotBefore))
}

func testCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Community+ test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}
