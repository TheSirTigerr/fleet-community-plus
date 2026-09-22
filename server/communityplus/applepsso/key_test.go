package applepsso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/psso/pssocrypto"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

func installTestCAAssets(t *testing.T, env *tokenTestEnv) *x509.Certificate {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Community+ PSSO Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &env.serverSigning.PublicKey, env.serverSigning)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	env.ds.GetAllMDMConfigAssetsByNameFunc = func(_ context.Context, names []fleet.MDMAssetName, _ sqlx.QueryerContext) (map[fleet.MDMAssetName]fleet.MDMConfigAsset, error) {
		available := map[fleet.MDMAssetName]fleet.MDMConfigAsset{
			fleet.MDMAssetPSSOSigningKey: {
				Name:  fleet.MDMAssetPSSOSigningKey,
				Value: privateKeyPEM(t, env.serverSigning),
			},
			fleet.MDMAssetPSSOEncryptionKey: {
				Name:  fleet.MDMAssetPSSOEncryptionKey,
				Value: privateKeyPEM(t, env.serverEncryption),
			},
			fleet.MDMAssetPSSOCACert: {
				Name:  fleet.MDMAssetPSSOCACert,
				Value: certPEM,
			},
			fleet.MDMAssetAppleAccountProvisioningIdPClientSecret: {
				Name:  fleet.MDMAssetAppleAccountProvisioningIdPClientSecret,
				Value: []byte("client-secret"),
			},
		}
		result := make(map[fleet.MDMAssetName]fleet.MDMConfigAsset)
		for _, name := range names {
			if asset, ok := available[name]; ok {
				result[name] = asset
			}
		}
		return result, nil
	}
	return cert
}

func (e *tokenTestEnv) keyAssertion(t *testing.T, requestType pssocrypto.RequestType, requestNonce, keyContext, otherPublicKey string) string {
	t.Helper()
	sessionNonce := "unlock-session-nonce"
	apv, err := pssocrypto.BuildAPV(&e.deviceEncryption.PublicKey, []byte(sessionNonce))
	require.NoError(t, err)
	now := time.Now()
	claims := &pssocrypto.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "client-id",
			Subject:   "user@example.com",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		Version:        pssocrypto.ProtocolVersion,
		Username:       "user@example.com",
		Nonce:          sessionNonce,
		RequestNonce:   requestNonce,
		RequestType:    requestType,
		KeyPurpose:     pssocrypto.KeyPurposeUserUnlock,
		KeyContext:     keyContext,
		OtherPublicKey: otherPublicKey,
		JWECrypto: &pssocrypto.JWECrypto{
			Alg: pssocrypto.EncryptionAlg,
			Enc: pssocrypto.ContentEncryptionAlg,
			APV: apv,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = e.deviceSigningKID
	signed, err := token.SignedString(e.deviceSigning)
	require.NoError(t, err)
	return signed
}

func TestUnlockKeyRequestAndExchange(t *testing.T) {
	env := newTokenTestEnv(t, "https://idp.example/token")
	caCert := installTestCAAssets(t, env)
	env.nonces.values["key-request-nonce"] = struct{}{}

	request := env.keyAssertion(t, pssocrypto.RequestKey, "key-request-nonce", "", "")
	body, err := env.svc.Handle(context.Background(), []byte(request))
	require.NoError(t, err)
	plaintext, err := pssocrypto.DecryptPartyInfoJWE(body, env.deviceEncryption, pssocrypto.TypKeyResponse)
	require.NoError(t, err)
	var keyResponse struct {
		Certificate string `json:"certificate"`
		IssuedAt    int64  `json:"iat"`
		ExpiresAt   int64  `json:"exp"`
		KeyContext  string `json:"key_context"`
	}
	require.NoError(t, json.Unmarshal(plaintext, &keyResponse))
	require.NotEmpty(t, keyResponse.KeyContext)
	require.Greater(t, keyResponse.ExpiresAt, keyResponse.IssuedAt)
	certificateDER, err := base64.RawURLEncoding.DecodeString(keyResponse.Certificate)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(certificateDER)
	require.NoError(t, err)
	require.Equal(t, "user@example.com", certificate.Subject.CommonName)
	require.Contains(t, certificate.Subject.OrganizationalUnit, env.hostUUID)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = certificate.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err)
	provisionedPublic, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	deviceDH, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerRaw, err := pssocrypto.RawECPoint(&deviceDH.PublicKey)
	require.NoError(t, err)
	env.nonces.values["key-exchange-nonce"] = struct{}{}
	exchange := env.keyAssertion(
		t,
		pssocrypto.RequestExchange,
		"key-exchange-nonce",
		keyResponse.KeyContext,
		base64.StdEncoding.EncodeToString(peerRaw),
	)
	exchangeBody, err := env.svc.Handle(context.Background(), []byte(exchange))
	require.NoError(t, err)
	exchangePlaintext, err := pssocrypto.DecryptPartyInfoJWE(exchangeBody, env.deviceEncryption, pssocrypto.TypKeyResponse)
	require.NoError(t, err)
	var exchangeResponse struct {
		Key        string `json:"key"`
		KeyContext string `json:"key_context"`
	}
	require.NoError(t, json.Unmarshal(exchangePlaintext, &exchangeResponse))
	require.Equal(t, keyResponse.KeyContext, exchangeResponse.KeyContext)
	serverShared, err := base64.StdEncoding.DecodeString(exchangeResponse.Key)
	require.NoError(t, err)
	provisionedRaw, err := pssocrypto.RawECPoint(provisionedPublic)
	require.NoError(t, err)
	deviceShared, err := pssocrypto.ComputeECDHShared(deviceDH, provisionedRaw)
	require.NoError(t, err)
	require.Equal(t, deviceShared, serverShared)
}

func TestUnlockKeyExchangeRejectsTamperedContext(t *testing.T) {
	env := newTokenTestEnv(t, "https://idp.example/token")
	installTestCAAssets(t, env)
	env.nonces.values["request"] = struct{}{}
	request := env.keyAssertion(t, pssocrypto.RequestKey, "request", "", "")
	body, err := env.svc.Handle(context.Background(), []byte(request))
	require.NoError(t, err)
	plaintext, err := pssocrypto.DecryptPartyInfoJWE(body, env.deviceEncryption, pssocrypto.TypKeyResponse)
	require.NoError(t, err)
	var response struct {
		KeyContext string `json:"key_context"`
	}
	require.NoError(t, json.Unmarshal(plaintext, &response))
	require.NotEmpty(t, response.KeyContext)

	wire, err := base64.RawURLEncoding.DecodeString(response.KeyContext)
	require.NoError(t, err)
	wire[len(wire)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(wire)
	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerRaw, err := pssocrypto.RawECPoint(&peer.PublicKey)
	require.NoError(t, err)
	env.nonces.values["exchange"] = struct{}{}
	exchange := env.keyAssertion(t, pssocrypto.RequestExchange, "exchange", tampered, base64.StdEncoding.EncodeToString(peerRaw))
	_, err = env.svc.Handle(context.Background(), []byte(exchange))
	require.ErrorContains(t, err, "key context")
}
