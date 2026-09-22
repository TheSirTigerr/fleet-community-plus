package applepsso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/psso/pssocrypto"
	fleetmock "github.com/fleetdm/fleet/v4/server/mock"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

type tokenTestEnv struct {
	svc              *Service
	ds               *fleetmock.Store
	nonces           *memoryNonceStore
	serverSigning    *ecdsa.PrivateKey
	serverEncryption *ecdsa.PrivateKey
	deviceSigning    *ecdsa.PrivateKey
	deviceEncryption *ecdsa.PrivateKey
	deviceSigningKID string
	deviceEncryptKID string
	hostUUID         string
	idpURL           string
}

func newTokenTestEnv(t *testing.T, idpURL string) *tokenTestEnv {
	t.Helper()
	makeKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	env := &tokenTestEnv{
		ds:               new(fleetmock.Store),
		nonces:           &memoryNonceStore{values: map[string]struct{}{}},
		serverSigning:    makeKey(),
		serverEncryption: makeKey(),
		deviceSigning:    makeKey(),
		deviceEncryption: makeKey(),
		hostUUID:         "A72B07D0-2E08-45CE-9423-1FCAFFAEC390",
		idpURL:           idpURL,
	}
	var err error
	env.deviceSigningKID, err = pssocrypto.KIDFromRawECPoint(&env.deviceSigning.PublicKey)
	require.NoError(t, err)
	env.deviceEncryptKID, err = pssocrypto.KIDFromRawECPoint(&env.deviceEncryption.PublicKey)
	require.NoError(t, err)

	env.ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		cfg := &fleet.AppConfig{}
		cfg.ServerSettings.ServerURL = "https://fleet.example"
		cfg.MDM.AppleAccountProvisioning = fleet.AppleAccountProvisioning{
			OAuthIdPTokenURL: optjson.SetString(env.idpURL),
			OAuthIdPClientID: optjson.SetString("client-id"),
		}
		return cfg, nil
	}
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
	env.ds.GetPSSOKeyFunc = func(_ context.Context, kid string) (*fleet.PSSOKey, error) {
		switch pssocrypto.CanonicalizeKID(kid) {
		case env.deviceSigningKID:
			return &fleet.PSSOKey{
				KID:      env.deviceSigningKID,
				HostUUID: env.hostUUID,
				KeyType:  fleet.PSSOKeyTypeSigning,
				PEM:      publicKeyPEM(t, &env.deviceSigning.PublicKey),
			}, nil
		case env.deviceEncryptKID:
			return &fleet.PSSOKey{
				KID:      env.deviceEncryptKID,
				HostUUID: env.hostUUID,
				KeyType:  fleet.PSSOKeyTypeEncryption,
				PEM:      publicKeyPEM(t, &env.deviceEncryption.PublicKey),
			}, nil
		default:
			return nil, tokenTestNotFoundError{}
		}
	}
	env.svc, err = New(env.ds, env.nonces, nil)
	require.NoError(t, err)
	return env
}

func publicKeyPEM(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

type tokenTestNotFoundError struct{}

func (tokenTestNotFoundError) Error() string    { return "not found" }
func (tokenTestNotFoundError) IsNotFound() bool { return true }

func upstreamIDToken(t *testing.T, sub string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub":                sub,
		"email":              "user@example.com",
		"name":               "Example User",
		"preferred_username": "user@example.com",
		"department":         "Engineering",
	})
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return signed
}

func idpServer(t *testing.T, wantPassword string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "password", r.Form.Get("grant_type"))
		require.Equal(t, "user@example.com", r.Form.Get("username"))
		require.Equal(t, wantPassword, r.Form.Get("password"))
		require.Equal(t, "client-id", r.Form.Get("client_id"))
		require.Equal(t, "client-secret", r.Form.Get("client_secret"))
		require.Equal(t, "openid profile email", r.Form.Get("scope"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":      upstreamIDToken(t, "idp-user-123"),
			"refresh_token": "refresh-123",
			"token_type":    "Bearer",
			"expires_in":    1800,
		})
	}))
}

func (e *tokenTestEnv) assertion(t *testing.T, password, requestNonce string, encrypted bool, signingKey *ecdsa.PrivateKey) string {
	t.Helper()
	sessionNonce := "session-nonce-123"
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
		Version:      pssocrypto.ProtocolVersion,
		Username:     "user@example.com",
		Nonce:        sessionNonce,
		RequestNonce: requestNonce,
		JWECrypto: &pssocrypto.JWECrypto{
			Alg: pssocrypto.EncryptionAlg,
			Enc: pssocrypto.ContentEncryptionAlg,
			APV: apv,
		},
	}
	if encrypted {
		plaintext, err := pssocrypto.BuildEmbeddedAssertionPlaintext(password)
		require.NoError(t, err)
		serverAPV, err := pssocrypto.BuildAPV(&e.serverEncryption.PublicKey, []byte(sessionNonce))
		require.NoError(t, err)
		wrapped, err := pssocrypto.BuildPartyInfoJWE(plaintext, &e.serverEncryption.PublicKey, serverAPV, pssocrypto.TypEncryptedLoginAssertion)
		require.NoError(t, err)
		claims.GrantType = pssocrypto.GrantTypeJWTBearer
		claims.Assertion = string(wrapped)
	} else {
		claims.GrantType = pssocrypto.GrantTypePassword
		claims.Password = password
	}
	if signingKey == nil {
		signingKey = e.deviceSigning
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = e.deviceSigningKID
	signed, err := token.SignedString(signingKey)
	require.NoError(t, err)
	return signed
}

func TestTokenPasswordLoginAndReplayProtection(t *testing.T) {
	idp := idpServer(t, "correct-horse-battery-staple")
	defer idp.Close()
	env := newTokenTestEnv(t, idp.URL)
	env.nonces.values["request-nonce"] = struct{}{}
	assertion := env.assertion(t, "correct-horse-battery-staple", "request-nonce", false, nil)

	body, err := env.svc.Token(context.Background(), []byte(assertion))
	require.NoError(t, err)
	plaintext, err := pssocrypto.DecryptPartyInfoJWE(body, env.deviceEncryption, pssocrypto.TypLoginResponse)
	require.NoError(t, err)
	var response struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(plaintext, &response))
	require.Equal(t, "refresh-123", response.RefreshToken)
	require.Equal(t, "Bearer", response.TokenType)
	require.Equal(t, 1800, response.ExpiresIn)

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(response.IDToken, claims, func(token *jwt.Token) (any, error) {
		return &env.serverSigning.PublicKey, nil
	}, jwt.WithValidMethods([]string{pssocrypto.SigningAlg}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.Equal(t, "https://fleet.example", claims["iss"])
	require.Equal(t, "idp-user-123", claims["sub"])
	require.Equal(t, "client-id", claims["aud"])
	require.Equal(t, "session-nonce-123", claims["nonce"])
	require.Equal(t, "Engineering", claims["department"])

	_, err = env.svc.Token(context.Background(), []byte(assertion))
	require.ErrorContains(t, err, "already consumed")
}

func TestTokenEncryptedPasswordLogin(t *testing.T) {
	idp := idpServer(t, "super-secret-password")
	defer idp.Close()
	env := newTokenTestEnv(t, idp.URL)
	env.nonces.values["encrypted-nonce"] = struct{}{}
	assertion := env.assertion(t, "super-secret-password", "encrypted-nonce", true, nil)
	require.NotContains(t, assertion, "super-secret-password")

	body, err := env.svc.Token(context.Background(), []byte(assertion))
	require.NoError(t, err)
	plaintext, err := pssocrypto.DecryptPartyInfoJWE(body, env.deviceEncryption, pssocrypto.TypLoginResponse)
	require.NoError(t, err)
	require.Contains(t, string(plaintext), "id_token")
}

func TestTokenRejectsWrongDeviceSigningKeyBeforeIdP(t *testing.T) {
	called := false
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer idp.Close()
	env := newTokenTestEnv(t, idp.URL)
	env.nonces.values["wrong-key-nonce"] = struct{}{}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assertion := env.assertion(t, "irrelevant", "wrong-key-nonce", false, wrongKey)

	_, err = env.svc.Token(context.Background(), []byte(assertion))
	require.ErrorContains(t, err, "signature")
	require.False(t, called)
	_, nonceStillPresent := env.nonces.values["wrong-key-nonce"]
	require.True(t, nonceStillPresent)
}

func TestExchangePasswordRejectsIdPCredentialsWithoutLeakingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"secret detail"}`)
	}))
	defer server.Close()
	settings := &tokenSettings{
		idpTokenURL: server.URL,
		idpClientID: "client-id",
		idpSecret:   "client-secret",
		idpScopes:   "openid profile email",
	}
	_, _, err := exchangePassword(context.Background(), server.Client(), settings, "user", "bad-password")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret detail")
}

func TestClaimsFromUpstreamIDToken(t *testing.T) {
	raw := upstreamIDToken(t, "subject-1")
	claims, err := claimsFromUpstreamIDToken(raw)
	require.NoError(t, err)
	require.Equal(t, "subject-1", claims.Subject)
	require.Equal(t, "user@example.com", claims.Email)
	require.Equal(t, "Engineering", claims.Extra["department"])
}

func TestIdPFormEncodingDoesNotPutPasswordInURL(t *testing.T) {
	values := url.Values{"password": {"p@ss & word"}}
	require.Equal(t, "password=p%40ss+%26+word", values.Encode())
	require.False(t, strings.Contains(values.Encode(), " "))
}
