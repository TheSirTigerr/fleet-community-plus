package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthorizationCodeFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	flow, err := NewFlowState()
	require.NoError(t, err)

	var provider *httptest.Server
	provider = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, DiscoveryDocument{
				Issuer:                provider.URL,
				AuthorizationEndpoint: provider.URL + "/authorize",
				TokenEndpoint:         provider.URL + "/token",
				JWKSURI:               provider.URL + "/jwks",
				IDTokenSigningAlgs:    []string{"RS256"},
			})
		case "/jwks":
			writeJSON(t, w, map[string]any{"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   encodeExponent(key.PublicKey.E),
			}}})
		case "/token":
			require.NoError(t, r.ParseForm())
			require.Equal(t, "test-code", r.Form.Get("code"))
			require.Equal(t, flow.CodeVerifier, r.Form.Get("code_verifier"))
			idToken := signedIDToken(t, key, "test-key", map[string]any{
				"iss":   provider.URL,
				"sub":   "user-123",
				"aud":   "fleet-client",
				"exp":   now.Add(5 * time.Minute).Unix(),
				"iat":   now.Unix(),
				"nonce": flow.Nonce,
				"email": "USER@example.com",
			})
			writeJSON(t, w, map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"expires_in":   300,
				"id_token":     idToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	settings := Settings{
		IssuerURL:    provider.URL,
		ClientID:     "fleet-client",
		ClientSecret: "secret",
	}
	discovery, err := Discover(context.Background(), provider.Client(), settings)
	require.NoError(t, err)

	redirectURI := "https://fleet.example/api/v1/fleet/sso/oidc/callback"
	authURL, err := AuthorizationURL(settings, discovery, redirectURI, flow)
	require.NoError(t, err)
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, flow.State, parsed.Query().Get("state"))
	require.Equal(t, flow.Nonce, parsed.Query().Get("nonce"))
	require.Equal(t, "S256", parsed.Query().Get("code_challenge_method"))
	challenge := sha256.Sum256([]byte(flow.CodeVerifier))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(challenge[:]), parsed.Query().Get("code_challenge"))
	require.Contains(t, parsed.Query().Get("scope"), "openid")

	identity, err := ExchangeAndVerify(
		context.Background(), provider.Client(), settings, discovery,
		redirectURI, "test-code", flow.Nonce, flow.CodeVerifier, now,
	)
	require.NoError(t, err)
	require.Equal(t, "user-123", identity.Subject)
	require.Equal(t, "user@example.com", identity.Email)
}

func TestValidateSettingsRejectsInsecureIssuer(t *testing.T) {
	err := ValidateSettings(Settings{IssuerURL: "http://idp.example", ClientID: "client"})
	require.EqualError(t, err, "issuer URL must be an https URL without credentials, query, or fragment")
}

func TestVerifyIDTokenRejectsNonceMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	var provider *httptest.Server
	provider = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   encodeExponent(key.PublicKey.E),
		}}})
	}))
	defer provider.Close()

	raw := signedIDToken(t, key, "test-key", map[string]any{
		"iss":   provider.URL,
		"sub":   "user-123",
		"aud":   "fleet-client",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": "wrong",
		"email": "user@example.com",
	})
	_, err = verifyIDToken(
		context.Background(), provider.Client(),
		Settings{IssuerURL: provider.URL, ClientID: "fleet-client"},
		&DiscoveryDocument{JWKSURI: provider.URL}, raw, "expected", now,
	)
	require.EqualError(t, err, "OIDC ID token nonce mismatch")
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(value))
}

func signedIDToken(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	unsigned := header + "." + payload
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeExponent(exponent int) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(exponent)).Bytes())
}
