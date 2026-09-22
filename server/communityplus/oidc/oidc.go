// Package oidc implements the protocol primitives used by Community+ OpenID Connect SSO.
package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	maxProviderResponseSize = 1 << 20
	flowSecretBytes         = 32
)

// Settings contains the non-secret and secret OIDC client settings needed by
// the authorization-code flow.
type Settings struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
}

// DiscoveryDocument is the subset of OpenID Provider metadata used by Fleet.
type DiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	IDTokenSigningAlgs    []string `json:"id_token_signing_alg_values_supported"`
}

// FlowState is short-lived browser state. It must be stored server-side and
// consumed exactly once when the callback is processed.
type FlowState struct {
	State        string
	Nonce        string
	CodeVerifier string
}

// Identity contains the verified identity claims used by Fleet login.
type Identity struct {
	Subject    string
	Email      string
	Attributes []Attribute
}

// ValidateSettings validates the static OIDC client configuration.
func ValidateSettings(settings Settings) error {
	if strings.TrimSpace(settings.IssuerURL) == "" {
		return errors.New("issuer URL is required")
	}
	issuer, err := url.Parse(settings.IssuerURL)
	if err != nil {
		return fmt.Errorf("parse issuer URL: %w", err)
	}
	if issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("issuer URL must be an https URL without credentials, query, or fragment")
	}
	if strings.TrimSpace(settings.ClientID) == "" {
		return errors.New("client ID is required")
	}
	return nil
}

// Discover loads and validates the provider's OpenID Connect discovery metadata.
func Discover(ctx context.Context, client *http.Client, settings Settings) (*DiscoveryDocument, error) {
	if err := ValidateSettings(settings); err != nil {
		return nil, err
	}
	issuer := strings.TrimSuffix(settings.IssuerURL, "/")
	var doc DiscoveryDocument
	if err := getJSON(ctx, client, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("load OIDC discovery document: %w", err)
	}
	if strings.TrimSuffix(doc.Issuer, "/") != issuer {
		return nil, errors.New("OIDC discovery issuer does not match configured issuer")
	}
	for name, raw := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"jwks_uri":               doc.JWKSURI,
	} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return nil, fmt.Errorf("OIDC discovery %s must be an https URL", name)
		}
	}
	if len(doc.IDTokenSigningAlgs) > 0 && !contains(doc.IDTokenSigningAlgs, "RS256") {
		return nil, errors.New("OIDC provider does not advertise RS256 ID token signing")
	}
	return &doc, nil
}

// NewFlowState creates cryptographically random state, nonce, and PKCE verifier values.
func NewFlowState() (FlowState, error) {
	state, err := randomURLToken(flowSecretBytes)
	if err != nil {
		return FlowState{}, err
	}
	nonce, err := randomURLToken(flowSecretBytes)
	if err != nil {
		return FlowState{}, err
	}
	verifier, err := randomURLToken(flowSecretBytes)
	if err != nil {
		return FlowState{}, err
	}
	return FlowState{State: state, Nonce: nonce, CodeVerifier: verifier}, nil
}

// AuthorizationURL creates an authorization-code URL with nonce and PKCE S256.
func AuthorizationURL(settings Settings, discovery *DiscoveryDocument, redirectURI string, flow FlowState) (string, error) {
	if discovery == nil {
		return "", errors.New("OIDC discovery document is required")
	}
	if flow.State == "" || flow.Nonce == "" || flow.CodeVerifier == "" {
		return "", errors.New("OIDC flow state is incomplete")
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil || redirect.Scheme != "https" || redirect.Host == "" {
		return "", errors.New("OIDC redirect URI must be an https URL")
	}
	scopes := normalizedScopes(settings.Scopes)
	cfg := oauth2.Config{
		ClientID:    settings.ClientID,
		RedirectURL: redirectURI,
		Scopes:      scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}
	challengeBytes := sha256.Sum256([]byte(flow.CodeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	return cfg.AuthCodeURL(
		flow.State,
		oauth2.SetAuthURLParam("nonce", flow.Nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

// ExchangeAndVerify exchanges an authorization code and verifies the returned
// ID token, including signature, issuer, audience, expiry, and nonce.
func ExchangeAndVerify(
	ctx context.Context,
	client *http.Client,
	settings Settings,
	discovery *DiscoveryDocument,
	redirectURI, code, expectedNonce, codeVerifier string,
	now time.Time,
) (*Identity, error) {
	if discovery == nil {
		return nil, errors.New("OIDC discovery document is required")
	}
	if code == "" || expectedNonce == "" || codeVerifier == "" {
		return nil, errors.New("OIDC callback is incomplete")
	}
	if client == nil {
		client = http.DefaultClient
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	cfg := oauth2.Config{
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
		RedirectURL:  redirectURI,
		Scopes:       normalizedScopes(settings.Scopes),
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}
	token, err := cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, errors.New("OIDC token response did not contain an ID token")
	}
	return verifyIDToken(ctx, client, settings, discovery, rawIDToken, expectedNonce, now)
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("invalid ID token audience")
	}
	*a = many
	return nil
}

type idTokenClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience audience `json:"aud"`
	Expires  int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	Nonce    string   `json:"nonce"`
	Email    string   `json:"email"`
	AZP      string   `json:"azp"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	N         string `json:"n"`
	E         string `json:"e"`
}

func verifyIDToken(ctx context.Context, client *http.Client, settings Settings, discovery *DiscoveryDocument, rawToken, expectedNonce string, now time.Time) (*Identity, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid OIDC ID token format")
	}
	var header jwtHeader
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return nil, fmt.Errorf("decode ID token header: %w", err)
	}
	if header.Algorithm != "RS256" || header.KeyID == "" {
		return nil, errors.New("OIDC ID token must use RS256 and include a key ID")
	}
	var keys jwks
	if err := getJSON(ctx, client, discovery.JWKSURI, &keys); err != nil {
		return nil, fmt.Errorf("load OIDC signing keys: %w", err)
	}
	key, err := rsaKey(keys, header.KeyID)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid OIDC ID token signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("OIDC ID token signature verification failed")
	}

	var claims idTokenClaims
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("decode ID token claims: %w", err)
	}
	if strings.TrimSuffix(claims.Issuer, "/") != strings.TrimSuffix(settings.IssuerURL, "/") {
		return nil, errors.New("OIDC ID token issuer mismatch")
	}
	if !contains([]string(claims.Audience), settings.ClientID) {
		return nil, errors.New("OIDC ID token audience mismatch")
	}
	if len(claims.Audience) > 1 && claims.AZP != settings.ClientID {
		return nil, errors.New("OIDC ID token authorized party mismatch")
	}
	if claims.Expires == 0 || !now.Before(time.Unix(claims.Expires, 0).Add(30*time.Second)) {
		return nil, errors.New("OIDC ID token is expired")
	}
	if claims.IssuedAt > now.Add(30*time.Second).Unix() {
		return nil, errors.New("OIDC ID token was issued in the future")
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return nil, errors.New("OIDC ID token nonce mismatch")
	}
	if strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.Email) == "" {
		return nil, errors.New("OIDC ID token is missing subject or email")
	}
	attributes, err := roleAttributesFromJWTPart(parts[1])
	if err != nil {
		return nil, err
	}
	return &Identity{
		Subject:    claims.Subject,
		Email:      strings.ToLower(strings.TrimSpace(claims.Email)),
		Attributes: attributes,
	}, nil
}

func rsaKey(keys jwks, keyID string) (*rsa.PublicKey, error) {
	for _, key := range keys.Keys {
		if key.KeyID != keyID || key.KeyType != "RSA" || (key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != "RS256") {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil || len(nBytes) == 0 {
			return nil, errors.New("invalid RSA modulus in OIDC signing key")
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
			return nil, errors.New("invalid RSA exponent in OIDC signing key")
		}
		exponent := 0
		for _, b := range eBytes {
			exponent = exponent<<8 | int(b)
		}
		if exponent < 3 {
			return nil, errors.New("invalid RSA exponent in OIDC signing key")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}, nil
	}
	return nil, errors.New("OIDC signing key not found")
}

func decodeJWTPart(part string, dst any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, dst)
}

func getJSON(ctx context.Context, client *http.Client, rawURL string, dst any) error {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxProviderResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxProviderResponseSize {
		return errors.New("provider response exceeds maximum size")
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return err
	}
	return nil
}

func normalizedScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes)+3)
	for _, required := range []string{"openid", "email", "profile"} {
		if !contains(scopes, required) {
			result = append(result, required)
		}
	}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" && !contains(result, scope) {
			result = append(result, scope)
		}
	}
	return result
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func randomURLToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate OIDC flow secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
