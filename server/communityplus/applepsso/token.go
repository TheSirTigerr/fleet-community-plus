package applepsso

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/psso/pssocrypto"
	jwt "github.com/golang-jwt/jwt/v4"
)

const defaultIdPTokenLifetime = time.Hour

type tokenSettings struct {
	issuerURL   string
	idpTokenURL string
	idpClientID string
	idpSecret   string
	idpScopes   string
}

type upstreamTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Token authenticates a registered Apple PSSO device, consumes its Fleet-issued
// nonce, validates the user's password against the configured OAuth token
// endpoint, then returns a login response encrypted to that device's registered
// encryption key.
func (s *Service) Token(ctx context.Context, assertion []byte) ([]byte, error) {
	settings, err := s.tokenSettings(ctx)
	if err != nil {
		return nil, err
	}
	claims, signingKey, err := s.verifyDeviceAssertion(ctx, assertion, settings.idpClientID)
	if err != nil {
		return nil, err
	}
	if claims.RequestType != "" {
		return nil, &fleet.BadRequestError{Message: "unsupported Apple Platform SSO request type"}
	}
	if claims.RequestNonce == "" {
		return nil, &fleet.BadRequestError{Message: "missing request nonce"}
	}
	consumed, err := s.nonceStore.Consume(ctx, claims.RequestNonce)
	if err != nil {
		return nil, fmt.Errorf("consume psso request nonce: %w", err)
	}
	if !consumed {
		return nil, &fleet.BadRequestError{Message: "invalid or already consumed request nonce"}
	}

	deviceEncryptionKey, err := s.resolveDeviceEncryptionKey(ctx, signingKey.HostUUID, claims)
	if err != nil {
		return nil, err
	}
	password, err := s.loginPassword(ctx, claims)
	if err != nil {
		return nil, err
	}
	if claims.Username == "" {
		return nil, &fleet.BadRequestError{Message: "missing username"}
	}

	upstream, upstreamClaims, err := exchangePassword(ctx, http.DefaultClient, settings, claims.Username, password)
	if err != nil {
		return nil, err
	}
	idToken, err := s.signLoginIDToken(ctx, settings.issuerURL, claims, upstreamClaims, upstream.ExpiresIn)
	if err != nil {
		return nil, err
	}

	tokenType := upstream.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	expiresIn := upstream.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int(defaultIdPTokenLifetime.Seconds())
	}
	payload, err := json.Marshal(struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token,omitempty"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}{
		IDToken:      idToken,
		RefreshToken: upstream.RefreshToken,
		TokenType:    tokenType,
		ExpiresIn:    expiresIn,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal psso login response: %w", err)
	}
	jwe, err := pssocrypto.BuildPartyInfoJWE(payload, deviceEncryptionKey, claims.JWECrypto.APV, pssocrypto.TypLoginResponse)
	if err != nil {
		return nil, fmt.Errorf("encrypt psso login response: %w", err)
	}
	return jwe, nil
}

func (s *Service) tokenSettings(ctx context.Context) (*tokenSettings, error) {
	public, err := s.publicSettings(ctx)
	if err != nil {
		return nil, err
	}
	assets, err := s.ds.GetAllMDMConfigAssetsByName(ctx, []fleet.MDMAssetName{fleet.MDMAssetAppleAccountProvisioningIdPClientSecret}, nil)
	if err != nil && !fleet.IsNotFound(err) {
		return nil, fmt.Errorf("load Apple account provisioning client secret: %w", err)
	}
	asset, ok := assets[fleet.MDMAssetAppleAccountProvisioningIdPClientSecret]
	if !ok || len(asset.Value) == 0 {
		return nil, &fleet.BadRequestError{Message: "Apple account provisioning is not configured"}
	}
	return &tokenSettings{
		issuerURL:   strings.TrimRight(public.serverURL, "/"),
		idpTokenURL: public.tokenURL,
		idpClientID: public.clientID,
		idpSecret:   string(asset.Value),
		idpScopes:   "openid profile email",
	}, nil
}

func (s *Service) verifyDeviceAssertion(ctx context.Context, assertion []byte, expectedIssuer string) (*pssocrypto.TokenClaims, *fleet.PSSOKey, error) {
	if len(assertion) == 0 {
		return nil, nil, &fleet.BadRequestError{Message: "missing Apple Platform SSO assertion"}
	}
	unverifiedClaims := &pssocrypto.TokenClaims{}
	parser := &jwt.Parser{}
	unverified, _, err := parser.ParseUnverified(string(assertion), unverifiedClaims)
	if err != nil {
		return nil, nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO assertion", InternalErr: err}
	}
	kid, _ := unverified.Header["kid"].(string)
	kid = pssocrypto.CanonicalizeKID(kid)
	if kid == "" {
		return nil, nil, &fleet.BadRequestError{Message: "Apple Platform SSO assertion is missing a signing key id"}
	}
	keyRow, err := s.ds.GetPSSOKey(ctx, kid)
	if err != nil {
		if fleet.IsNotFound(err) {
			return nil, nil, &fleet.BadRequestError{Message: "unknown Apple Platform SSO signing key", InternalErr: err}
		}
		return nil, nil, fmt.Errorf("load psso signing key: %w", err)
	}
	if keyRow == nil || keyRow.KeyType != fleet.PSSOKeyTypeSigning {
		return nil, nil, &fleet.BadRequestError{Message: "Apple Platform SSO key is not a signing key"}
	}
	pub, err := pssocrypto.ParseECPublicKeyPEM([]byte(keyRow.PEM))
	if err != nil {
		return nil, nil, fmt.Errorf("parse registered psso signing key: %w", err)
	}

	claims := &pssocrypto.TokenClaims{}
	token, err := jwt.ParseWithClaims(string(assertion), claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != pssocrypto.SigningAlg {
			return nil, fmt.Errorf("unexpected signing algorithm %q", token.Method.Alg())
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{pssocrypto.SigningAlg}))
	if err != nil || token == nil || !token.Valid {
		return nil, nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO assertion signature", InternalErr: err}
	}
	if claims.Version != pssocrypto.ProtocolVersion {
		return nil, nil, &fleet.BadRequestError{Message: "unsupported Apple Platform SSO protocol version"}
	}
	if claims.Issuer != expectedIssuer {
		return nil, nil, &fleet.BadRequestError{Message: "Apple Platform SSO assertion issuer does not match configured client"}
	}
	if claims.Nonce == "" || claims.JWECrypto == nil {
		return nil, nil, &fleet.BadRequestError{Message: "Apple Platform SSO assertion is missing response encryption parameters"}
	}
	if claims.JWECrypto.Alg != pssocrypto.EncryptionAlg || claims.JWECrypto.Enc != pssocrypto.ContentEncryptionAlg || claims.JWECrypto.APV == "" {
		return nil, nil, &fleet.BadRequestError{Message: "unsupported Apple Platform SSO response encryption parameters"}
	}
	return claims, keyRow, nil
}

func (s *Service) resolveDeviceEncryptionKey(ctx context.Context, hostUUID string, claims *pssocrypto.TokenClaims) (*ecdsa.PublicKey, error) {
	apv, err := pssocrypto.DecodeJOSEB64(claims.JWECrypto.APV)
	if err != nil {
		return nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO APV", InternalErr: err}
	}
	fields, err := pssocrypto.ParseApplePartyInfo(apv)
	if err != nil || len(fields) != 3 || string(fields[0]) != pssocrypto.APVPartyLabel {
		return nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO APV structure", InternalErr: err}
	}
	if string(fields[2]) != claims.Nonce {
		return nil, &fleet.BadRequestError{Message: "Apple Platform SSO APV nonce does not match assertion nonce"}
	}
	apvKey, err := pssocrypto.ParseRawECPoint(fields[1])
	if err != nil {
		return nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO encryption key in APV", InternalErr: err}
	}
	kid, err := pssocrypto.KIDFromRawECPoint(apvKey)
	if err != nil {
		return nil, fmt.Errorf("derive psso encryption key id: %w", err)
	}
	keyRow, err := s.ds.GetPSSOKey(ctx, kid)
	if err != nil {
		if fleet.IsNotFound(err) {
			return nil, &fleet.BadRequestError{Message: "unknown Apple Platform SSO encryption key", InternalErr: err}
		}
		return nil, fmt.Errorf("load psso encryption key: %w", err)
	}
	if keyRow == nil || keyRow.KeyType != fleet.PSSOKeyTypeEncryption || keyRow.HostUUID != hostUUID {
		return nil, &fleet.BadRequestError{Message: "Apple Platform SSO encryption key does not belong to the signing device"}
	}
	pub, err := pssocrypto.ParseECPublicKeyPEM([]byte(keyRow.PEM))
	if err != nil {
		return nil, fmt.Errorf("parse registered psso encryption key: %w", err)
	}
	return pub, nil
}

func (s *Service) loginPassword(ctx context.Context, claims *pssocrypto.TokenClaims) (string, error) {
	switch claims.GrantType {
	case pssocrypto.GrantTypePassword:
		if claims.Password == "" {
			return "", &fleet.BadRequestError{Message: "missing password"}
		}
		return claims.Password, nil
	case pssocrypto.GrantTypeJWTBearer:
		if claims.Assertion == "" {
			return "", &fleet.BadRequestError{Message: "missing encrypted password assertion"}
		}
		serverEncryptionKey, err := s.privateKeyAsset(ctx, fleet.MDMAssetPSSOEncryptionKey)
		if err != nil {
			return "", fmt.Errorf("load Fleet psso encryption key: %w", err)
		}
		plaintext, err := pssocrypto.DecryptPartyInfoJWE([]byte(claims.Assertion), serverEncryptionKey, pssocrypto.TypEncryptedLoginAssertion)
		if err != nil {
			return "", &fleet.BadRequestError{Message: "invalid encrypted password assertion", InternalErr: err}
		}
		password, err := pssocrypto.ParseEmbeddedAssertionPassword(plaintext)
		if err != nil || password == "" {
			return "", &fleet.BadRequestError{Message: "encrypted password assertion is missing a password", InternalErr: err}
		}
		return password, nil
	default:
		return "", &fleet.BadRequestError{Message: "unsupported Apple Platform SSO grant type"}
	}
}

func exchangePassword(ctx context.Context, client *http.Client, settings *tokenSettings, username, password string) (*upstreamTokenResponse, *fleet.PSSOClaims, error) {
	if client == nil {
		client = http.DefaultClient
	}
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("client_id", settings.idpClientID)
	form.Set("client_secret", settings.idpSecret)
	form.Set("scope", settings.idpScopes)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.idpTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("build IdP password request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("validate password with identity provider: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("read identity provider response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, nil, &fleet.BadRequestError{Message: "identity provider rejected username or password"}
		}
		return nil, nil, fmt.Errorf("identity provider token endpoint returned status %d", resp.StatusCode)
	}
	var tokenResponse upstreamTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, nil, fmt.Errorf("decode identity provider token response: %w", err)
	}
	if tokenResponse.IDToken == "" {
		return nil, nil, errors.New("identity provider token response is missing id_token")
	}
	claims, err := claimsFromUpstreamIDToken(tokenResponse.IDToken)
	if err != nil {
		return nil, nil, fmt.Errorf("read identity provider id_token claims: %w", err)
	}
	claims.RefreshToken = tokenResponse.RefreshToken
	claims.ExpiresIn = tokenResponse.ExpiresIn
	return &tokenResponse, claims, nil
}

func claimsFromUpstreamIDToken(raw string) (*fleet.PSSOClaims, error) {
	claims := jwt.MapClaims{}
	parser := &jwt.Parser{}
	if _, _, err := parser.ParseUnverified(raw, claims); err != nil {
		return nil, err
	}
	stringClaim := func(name string) string {
		value, _ := claims[name].(string)
		return value
	}
	sub := stringClaim("sub")
	if sub == "" {
		return nil, errors.New("upstream id_token is missing sub")
	}
	extra := make(map[string]any, len(claims))
	for key, value := range claims {
		switch key {
		case "sub", "email", "name", "preferred_username", "iss", "aud", "exp", "iat", "nbf", "nonce":
			continue
		default:
			extra[key] = value
		}
	}
	return &fleet.PSSOClaims{
		Subject:           sub,
		Email:             stringClaim("email"),
		Name:              stringClaim("name"),
		PreferredUsername: stringClaim("preferred_username"),
		Extra:             extra,
	}, nil
}

func (s *Service) signLoginIDToken(ctx context.Context, issuer string, request *pssocrypto.TokenClaims, upstream *fleet.PSSOClaims, upstreamExpiresIn int) (string, error) {
	if upstream == nil || upstream.Subject == "" {
		return "", errors.New("identity provider claims are missing subject")
	}
	signingKey, err := s.privateKeyAsset(ctx, fleet.MDMAssetPSSOSigningKey)
	if err != nil {
		return "", fmt.Errorf("load Fleet psso signing key: %w", err)
	}
	now := s.now()
	lifetime := defaultIdPTokenLifetime
	if upstreamExpiresIn > 0 {
		lifetime = time.Duration(upstreamExpiresIn) * time.Second
	}
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   upstream.Subject,
		"aud":   request.Issuer,
		"iat":   now.Unix(),
		"exp":   now.Add(lifetime).Unix(),
		"nonce": request.Nonce,
	}
	if upstream.Email != "" {
		claims["email"] = upstream.Email
	}
	if upstream.Name != "" {
		claims["name"] = upstream.Name
	}
	if upstream.PreferredUsername != "" {
		claims["preferred_username"] = upstream.PreferredUsername
	}
	for key, value := range upstream.Extra {
		if _, reserved := claims[key]; !reserved {
			claims[key] = value
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = serverKeyKID(&signingKey.PublicKey)
	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("sign psso id_token: %w", err)
	}
	return signed, nil
}
