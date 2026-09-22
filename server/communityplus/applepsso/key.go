package applepsso

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/psso/pssocrypto"
	jwt "github.com/golang-jwt/jwt/v4"
)

const (
	unlockCertificateLifetime = 365 * 24 * time.Hour
	keyContextVersion         = 1
)

var keyContextDomain = []byte("fleet-community-plus/apple-psso/key-context/v1")

type sealedKeyContext struct {
	Version    int    `json:"version"`
	HostUUID   string `json:"host_uuid"`
	Username   string `json:"username"`
	PrivateKey string `json:"private_key"`
	ExpiresAt  int64  `json:"expires_at"`
}

// Handle is the complete Community+ PSSO token entry point. Login requests use
// Token; Apple user-unlock key requests and exchanges use the stateless key
// flow below. The initial unverified parse is routing-only; each handler fully
// verifies the device signature and nonce before processing any request data.
func (s *Service) Handle(ctx context.Context, assertion []byte) ([]byte, error) {
	claims := &pssocrypto.TokenClaims{}
	parser := &jwt.Parser{}
	if _, _, err := parser.ParseUnverified(string(assertion), claims); err != nil {
		return nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO assertion", InternalErr: err}
	}
	switch claims.RequestType {
	case "":
		return s.Token(ctx, assertion)
	case pssocrypto.RequestKey, pssocrypto.RequestExchange:
		return s.keyToken(ctx, assertion)
	default:
		return nil, &fleet.BadRequestError{Message: "unsupported Apple Platform SSO request type"}
	}
}

func (s *Service) keyToken(ctx context.Context, assertion []byte) ([]byte, error) {
	settings, err := s.tokenSettings(ctx)
	if err != nil {
		return nil, err
	}
	claims, signingKey, err := s.verifyDeviceAssertion(ctx, assertion, settings.idpClientID)
	if err != nil {
		return nil, err
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
	if claims.KeyPurpose != pssocrypto.KeyPurposeUserUnlock {
		return nil, &fleet.BadRequestError{Message: "unsupported Apple Platform SSO key purpose"}
	}
	if claims.Username == "" {
		return nil, &fleet.BadRequestError{Message: "missing username for Apple Platform SSO key operation"}
	}

	switch claims.RequestType {
	case pssocrypto.RequestKey:
		return s.keyRequest(ctx, signingKey.HostUUID, claims, deviceEncryptionKey)
	case pssocrypto.RequestExchange:
		return s.keyExchange(ctx, signingKey.HostUUID, claims, deviceEncryptionKey)
	default:
		return nil, &fleet.BadRequestError{Message: "unsupported Apple Platform SSO key request"}
	}
}

func (s *Service) keyRequest(ctx context.Context, hostUUID string, claims *pssocrypto.TokenClaims, deviceEncryptionKey *ecdsa.PublicKey) ([]byte, error) {
	provisioned, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate psso unlock key: %w", err)
	}
	caCert, err := s.caCertificateAsset(ctx)
	if err != nil {
		return nil, err
	}
	caKey, err := s.privateKeyAsset(ctx, fleet.MDMAssetPSSOSigningKey)
	if err != nil {
		return nil, fmt.Errorf("load psso CA signing key: %w", err)
	}
	now := s.now()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate psso unlock certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         claims.Username,
			OrganizationalUnit: []string{hostUUID},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(unlockCertificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &provisioned.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign psso unlock certificate: %w", err)
	}
	keyContext, err := s.sealKeyContext(ctx, hostUUID, claims.Username, provisioned, template.NotAfter)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(struct {
		Certificate string `json:"certificate"`
		IssuedAt    int64  `json:"iat"`
		ExpiresAt   int64  `json:"exp"`
		KeyContext  string `json:"key_context"`
	}{
		Certificate: base64.RawURLEncoding.EncodeToString(certificateDER),
		IssuedAt:    now.Unix(),
		ExpiresAt:   template.NotAfter.Unix(),
		KeyContext:  keyContext,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal psso key response: %w", err)
	}
	return encryptKeyResponse(payload, deviceEncryptionKey, claims)
}

func (s *Service) keyExchange(ctx context.Context, hostUUID string, claims *pssocrypto.TokenClaims, deviceEncryptionKey *ecdsa.PublicKey) ([]byte, error) {
	if claims.KeyContext == "" || claims.OtherPublicKey == "" {
		return nil, &fleet.BadRequestError{Message: "Apple Platform SSO key exchange is missing key context or peer key"}
	}
	contextPayload, provisioned, err := s.openKeyContext(ctx, claims.KeyContext)
	if err != nil {
		return nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO key context", InternalErr: err}
	}
	if contextPayload.HostUUID != hostUUID || contextPayload.Username != claims.Username {
		return nil, &fleet.BadRequestError{Message: "Apple Platform SSO key context does not belong to this device and user"}
	}
	if s.now().Unix() > contextPayload.ExpiresAt {
		return nil, &fleet.BadRequestError{Message: "Apple Platform SSO key context has expired"}
	}
	peerRaw, err := pssocrypto.DecodeBase64Flexible(claims.OtherPublicKey)
	if err != nil {
		return nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO peer public key", InternalErr: err}
	}
	shared, err := pssocrypto.ComputeECDHShared(provisioned, peerRaw)
	if err != nil {
		return nil, &fleet.BadRequestError{Message: "invalid Apple Platform SSO peer public key", InternalErr: err}
	}
	now := s.now()
	payload, err := json.Marshal(struct {
		IssuedAt   int64  `json:"iat"`
		ExpiresAt  int64  `json:"exp"`
		Key        string `json:"key"`
		KeyContext string `json:"key_context"`
	}{
		IssuedAt:   now.Unix(),
		ExpiresAt:  contextPayload.ExpiresAt,
		Key:        base64.StdEncoding.EncodeToString(shared),
		KeyContext: claims.KeyContext,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal psso key exchange response: %w", err)
	}
	return encryptKeyResponse(payload, deviceEncryptionKey, claims)
}

func encryptKeyResponse(payload []byte, deviceEncryptionKey *ecdsa.PublicKey, claims *pssocrypto.TokenClaims) ([]byte, error) {
	jwe, err := pssocrypto.BuildPartyInfoJWE(payload, deviceEncryptionKey, claims.JWECrypto.APV, pssocrypto.TypKeyResponse)
	if err != nil {
		return nil, fmt.Errorf("encrypt psso key response: %w", err)
	}
	return jwe, nil
}

func (s *Service) caCertificateAsset(ctx context.Context) (*x509.Certificate, error) {
	assets, err := s.ds.GetAllMDMConfigAssetsByName(ctx, []fleet.MDMAssetName{fleet.MDMAssetPSSOCACert}, nil)
	if err != nil && !fleet.IsNotFound(err) {
		return nil, fmt.Errorf("load psso CA certificate: %w", err)
	}
	asset, ok := assets[fleet.MDMAssetPSSOCACert]
	if !ok || len(asset.Value) == 0 {
		return nil, errors.New("psso CA certificate asset is missing")
	}
	block, _ := pem.Decode(asset.Value)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("psso CA certificate asset is invalid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse psso CA certificate: %w", err)
	}
	return cert, nil
}

func (s *Service) sealKeyContext(ctx context.Context, hostUUID, username string, privateKey *ecdsa.PrivateKey, expiresAt time.Time) (string, error) {
	sealingKey, err := s.privateKeyAsset(ctx, fleet.MDMAssetPSSOSigningKey)
	if err != nil {
		return "", fmt.Errorf("load psso key-context sealing key: %w", err)
	}
	block, err := keyContextAEAD(sealingKey)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("marshal psso key-context private key: %w", err)
	}
	plaintext, err := json.Marshal(sealedKeyContext{
		Version:    keyContextVersion,
		HostUUID:   hostUUID,
		Username:   username,
		PrivateKey: base64.RawURLEncoding.EncodeToString(der),
		ExpiresAt:  expiresAt.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("marshal psso key context: %w", err)
	}
	nonce := make([]byte, block.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate psso key-context nonce: %w", err)
	}
	sealed := block.Seal(nil, nonce, plaintext, keyContextDomain)
	wire := append(append([]byte(nil), nonce...), sealed...)
	return base64.RawURLEncoding.EncodeToString(wire), nil
}

func (s *Service) openKeyContext(ctx context.Context, encoded string) (*sealedKeyContext, *ecdsa.PrivateKey, error) {
	sealingKey, err := s.privateKeyAsset(ctx, fleet.MDMAssetPSSOSigningKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load psso key-context sealing key: %w", err)
	}
	block, err := keyContextAEAD(sealingKey)
	if err != nil {
		return nil, nil, err
	}
	wire, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("decode psso key context: %w", err)
	}
	if len(wire) <= block.NonceSize() {
		return nil, nil, errors.New("psso key context is truncated")
	}
	plaintext, err := block.Open(nil, wire[:block.NonceSize()], wire[block.NonceSize():], keyContextDomain)
	if err != nil {
		return nil, nil, fmt.Errorf("open psso key context: %w", err)
	}
	var payload sealedKeyContext
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, nil, fmt.Errorf("decode psso key context payload: %w", err)
	}
	if payload.Version != keyContextVersion || payload.HostUUID == "" || payload.Username == "" || payload.PrivateKey == "" || payload.ExpiresAt == 0 {
		return nil, nil, errors.New("psso key context payload is incomplete")
	}
	der, err := base64.RawURLEncoding.DecodeString(payload.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode psso provisioned private key: %w", err)
	}
	privateKey, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse psso provisioned private key: %w", err)
	}
	return &payload, privateKey, nil
}

func keyContextAEAD(privateKey *ecdsa.PrivateKey) (cipher.AEAD, error) {
	if privateKey == nil || privateKey.D == nil {
		return nil, errors.New("psso key-context sealing key is nil")
	}
	hash := sha256.New()
	_, _ = hash.Write(keyContextDomain)
	_, _ = hash.Write(privateKey.D.Bytes())
	key := hash.Sum(nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create psso key-context cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create psso key-context AEAD: %w", err)
	}
	return aead, nil
}
