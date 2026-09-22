// Package applepsso implements Community+ Apple Platform SSO account provisioning.
package applepsso

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/psso/pssocrypto"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/psso/regtoken"
)

const nonceTTL = 5 * time.Minute

var defaultAASAAppIDs = []string{
	"8VBZ3948LU.com.fleetdm.fleet-desktop",
	"8VBZ3948LU.com.fleetdm.fleet-desktop.pssoextension",
}

// Service owns the protocol-level PSSO operations that replace the core
// license stubs. The HTTP endpoints remain in server/service/apple_psso.go.
type Service struct {
	ds         fleet.Datastore
	nonceStore fleet.PSSONonceStore
	logger     *slog.Logger
	now        func() time.Time
}

func New(ds fleet.Datastore, nonceStore fleet.PSSONonceStore, logger *slog.Logger) (*Service, error) {
	if ds == nil {
		return nil, errors.New("apple psso datastore is nil")
	}
	if nonceStore == nil {
		return nil, errors.New("apple psso nonce store is nil")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{ds: ds, nonceStore: nonceStore, logger: logger, now: time.Now}, nil
}

type publicSettings struct {
	serverURL string
	tokenURL  string
	clientID  string
}

func (s *Service) publicSettings(ctx context.Context) (*publicSettings, error) {
	cfg, err := s.ds.AppConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load app config: %w", err)
	}
	if cfg == nil || cfg.ServerSettings.ServerURL == "" || !cfg.MDM.AppleAccountProvisioning.Configured() {
		return nil, &fleet.BadRequestError{Message: "Apple account provisioning is not configured"}
	}
	return &publicSettings{
		serverURL: cfg.ServerSettings.ServerURL,
		tokenURL:  cfg.MDM.AppleAccountProvisioning.OAuthIdPTokenURL.Value,
		clientID:  cfg.MDM.AppleAccountProvisioning.OAuthIdPClientID.Value,
	}, nil
}

func (s *Service) discoveryConfigured(ctx context.Context) error {
	if _, err := s.publicSettings(ctx); err != nil {
		return discoveryNotFoundError{cause: err}
	}
	return nil
}

// Nonce issues a cryptographically-random, single-use request nonce.
func (s *Service) Nonce(ctx context.Context) (string, error) {
	if _, err := s.publicSettings(ctx); err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate psso nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.nonceStore.Store(ctx, nonce, nonceTTL); err != nil {
		return "", fmt.Errorf("store psso nonce: %w", err)
	}
	return nonce, nil
}

// RegisterDevice validates Fleet's per-device registration token, verifies the
// submitted P-256 key IDs from the key material itself, and persists the keys
// against the host UUID bound into the signed token.
func (s *Service) RegisterDevice(ctx context.Context, req fleet.PSSODeviceRegistrationRequest) error {
	if _, err := s.publicSettings(ctx); err != nil {
		return err
	}
	if req.RegistrationToken == "" {
		return &fleet.BadRequestError{Message: "missing registration token"}
	}

	signingKey, err := s.privateKeyAsset(ctx, fleet.MDMAssetPSSOSigningKey)
	if err != nil {
		return fmt.Errorf("load psso signing key: %w", err)
	}
	hostUUID, err := regtoken.Validate(req.RegistrationToken, &signingKey.PublicKey, s.now())
	if err != nil {
		return &fleet.BadRequestError{Message: "invalid registration token", InternalErr: err}
	}
	if req.DeviceUUID != "" && req.DeviceUUID != hostUUID {
		return &fleet.BadRequestError{Message: "device UUID does not match registration token"}
	}
	if _, err := s.ds.HostByUUID(ctx, hostUUID); err != nil {
		if fleet.IsNotFound(err) {
			return &fleet.BadRequestError{Message: "registration token references no enrolled host", InternalErr: err}
		}
		return fmt.Errorf("load psso host: %w", err)
	}

	deviceSigning, signingKID, err := validateDeviceKey(req.DeviceSigningKey, req.SigningKeyID, "signing")
	if err != nil {
		return err
	}
	_, encryptionKID, err := validateDeviceKey(req.DeviceEncryptionKey, req.EncryptionKeyID, "encryption")
	if err != nil {
		return err
	}
	if signingKID == encryptionKID {
		return &fleet.BadRequestError{Message: "signing and encryption key IDs must differ"}
	}
	_ = deviceSigning // parsed above to enforce P-256 and a matching key ID.

	keys := []fleet.PSSOKey{
		{KID: signingKID, HostUUID: hostUUID, KeyType: fleet.PSSOKeyTypeSigning, PEM: req.DeviceSigningKey},
		{KID: encryptionKID, HostUUID: hostUUID, KeyType: fleet.PSSOKeyTypeEncryption, PEM: req.DeviceEncryptionKey},
	}
	if err := s.ds.SetOrUpdatePSSODevice(ctx, hostUUID, keys); err != nil {
		return fmt.Errorf("persist psso device registration: %w", err)
	}
	return nil
}

func validateDeviceKey(keyPEM, claimedKID, label string) (*ecdsa.PublicKey, string, error) {
	if keyPEM == "" || claimedKID == "" {
		return nil, "", &fleet.BadRequestError{Message: fmt.Sprintf("missing %s key or key id", label)}
	}
	pub, err := pssocrypto.ParseECPublicKeyPEM([]byte(keyPEM))
	if err != nil {
		return nil, "", &fleet.BadRequestError{Message: fmt.Sprintf("invalid %s key", label), InternalErr: err}
	}
	kid, err := pssocrypto.KIDFromRawECPoint(pub)
	if err != nil {
		return nil, "", fmt.Errorf("derive %s key id: %w", label, err)
	}
	if pssocrypto.CanonicalizeKID(claimedKID) != kid {
		return nil, "", &fleet.BadRequestError{Message: fmt.Sprintf("%s key id does not match key", label)}
	}
	return pub, kid, nil
}

// JWKS publishes Fleet's PSSO signing and password-encryption public keys.
func (s *Service) JWKS(ctx context.Context) ([]byte, error) {
	if err := s.discoveryConfigured(ctx); err != nil {
		return nil, err
	}
	signingKey, err := s.privateKeyAsset(ctx, fleet.MDMAssetPSSOSigningKey)
	if err != nil {
		return nil, fmt.Errorf("load psso signing key: %w", err)
	}
	encryptionKey, err := s.privateKeyAsset(ctx, fleet.MDMAssetPSSOEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("load psso encryption key: %w", err)
	}

	keys := []jwk{
		publicJWK(&signingKey.PublicKey, "sig", pssocrypto.SigningAlg),
		publicJWK(&encryptionKey.PublicKey, "enc", pssocrypto.EncryptionAlg),
	}
	return json.Marshal(struct {
		Keys []jwk `json:"keys"`
	}{Keys: keys})
}

// AASA publishes the app identifiers Apple's authsrv associated-domain check
// needs for Fleet Desktop and its PSSO extension.
func (s *Service) AASA(ctx context.Context) ([]byte, error) {
	if err := s.discoveryConfigured(ctx); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		AuthSrv struct {
			Apps []string `json:"apps"`
		} `json:"authsrv"`
	}{AuthSrv: struct {
		Apps []string `json:"apps"`
	}{Apps: append([]string(nil), defaultAASAAppIDs...)}})
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

func publicJWK(pub *ecdsa.PublicKey, use, alg string) jwk {
	coordinate := func(v []byte) string {
		buf := make([]byte, 32)
		copy(buf[32-len(v):], v)
		return base64.RawURLEncoding.EncodeToString(buf)
	}
	return jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   coordinate(pub.X.Bytes()),
		Y:   coordinate(pub.Y.Bytes()),
		Use: use,
		Alg: alg,
		Kid: serverKeyKID(pub),
	}
}

func serverKeyKID(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Service) privateKeyAsset(ctx context.Context, name fleet.MDMAssetName) (*ecdsa.PrivateKey, error) {
	assets, err := s.ds.GetAllMDMConfigAssetsByName(ctx, []fleet.MDMAssetName{name}, nil)
	if err != nil && !fleet.IsNotFound(err) {
		return nil, err
	}
	asset, ok := assets[name]
	if !ok || len(asset.Value) == 0 {
		return nil, fmt.Errorf("asset %s is missing", name)
	}
	block, _ := pem.Decode(asset.Value)
	if block == nil {
		return nil, fmt.Errorf("asset %s is not PEM", name)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse asset %s: %w", name, err)
	}
	return key, nil
}

type discoveryNotFoundError struct{ cause error }

func (e discoveryNotFoundError) Error() string {
	return "Apple Platform SSO discovery is not configured"
}
func (e discoveryNotFoundError) Unwrap() error    { return e.cause }
func (e discoveryNotFoundError) IsNotFound() bool { return true }
