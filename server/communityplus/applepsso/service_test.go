package applepsso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/psso/pssocrypto"
	"github.com/fleetdm/fleet/v4/server/mdm/apple/psso/regtoken"
	fleetmock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

type memoryNonceStore struct {
	values map[string]struct{}
}

func (s *memoryNonceStore) Store(_ context.Context, nonce string, _ time.Duration) error {
	if s.values == nil {
		s.values = make(map[string]struct{})
	}
	s.values[nonce] = struct{}{}
	return nil
}

func (s *memoryNonceStore) Consume(_ context.Context, nonce string) (bool, error) {
	if _, ok := s.values[nonce]; !ok {
		return false, nil
	}
	delete(s.values, nonce)
	return true, nil
}

func configuredStore(t *testing.T) (*fleetmock.Store, *ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	ds := new(fleetmock.Store)
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		cfg := &fleet.AppConfig{}
		cfg.ServerSettings.ServerURL = "https://fleet.example"
		cfg.MDM.AppleAccountProvisioning = fleet.AppleAccountProvisioning{
			OAuthIdPTokenURL: optjson.SetString("https://idp.example/oauth2/token"),
			OAuthIdPClientID: optjson.SetString("client-id"),
		}
		return cfg, nil
	}
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	assets := map[fleet.MDMAssetName]fleet.MDMConfigAsset{
		fleet.MDMAssetPSSOSigningKey:    {Name: fleet.MDMAssetPSSOSigningKey, Value: privateKeyPEM(t, signKey)},
		fleet.MDMAssetPSSOEncryptionKey: {Name: fleet.MDMAssetPSSOEncryptionKey, Value: privateKeyPEM(t, encKey)},
	}
	ds.GetAllMDMConfigAssetsByNameFunc = func(_ context.Context, names []fleet.MDMAssetName, _ sqlx.QueryerContext) (map[fleet.MDMAssetName]fleet.MDMConfigAsset, error) {
		result := make(map[fleet.MDMAssetName]fleet.MDMConfigAsset)
		for _, name := range names {
			if asset, ok := assets[name]; ok {
				result[name] = asset
			}
		}
		return result, nil
	}
	return ds, signKey, encKey
}

func privateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func devicePublicKey(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	kid, err := pssocrypto.KIDFromRawECPoint(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), kid
}

func TestNonceRequiresConfigurationAndIsStored(t *testing.T) {
	ds := new(fleetmock.Store)
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) { return &fleet.AppConfig{}, nil }
	store := &memoryNonceStore{}
	svc, err := New(ds, store, nil)
	require.NoError(t, err)

	_, err = svc.Nonce(context.Background())
	require.Error(t, err)

	ds, _, _ = configuredStore(t)
	store = &memoryNonceStore{}
	svc, err = New(ds, store, nil)
	require.NoError(t, err)
	nonce, err := svc.Nonce(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, nonce)
	_, ok := store.values[nonce]
	require.True(t, ok)
}

func TestJWKSAndAASA(t *testing.T) {
	ds, _, _ := configuredStore(t)
	svc, err := New(ds, &memoryNonceStore{}, nil)
	require.NoError(t, err)

	body, err := svc.JWKS(context.Background())
	require.NoError(t, err)
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(body, &document))
	require.Len(t, document.Keys, 2)
	uses := map[string]string{}
	for _, key := range document.Keys {
		require.Equal(t, "EC", key.Kty)
		require.Equal(t, "P-256", key.Crv)
		require.NotEmpty(t, key.Kid)
		uses[key.Use] = key.Alg
	}
	require.Equal(t, pssocrypto.SigningAlg, uses["sig"])
	require.Equal(t, pssocrypto.EncryptionAlg, uses["enc"])

	aasa, err := svc.AASA(context.Background())
	require.NoError(t, err)
	var association struct {
		AuthSrv struct {
			Apps []string `json:"apps"`
		} `json:"authsrv"`
	}
	require.NoError(t, json.Unmarshal(aasa, &association))
	require.Equal(t, defaultAASAAppIDs, association.AuthSrv.Apps)
}

func TestRegisterDeviceBindsKeysToSignedHost(t *testing.T) {
	const hostUUID = "A72B07D0-2E08-45CE-9423-1FCAFFAEC390"
	ds, signingKey, _ := configuredStore(t)
	ds.HostByUUIDFunc = func(_ context.Context, uuid string) (*fleet.Host, error) {
		require.Equal(t, hostUUID, uuid)
		return &fleet.Host{UUID: uuid}, nil
	}
	var storedUUID string
	var storedKeys []fleet.PSSOKey
	ds.SetOrUpdatePSSODeviceFunc = func(_ context.Context, uuid string, keys []fleet.PSSOKey) error {
		storedUUID = uuid
		storedKeys = append([]fleet.PSSOKey(nil), keys...)
		return nil
	}

	svc, err := New(ds, &memoryNonceStore{}, nil)
	require.NoError(t, err)
	svc.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	token, err := regtoken.Mint(signingKey, hostUUID, svc.now())
	require.NoError(t, err)
	signingPEM, signingKID := devicePublicKey(t)
	encryptionPEM, encryptionKID := devicePublicKey(t)

	err = svc.RegisterDevice(context.Background(), fleet.PSSODeviceRegistrationRequest{
		DeviceUUID:          hostUUID,
		DeviceSigningKey:    signingPEM,
		DeviceEncryptionKey: encryptionPEM,
		SigningKeyID:        signingKID,
		EncryptionKeyID:     encryptionKID,
		RegistrationToken:   token,
	})
	require.NoError(t, err)
	require.Equal(t, hostUUID, storedUUID)
	require.Len(t, storedKeys, 2)
	require.Equal(t, signingKID, storedKeys[0].KID)
	require.Equal(t, fleet.PSSOKeyTypeSigning, storedKeys[0].KeyType)
	require.Equal(t, encryptionKID, storedKeys[1].KID)
	require.Equal(t, fleet.PSSOKeyTypeEncryption, storedKeys[1].KeyType)
}

func TestRegisterDeviceRejectsMismatchedKID(t *testing.T) {
	const hostUUID = "A72B07D0-2E08-45CE-9423-1FCAFFAEC390"
	ds, signingKey, _ := configuredStore(t)
	ds.HostByUUIDFunc = func(context.Context, string) (*fleet.Host, error) {
		return &fleet.Host{UUID: hostUUID}, nil
	}
	svc, err := New(ds, &memoryNonceStore{}, nil)
	require.NoError(t, err)
	svc.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	token, err := regtoken.Mint(signingKey, hostUUID, svc.now())
	require.NoError(t, err)
	signingPEM, _ := devicePublicKey(t)
	encryptionPEM, encryptionKID := devicePublicKey(t)

	err = svc.RegisterDevice(context.Background(), fleet.PSSODeviceRegistrationRequest{
		DeviceUUID:          hostUUID,
		DeviceSigningKey:    signingPEM,
		DeviceEncryptionKey: encryptionPEM,
		SigningKeyID:        encryptionKID,
		EncryptionKeyID:     encryptionKID,
		RegistrationToken:   token,
	})
	require.ErrorContains(t, err, "signing key id does not match")
	require.False(t, ds.SetOrUpdatePSSODeviceFuncInvoked)
}
