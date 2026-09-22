package applepsso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKeyContextRoundTripPreservesBindingAndKey(t *testing.T) {
	ds, _, _ := configuredStore(t)
	svc, err := New(ds, &memoryNonceStore{}, nil)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	expiresAt := time.Now().Add(time.Hour)
	encoded, err := svc.sealKeyContext(context.Background(), "host-123", "user@example.com", privateKey, expiresAt)
	require.NoError(t, err)

	payload, recovered, err := svc.openKeyContext(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "host-123", payload.HostUUID)
	require.Equal(t, "user@example.com", payload.Username)
	require.Equal(t, expiresAt.Unix(), payload.ExpiresAt)
	require.Equal(t, privateKey.D, recovered.D)
}
