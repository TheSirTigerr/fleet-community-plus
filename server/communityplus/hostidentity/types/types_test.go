package types

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECDSAPublicKeyRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := CreateECDSAPublicKeyRaw(&privateKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate := HostIdentityCertificate{PublicKeyRaw: raw}
		publicKey, err := certificate.UnmarshalPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if !publicKey.Equal(&privateKey.PublicKey) {
			t.Fatal("public key changed during round trip")
		}
	}
}

func TestUnmarshalPublicKeyRejectsInvalidData(t *testing.T) {
	for _, raw := range [][]byte{nil, make([]byte, 32), make([]byte, 33)} {
		if _, err := (HostIdentityCertificate{PublicKeyRaw: raw}).UnmarshalPublicKey(); err == nil {
			t.Fatalf("expected invalid key of length %d to fail", len(raw))
		}
	}
}
