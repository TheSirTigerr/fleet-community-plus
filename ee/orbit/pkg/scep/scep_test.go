package scep

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestPublicKeysEqual(t *testing.T) {
	first, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	equal, err := PublicKeysEqual(&first.PublicKey, &first.PublicKey)
	if err != nil || !equal {
		t.Fatalf("same key: equal=%v err=%v", equal, err)
	}
	equal, err = PublicKeysEqual(&first.PublicKey, &second.PublicKey)
	if err != nil || equal {
		t.Fatalf("different keys: equal=%v err=%v", equal, err)
	}
}
