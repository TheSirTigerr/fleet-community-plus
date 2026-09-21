// Package scep contains protocol-neutral helpers shared by Community+ Orbit enrollment.
package scep

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// PublicKeysEqual compares keys through their PKIX encodings, avoiding unsafe
// comparisons across concrete key implementations.
func PublicKeysEqual(first, second crypto.PublicKey) (bool, error) {
	if first == nil || second == nil {
		return false, errors.New("public key is nil")
	}
	firstDER, err := x509.MarshalPKIXPublicKey(first)
	if err != nil {
		return false, err
	}
	secondDER, err := x509.MarshalPKIXPublicKey(second)
	if err != nil {
		return false, err
	}
	return string(firstDER) == string(secondDER), nil
}
