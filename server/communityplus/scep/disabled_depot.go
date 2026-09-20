package scep

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
)

// ErrFeatureUnavailable is returned by certificate depots for Community+
// capabilities that have not been implemented yet.
var ErrFeatureUnavailable = errors.New("Community+ certificate capability is unavailable")

// DisabledDepot satisfies the SCEP depot contract without silently issuing or
// persisting certificates. It is used only behind disabled capability gates.
type DisabledDepot struct{}

func (DisabledDepot) CA([]byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	return nil, nil, ErrFeatureUnavailable
}

func (DisabledDepot) Put(string, *x509.Certificate) error { return ErrFeatureUnavailable }

func (DisabledDepot) Serial() (*big.Int, error) { return nil, ErrFeatureUnavailable }

func (DisabledDepot) HasCN(string, int, *x509.Certificate, bool) (bool, error) {
	return false, ErrFeatureUnavailable
}
