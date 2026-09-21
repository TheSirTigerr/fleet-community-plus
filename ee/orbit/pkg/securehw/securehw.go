// Package securehw defines the hardware-key boundary used by Orbit host identity.
package securehw

import (
	"crypto"
	"errors"

	"github.com/rs/zerolog"
)

var ErrUnavailable = errors.New("Community+ secure hardware provider is unavailable")

type ErrKeyNotFound struct{}

func (*ErrKeyNotFound) Error() string { return "secure hardware key not found" }

type ErrSecureHWUnavailable struct{}

func (*ErrSecureHWUnavailable) Error() string { return ErrUnavailable.Error() }

type ECCAlgorithm string

const (
	ECCAlgorithmP256 ECCAlgorithm = "P-256"
	ECCAlgorithmP384 ECCAlgorithm = "P-384"
)

type HTTPSigner interface {
	crypto.Signer
	ECCAlgorithm() ECCAlgorithm
}

type Key interface {
	Public() (crypto.PublicKey, error)
	HTTPSigner() (HTTPSigner, error)
}

type SecureHW interface {
	LoadKey() (Key, error)
	Close()
}

type unavailableSecureHW struct{}

func New(_ string, _ zerolog.Logger) (SecureHW, error) { return nil, &ErrSecureHWUnavailable{} }

func (unavailableSecureHW) LoadKey() (Key, error) { return nil, &ErrKeyNotFound{} }

func (unavailableSecureHW) Close() {}
