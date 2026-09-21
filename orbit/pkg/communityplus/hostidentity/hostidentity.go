// Package hostidentity is the Community+ Orbit enrollment boundary.
package hostidentity

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/fleetdm/fleet/v4/orbit/pkg/communityplus/securehw"
	"github.com/rs/zerolog"
)

var ErrUnavailable = errors.New("Community+ Orbit host identity enrollment is unavailable")

type Credentials struct {
	Certificate     *x509.Certificate
	CertificatePath string
	SecureHWKey     securehw.Key
	SecureHW        securehw.SecureHW
}

func (c *Credentials) Close() {
	if c != nil && c.SecureHW != nil {
		c.SecureHW.Close()
	}
}

// Setup intentionally fails until a TPM-backed enrollment implementation is
// available. It never falls back to a filesystem private key.
func Setup(_ context.Context, _ string, _ string, _ string, _ string, _ string, _ bool, _ zerolog.Logger, _ func(string)) (*Credentials, error) {
	return nil, ErrUnavailable
}
