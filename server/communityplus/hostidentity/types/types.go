// Package types contains the Community+ host-identity certificate model.
package types

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"time"
)

// HostIdentityCertificate is the validated public identity associated with a
// Fleet host. Private key material is never stored by the server.
type HostIdentityCertificate struct {
	SerialNumber  uint64     `db:"serial" json:"serial_number"`
	HostID        *uint      `db:"host_id" json:"host_id,omitempty"`
	CommonName    string     `db:"name" json:"common_name"`
	NotValidAfter time.Time  `db:"not_valid_after" json:"not_valid_after"`
	PublicKeyRaw  []byte     `db:"public_key_raw" json:"-"`
	CreatedAt     *time.Time `db:"created_at" json:"created_at,omitempty"`
}

// CreateECDSAPublicKeyRaw serializes an ECDSA public key using SEC1 compressed
// point encoding. The curve is recovered from the encoded point length.
func CreateECDSAPublicKeyRaw(key *ecdsa.PublicKey) ([]byte, error) {
	if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
		return nil, fmt.Errorf("communityplus: invalid ECDSA public key")
	}
	switch key.Curve {
	case elliptic.P256(), elliptic.P384():
	default:
		return nil, fmt.Errorf("communityplus: unsupported ECDSA curve %q", key.Curve.Params().Name)
	}
	return elliptic.MarshalCompressed(key.Curve, key.X, key.Y), nil
}

// UnmarshalPublicKey parses the stored compressed P-256 or P-384 public key.
func (c HostIdentityCertificate) UnmarshalPublicKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch len(c.PublicKeyRaw) {
	case 33:
		curve = elliptic.P256()
	case 49:
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("communityplus: unsupported ECDSA public key length %d", len(c.PublicKeyRaw))
	}
	x, y := elliptic.UnmarshalCompressed(curve, c.PublicKeyRaw)
	if x == nil || y == nil {
		return nil, fmt.Errorf("communityplus: invalid ECDSA public key")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
