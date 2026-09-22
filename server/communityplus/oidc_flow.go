package communityplus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var ErrOIDCFlowInvalid = errors.New("communityplus: OIDC flow is invalid, expired, or already consumed")

// OIDCFlow contains the ephemeral server-side state required to complete one
// authorization-code flow. State is never persisted directly; SQLStore hashes
// it before storage so a database read cannot be used to forge callbacks.
type OIDCFlow struct {
	State        string
	Nonce        string
	CodeVerifier string
	RedirectURL  string
	ExpiresAt    time.Time
}

func (f OIDCFlow) Validate() error {
	if f.State == "" || f.Nonce == "" || f.CodeVerifier == "" {
		return fmt.Errorf("communityplus: OIDC flow state, nonce, and code verifier are required")
	}
	if f.RedirectURL == "" {
		return fmt.Errorf("communityplus: OIDC flow redirect URL is required")
	}
	if f.ExpiresAt.IsZero() {
		return fmt.Errorf("communityplus: OIDC flow expiry is required")
	}
	return nil
}

type OIDCFlowStore interface {
	SaveOIDCFlow(context.Context, OIDCFlow) error
	ConsumeOIDCFlow(context.Context, string) (OIDCFlow, error)
}

func oidcStateHash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}
