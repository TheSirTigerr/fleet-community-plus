package hostidentity

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"
)

func TestSetupFailsClosedUntilSecureEnrollmentExists(t *testing.T) {
	credentials, err := Setup(context.Background(), t.TempDir(), "https://fleet.example", "secret", "cert.pem", "key", false, zerolog.Nop(), func(string) {})
	if credentials != nil {
		t.Fatalf("expected no credentials, got %#v", credentials)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}
