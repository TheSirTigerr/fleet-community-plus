package securehw

import (
	"errors"
	"testing"

	"github.com/rs/zerolog"
)

func TestNewFailsClosedWhenProviderUnavailable(t *testing.T) {
	device, err := New(t.TempDir(), zerolog.Nop())
	if device != nil {
		t.Fatalf("expected no secure hardware device, got %T", device)
	}
	var unavailable *ErrSecureHWUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected ErrSecureHWUnavailable, got %v", err)
	}
}
