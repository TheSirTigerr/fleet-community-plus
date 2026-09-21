package httpsigproxy

import (
	"errors"
	"testing"
)

func TestNewProxyFailsClosedUntilProxyExists(t *testing.T) {
	proxy, err := NewProxy(t.TempDir(), "https://fleet.example", "cert.pem", false, nil)
	if proxy != nil {
		t.Fatalf("expected no proxy, got %#v", proxy)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}
