package est

import (
	"log/slog"
	"testing"
)

func TestNewServiceWithoutOptions(t *testing.T) {
	if svc := NewService(); svc == nil {
		t.Fatal("expected default EST service")
	}
}

func TestNewServiceAppliesOptions(t *testing.T) {
	called := false
	svc := NewService(
		WithLogger(slog.Default()),
		func(*Service) { called = true },
	)
	if svc == nil {
		t.Fatal("expected EST service")
	}
	if !called {
		t.Fatal("expected EST option to run")
	}
}
