package servicecompat

import (
	"context"
	"testing"
)

func TestNewServicePreservesBaseService(t *testing.T) {
	service, err := NewService(nil, struct{}{}, "ignored-startup-option", 42)
	if err != nil {
		t.Fatalf("new Community+ service: %v", err)
	}
	if service != nil {
		t.Fatalf("expected nil base service to remain nil, got %T", service)
	}
}

func TestCompatibilityMigrationsAreNoOps(t *testing.T) {
	ctx := context.Background()
	if err := UninstallSoftwareMigration(ctx, nil, nil, nil); err != nil {
		t.Fatalf("uninstall software migration: %v", err)
	}
	if err := UpgradeCodeMigration(ctx, nil, nil, nil); err != nil {
		t.Fatalf("upgrade code migration: %v", err)
	}
	if err := AutoUpdateFleetMaintainedApps(ctx, nil, nil, nil); err != nil {
		t.Fatalf("maintained apps migration: %v", err)
	}
}

func TestValidateSoftwareLabelsRejectsMultipleScopesBeforeServiceCall(t *testing.T) {
	_, err := ValidateSoftwareLabels(context.Background(), nil, nil, []string{"a"}, []string{"b"}, nil)
	if err == nil {
		t.Fatal("expected mutually exclusive label scopes to be rejected")
	}
}
