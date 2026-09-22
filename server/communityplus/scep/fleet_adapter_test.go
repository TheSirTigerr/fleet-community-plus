package scep

import (
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestNewSCEPConfigServiceUsesDefaultTimeout(t *testing.T) {
	service := NewSCEPConfigService(nil, nil)
	adapter, ok := service.(*SCEPConfigService)
	if !ok || adapter == nil {
		t.Fatalf("expected Community+ SCEP adapter, got %T", service)
	}
	if adapter.Timeout == nil || *adapter.Timeout != 10*time.Second {
		t.Fatalf("expected 10s default timeout, got %v", adapter.Timeout)
	}
}

func TestFleetSmallstepConfig(t *testing.T) {
	input := fleet.SmallstepSCEPProxyCA{
		URL:          "https://scep.example.test/scep",
		ChallengeURL: "https://scep.example.test/challenge",
		Username:     "user",
		Password:     "secret",
	}
	got := fleetSmallstepConfig(input)
	if got.SCEPURL != input.URL || got.ChallengeURL != input.ChallengeURL || got.Username != input.Username || got.Password != input.Password {
		t.Fatalf("unexpected Smallstep mapping: %#v", got)
	}
}
