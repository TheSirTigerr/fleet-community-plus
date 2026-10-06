package communityplus

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestValidateAgentOptionsAllowsUpdateChannelsWithoutPremium(t *testing.T) {
	raw := json.RawMessage(`{
		"config":{},
		"update_channels":{"orbit":"stable","osqueryd":"stable","desktop":"stable"}
	}`)
	if err := ValidateAgentOptions(context.Background(), nil, raw, false, 0); err != nil {
		t.Fatalf("validate Community+ update channels: %v", err)
	}
}

func TestValidateAgentOptionsKeepsOtherPremiumAgentOptionsGated(t *testing.T) {
	raw := json.RawMessage(`{
		"extensions":{
			"example":{"platform":"windows","channel":"stable","labels":["workstations"]}
		},
		"update_channels":{"orbit":"stable"}
	}`)
	err := ValidateAgentOptions(context.Background(), nil, raw, false, 0)
	if !errors.Is(err, fleet.ErrMissingLicense) {
		t.Fatalf("expected non-update-channel Premium option to remain gated, got %v", err)
	}
}

func TestValidateAgentOptionsRejectsInvalidUpdateChannels(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"update_channels":null}`),
		json.RawMessage(`{"update_channels":{"orbit":""}}`),
		json.RawMessage(`{"update_channels":{"future":"stable"}}`),
	} {
		if err := ValidateAgentOptions(context.Background(), nil, raw, false, 0); err == nil {
			t.Fatalf("expected invalid update channels to fail: %s", raw)
		}
	}
}
