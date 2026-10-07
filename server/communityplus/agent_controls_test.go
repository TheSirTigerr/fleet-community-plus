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


func TestValidateAgentOptionsAllowsControlledUpdateRollout(t *testing.T) {
	raw := json.RawMessage(`{
		"config":{},
		"update_channels":{"orbit":"edge","osqueryd":"stable","desktop":"stable"},
		"update_rollout":{"percentage":25,"rollout_id":"fleetd-2026-10"}
	}`)
	if err := ValidateAgentOptions(context.Background(), nil, raw, false, 0); err != nil {
		t.Fatalf("validate controlled update rollout: %v", err)
	}
}

func TestValidateAgentOptionsRejectsInvalidUpdateRollout(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"update_rollout":{"percentage":10,"rollout_id":"wave-1"}}`),
		json.RawMessage(`{"update_channels":{"orbit":"stable"},"update_rollout":null}`),
		json.RawMessage(`{"update_channels":{"orbit":"stable"},"update_rollout":{"percentage":101,"rollout_id":"wave-1"}}`),
		json.RawMessage(`{"update_channels":{"orbit":"stable"},"update_rollout":{"percentage":10,"rollout_id":""}}`),
		json.RawMessage(`{"update_channels":{"orbit":"stable"},"update_rollout":{"percentage":10,"rollout_id":"wave-1","future":true}}`),
	} {
		if err := ValidateAgentOptions(context.Background(), nil, raw, false, 0); err == nil {
			t.Fatalf("expected invalid rollout to fail: %s", raw)
		}
	}
}

func TestAgentUpdateChannelsForHostRollout(t *testing.T) {
	channels := json.RawMessage(`{"orbit":"edge","osqueryd":"stable","desktop":"stable"}`)

	got, err := AgentUpdateChannelsForHost(42, channels, json.RawMessage(`{"percentage":0,"rollout_id":"wave-a"}`))
	if err != nil {
		t.Fatalf("0%% rollout: %v", err)
	}
	if got != nil {
		t.Fatalf("0%% rollout unexpectedly returned channels: %#v", got)
	}

	got, err = AgentUpdateChannelsForHost(42, channels, json.RawMessage(`{"percentage":100,"rollout_id":"wave-a"}`))
	if err != nil {
		t.Fatalf("100%% rollout: %v", err)
	}
	if got == nil || got.Orbit != "edge" || got.Osqueryd != "stable" || got.Desktop != "stable" {
		t.Fatalf("100%% rollout returned unexpected channels: %#v", got)
	}

	rollout := AgentUpdateRollout{Percentage: 35, RolloutID: "wave-stable"}
	first := hostInAgentUpdateRollout(12345, rollout)
	for i := 0; i < 20; i++ {
		if got := hostInAgentUpdateRollout(12345, rollout); got != first {
			t.Fatal("rollout cohort assignment was not stable")
		}
	}

	included := 0
	for hostID := uint(1); hostID <= 1000; hostID++ {
		if hostInAgentUpdateRollout(hostID, rollout) {
			included++
		}
	}
	if included < 250 || included > 450 {
		t.Fatalf("35%% rollout cohort distribution looks wrong: %d/1000", included)
	}
}
