package communityplus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// ValidateAgentOptions preserves Fleet Community validation while independently
// enabling update_channels for Community+. Other Premium-only agent options
// (for example label-scoped extensions) remain gated by Fleet's normal validator.
func ValidateAgentOptions(ctx context.Context, ds fleet.Datastore, raw json.RawMessage, isPremium bool, teamID uint) error {
	if isPremium {
		return fleet.ValidateJSONAgentOptions(ctx, ds, raw, true, teamID)
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return fleet.ValidateJSONAgentOptions(ctx, ds, raw, false, teamID)
	}
	channelsRaw, hasChannels := root["update_channels"]
	rolloutRaw, hasRollout := root["update_rollout"]
	if !hasChannels {
		if hasRollout {
			return errors.New("update_rollout requires update_channels")
		}
		return fleet.ValidateJSONAgentOptions(ctx, ds, raw, false, teamID)
	}

	delete(root, "update_channels")
	withoutChannels, err := json.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshal agent options without update_channels: %w", err)
	}
	if err := fleet.ValidateJSONAgentOptions(ctx, ds, withoutChannels, false, teamID); err != nil {
		return err
	}

	if bytes.Equal(bytes.TrimSpace(channelsRaw), []byte("null")) {
		return errors.New("update_channels cannot be null")
	}

	var channels fleet.OrbitUpdateChannels
	if err := fleet.JSONStrictDecode(bytes.NewReader(channelsRaw), &channels); err != nil {
		return fmt.Errorf("update_channels: %w", err)
	}

	var provided map[string]json.RawMessage
	if err := json.Unmarshal(channelsRaw, &provided); err != nil {
		return fmt.Errorf("update_channels: %w", err)
	}
	for key, rawValue := range provided {
		var value string
		if err := json.Unmarshal(rawValue, &value); err != nil {
			// JSONStrictDecode above provides the user-facing type error.
			continue
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("update_channels.%s is set to an empty string", key)
		}
	}
	if hasRollout {
		if _, err := parseAgentUpdateRollout(rolloutRaw); err != nil {
			return err
		}
	}
	return nil
}

type AgentUpdateRollout struct {
	Percentage int    `json:"percentage"`
	RolloutID  string `json:"rollout_id"`
}

func parseAgentUpdateRollout(raw json.RawMessage) (AgentUpdateRollout, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return AgentUpdateRollout{}, errors.New("update_rollout cannot be null")
	}
	var rollout AgentUpdateRollout
	if err := fleet.JSONStrictDecode(bytes.NewReader(raw), &rollout); err != nil {
		return AgentUpdateRollout{}, fmt.Errorf("update_rollout: %w", err)
	}
	rollout.RolloutID = strings.TrimSpace(rollout.RolloutID)
	if rollout.Percentage < 0 || rollout.Percentage > 100 {
		return AgentUpdateRollout{}, errors.New("update_rollout.percentage must be between 0 and 100")
	}
	if rollout.RolloutID == "" {
		return AgentUpdateRollout{}, errors.New("update_rollout.rollout_id is required")
	}
	if len(rollout.RolloutID) > 128 {
		return AgentUpdateRollout{}, errors.New("update_rollout.rollout_id must be at most 128 characters")
	}
	return rollout, nil
}

func hostInAgentUpdateRollout(hostID uint, rollout AgentUpdateRollout) bool {
	if rollout.Percentage <= 0 {
		return false
	}
	if rollout.Percentage >= 100 {
		return true
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", rollout.RolloutID, hostID)))
	bucket := binary.BigEndian.Uint32(sum[:4]) % 100
	return int(bucket) < rollout.Percentage
}

// AgentUpdateChannelsForHost returns the configured fleetd channels only when
// the host is inside the optional deterministic rollout cohort. A nil result
// means Orbit keeps its current channels, which is what we want outside the wave.
func AgentUpdateChannelsForHost(
	hostID uint,
	channelsRaw json.RawMessage,
	rolloutRaw json.RawMessage,
) (*fleet.OrbitUpdateChannels, error) {
	if len(bytes.TrimSpace(channelsRaw)) == 0 {
		if len(bytes.TrimSpace(rolloutRaw)) > 0 {
			return nil, errors.New("update_rollout requires update_channels")
		}
		return nil, nil
	}

	var channels fleet.OrbitUpdateChannels
	if err := fleet.JSONStrictDecode(bytes.NewReader(channelsRaw), &channels); err != nil {
		return nil, fmt.Errorf("update_channels: %w", err)
	}
	if len(bytes.TrimSpace(rolloutRaw)) == 0 {
		return &channels, nil
	}

	rollout, err := parseAgentUpdateRollout(rolloutRaw)
	if err != nil {
		return nil, err
	}
	if !hostInAgentUpdateRollout(hostID, rollout) {
		return nil, nil
	}
	return &channels, nil
}
