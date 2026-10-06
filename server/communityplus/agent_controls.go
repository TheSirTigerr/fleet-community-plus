package communityplus

import (
	"bytes"
	"context"
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
	if !hasChannels {
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
	return nil
}
