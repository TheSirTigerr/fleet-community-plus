package communityplus

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func TestCustomTablesUseCommunityAgentOptions(t *testing.T) {
	agentOptions := json.RawMessage(`{
		"config": {
			"auto_table_construction": {
				"local_inventory": {
					"query": "SELECT key, value FROM inventory",
					"path": "/var/lib/example/inventory.db",
					"columns": ["key", "value"]
			}
		},
		"command_line_flags": {
			"disable_tables": "chrome_extensions"
		},
		"extensions": {
			"inventory_linux": {
				"channel": "stable",
				"platform": "linux"
			}
		}
	}`)

	if err := fleet.ValidateJSONAgentOptions(context.Background(), nil, agentOptions, false, 0); err != nil {
		t.Fatalf("validate Community+ custom table agent options: %v", err)
	}
}
