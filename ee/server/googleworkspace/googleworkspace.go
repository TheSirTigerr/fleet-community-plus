// Package googleworkspace defines the disabled external-directory boundary.
package googleworkspace

import (
	"context"
	"errors"
	"log/slog"

	"github.com/fleetdm/fleet/v4/server/cron"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

var ErrUnavailable = errors.New("Community+ Google Workspace directory is unavailable")

type Limits struct {
	MaxUsers            int
	MaxGroups           int
	MaxGroupMembers     int
	MaxGroupMemberships int
}

func NewDirectoryFactory(_ Limits) cron.GoogleWorkspaceDirectoryFactory {
	return func(context.Context, *fleet.GoogleWorkspaceIntegration, *slog.Logger) (fleet.GoogleWorkspaceDirectory, error) {
		return nil, ErrUnavailable
	}
}
