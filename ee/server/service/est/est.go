// Package est is a compatibility facade for the Community+ EST boundary.
package est

import (
	"log/slog"

	communityest "github.com/fleetdm/fleet/v4/server/communityplus/est"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type Service = communityest.Service
type Option = communityest.Option

func WithLogger(logger *slog.Logger) Option { return communityest.WithLogger(logger) }

func NewService(opts ...Option) fleet.ESTService { return communityest.NewService(opts...) }
