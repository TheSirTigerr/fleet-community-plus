package osquery_utils

import (
	"context"
	"log/slog"
	"testing"

	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

func TestCommunityPlusMunkiBaseQueryAndIngest(t *testing.T) {
	queries := GetDetailQueries(context.Background(), config.FleetConfig{}, nil, nil, Integrations{}, nil)
	query, ok := queries["munki_info"]
	require.True(t, ok, "munki_info must be part of the Community detail-query set")
	require.Equal(t, []string{"darwin"}, query.Platforms)
	require.NotNil(t, query.DirectIngestFunc)

	store := new(mock.Store)
	var (
		gotHostID   uint
		gotVersion  string
		gotErrors   []string
		gotWarnings []string
	)
	store.SetOrUpdateMunkiInfoFunc = func(_ context.Context, hostID uint, version string, errors, warnings []string) error {
		gotHostID = hostID
		gotVersion = version
		gotErrors = append([]string(nil), errors...)
		gotWarnings = append([]string(nil), warnings...)
		return nil
	}

	host := &fleet.Host{ID: 42}
	rows := []map[string]string{{
		"version":  "6.6.2",
		"errors":   "first error; second error ;",
		"warnings": "one warning",
	}}
	err := query.DirectIngestFunc(
		context.Background(),
		slog.New(slog.DiscardHandler),
		host,
		store,
		rows,
	)
	require.NoError(t, err)
	require.Equal(t, uint(42), gotHostID)
	require.Equal(t, "6.6.2", gotVersion)
	require.Equal(t, []string{"first error", "second error"}, gotErrors)
	require.Equal(t, []string{"one warning"}, gotWarnings)

	err = query.DirectIngestFunc(
		context.Background(),
		slog.New(slog.DiscardHandler),
		host,
		store,
		nil,
	)
	require.NoError(t, err)
	require.Empty(t, gotVersion)
	require.Empty(t, gotErrors)
	require.Empty(t, gotWarnings)
}
