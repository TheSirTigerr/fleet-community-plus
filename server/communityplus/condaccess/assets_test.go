package condaccess

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	fleetmock "github.com/fleetdm/fleet/v4/server/mock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

func TestEnsureAssetsSkipsCompleteMaterial(t *testing.T) {
	ds := new(fleetmock.Store)
	ds.GetAllMDMConfigAssetsByNameFunc = func(_ context.Context, names []fleet.MDMAssetName, _ sqlx.QueryerContext) (map[fleet.MDMAssetName]fleet.MDMConfigAsset, error) {
		result := make(map[fleet.MDMAssetName]fleet.MDMConfigAsset, len(names))
		for _, name := range names {
			result[name] = fleet.MDMConfigAsset{Name: name, Value: []byte("present")}
		}
		return result, nil
	}

	require.NoError(t, ensureAssets(context.Background(), ds))
	require.False(t, ds.InsertMDMConfigAssetsFuncInvoked)
}

func TestEnsureAssetsCreatesOnlyMissingMaterial(t *testing.T) {
	ds := new(fleetmock.Store)
	ds.GetAllMDMConfigAssetsByNameFunc = func(context.Context, []fleet.MDMAssetName, sqlx.QueryerContext) (map[fleet.MDMAssetName]fleet.MDMConfigAsset, error) {
		return map[fleet.MDMAssetName]fleet.MDMConfigAsset{
			fleet.MDMAssetConditionalAccessCACert: {
				Name:  fleet.MDMAssetConditionalAccessCACert,
				Value: []byte("existing-ca"),
			},
		}, nil
	}

	created := make(map[fleet.MDMAssetName][]byte)
	ds.InsertMDMConfigAssetsFunc = func(_ context.Context, assets []fleet.MDMConfigAsset, _ sqlx.ExtContext) error {
		for _, asset := range assets {
			created[asset.Name] = append([]byte(nil), asset.Value...)
		}
		return nil
	}

	require.NoError(t, ensureAssets(context.Background(), ds))
	require.NotContains(t, created, fleet.MDMAssetConditionalAccessCACert)
	for _, name := range []fleet.MDMAssetName{
		fleet.MDMAssetConditionalAccessCAKey,
		fleet.MDMAssetConditionalAccessIDPCert,
		fleet.MDMAssetConditionalAccessIDPKey,
	} {
		require.NotEmpty(t, created[name], "missing generated asset %s", name)
	}
}
