package condaccess

import (
	"context"
	"fmt"

	"github.com/fleetdm/fleet/v4/pkg/certificate"
	"github.com/fleetdm/fleet/v4/server/datastore/mysql"
	"github.com/fleetdm/fleet/v4/server/fleet"
	scepdepot "github.com/fleetdm/fleet/v4/server/mdm/scep/depot"
)

type conditionalAccessAssetPair struct {
	certName fleet.MDMAssetName
	keyName  fleet.MDMAssetName
	common   string
}

var conditionalAccessAssetPairs = []conditionalAccessAssetPair{
	{
		certName: fleet.MDMAssetConditionalAccessCACert,
		keyName:  fleet.MDMAssetConditionalAccessCAKey,
		common:   "Fleet Community+ conditional access CA",
	},
	{
		certName: fleet.MDMAssetConditionalAccessIDPCert,
		keyName:  fleet.MDMAssetConditionalAccessIDPKey,
		common:   "Fleet Community+ conditional access IdP",
	},
}

// ensureAssets creates the local certificate material required by conditional
// access. The datastore encrypts private-key assets using Fleet's configured
// server private key; this function never writes keys to the filesystem.
func ensureAssets(ctx context.Context, ds fleet.Datastore) error {
	if ds == nil {
		return fmt.Errorf("conditional access datastore is nil")
	}

	names := make([]fleet.MDMAssetName, 0, len(conditionalAccessAssetPairs)*2)
	for _, pair := range conditionalAccessAssetPairs {
		names = append(names, pair.certName, pair.keyName)
	}

	existing, err := ds.GetAllMDMConfigAssetsByName(ctx, names, nil)
	if err != nil && !fleet.IsNotFound(err) && len(existing) == 0 {
		return fmt.Errorf("load conditional access certificate assets: %w", err)
	}
	if existing == nil {
		existing = make(map[fleet.MDMAssetName]fleet.MDMConfigAsset)
	}

	for _, pair := range conditionalAccessAssetPairs {
		_, hasCert := existing[pair.certName]
		_, hasKey := existing[pair.keyName]
		if hasCert && hasKey {
			continue
		}

		template := scepdepot.NewCACert(
			scepdepot.WithYears(10),
			scepdepot.WithCommonName(pair.common),
			scepdepot.WithOrganization("Local certificate authority"),
			scepdepot.WithCountry("US"),
		)
		cert, key, err := scepdepot.NewCACertKey(template)
		if err != nil {
			return fmt.Errorf("generate %s certificate material: %w", pair.common, err)
		}

		missing := make([]fleet.MDMConfigAsset, 0, 2)
		if !hasCert {
			missing = append(missing, fleet.MDMConfigAsset{Name: pair.certName, Value: certificate.EncodeCertPEM(cert)})
		}
		if !hasKey {
			missing = append(missing, fleet.MDMConfigAsset{Name: pair.keyName, Value: certificate.EncodePrivateKeyPEM(key)})
		}
		if len(missing) == 0 {
			continue
		}
		if err := ds.InsertMDMConfigAssets(ctx, missing, nil); err != nil && !mysql.IsDuplicate(err) {
			return fmt.Errorf("store %s certificate material: %w", pair.common, err)
		}
	}
	return nil
}
