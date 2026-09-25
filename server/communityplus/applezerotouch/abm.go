package applezerotouch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/fleetdm/fleet/v4/pkg/optjson"
	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/fleet"
	apple_mdm "github.com/fleetdm/fleet/v4/server/mdm/apple"
	"github.com/fleetdm/fleet/v4/server/mdm/assets"
	depclient "github.com/fleetdm/fleet/v4/server/mdm/nanodep/client"
	nanodep_storage "github.com/fleetdm/fleet/v4/server/mdm/nanodep/storage"
)

// ABMService implements the Apple Business Manager token operations required by
// Automated Device Enrollment. Cryptographic token parsing and Apple DEP
// metadata retrieval use Fleet's public Community MDM primitives; authorization
// and orchestration live here so the API is not tied to Fleet Premium.
type ABMService struct {
	ds         fleet.Datastore
	depStorage nanodep_storage.AllDEPStorage
	authorizer *authz.Authorizer
	logger     *slog.Logger
}

func NewABMService(ds fleet.Datastore, depStorage nanodep_storage.AllDEPStorage, authorizer *authz.Authorizer, logger *slog.Logger) (*ABMService, error) {
	if ds == nil {
		return nil, errors.New("apple zero-touch ABM datastore is nil")
	}
	if depStorage == nil {
		return nil, errors.New("apple zero-touch DEP storage is nil")
	}
	if authorizer == nil {
		return nil, errors.New("apple zero-touch ABM authorizer is nil")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &ABMService{ds: ds, depStorage: depStorage, authorizer: authorizer, logger: logger}, nil
}

func (s *ABMService) UploadToken(ctx context.Context, reader io.Reader) (*fleet.ABMToken, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.AppleBM{}, fleet.ActionWrite); err != nil {
		return nil, err
	}
	encrypted, decrypted, err := s.decryptUploadedToken(ctx, reader)
	if err != nil {
		return nil, err
	}

	token := &fleet.ABMToken{EncryptedToken: encrypted}
	if err := apple_mdm.SetDecryptedABMTokenMetadata(ctx, token, decrypted, s.depStorage, s.ds, s.logger, false); err != nil {
		return nil, fmt.Errorf("load Apple Business Manager token metadata: %w", err)
	}
	token, err = s.ds.InsertABMToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("store Apple Business Manager token: %w", err)
	}
	if err := s.syncAppConfig(ctx); err != nil {
		return nil, err
	}
	return token, nil
}

func (s *ABMService) RenewToken(ctx context.Context, reader io.Reader, tokenID uint) (*fleet.ABMToken, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.AppleBM{}, fleet.ActionWrite); err != nil {
		return nil, err
	}
	token, err := s.ds.GetABMTokenByID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("load Apple Business Manager token: %w", err)
	}
	encrypted, decrypted, err := s.decryptUploadedToken(ctx, reader)
	if err != nil {
		return nil, err
	}
	if err := apple_mdm.SetDecryptedABMTokenMetadata(ctx, token, decrypted, s.depStorage, s.ds, s.logger, true); err != nil {
		return nil, fmt.Errorf("refresh Apple Business Manager token metadata: %w", err)
	}
	token.EncryptedToken = encrypted
	token.TokenInvalid = false
	token.TermsExpired = false
	if err := s.ds.SaveABMToken(ctx, token); err != nil {
		return nil, fmt.Errorf("save renewed Apple Business Manager token: %w", err)
	}
	if err := s.syncAppConfig(ctx); err != nil {
		return nil, err
	}
	return token, nil
}

func (s *ABMService) ListTokens(ctx context.Context) ([]*fleet.ABMToken, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.AppleBM{}, fleet.ActionList); err != nil {
		return nil, err
	}
	tokens, err := s.ds.ListABMTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Apple Business Manager tokens: %w", err)
	}
	return tokens, nil
}

func (s *ABMService) CountTokens(ctx context.Context) (int, error) {
	// The count is used by GitOps/config plumbing and does not expose token data.
	if err := s.authorizer.Authorize(ctx, &fleet.AppConfig{}, fleet.ActionRead); err != nil {
		return 0, err
	}
	count, err := s.ds.GetABMTokenCount(ctx)
	if err != nil {
		return 0, fmt.Errorf("count Apple Business Manager tokens: %w", err)
	}
	return count, nil
}

func (s *ABMService) UpdateTokenTeams(ctx context.Context, tokenID uint, macOSTeamID, iOSTeamID, iPadOSTeamID, byodTeamID *uint) (*fleet.ABMToken, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.AppleBM{}, fleet.ActionWrite); err != nil {
		return nil, err
	}
	for _, teamID := range []*uint{macOSTeamID, iOSTeamID, iPadOSTeamID, byodTeamID} {
		if teamID == nil || *teamID == 0 {
			continue
		}
		if _, err := s.ds.TeamWithExtras(ctx, *teamID); err != nil {
			return nil, fmt.Errorf("load default fleet %d for Apple Business Manager token: %w", *teamID, err)
		}
	}

	token, err := s.ds.GetABMTokenByID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("load Apple Business Manager token: %w", err)
	}
	token.MacOSDefaultTeamID = normalizeTeamID(macOSTeamID)
	token.IOSDefaultTeamID = normalizeTeamID(iOSTeamID)
	token.IPadOSDefaultTeamID = normalizeTeamID(iPadOSTeamID)
	token.BYODDefaultTeamID = normalizeTeamID(byodTeamID)
	if err := s.ds.SaveABMToken(ctx, token); err != nil {
		return nil, fmt.Errorf("save Apple Business Manager default fleets: %w", err)
	}
	if err := s.syncAppConfig(ctx); err != nil {
		return nil, err
	}
	return token, nil
}

func (s *ABMService) SetDefaultToken(ctx context.Context, tokenID uint, isDefault *bool) (*fleet.ABMToken, error) {
	if err := s.authorizer.Authorize(ctx, &fleet.AppleBM{}, fleet.ActionWrite); err != nil {
		return nil, err
	}
	if isDefault == nil {
		return nil, &fleet.BadRequestError{Message: "default is required"}
	}
	if _, err := s.ds.GetABMTokenByID(ctx, tokenID); err != nil {
		return nil, fmt.Errorf("load Apple Business Manager token: %w", err)
	}
	if *isDefault {
		if err := s.ds.SetABMTokenDefault(ctx, tokenID); err != nil {
			return nil, fmt.Errorf("set default Apple Business Manager token: %w", err)
		}
	} else {
		if err := s.ds.ClearABMTokenDefault(ctx); err != nil {
			return nil, fmt.Errorf("clear default Apple Business Manager token: %w", err)
		}
	}
	if err := s.syncAppConfig(ctx); err != nil {
		return nil, err
	}
	token, err := s.ds.GetABMTokenByID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("reload Apple Business Manager token: %w", err)
	}
	return token, nil
}

func (s *ABMService) DeleteToken(ctx context.Context, tokenID uint) error {
	if err := s.authorizer.Authorize(ctx, &fleet.AppleBM{}, fleet.ActionWrite); err != nil {
		return err
	}
	if _, err := s.ds.GetABMTokenByID(ctx, tokenID); err != nil {
		return fmt.Errorf("load Apple Business Manager token: %w", err)
	}
	if err := s.ds.DeleteABMToken(ctx, tokenID); err != nil {
		return fmt.Errorf("delete Apple Business Manager token: %w", err)
	}
	return s.syncAppConfig(ctx)
}

func (s *ABMService) decryptUploadedToken(ctx context.Context, reader io.Reader) ([]byte, *depclient.OAuth1Tokens, error) {
	if reader == nil {
		return nil, nil, &fleet.BadRequestError{Message: "Apple Business Manager token is required"}
	}
	encrypted, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("read Apple Business Manager token: %w", err)
	}
	if len(encrypted) == 0 {
		return nil, nil, &fleet.BadRequestError{Message: "Apple Business Manager token is empty"}
	}
	cert, err := assets.X509Cert(ctx, s.ds, fleet.MDMAssetABMCert)
	if err != nil {
		return nil, nil, fmt.Errorf("load Apple Business Manager certificate: %w", err)
	}
	keyAssets, err := s.ds.GetAllMDMConfigAssetsByName(ctx, []fleet.MDMAssetName{fleet.MDMAssetABMKey}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("load Apple Business Manager private key: %w", err)
	}
	keyAsset, ok := keyAssets[fleet.MDMAssetABMKey]
	if !ok || len(keyAsset.Value) == 0 {
		return nil, nil, errors.New("Apple Business Manager private key is missing")
	}
	decrypted, err := assets.DecryptRawABMToken(encrypted, cert, keyAsset.Value)
	if err != nil {
		return nil, nil, &fleet.BadRequestError{Message: "Apple Business Manager token could not be decrypted", InternalErr: err}
	}
	return encrypted, decrypted, nil
}

func (s *ABMService) syncAppConfig(ctx context.Context) error {
	tokens, err := s.ds.ListABMTokens(ctx)
	if err != nil {
		return fmt.Errorf("list Apple Business Manager tokens for app config sync: %w", err)
	}
	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("load app config for Apple Business Manager: %w", err)
	}

	entries := make([]fleet.MDMAppleABMAssignmentInfo, 0, len(tokens))
	termsExpired := false
	for _, token := range tokens {
		if token == nil {
			continue
		}
		entries = append(entries, fleet.MDMAppleABMAssignmentInfo{
			OrganizationName: token.OrganizationName,
			Default:          token.IsDefault,
			MacOSTeam:        appConfigABMTeamName(token.MacOSTeamName),
			IOSTeam:          appConfigABMTeamName(token.IOSTeamName),
			IpadOSTeam:       appConfigABMTeamName(token.IPadOSTeamName),
			BYODTeam:         appConfigABMTeamName(token.BYODTeamName),
		})
		termsExpired = termsExpired || token.TermsExpired
	}
	appConfig.MDM.AppleBusinessManager = optjson.SetSlice(entries)
	appConfig.MDM.AppleBMEnabledAndConfigured = len(entries) > 0
	appConfig.MDM.AppleBMTermsExpired = termsExpired
	if err := s.ds.SaveAppConfig(ctx, appConfig); err != nil {
		return fmt.Errorf("save Apple Business Manager app config: %w", err)
	}
	return nil
}

func appConfigABMTeamName(name string) string {
	if name == "No team" {
		return ""
	}
	return name
}

func normalizeTeamID(teamID *uint) *uint {
	if teamID == nil || *teamID == 0 {
		return nil
	}
	id := *teamID
	return &id
}
