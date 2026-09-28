package service

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxdb"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	apple_mdm "github.com/fleetdm/fleet/v4/server/mdm/apple"
	"github.com/fleetdm/fleet/v4/server/sso"
)

// communityPlusInitiateMDMSSO implements the SAML initiation needed by Apple's
// Account-Driven User Enrollment without changing Fleet's Free license identity.
// Other MDM SSO initiators retain the Community behavior until their feature is
// implemented independently.
func (svc *Service) communityPlusInitiateMDMSSO(
	ctx context.Context,
	initiator, customOriginalURL, hostUUID string,
) (sessionID string, sessionDurationSeconds int, idpURL string, err error) {
	svc.authz.SkipAuthorization(ctx)
	if !strings.HasPrefix(initiator, fleet.SSOInitiatorAccountDrivenEnroll) {
		return "", 0, "", fleet.ErrMissingLicense
	}

	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return "", 0, "", ctxerr.Wrap(ctx, err, "getting app config")
	}
	settings := appConfig.MDM.EndUserAuthentication.SSOProviderSettings
	if settings.IsEmpty() {
		return "", 0, "", ctxerr.Wrap(ctx,
			&fleet.BadRequestError{Message: "organization not configured to use sso"},
			"initiate mdm sso",
		)
	}

	serverURL := appConfig.MDMUrl()
	parsedServerURL, err := url.Parse(serverURL)
	if err != nil {
		return "", 0, "", ctxerr.Wrap(ctx, err, "invalid MDM URL")
	}
	acsURL := sso.CallbackURL(parsedServerURL, svc.config.Server.URLPrefix, "/api/v1/fleet/mdm/sso/callback").String()
	provider, err := sso.SAMLProviderFromConfiguredMetadata(ctx, settings.EntityID, acsURL, &settings)
	if err != nil {
		return "", 0, "", ctxerr.Wrap(ctx, err, "failed to create provider from metadata")
	}

	originalURL := "/"
	if customOriginalURL != "" {
		originalURL = customOriginalURL
	}
	sessionDurationSeconds = int(svc.config.Auth.SsoSessionValidityPeriod.Seconds())
	sessionID, idpURL, err = sso.CreateAuthorizationRequest(
		ctx,
		provider,
		svc.ssoSessionStore,
		originalURL,
		uint(sessionDurationSeconds), //nolint:gosec // duration is configured by the Fleet operator
		fleet.SSORelayStateNone,
		sso.SSORequestData{HostUUID: hostUUID, Initiator: initiator},
	)
	if err != nil {
		return "", 0, "", ctxerr.Wrap(ctx, err, "create MDM SSO authorization request")
	}
	return sessionID, sessionDurationSeconds, idpURL, nil
}

// communityPlusMDMSSOCallback completes only the ADUE lane. It consumes the
// single-use SAML session, persists the IdP identity, then mints the one-time
// enrollment challenge returned to iOS/iPadOS via Apple's custom URL scheme.
func (svc *Service) communityPlusMDMSSOCallback(
	ctx context.Context,
	sessionID string,
	samlResponse []byte,
) (redirectURL, byodCookieValue, deviceSSOSessionID string, deviceSSOSessionDurationSeconds int) {
	svc.authz.SkipAuthorization(ctx)

	idpAccountUUID, requestData, err := svc.communityPlusAuthenticateADUESAML(ctx, sessionID, samlResponse)
	if err != nil {
		if svc.logger != nil {
			svc.logger.ErrorContext(ctx, "Community+ ADUE SSO callback failed", "err", err)
		}
		return apple_mdm.FleetUISSOCallbackError, "", "", 0
	}
	if !strings.HasPrefix(requestData.Initiator, fleet.SSOInitiatorAccountDrivenEnroll) {
		return apple_mdm.FleetUISSOCallbackError, "", "", 0
	}

	var abmTokenID *uint
	if uniqueToken, ok := strings.CutPrefix(requestData.Initiator, fleet.SSOInitiatorAccountDrivenEnroll+":"); ok {
		if uniqueToken == "" {
			return apple_mdm.FleetUISSOCallbackError, "", "", 0
		}
		token, err := svc.ds.GetABMTokenByUniqueToken(ctx, uniqueToken)
		if err != nil {
			if svc.logger != nil {
				svc.logger.ErrorContext(ctx, "get ABM token for ADUE SSO callback", "err", err)
			}
			return apple_mdm.FleetUISSOCallbackError, "", "", 0
		}
		abmTokenID = &token.ID
	}

	challenge, err := svc.ds.InsertADUEEnrollmentChallenge(
		ctx,
		abmTokenID,
		idpAccountUUID,
		fleet.ADUEEnrollmentChallengeExpiration,
	)
	if err != nil {
		if svc.logger != nil {
			svc.logger.ErrorContext(ctx, "insert ADUE enrollment challenge", "err", err)
		}
		return apple_mdm.FleetUISSOCallbackError, "", "", 0
	}

	return fmt.Sprintf("apple-remotemanagement-user-login://authentication-results?access-token=%s", challenge), "", "", 0
}

func (svc *Service) communityPlusAuthenticateADUESAML(
	ctx context.Context,
	sessionID string,
	samlResponse []byte,
) (idpAccountUUID string, requestData sso.SSORequestData, err error) {
	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return "", sso.SSORequestData{}, ctxerr.Wrap(ctx, err, "getting app config for MDM SSO callback")
	}
	settings := appConfig.MDM.EndUserAuthentication.SSOProviderSettings
	if settings.IsEmpty() {
		return "", sso.SSORequestData{}, ctxerr.Wrap(ctx,
			&fleet.BadRequestError{Message: "organization not configured to use sso"},
			"get config for MDM SSO callback",
		)
	}

	serverURL := appConfig.MDMUrl()
	parsedServerURL, err := url.Parse(serverURL)
	if err != nil {
		return "", sso.SSORequestData{}, ctxerr.Wrap(ctx, err, "invalid MDM URL")
	}
	acsURL := sso.CallbackURL(parsedServerURL, svc.config.Server.URLPrefix, "/api/v1/fleet/mdm/sso/callback")

	session, err := svc.ssoSessionStore.Fullfill(sessionID)
	if err != nil {
		return "", sso.SSORequestData{}, ctxerr.Wrap(ctx, err, "fulfill MDM SSO session")
	}
	provider, requestID, _, requestData, err := sso.SAMLProviderFromSession(
		ctx,
		session,
		acsURL,
		settings.EntityID,
		[]string{settings.EntityID, serverURL, acsURL.String()},
	)
	if err != nil {
		return "", sso.SSORequestData{}, ctxerr.Wrap(ctx, err, "create MDM SAML provider from session")
	}
	auth, err := sso.ParseAndVerifySAMLResponse(provider, samlResponse, requestID, acsURL)
	if err != nil {
		return "", sso.SSORequestData{}, ctxerr.Wrap(ctx, err, "verify MDM SAML response")
	}
	if auth == nil || auth.UserID() == "" {
		return "", sso.SSORequestData{}, &fleet.BadRequestError{Message: "SAML response did not contain an IdP user"}
	}

	username := fleet.EmailLocalPart(auth.UserID())
	if err := svc.ds.InsertMDMIdPAccount(ctx, &fleet.MDMIdPAccount{
		Username: username,
		Fullname: auth.UserDisplayName(),
		Email:    auth.UserID(),
	}); err != nil {
		return "", sso.SSORequestData{}, ctxerr.Wrap(ctx, err, "save account data from IdP")
	}

	idpAccount, err := svc.ds.GetMDMIdPAccountByEmail(ctxdb.RequirePrimary(ctx, true), auth.UserID())
	if err != nil {
		return "", sso.SSORequestData{}, ctxerr.Wrap(ctx, err, "read account data from IdP")
	}
	return idpAccount.UUID, requestData, nil
}
