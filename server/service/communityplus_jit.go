package service

import (
	"context"
	"errors"
	"strings"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/platform/endpointer"
)

// CommunityPlusGetSSOUser resolves an SSO identity to a Fleet user and, when
// explicitly enabled, provisions a missing user on first successful IdP login.
// Newly provisioned users receive the least-privileged built-in global role;
// role/group mapping is intentionally handled by a separate integration layer.
func (svc *Service) CommunityPlusGetSSOUser(ctx context.Context, auth fleet.Auth, enableJIT bool) (*fleet.User, error) {
	email := strings.ToLower(strings.TrimSpace(auth.UserID()))
	if email == "" {
		return nil, ctxerr.Wrap(ctx, newSSOError(errors.New("SSO identity did not contain an email address"), ssoAccountInvalid))
	}

	user, err := svc.ds.UserByEmail(ctx, email)
	if err == nil {
		return user, nil
	}
	var notFound endpointer.NotFoundErrorInterface
	if !errors.As(err, &notFound) {
		return nil, ctxerr.Wrap(ctx, err, "find user in Community+ sso callback")
	}
	if !enableJIT {
		return nil, ctxerr.Wrap(ctx, newSSOError(err, ssoAccountInvalid))
	}
	if err := fleet.ValidateEmail(email); err != nil {
		return nil, ctxerr.Wrap(ctx, newSSOError(err, ssoAccountInvalid))
	}

	displayName := strings.TrimSpace(auth.UserDisplayName())
	if displayName == "" {
		displayName = email
	}
	globalRole := fleet.RoleObserver
	ssoEnabled := true
	adminForcedPasswordReset := false

	// This endpoint is intentionally unauthenticated until the IdP assertion has
	// been verified. JIT provisioning is authorized by that verified identity and
	// the explicit server-side JIT setting rather than an existing Fleet viewer.
	svc.authz.SkipAuthorization(ctx)
	user, err = svc.NewUser(ctx, fleet.UserPayload{
		Name:                     &displayName,
		Email:                    &email,
		SSOEnabled:               &ssoEnabled,
		GlobalRole:               &globalRole,
		AdminForcedPasswordReset: &adminForcedPasswordReset,
		JITProvisioned:           true,
	})
	if err != nil {
		// Do not turn an arbitrary provisioning failure into success by re-reading
		// the user. NewUser also records creation/role activities, so a post-insert
		// activity failure must remain visible to the caller rather than being
		// mistaken for a harmless concurrent insert.
		return nil, ctxerr.Wrap(ctx, err, "JIT provision Community+ SSO user")
	}
	return user, nil
}

// CommunityPlusGetSSOUser forwards the Community+ extension through Fleet's
// validation middleware. The middleware embeds fleet.Service, whose interface
// does not expose Community+ extension methods, so an explicit forwarder is
// required for callers such as the OIDC login router to reach the core service.
func (mw validationMiddleware) CommunityPlusGetSSOUser(ctx context.Context, auth fleet.Auth, enableJIT bool) (*fleet.User, error) {
	resolver, ok := mw.Service.(interface {
		CommunityPlusGetSSOUser(context.Context, fleet.Auth, bool) (*fleet.User, error)
	})
	if !ok {
		return nil, errors.New("communityplus: JIT SSO resolver is unavailable")
	}
	return resolver.CommunityPlusGetSSOUser(ctx, auth, enableJIT)
}
