package service

import (
	"context"
	"errors"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

// communityPlusSSORoles resolves Fleet's documented JIT role attributes to
// concrete global/fleet roles. The parser already validates role names,
// duplicate fleet assignments, and global-vs-fleet conflicts; this layer also
// verifies that referenced fleets exist before any user state is changed.
func (svc *Service) communityPlusSSORoles(ctx context.Context, attrs []fleet.SAMLAttribute) (*string, []fleet.UserTeam, bool, error) {
	info, coerced, err := fleet.RolesFromSSOAttributes(attrs)
	if err != nil {
		return nil, nil, false, ctxerr.Wrap(ctx, err, "invalid Community+ SSO role attributes")
	}
	if len(coerced) > 0 && svc.logger != nil {
		svc.logger.WarnContext(ctx, "Community+ SSO role attribute value coerced to null", "attributes", coerced)
	}
	if !info.IsSet() {
		return nil, nil, false, nil
	}

	roles := make([]fleet.UserTeam, 0, len(info.Teams))
	for _, mapped := range info.Teams {
		team, err := svc.ds.TeamWithExtras(ctx, mapped.ID)
		if err != nil {
			return nil, nil, false, ctxerr.Wrap(ctx, err, "resolve Community+ SSO fleet role")
		}
		if team == nil {
			return nil, nil, false, ctxerr.New(ctx, "Community+ SSO fleet role resolved to nil fleet")
		}
		roles = append(roles, fleet.UserTeam{Team: *team, Role: mapped.Role})
	}
	return info.Global, roles, true, nil
}

func communityPlusSSORolesChanged(oldGlobal *string, oldTeams []fleet.UserTeam, newGlobal *string, newTeams []fleet.UserTeam) bool {
	if oldGlobal == nil != (newGlobal == nil) {
		return true
	}
	if oldGlobal != nil && newGlobal != nil && *oldGlobal != *newGlobal {
		return true
	}
	if len(oldTeams) != len(newTeams) {
		return true
	}
	oldByID := make(map[uint]string, len(oldTeams))
	for _, team := range oldTeams {
		oldByID[team.ID] = team.Role
	}
	for _, team := range newTeams {
		if role, ok := oldByID[team.ID]; !ok || role != team.Role {
			return true
		}
	}
	return false
}

// communityPlusSyncSSORoles applies authoritative IdP roles to an existing
// user. The datastore operation atomically protects the last global admin.
func (svc *Service) communityPlusSyncSSORoles(ctx context.Context, user *fleet.User, globalRole *string, teams []fleet.UserTeam) error {
	if user == nil || !communityPlusSSORolesChanged(user.GlobalRole, user.Teams, globalRole, teams) {
		return nil
	}

	oldGlobal := user.GlobalRole
	oldTeams := append([]fleet.UserTeam(nil), user.Teams...)
	user.GlobalRole = globalRole
	user.Teams = append([]fleet.UserTeam(nil), teams...)

	if err := svc.ds.SaveUserIfNotLastAdmin(ctx, user); err != nil {
		user.GlobalRole = oldGlobal
		user.Teams = oldTeams
		if errors.Is(err, fleet.ErrLastGlobalAdmin) {
			return ctxerr.Wrap(ctx, err, "IdP role mapping cannot demote the last global admin")
		}
		return ctxerr.Wrap(ctx, err, "save Community+ SSO role mapping")
	}
	if err := fleet.LogRoleChangeActivities(ctx, svc, user, oldGlobal, oldTeams, user, true); err != nil {
		return ctxerr.Wrap(ctx, err, "log Community+ SSO role mapping activity")
	}
	return nil
}

// communityPlusCreateMappedJITUser creates an SSO-only user with Community+
// roles without pretending that the deployment owns a Fleet Premium license.
// Role validity comes from RolesFromSSOAttributes and fleet existence is
// checked by communityPlusSSORoles before this function is called.
func (svc *Service) communityPlusCreateMappedJITUser(ctx context.Context, payload fleet.UserPayload) (*fleet.User, error) {
	user, err := payload.User(svc.config.Auth.SaltKeySize, svc.config.Auth.BcryptCost)
	if err != nil {
		return nil, err
	}
	user, err = svc.ds.NewUser(ctx, user)
	if err != nil {
		return nil, err
	}

	actor := authz.UserFromContext(ctx)
	if actor == nil {
		actor = user
	}
	if err := svc.NewActivity(ctx, actor, fleet.ActivityTypeCreatedUser{
		UserID: user.ID, UserName: user.Name, UserEmail: user.Email,
	}); err != nil {
		return nil, err
	}
	if err := fleet.LogRoleChangeActivities(ctx, svc, actor, nil, nil, user, true); err != nil {
		return nil, err
	}
	return user, nil
}
