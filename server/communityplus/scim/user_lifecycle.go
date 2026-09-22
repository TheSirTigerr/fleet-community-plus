package scim

import (
	"context"
	"errors"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// wasDeactivated reports an active -> inactive transition. A nil previous value
// is treated as active for compatibility with IdPs that omit active on create.
func wasDeactivated(previous, current *bool) bool {
	if current == nil || *current {
		return false
	}
	return previous == nil || *previous
}

func fleetUserLookupEmails(scimUser *fleet.ScimUser) []string {
	if scimUser == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(scimUser.Emails)+1)
	result := make([]string, 0, len(scimUser.Emails)+1)
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || !strings.Contains(value, "@") {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	add(scimUser.UserName)
	for _, email := range scimUser.Emails {
		add(email.Email)
	}
	return result
}

// linkMatchingFleetUser establishes the durable scim_users.user_id link once.
// Existing links are never repointed when an IdP later mutates identifiers.
func (p *provider) linkMatchingFleetUser(ctx context.Context, scimUser *fleet.ScimUser) error {
	if scimUser == nil || scimUser.ID == 0 || scimUser.FleetUserID != nil {
		return nil
	}
	for _, email := range fleetUserLookupEmails(scimUser) {
		user, err := p.ds.UserByEmail(ctx, email)
		if err != nil {
			if fleet.IsNotFound(err) {
				continue
			}
			return err
		}
		if err := p.ds.SetScimUserFleetUserID(ctx, scimUser.ID, user.ID); err != nil {
			return err
		}
		id := user.ID
		scimUser.FleetUserID = &id
		return nil
	}
	return nil
}

func (p *provider) resolveFleetUser(ctx context.Context, scimUser *fleet.ScimUser) (*fleet.User, error) {
	if scimUser == nil {
		return nil, nil
	}
	if scimUser.FleetUserID != nil {
		user, err := p.ds.UserByID(ctx, *scimUser.FleetUserID)
		if err == nil {
			return user, nil
		}
		if fleet.IsNotFound(err) {
			// A durable link must never silently move to a different Fleet account.
			return nil, nil
		}
		return nil, err
	}
	for _, email := range fleetUserLookupEmails(scimUser) {
		user, err := p.ds.UserByEmail(ctx, email)
		if err == nil {
			return user, nil
		}
		if !fleet.IsNotFound(err) {
			return nil, err
		}
	}
	return nil, nil
}

// deprovisionMatchingFleetUser removes only SSO users. Local/password users and
// API-only accounts are deliberately never deleted by an IdP lifecycle event.
func (p *provider) deprovisionMatchingFleetUser(ctx context.Context, scimUser *fleet.ScimUser) error {
	user, err := p.resolveFleetUser(ctx, scimUser)
	if err != nil || user == nil {
		return err
	}
	if user.APIOnly || !user.SSOEnabled {
		return nil
	}
	if user.GlobalRole != nil && *user.GlobalRole == fleet.RoleAdmin {
		if err := p.ds.DeleteUserIfNotLastAdmin(ctx, user.ID); err != nil {
			if errors.Is(err, fleet.ErrLastGlobalAdmin) {
				return nil
			}
			return err
		}
		return nil
	}
	return p.ds.DeleteUser(ctx, user.ID)
}

func cloneScimUser(user *fleet.ScimUser) *fleet.ScimUser {
	if user == nil {
		return nil
	}
	clone := *user
	clone.Emails = append([]fleet.ScimUserEmail(nil), user.Emails...)
	clone.Groups = append([]fleet.ScimUserGroup(nil), user.Groups...)
	return &clone
}
