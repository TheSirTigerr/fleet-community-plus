package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func (p *provider) handleGroups(w http.ResponseWriter, r *http.Request, tail string) {
	if strings.Trim(tail, "/") == "" {
		switch r.Method {
		case http.MethodGet:
			p.listGroups(w, r)
		case http.MethodPost:
			p.createGroup(w, r)
		default:
			writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed", "")
		}
		return
	}

	id, err := resourceID(tail)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}
	switch r.Method {
	case http.MethodGet:
		p.getGroup(w, r, id)
	case http.MethodPut:
		p.replaceGroup(w, r, id)
	case http.MethodPatch:
		p.patchGroup(w, r, id)
	case http.MethodDelete:
		p.deleteGroup(w, r, id)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed", "")
	}
}

func (p *provider) listGroups(w http.ResponseWriter, r *http.Request) {
	startIndex, count, err := listWindow(r)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}
	perPage := count
	if perPage == 0 {
		perPage = 1
	}
	opts := fleet.ScimGroupsListOptions{
		ScimListOptions: fleet.ScimListOptions{StartIndex: startIndex, PerPage: perPage},
	}
	if !applyGroupFilter(r.URL.Query().Get("filter"), &opts) {
		writeSCIMError(w, http.StatusBadRequest, "unsupported SCIM group filter", "invalidFilter")
		return
	}

	groups, total, err := p.ds.ListScimGroups(r.Context(), opts)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	resources := make([]map[string]any, 0, len(groups))
	if count != 0 {
		for i := range groups {
			resources = append(resources, groupResource(&groups[i], apiVersionFromRequest(r)))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{listSchemaURN},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

func (p *provider) createGroup(w http.ResponseWriter, r *http.Request) {
	var payload groupPayload
	if err := decodeJSON(w, r, &payload); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidSyntax")
		return
	}
	payload.DisplayName = strings.TrimSpace(payload.DisplayName)
	if payload.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
		return
	}
	users, childGroups, err := p.resolveMembers(r.Context(), payload.Members, 0)
	if err != nil {
		if isPatchError(err) {
			writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		} else {
			p.writeStoreError(w, r, err)
		}
		return
	}
	group := &fleet.ScimGroup{
		ExternalID:  payload.ExternalID,
		DisplayName: payload.DisplayName,
		ScimUsers:   users,
		ChildGroups: childGroups,
	}
	id, err := p.ds.CreateScimGroup(r.Context(), group)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	group.ID = id
	if stored, getErr := p.ds.ScimGroupByID(r.Context(), id, false); getErr == nil {
		group = stored
	}
	w.Header().Set("Location", groupLocation(r, id))
	writeJSON(w, http.StatusCreated, groupResource(group, apiVersionFromRequest(r)))
}

func (p *provider) getGroup(w http.ResponseWriter, r *http.Request, id uint) {
	group, err := p.ds.ScimGroupByID(r.Context(), id, false)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, groupResource(group, apiVersionFromRequest(r)))
}

func (p *provider) replaceGroup(w http.ResponseWriter, r *http.Request, id uint) {
	var payload groupPayload
	if err := decodeJSON(w, r, &payload); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidSyntax")
		return
	}
	payload.DisplayName = strings.TrimSpace(payload.DisplayName)
	if payload.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
		return
	}
	users, childGroups, err := p.resolveMembers(r.Context(), payload.Members, id)
	if err != nil {
		if isPatchError(err) {
			writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		} else {
			p.writeStoreError(w, r, err)
		}
		return
	}
	group := &fleet.ScimGroup{
		ID:          id,
		ExternalID:  payload.ExternalID,
		DisplayName: payload.DisplayName,
		ScimUsers:   users,
		ChildGroups: childGroups,
	}
	if err := p.ds.ReplaceScimGroup(r.Context(), group); err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	stored, err := p.ds.ScimGroupByID(r.Context(), id, false)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, groupResource(stored, apiVersionFromRequest(r)))
}

func (p *provider) patchGroup(w http.ResponseWriter, r *http.Request, id uint) {
	group, err := p.ds.ScimGroupByID(r.Context(), id, false)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	var patch patchRequest
	if err := decodeJSON(w, r, &patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidSyntax")
		return
	}
	if len(patch.Operations) == 0 {
		writeSCIMError(w, http.StatusBadRequest, "PATCH requires at least one operation", "invalidValue")
		return
	}
	for _, operation := range patch.Operations {
		if err := p.applyGroupPatch(r.Context(), group, operation); err != nil {
			if isPatchError(err) {
				writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidPath")
			} else {
				p.writeStoreError(w, r, err)
			}
			return
		}
	}
	group.DisplayName = strings.TrimSpace(group.DisplayName)
	if group.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName cannot be removed", "mutability")
		return
	}
	if err := p.ds.ReplaceScimGroup(r.Context(), group); err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	stored, err := p.ds.ScimGroupByID(r.Context(), id, false)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, groupResource(stored, apiVersionFromRequest(r)))
}

func (p *provider) deleteGroup(w http.ResponseWriter, r *http.Request, id uint) {
	if err := p.ds.DeleteScimGroup(r.Context(), id); err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var memberPathPattern = regexp.MustCompile(`(?i)^members\[value\s+eq\s+"([0-9]+)"\]$`)

func (p *provider) applyGroupPatch(ctx context.Context, group *fleet.ScimGroup, operation patchOperation) error {
	op := strings.ToLower(strings.TrimSpace(operation.Op))
	if op != "add" && op != "replace" && op != "remove" {
		return &patchError{"unsupported PATCH operation"}
	}
	path := strings.TrimSpace(operation.Path)
	lowerPath := strings.ToLower(path)
	if path == "" {
		if op == "remove" {
			return &patchError{"PATCH remove requires a path"}
		}
		return p.applyGroupObjectPatch(ctx, group, operation.Value)
	}

	if match := memberPathPattern.FindStringSubmatch(path); len(match) == 2 {
		if op != "remove" {
			return &patchError{"member value filters are supported only for remove"}
		}
		id, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil || id == 0 {
			return &patchError{"invalid member ID"}
		}
		group.ScimUsers = removeUint(group.ScimUsers, uint(id))
		group.ChildGroups = removeUint(group.ChildGroups, uint(id))
		return nil
	}

	switch {
	case lowerPath == "displayname":
		if op == "remove" {
			return &patchError{"displayName cannot be removed"}
		}
		value, err := rawString(operation.Value)
		if err != nil {
			return err
		}
		group.DisplayName = value
	case lowerPath == "externalid":
		if op == "remove" {
			group.ExternalID = nil
			return nil
		}
		value, err := rawString(operation.Value)
		if err != nil {
			return err
		}
		group.ExternalID = &value
	case lowerPath == "members":
		if op == "remove" && len(operation.Value) == 0 {
			group.ScimUsers = nil
			group.ChildGroups = nil
			return nil
		}
		var members []scimMember
		if err := json.Unmarshal(operation.Value, &members); err != nil {
			return &patchError{"members must be an array"}
		}
		if op == "remove" {
			for _, member := range members {
				id, err := memberID(member)
				if err != nil {
					return err
				}
				group.ScimUsers = removeUint(group.ScimUsers, id)
				group.ChildGroups = removeUint(group.ChildGroups, id)
			}
			return nil
		}
		users, childGroups, err := p.resolveMembers(ctx, members, group.ID)
		if err != nil {
			return err
		}
		if op == "replace" {
			group.ScimUsers = users
			group.ChildGroups = childGroups
			return nil
		}
		for _, id := range users {
			group.ScimUsers = appendUniqueUint(group.ScimUsers, id)
		}
		for _, id := range childGroups {
			group.ChildGroups = appendUniqueUint(group.ChildGroups, id)
		}
	default:
		return &patchError{"unsupported group PATCH path: " + operation.Path}
	}
	return nil
}

func (p *provider) applyGroupObjectPatch(ctx context.Context, group *fleet.ScimGroup, raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return &patchError{"PATCH value must be an object"}
	}
	for key, value := range fields {
		if err := p.applyGroupPatch(ctx, group, patchOperation{Op: "replace", Path: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (p *provider) resolveMembers(ctx context.Context, members []scimMember, selfID uint) ([]uint, []uint, error) {
	users := make([]uint, 0, len(members))
	groups := make([]uint, 0, len(members))
	for _, member := range members {
		id, err := memberID(member)
		if err != nil {
			return nil, nil, err
		}
		isGroup := strings.EqualFold(member.Type, "Group") || strings.Contains(member.Ref, "/Groups/")
		isUser := strings.EqualFold(member.Type, "User") || strings.Contains(member.Ref, "/Users/")
		switch {
		case isGroup:
			if selfID != 0 && id == selfID {
				return nil, nil, &patchError{"a group cannot contain itself"}
			}
			if _, err := p.ds.ScimGroupByID(ctx, id, true); err != nil {
				if fleet.IsNotFound(err) {
					return nil, nil, &patchError{"group member not found: " + uintString(id)}
				}
				return nil, nil, err
			}
			groups = appendUniqueUint(groups, id)
		case isUser:
			if _, err := p.ds.ScimUserByID(ctx, id); err != nil {
				if fleet.IsNotFound(err) {
					return nil, nil, &patchError{"user member not found: " + uintString(id)}
				}
				return nil, nil, err
			}
			users = appendUniqueUint(users, id)
		default:
			if _, err := p.ds.ScimUserByID(ctx, id); err == nil {
				users = appendUniqueUint(users, id)
				continue
			} else if !fleet.IsNotFound(err) {
				return nil, nil, err
			}
			if selfID != 0 && id == selfID {
				return nil, nil, &patchError{"a group cannot contain itself"}
			}
			if _, err := p.ds.ScimGroupByID(ctx, id, true); err != nil {
				if fleet.IsNotFound(err) {
					return nil, nil, &patchError{"SCIM member not found: " + uintString(id)}
				}
				return nil, nil, err
			}
			groups = appendUniqueUint(groups, id)
		}
	}
	return users, groups, nil
}

func memberID(member scimMember) (uint, error) {
	value := strings.TrimSpace(member.Value)
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || id == 0 {
		return 0, &patchError{"invalid member ID: " + value}
	}
	return uint(id), nil
}

func appendUniqueUint(values []uint, value uint) []uint {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func removeUint(values []uint, value uint) []uint {
	result := values[:0]
	for _, current := range values {
		if current != value {
			result = append(result, current)
		}
	}
	return result
}

func isPatchError(err error) bool {
	var target *patchError
	return errors.As(err, &target)
}
