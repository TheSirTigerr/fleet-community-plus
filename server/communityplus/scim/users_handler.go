package scim

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

func (p *provider) handleUsers(w http.ResponseWriter, r *http.Request, tail string) {
	if strings.Trim(tail, "/") == "" {
		switch r.Method {
		case http.MethodGet:
			p.listUsers(w, r)
		case http.MethodPost:
			p.createUser(w, r)
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
		p.getUser(w, r, id)
	case http.MethodPut:
		p.replaceUser(w, r, id)
	case http.MethodPatch:
		p.patchUser(w, r, id)
	case http.MethodDelete:
		p.deleteUser(w, r, id)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed", "")
	}
}

func (p *provider) listUsers(w http.ResponseWriter, r *http.Request) {
	startIndex, count, err := listWindow(r)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}
	perPage := count
	if perPage == 0 {
		perPage = 1
	}
	opts := fleet.ScimUsersListOptions{
		ScimListOptions: fleet.ScimListOptions{StartIndex: startIndex, PerPage: perPage},
	}
	if !applyUserFilter(r.URL.Query().Get("filter"), &opts) {
		writeSCIMError(w, http.StatusBadRequest, "unsupported SCIM user filter", "invalidFilter")
		return
	}

	users, total, err := p.ds.ListScimUsers(r.Context(), opts)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	resources := make([]map[string]any, 0, len(users))
	if count != 0 {
		for i := range users {
			resources = append(resources, userResource(&users[i], apiVersionFromRequest(r)))
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

func (p *provider) createUser(w http.ResponseWriter, r *http.Request) {
	var payload userPayload
	if err := decodeJSON(w, r, &payload); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidSyntax")
		return
	}
	user := userFromPayload(payload)
	if user.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required", "invalidValue")
		return
	}

	// A deactivated SCIM identity may be re-provisioned by an IdP with POST.
	// Reactivate the existing record instead of manufacturing a duplicate ID.
	existing, lookupErr := p.ds.ScimUserByUserName(r.Context(), user.UserName)
	switch {
	case lookupErr == nil:
		if existing.Active == nil || *existing.Active || user.Active == nil || !*user.Active {
			writeSCIMError(w, http.StatusConflict, "SCIM user already exists", "uniqueness")
			return
		}
		if err := p.linkMatchingFleetUser(r.Context(), existing); err != nil {
			p.logger.ErrorContext(r.Context(), "Community+ SCIM: link Fleet user during reactivation", "err", err)
		}
		user.ID = existing.ID
		user.FleetUserID = existing.FleetUserID
		if _, err := p.ds.ReplaceScimUser(r.Context(), user); err != nil {
			p.writeStoreError(w, r, err)
			return
		}
	case !fleet.IsNotFound(lookupErr):
		p.writeStoreError(w, r, lookupErr)
		return
	default:
		id, err := p.ds.CreateScimUser(r.Context(), user)
		if err != nil {
			p.writeStoreError(w, r, err)
			return
		}
		user.ID = id
		if err := p.linkMatchingFleetUser(r.Context(), user); err != nil {
			p.logger.ErrorContext(r.Context(), "Community+ SCIM: link Fleet user on create", "err", err)
		}
	}

	if stored, getErr := p.ds.ScimUserByID(r.Context(), user.ID); getErr == nil {
		user = stored
	}
	resource := userResource(user, apiVersionFromRequest(r))
	if meta, ok := resource["meta"].(map[string]any); ok {
		if location, ok := meta["location"].(string); ok {
			w.Header().Set("Location", location)
		}
	}
	writeJSON(w, http.StatusCreated, resource)
}

func (p *provider) getUser(w http.ResponseWriter, r *http.Request, id uint) {
	user, err := p.ds.ScimUserByID(r.Context(), id)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userResource(user, apiVersionFromRequest(r)))
}

func (p *provider) replaceUser(w http.ResponseWriter, r *http.Request, id uint) {
	var payload userPayload
	if err := decodeJSON(w, r, &payload); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidSyntax")
		return
	}
	user := userFromPayload(payload)
	if user.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required", "invalidValue")
		return
	}

	existing, err := p.ds.ScimUserByID(r.Context(), id)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	previousActive := existing.Active
	if err := p.linkMatchingFleetUser(r.Context(), existing); err != nil {
		p.logger.ErrorContext(r.Context(), "Community+ SCIM: link Fleet user before replace", "err", err)
	}
	user.ID = id
	user.FleetUserID = existing.FleetUserID
	if _, err := p.ds.ReplaceScimUser(r.Context(), user); err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	if wasDeactivated(previousActive, user.Active) {
		if err := p.deprovisionMatchingFleetUser(r.Context(), existing); err != nil {
			p.logger.ErrorContext(r.Context(), "Community+ SCIM: deprovision Fleet user after replace", "err", err)
		}
	}
	stored, err := p.ds.ScimUserByID(r.Context(), id)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userResource(stored, apiVersionFromRequest(r)))
}

func (p *provider) patchUser(w http.ResponseWriter, r *http.Request, id uint) {
	user, err := p.ds.ScimUserByID(r.Context(), id)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	prePatch := cloneScimUser(user)
	previousActive := prePatch.Active
	if err := p.linkMatchingFleetUser(r.Context(), prePatch); err != nil {
		p.logger.ErrorContext(r.Context(), "Community+ SCIM: link Fleet user before patch", "err", err)
	}
	if user.FleetUserID == nil && prePatch.FleetUserID != nil {
		id := *prePatch.FleetUserID
		user.FleetUserID = &id
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
		if err := applyUserPatch(user, operation); err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidPath")
			return
		}
	}
	if strings.TrimSpace(user.UserName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName cannot be removed", "mutability")
		return
	}
	if _, err := p.ds.ReplaceScimUser(r.Context(), user); err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	if wasDeactivated(previousActive, user.Active) {
		if err := p.deprovisionMatchingFleetUser(r.Context(), prePatch); err != nil {
			p.logger.ErrorContext(r.Context(), "Community+ SCIM: deprovision Fleet user after patch", "err", err)
		}
	}
	stored, err := p.ds.ScimUserByID(r.Context(), id)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userResource(stored, apiVersionFromRequest(r)))
}

func (p *provider) deleteUser(w http.ResponseWriter, r *http.Request, id uint) {
	user, err := p.ds.ScimUserByID(r.Context(), id)
	if err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	if err := p.deprovisionMatchingFleetUser(r.Context(), user); err != nil {
		// SCIM deletion remains authoritative even when the linked Fleet account
		// cannot be removed (for example because it is the last global admin).
		p.logger.ErrorContext(r.Context(), "Community+ SCIM: deprovision Fleet user on delete", "err", err)
	}
	if _, err := p.ds.DeleteScimUser(r.Context(), id); err != nil {
		p.writeStoreError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func applyUserPatch(user *fleet.ScimUser, operation patchOperation) error {
	op := strings.ToLower(strings.TrimSpace(operation.Op))
	if op != "add" && op != "replace" && op != "remove" {
		return &patchError{"unsupported PATCH operation"}
	}
	path := strings.ToLower(strings.TrimSpace(operation.Path))
	if path == "" {
		if op == "remove" {
			return &patchError{"PATCH remove requires a path"}
		}
		return applyUserObjectPatch(user, operation.Value)
	}

	switch {
	case path == "username":
		if op == "remove" {
			return &patchError{"userName cannot be removed"}
		}
		value, err := rawString(operation.Value)
		if err != nil {
			return err
		}
		user.UserName = strings.TrimSpace(value)
	case path == "externalid":
		if op == "remove" {
			user.ExternalID = nil
			return nil
		}
		value, err := rawString(operation.Value)
		if err != nil {
			return err
		}
		user.ExternalID = &value
	case path == "active":
		if op == "remove" {
			user.Active = nil
			return nil
		}
		value, err := rawBool(operation.Value)
		if err != nil {
			return err
		}
		user.Active = &value
	case path == "name.givenname":
		if op == "remove" {
			user.GivenName = nil
			return nil
		}
		value, err := rawString(operation.Value)
		if err != nil {
			return err
		}
		user.GivenName = &value
	case path == "name.familyname":
		if op == "remove" {
			user.FamilyName = nil
			return nil
		}
		value, err := rawString(operation.Value)
		if err != nil {
			return err
		}
		user.FamilyName = &value
	case path == "name":
		if op == "remove" {
			user.GivenName = nil
			user.FamilyName = nil
			return nil
		}
		var name scimName
		if err := json.Unmarshal(operation.Value, &name); err != nil {
			return &patchError{"name must be an object"}
		}
		user.GivenName = name.GivenName
		user.FamilyName = name.FamilyName
	case path == "emails":
		if op == "remove" {
			user.Emails = nil
			return nil
		}
		var emails []scimEmail
		if err := json.Unmarshal(operation.Value, &emails); err != nil {
			return &patchError{"emails must be an array"}
		}
		user.Emails = fleetEmails(emails)
	case path == "department" || strings.HasSuffix(path, ":department"):
		if op == "remove" {
			user.Department = nil
			return nil
		}
		value, err := rawString(operation.Value)
		if err != nil {
			return err
		}
		user.Department = &value
	default:
		return &patchError{"unsupported user PATCH path: " + operation.Path}
	}
	return nil
}

func applyUserObjectPatch(user *fleet.ScimUser, raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return &patchError{"PATCH value must be an object"}
	}
	for key, value := range fields {
		path := key
		if key == enterpriseSchemaURN {
			var extension enterpriseUserExtension
			if err := json.Unmarshal(value, &extension); err != nil {
				return &patchError{"enterprise user extension must be an object"}
			}
			if extension.Department != nil {
				user.Department = extension.Department
			}
			continue
		}
		if err := applyUserPatch(user, patchOperation{Op: "replace", Path: path, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func fleetEmails(emails []scimEmail) []fleet.ScimUserEmail {
	result := make([]fleet.ScimUserEmail, 0, len(emails))
	for _, email := range emails {
		value := strings.TrimSpace(email.Value)
		if value == "" {
			continue
		}
		result = append(result, fleet.ScimUserEmail{Email: value, Type: email.Type, Primary: email.Primary})
	}
	return result
}

type patchError struct{ message string }

func (e *patchError) Error() string { return e.message }

func rawString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", &patchError{"PATCH value must be a string"}
	}
	return value, nil
}

func rawBool(raw json.RawMessage) (bool, error) {
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, &patchError{"PATCH value must be a boolean"}
	}
	return value, nil
}
