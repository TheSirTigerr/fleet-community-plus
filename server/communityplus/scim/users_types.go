package scim

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type scimName struct {
	GivenName  *string `json:"givenName,omitempty"`
	FamilyName *string `json:"familyName,omitempty"`
}

type scimEmail struct {
	Value   string  `json:"value"`
	Type    *string `json:"type,omitempty"`
	Primary *bool   `json:"primary,omitempty"`
}

type enterpriseUserExtension struct {
	Department *string `json:"department,omitempty"`
}

type userPayload struct {
	Schemas    []string                 `json:"schemas,omitempty"`
	ExternalID *string                  `json:"externalId,omitempty"`
	UserName   string                   `json:"userName,omitempty"`
	Name       scimName                 `json:"name,omitempty"`
	Emails     []scimEmail              `json:"emails,omitempty"`
	Active     *bool                    `json:"active,omitempty"`
	Enterprise *enterpriseUserExtension `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}

type patchRequest struct {
	Schemas    []string         `json:"schemas,omitempty"`
	Operations []patchOperation `json:"Operations"`
}

type patchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

func userFromPayload(payload userPayload) *fleet.ScimUser {
	active := payload.Active
	if active == nil {
		v := true
		active = &v
	}
	user := &fleet.ScimUser{
		ExternalID: payload.ExternalID,
		UserName:   strings.TrimSpace(payload.UserName),
		GivenName:  payload.Name.GivenName,
		FamilyName: payload.Name.FamilyName,
		Active:     active,
	}
	if payload.Enterprise != nil {
		user.Department = payload.Enterprise.Department
	}
	for _, email := range payload.Emails {
		if strings.TrimSpace(email.Value) == "" {
			continue
		}
		user.Emails = append(user.Emails, fleet.ScimUserEmail{
			Email:   strings.TrimSpace(email.Value),
			Type:    email.Type,
			Primary: email.Primary,
		})
	}
	return user
}

func userResource(user *fleet.ScimUser, apiVersion string) map[string]any {
	if apiVersion == "" {
		apiVersion = "v1"
	}
	resource := map[string]any{
		"schemas":  []string{userSchemaURN, enterpriseSchemaURN},
		"id":       uintString(user.ID),
		"userName": user.UserName,
		"meta": map[string]any{
			"resourceType": "User",
			"location":     "/api/" + apiVersion + "/fleet/scim/Users/" + uintString(user.ID),
		},
	}
	if user.ExternalID != nil {
		resource["externalId"] = *user.ExternalID
	}
	if user.Active != nil {
		resource["active"] = *user.Active
	}
	if user.GivenName != nil || user.FamilyName != nil {
		name := map[string]any{}
		if user.GivenName != nil {
			name["givenName"] = *user.GivenName
		}
		if user.FamilyName != nil {
			name["familyName"] = *user.FamilyName
		}
		resource["name"] = name
	}
	if len(user.Emails) > 0 {
		emails := make([]map[string]any, 0, len(user.Emails))
		for _, email := range user.Emails {
			item := map[string]any{"value": email.Email}
			if email.Type != nil {
				item["type"] = *email.Type
			}
			if email.Primary != nil {
				item["primary"] = *email.Primary
			}
			emails = append(emails, item)
		}
		resource["emails"] = emails
	}
	if len(user.Groups) > 0 {
		groups := make([]map[string]any, 0, len(user.Groups))
		for _, group := range user.Groups {
			groups = append(groups, map[string]any{
				"value":   uintString(group.ID),
				"display": group.DisplayName,
				"$ref":    "/api/" + apiVersion + "/fleet/scim/Groups/" + uintString(group.ID),
			})
		}
		resource["groups"] = groups
	}
	if user.Department != nil {
		resource[enterpriseSchemaURN] = map[string]any{"department": *user.Department}
	}
	if !user.UpdatedAt.IsZero() {
		resource["meta"].(map[string]any)["lastModified"] = user.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	return resource
}

func apiVersionFromRequest(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/api/latest/") {
		return "latest"
	}
	return "v1"
}

var (
	userNameFilterPattern = regexp.MustCompile(`(?i)^\s*userName\s+eq\s+"([^"]+)"\s*$`)
	emailFilterPattern    = regexp.MustCompile(`(?i)^\s*emails\[type\s+eq\s+"([^"]+)"\]\.value\s+eq\s+"([^"]+)"\s*$`)
)

func applyUserFilter(raw string, opts *fleet.ScimUsersListOptions) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	if match := userNameFilterPattern.FindStringSubmatch(raw); len(match) == 2 {
		value := match[1]
		opts.UserNameFilter = &value
		return true
	}
	if match := emailFilterPattern.FindStringSubmatch(raw); len(match) == 3 {
		typ, value := match[1], match[2]
		opts.EmailTypeFilter = &typ
		opts.EmailValueFilter = &value
		return true
	}
	return false
}
