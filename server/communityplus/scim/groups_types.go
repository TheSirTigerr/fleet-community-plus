package scim

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type scimMember struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
	Ref   string `json:"$ref,omitempty"`
}

type groupPayload struct {
	Schemas     []string     `json:"schemas,omitempty"`
	ExternalID  *string      `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName,omitempty"`
	Members     []scimMember `json:"members,omitempty"`
}

func groupResource(group *fleet.ScimGroup, apiVersion string) map[string]any {
	if apiVersion == "" {
		apiVersion = "v1"
	}
	resource := map[string]any{
		"schemas":     []string{groupSchemaURN},
		"id":          uintString(group.ID),
		"displayName": group.DisplayName,
		"meta": map[string]any{
			"resourceType": "Group",
			"location":     "/api/" + apiVersion + "/fleet/scim/Groups/" + uintString(group.ID),
		},
	}
	if group.ExternalID != nil {
		resource["externalId"] = *group.ExternalID
	}
	members := make([]map[string]any, 0, len(group.ScimUsers)+len(group.ChildGroups))
	for _, id := range group.ScimUsers {
		members = append(members, map[string]any{
			"value": uintString(id),
			"type":  "User",
			"$ref":  "/api/" + apiVersion + "/fleet/scim/Users/" + uintString(id),
		})
	}
	for _, id := range group.ChildGroups {
		members = append(members, map[string]any{
			"value": uintString(id),
			"type":  "Group",
			"$ref":  "/api/" + apiVersion + "/fleet/scim/Groups/" + uintString(id),
		})
	}
	if len(members) > 0 {
		resource["members"] = members
	}
	return resource
}

var displayNameFilterPattern = regexp.MustCompile(`(?i)^\s*displayName\s+eq\s+"([^"]+)"\s*$`)

func applyGroupFilter(raw string, opts *fleet.ScimGroupsListOptions) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	if match := displayNameFilterPattern.FindStringSubmatch(raw); len(match) == 2 {
		value := match[1]
		opts.DisplayNameFilter = &value
		return true
	}
	return false
}

func groupLocation(r *http.Request, id uint) string {
	return "/api/" + apiVersionFromRequest(r) + "/fleet/scim/Groups/" + uintString(id)
}
