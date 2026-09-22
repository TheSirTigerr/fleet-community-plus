package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	userSchemaURN       = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupSchemaURN      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	enterpriseSchemaURN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	listSchemaURN       = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchemaURN      = "urn:ietf:params:scim:api:messages:2.0:Error"
	patchSchemaURN      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	maxResults          = uint(100)
	maxRequestBody      = int64(1 << 20)
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/scim+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeSCIMError(w http.ResponseWriter, status int, detail, scimType string) {
	body := map[string]any{
		"schemas": []string{errorSchemaURN},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	}
	if scimType != "" {
		body["scimType"] = scimType
	}
	writeJSON(w, status, body)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid SCIM JSON: %w", err)
	}
	return nil
}

func resourceID(path string) (uint, error) {
	value := strings.Trim(path, "/")
	if value == "" || strings.Contains(value, "/") {
		return 0, errors.New("missing or invalid resource ID")
	}
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || id == 0 {
		return 0, errors.New("invalid resource ID")
	}
	return uint(id), nil
}

func listWindow(r *http.Request) (startIndex, count uint, err error) {
	startIndex = 1
	count = maxResults
	if raw := r.URL.Query().Get("startIndex"); raw != "" {
		parsed, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil || parsed == 0 {
			return 0, 0, errors.New("startIndex must be a positive integer")
		}
		startIndex = uint(parsed)
	}
	if raw := r.URL.Query().Get("count"); raw != "" {
		parsed, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil {
			return 0, 0, errors.New("count must be a non-negative integer")
		}
		count = uint(parsed)
		if count > maxResults {
			count = maxResults
		}
	}
	return startIndex, count, nil
}

func serviceProviderConfig() map[string]any {
	return map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://fleetdm.com/docs",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": maxResults},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "Fleet API bearer token",
			"description": "Authenticate with a Fleet API token belonging to a global administrator.",
			"primary":     true,
		}},
	}
}

func schemasResponse() map[string]any {
	user := map[string]any{
		"id":          userSchemaURN,
		"name":        "User",
		"description": "Community+ SCIM User",
		"attributes": []map[string]any{
			{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
			{"name": "externalId", "type": "string"},
			{"name": "active", "type": "boolean"},
			{"name": "name", "type": "complex", "subAttributes": []map[string]any{{"name": "givenName", "type": "string"}, {"name": "familyName", "type": "string"}}},
			{"name": "emails", "type": "complex", "multiValued": true, "subAttributes": []map[string]any{{"name": "value", "type": "string"}, {"name": "type", "type": "string"}, {"name": "primary", "type": "boolean"}}},
		},
	}
	group := map[string]any{
		"id":          groupSchemaURN,
		"name":        "Group",
		"description": "Community+ SCIM Group",
		"attributes": []map[string]any{
			{"name": "displayName", "type": "string", "required": true},
			{"name": "externalId", "type": "string"},
			{"name": "members", "type": "complex", "multiValued": true},
		},
	}
	enterprise := map[string]any{
		"id":          enterpriseSchemaURN,
		"name":        "EnterpriseUser",
		"description": "Enterprise User extension",
		"attributes":  []map[string]any{{"name": "department", "type": "string"}},
	}
	return map[string]any{
		"schemas":      []string{listSchemaURN},
		"totalResults": 3,
		"Resources":    []map[string]any{user, group, enterprise},
	}
}

func resourceTypesResponse() map[string]any {
	return map[string]any{
		"schemas":      []string{listSchemaURN},
		"totalResults": 2,
		"Resources": []map[string]any{
			{
				"id":       "User",
				"name":     "User",
				"endpoint": "/Users",
				"schema":   userSchemaURN,
				"schemaExtensions": []map[string]any{{
					"schema": enterpriseSchemaURN,
					"required": false,
				}},
			},
			{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": groupSchemaURN},
		},
	}
}
