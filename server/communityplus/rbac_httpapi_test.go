package communityplus

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCatalogDeploymentUsesExecutePermission(t *testing.T) {
	tests := []struct {
		name       string
		role       func() (Role, error)
		wantStatus int
	}{
		{name: "maintainer", role: func() (Role, error) { return MaintainerRole(7) }, wantStatus: http.StatusCreated},
		{name: "technician", role: func() (Role, error) { return TechnicianRole(7) }, wantStatus: http.StatusCreated},
		{name: "gitops", role: func() (Role, error) { return GitOpsRole(7) }, wantStatus: http.StatusForbidden},
		{name: "observer", role: func() (Role, error) { return ObserverRole(7) }, wantStatus: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			role, err := test.role()
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewAutomationEngine(&recordingExecutor{})
			if err != nil {
				t.Fatal(err)
			}
			foundation := newMemoryFoundationStore()
			catalog := &memoryCatalogStore{entries: []CatalogEntry{validCatalogEntry()}}
			api, err := NewHTTPAPI(NewRegistry(), engine, foundation, foundation, roleAccessController{actor: test.name, roles: []Role{role}}, catalog)
			if err != nil {
				t.Fatal(err)
			}

			body := []byte(`{"id":"deployment-1","catalog_entry_id":"entry-1","scope":{"kind":"fleet","fleet_id":7},"automatic":true,"patch":false}`)
			req := httptest.NewRequest(http.MethodPost, "/api/latest/fleet/communityplus/catalog/deployments", bytes.NewReader(body))
			res := httptest.NewRecorder()
			api.Handler().ServeHTTP(res, req)
			if res.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", res.Code, test.wantStatus, res.Body.String())
			}
			if test.wantStatus == http.StatusCreated {
				if len(catalog.deployments) != 1 || catalog.deployments[0].CreatedBy != test.name {
					t.Fatalf("unexpected deployment: %#v", catalog.deployments)
				}
			} else if len(catalog.deployments) != 0 {
				t.Fatalf("forbidden role created deployment: %#v", catalog.deployments)
			}
		})
	}
}

func TestCatalogDeploymentReadPermissionsRemainReadOnly(t *testing.T) {
	role, err := ObserverRole(7)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewAutomationEngine(&recordingExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	foundation := newMemoryFoundationStore()
	catalog := &memoryCatalogStore{
		entries: []CatalogEntry{validCatalogEntry()},
		deployments: []Deployment{{
			ID: "deployment-1", CatalogEntryID: "entry-1", Scope: FleetScope(7), CreatedBy: "admin",
		}},
	}
	api, err := NewHTTPAPI(NewRegistry(), engine, foundation, foundation, roleAccessController{actor: "observer", roles: []Role{role}}, catalog)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/latest/fleet/communityplus/catalog/deployments?fleet_id=7", nil)
	res := httptest.NewRecorder()
	api.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !bytes.Contains(res.Body.Bytes(), []byte("deployment-1")) {
		t.Fatalf("observer list status=%d body=%s", res.Code, res.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/latest/fleet/communityplus/catalog/deployments?fleet_id=8", nil)
	res = httptest.NewRecorder()
	api.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("cross-fleet observer status=%d body=%s", res.Code, res.Body.String())
	}
}
