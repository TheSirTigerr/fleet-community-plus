package scim

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"
)

func TestRegisterSCIMLeavesLiveProvisioningUnmounted(t *testing.T) {
	if err := RegisterSCIM(nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("register SCIM boundary: %v", err)
	}
}

func TestRegisterValidationRoutes(t *testing.T) {
	r := mux.NewRouter()
	RegisterValidationRoutes(r, nil)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/fleet/scim/Users"},
		{http.MethodPatch, "/api/v1/fleet/scim/Users/123"},
		{http.MethodDelete, "/api/v1/fleet/scim/Groups/456"},
		{http.MethodGet, "/api/v1/fleet/scim/ServiceProviderConfig"},
	} {
		req, err := http.NewRequest(tc.method, tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		match := &mux.RouteMatch{}
		if !r.Match(req, match) {
			t.Fatalf("route not declared: %s %s", tc.method, tc.path)
		}
	}
}
