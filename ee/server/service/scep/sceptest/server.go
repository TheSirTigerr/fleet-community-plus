// Package sceptest contains protocol-level fixtures used by the public service
// integration tests.
package sceptest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/fleetdm/fleet/v4/server/service/integrationtest/scep_server"
)

func NewTestSCEPServer(t *testing.T) *httptest.Server {
	return scep_server.StartTestSCEPServer(t)
}

func NewTestNDESAdminServer(t *testing.T, challenge string, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if status >= 200 && status < 300 {
			_, _ = fmt.Fprintf(w, "<HTML>The enrollment challenge password is: <B>%s</B></HTML>", challenge)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func NewTestNDESAdminServerWithAuth(t *testing.T, authenticate func(string, string) bool, authenticatedRequests *atomic.Int64) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || !authenticate(username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="NDES"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authenticatedRequests.Add(1)
		_, _ = fmt.Fprint(w, "<HTML>The enrollment challenge password is: <B>challenge</B></HTML>")
	}))
	t.Cleanup(server.Close)
	return server
}

func NewTestDynamicChallengeServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "dynamic-challenge")
	}))
	t.Cleanup(server.Close)
	return server
}
