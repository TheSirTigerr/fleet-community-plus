package communityplus

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WithHomebrew mounts Homebrew catalog routes in front of the existing
// Community+ handler without changing the stable WinGet API implementation.
func (a *HTTPAPI) WithHomebrew(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	for _, version := range []string{"v1", "2022-04", "latest"} {
		base := "/api/" + version + "/fleet/communityplus/catalog/homebrew"
		mux.HandleFunc("GET "+base, a.searchHomebrewCatalog)
		mux.HandleFunc("GET "+base+"/upstream", a.searchHomebrewUpstream)
		mux.HandleFunc("POST "+base+"/import", a.importHomebrewCatalogEntry)
	}
	mux.Handle("/", next)
	return mux
}

func (a *HTTPAPI) searchHomebrewUpstream(w http.ResponseWriter, r *http.Request) {
	if _, err := a.access.Authorize(r.Context(), Request{Resource: ResourceSoftware, Action: ActionAdmin, Scope: GlobalScope()}); err != nil {
		writeAPIError(w, err)
		return
	}
	limit := 10
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writeAPIError(w, fmt.Errorf("communityplus: invalid Homebrew search limit"))
			return
		}
	}
	entries, err := SearchHomebrewUpstream(r.Context(), r.URL.Query().Get("query"), limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"upstream_entries": entries})
}

func (a *HTTPAPI) searchHomebrewCatalog(w http.ResponseWriter, r *http.Request) {
	store, err := a.requireCatalogStore()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	scope := GlobalScope()
	if fleetID := r.URL.Query().Get("fleet_id"); fleetID != "" {
		id, parseErr := strconv.ParseUint(fleetID, 10, 0)
		if parseErr != nil || id == 0 {
			writeAPIError(w, fmt.Errorf("communityplus: invalid fleet_id"))
			return
		}
		scope = FleetScope(uint(id))
	}
	if _, err := a.access.Authorize(r.Context(), Request{Resource: ResourceSoftware, Action: ActionRead, Scope: scope}); err != nil {
		writeAPIError(w, err)
		return
	}
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writeAPIError(w, fmt.Errorf("communityplus: invalid search limit"))
			return
		}
	}
	entries, err := SearchCatalogEntries(r.Context(), store, CatalogProviderHomebrew, r.URL.Query().Get("query"), limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"catalog_entries": entries})
}

type importHomebrewCatalogEntryRequest struct {
	Token   string `json:"token"`
	Version string `json:"version"`
}

func (a *HTTPAPI) importHomebrewCatalogEntry(w http.ResponseWriter, r *http.Request) {
	store, err := a.requireCatalogStore()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	var req importHomebrewCatalogEntryRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeAPIError(w, err)
		return
	}
	if strings.TrimSpace(req.Token) == "" || strings.TrimSpace(req.Version) == "" {
		writeAPIError(w, fmt.Errorf("communityplus: token and reviewed version are required"))
		return
	}
	actor, err := a.access.Authorize(r.Context(), Request{Resource: ResourceSoftware, Action: ActionAdmin, Scope: GlobalScope()})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	entry, err := FetchHomebrewCask(r.Context(), req.Token, req.Version)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	entry.ImportedAt = time.Now().UTC()
	entry.ImportedBy = actor
	if err := entry.Validate(); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := store.UpsertCatalogEntry(r.Context(), entry); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.auditRecorder.Record(r.Context(), AuditEvent{ActorID: actor, Action: "catalog_entry.import", Resource: ResourceSoftware, ResourceID: entry.ID, Scope: GlobalScope(), Metadata: map[string]string{"provider": string(entry.Provider), "package_identifier": entry.PackageIdentifier, "version": entry.Version}}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"catalog_entry": entry})
}
