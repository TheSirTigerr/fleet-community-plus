package communityplus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/communityplus/winget"
)

var (
	ErrUnauthenticated = errors.New("communityplus: authentication required")
	ErrForbidden       = errors.New("communityplus: access denied")
)

// AccessController authenticates a request and authorizes one scoped action.
// The Fleet adapter must return a stable actor ID for audit records.
type AccessController interface {
	Authorize(context.Context, Request) (actorID string, err error)
}

// HTTPAPI exposes the Community+ foundation without depending on Fleet's
// restricted server packages. It is designed to be mounted in Fleet's router
// behind an AccessController adapter.
type HTTPAPI struct {
	registry        *Registry
	engine          *AutomationEngine
	automationStore AutomationStore
	auditStore      AuditStore
	auditRecorder   *AuditRecorder
	access          AccessController
	catalogStore    CatalogStore
}

func NewHTTPAPI(
	registry *Registry,
	engine *AutomationEngine,
	automationStore AutomationStore,
	auditStore AuditStore,
	access AccessController,
	catalogStores ...CatalogStore,
) (*HTTPAPI, error) {
	if registry == nil || engine == nil || automationStore == nil || auditStore == nil || access == nil {
		return nil, fmt.Errorf("communityplus: HTTP API dependencies are required")
	}
	recorder, err := NewAuditRecorder(auditStore)
	if err != nil {
		return nil, err
	}
	api := &HTTPAPI{
		registry: registry, engine: engine, automationStore: automationStore,
		auditStore: auditStore, auditRecorder: recorder, access: access,
	}
	if len(catalogStores) > 1 {
		return nil, fmt.Errorf("communityplus: only one catalog store may be configured")
	}
	if len(catalogStores) == 1 {
		if catalogStores[0] == nil {
			return nil, fmt.Errorf("communityplus: catalog store must not be nil")
		}
		api.catalogStore = catalogStores[0]
	}
	return api, nil
}

// Handler returns routes for Fleet's supported API aliases.
func (a *HTTPAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, version := range []string{"v1", "2022-04", "latest"} {
		base := "/api/" + version + "/fleet/communityplus"
		mux.HandleFunc("GET "+base+"/capabilities", a.getCapabilities)
		mux.HandleFunc("GET "+base+"/automation-rules", a.listAutomationRules)
		mux.HandleFunc("PUT "+base+"/automation-rules/{id}", a.putAutomationRule)
		mux.HandleFunc("DELETE "+base+"/automation-rules/{id}", a.deleteAutomationRule)
		mux.HandleFunc("GET "+base+"/audit", a.listAuditEvents)
		mux.HandleFunc("GET "+base+"/catalog/winget", a.searchWingetCatalog)
		mux.HandleFunc("GET "+base+"/catalog/winget/upstream", a.searchWingetUpstream)
		mux.HandleFunc("POST "+base+"/catalog/winget/import", a.importWingetCatalogEntry)
		mux.HandleFunc("POST "+base+"/catalog/deployments", a.createCatalogDeployment)
		mux.HandleFunc("GET "+base+"/catalog/deployments", a.listCatalogDeployments)
		mux.HandleFunc("GET "+base+"/catalog/deployments/{id}/results", a.listCatalogDeploymentResults)
	}
	return mux
}

func (a *HTTPAPI) searchWingetUpstream(w http.ResponseWriter, r *http.Request) {
	if _, err := a.access.Authorize(r.Context(), Request{Resource: ResourceSoftware, Action: ActionAdmin, Scope: GlobalScope()}); err != nil {
		writeAPIError(w, err)
		return
	}
	limit := 10
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writeAPIError(w, fmt.Errorf("communityplus: invalid upstream search limit"))
			return
		}
	}
	entries, err := SearchWinGetUpstream(r.Context(), r.URL.Query().Get("query"), limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"upstream_entries": entries})
}

func (a *HTTPAPI) requireCatalogStore() (CatalogStore, error) {
	if a.catalogStore == nil {
		return nil, fmt.Errorf("communityplus: server catalog is not configured")
	}
	return a.catalogStore, nil
}

func (a *HTTPAPI) searchWingetCatalog(w http.ResponseWriter, r *http.Request) {
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
	entries, err := SearchCatalogEntries(r.Context(), store, CatalogProviderWinget, r.URL.Query().Get("query"), limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"catalog_entries": entries})
}

type importWingetCatalogEntryRequest struct {
	SourceURL    string `json:"source_url"`
	SourceSHA256 string `json:"source_sha256"`
	DisplayName  string `json:"display_name"`
}

func (a *HTTPAPI) importWingetCatalogEntry(w http.ResponseWriter, r *http.Request) {
	store, err := a.requireCatalogStore()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	var req importWingetCatalogEntryRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeAPIError(w, err)
		return
	}
	if strings.TrimSpace(req.DisplayName) == "" || !validSHA256(req.SourceSHA256) {
		writeAPIError(w, fmt.Errorf("communityplus: display_name and source_sha256 are required"))
		return
	}
	actor, err := a.access.Authorize(r.Context(), Request{Resource: ResourceSoftware, Action: ActionAdmin, Scope: GlobalScope()})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	manifest, err := downloadPinnedWingetManifest(r.Context(), req.SourceURL, req.SourceSHA256)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	parsed, err := winget.Parse(manifest)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	entry := CatalogEntry{ID: catalogEntryID(parsed.PackageIdentifier, parsed.PackageVersion, parsed.InstallerSHA256), Provider: CatalogProviderWinget, PackageIdentifier: parsed.PackageIdentifier, Name: strings.TrimSpace(req.DisplayName), Version: parsed.PackageVersion, InstallerType: parsed.InstallerType, InstallerURL: parsed.InstallerURL, InstallerSHA256: parsed.InstallerSHA256, ProductCode: parsed.ProductCode, SourceURL: req.SourceURL, SourceSHA256: strings.ToLower(req.SourceSHA256), ImportedAt: time.Now().UTC(), ImportedBy: actor}
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

func catalogEntryID(packageID, version, installerSHA string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(packageID) + "\x00" + version + "\x00" + strings.ToLower(installerSHA)))
	return "winget-" + hex.EncodeToString(sum[:16])
}

func downloadPinnedWingetManifest(ctx context.Context, rawURL, expectedSHA string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "raw.githubusercontent.com") || !strings.HasPrefix(u.Path, "/microsoft/winget-pkgs/") {
		return nil, fmt.Errorf("communityplus: source_url must be an HTTPS raw.githubusercontent.com/microsoft/winget-pkgs URL")
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("communityplus: create WinGet manifest request: %w", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("communityplus: download WinGet manifest: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("communityplus: WinGet manifest returned HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("communityplus: read WinGet manifest: %w", err)
	}
	if len(data) > 2<<20 {
		return nil, fmt.Errorf("communityplus: WinGet manifest exceeds 2 MiB")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), expectedSHA) {
		return nil, fmt.Errorf("communityplus: WinGet manifest hash mismatch")
	}
	return data, nil
}

func (a *HTTPAPI) createCatalogDeployment(w http.ResponseWriter, r *http.Request) {
	store, err := a.requireCatalogStore()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	var deployment Deployment
	if err := decodeJSONBody(w, r, &deployment); err != nil {
		writeAPIError(w, err)
		return
	}
	if deployment.ID == "" {
		writeAPIError(w, fmt.Errorf("communityplus: deployment id is required"))
		return
	}
	actor, err := a.access.Authorize(r.Context(), Request{Resource: ResourceSoftware, Action: ActionWrite, Scope: deployment.Scope})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := store.GetCatalogEntry(r.Context(), deployment.CatalogEntryID); err != nil {
		writeAPIError(w, err)
		return
	}
	deployment.CreatedBy, deployment.CreatedAt = actor, time.Now().UTC()
	if err := deployment.Validate(); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := store.UpsertDeployment(r.Context(), deployment); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.auditRecorder.Record(r.Context(), AuditEvent{ActorID: actor, Action: "catalog_deployment.upsert", Resource: ResourceSoftware, ResourceID: deployment.ID, Scope: deployment.Scope, Metadata: map[string]string{"catalog_entry_id": deployment.CatalogEntryID, "automatic": strconv.FormatBool(deployment.Automatic), "patch": strconv.FormatBool(deployment.Patch)}}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"deployment": deployment})
}

func (a *HTTPAPI) listCatalogDeployments(w http.ResponseWriter, r *http.Request) {
	store, err := a.requireCatalogStore()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	fleetID, err := strconv.ParseUint(r.URL.Query().Get("fleet_id"), 10, 0)
	if err != nil || fleetID == 0 {
		writeAPIError(w, fmt.Errorf("communityplus: fleet_id is required"))
		return
	}
	scope := FleetScope(uint(fleetID))
	if _, err := a.access.Authorize(r.Context(), Request{Resource: ResourceSoftware, Action: ActionRead, Scope: scope}); err != nil {
		writeAPIError(w, err)
		return
	}
	deployments, err := store.ListDeployments(r.Context(), scope)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deployments": deployments})
}

func (a *HTTPAPI) getCapabilities(w http.ResponseWriter, r *http.Request) {
	if _, err := a.access.Authorize(r.Context(), Request{
		Resource: ResourceSettings, Action: ActionRead, Scope: GlobalScope(),
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"capabilities": a.registry.Capabilities()})
}

func (a *HTTPAPI) listAutomationRules(w http.ResponseWriter, r *http.Request) {
	rules := a.engine.Rules()
	visible := make([]AutomationRule, 0, len(rules))
	for _, rule := range rules {
		_, err := a.access.Authorize(r.Context(), Request{
			Resource: ResourceAutomations, Action: ActionRead, Scope: rule.Scope,
		})
		if errors.Is(err, ErrForbidden) {
			continue
		}
		if err != nil {
			writeAPIError(w, err)
			return
		}
		visible = append(visible, rule)
	}
	writeJSON(w, http.StatusOK, map[string]any{"automation_rules": visible})
}

func (a *HTTPAPI) putAutomationRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || strings.Contains(id, "/") {
		writeAPIError(w, fmt.Errorf("communityplus: invalid automation rule id"))
		return
	}
	var rule AutomationRule
	if err := decodeJSONBody(w, r, &rule); err != nil {
		writeAPIError(w, err)
		return
	}
	if rule.ID != "" && rule.ID != id {
		writeAPIError(w, fmt.Errorf("communityplus: body id must match path id"))
		return
	}
	rule.ID = id
	if err := rule.Validate(); err != nil {
		writeAPIError(w, err)
		return
	}
	actorID, err := a.access.Authorize(r.Context(), Request{
		Resource: ResourceAutomations, Action: ActionWrite, Scope: rule.Scope,
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.automationStore.UpsertAutomationRule(r.Context(), rule); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.engine.UpsertRule(rule); err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.auditRecorder.Record(r.Context(), AuditEvent{
		ActorID: actorID, Action: "automation_rule.upsert", Resource: ResourceAutomations,
		ResourceID: rule.ID, Scope: rule.Scope,
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"automation_rule": rule})
}

func (a *HTTPAPI) deleteAutomationRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule *AutomationRule
	for _, candidate := range a.engine.Rules() {
		if candidate.ID == id {
			copy := candidate
			rule = &copy
			break
		}
	}
	if rule == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "automation rule not found"})
		return
	}
	actorID, err := a.access.Authorize(r.Context(), Request{
		Resource: ResourceAutomations, Action: ActionWrite, Scope: rule.Scope,
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.automationStore.DeleteAutomationRule(r.Context(), id); err != nil {
		writeAPIError(w, err)
		return
	}
	a.engine.DeleteRule(id)
	if err := a.auditRecorder.Record(r.Context(), AuditEvent{
		ActorID: actorID, Action: "automation_rule.delete", Resource: ResourceAutomations,
		ResourceID: id, Scope: rule.Scope,
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *HTTPAPI) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	filter := AuditFilter{Limit: 100}
	scope := GlobalScope()
	if value := r.URL.Query().Get("fleet_id"); value != "" {
		fleetID, err := strconv.ParseUint(value, 10, 64)
		if err != nil || fleetID == 0 || uint64(uint(fleetID)) != fleetID {
			writeAPIError(w, fmt.Errorf("communityplus: invalid fleet_id"))
			return
		}
		id := uint(fleetID)
		filter.FleetID = &id
		scope = FleetScope(id)
	}
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit <= 0 || limit > 1000 {
			writeAPIError(w, fmt.Errorf("communityplus: limit must be between 1 and 1000"))
			return
		}
		filter.Limit = limit
	}
	if _, err := a.access.Authorize(r.Context(), Request{
		Resource: ResourceAudit, Action: ActionRead, Scope: scope,
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	events, err := a.auditStore.ListAuditEvents(r.Context(), filter)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit_events": events})
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("communityplus: invalid JSON body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("communityplus: request body must contain one JSON object")
	}
	return nil
}

func writeAPIError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrUnauthenticated):
		status = http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		status = http.StatusForbidden
	case strings.Contains(err.Error(), "invalid"), strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "must"):
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *HTTPAPI) listCatalogDeploymentResults(w http.ResponseWriter, r *http.Request) { store, err := a.requireCatalogStore(); if err != nil { writeAPIError(w, err); return }; deployment, err := store.GetDeployment(r.Context(), r.PathValue("id")); if err != nil { writeAPIError(w, err); return }; if _, err = a.access.Authorize(r.Context(), Request{Resource: ResourceSoftware, Action: ActionRead, Scope: deployment.Scope}); err != nil { writeAPIError(w, err); return }; results, err := store.ListDeploymentResults(r.Context(), deployment.ID); if err != nil { writeAPIError(w, err); return }; writeJSON(w, http.StatusOK, map[string]any{"deployment": deployment, "results": results}) }
