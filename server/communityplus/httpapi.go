package communityplus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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
}

func NewHTTPAPI(
	registry *Registry,
	engine *AutomationEngine,
	automationStore AutomationStore,
	auditStore AuditStore,
	access AccessController,
) (*HTTPAPI, error) {
	if registry == nil || engine == nil || automationStore == nil || auditStore == nil || access == nil {
		return nil, fmt.Errorf("communityplus: HTTP API dependencies are required")
	}
	recorder, err := NewAuditRecorder(auditStore)
	if err != nil {
		return nil, err
	}
	return &HTTPAPI{
		registry: registry, engine: engine, automationStore: automationStore,
		auditStore: auditStore, auditRecorder: recorder, access: access,
	}, nil
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
	}
	return mux
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
