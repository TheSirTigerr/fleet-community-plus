package communityplus

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// AuditEvent is a durable description of a security- or operations-relevant action.
type AuditEvent struct {
	ID         string            `json:"id"`
	OccurredAt time.Time         `json:"occurred_at"`
	ActorID    string            `json:"actor_id"`
	Action     string            `json:"action"`
	Resource   Resource          `json:"resource"`
	ResourceID string            `json:"resource_id,omitempty"`
	Scope      Scope             `json:"scope"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func (e AuditEvent) Validate() error {
	if e.ActorID == "" {
		return fmt.Errorf("communityplus: audit actor_id is required")
	}
	if e.Action == "" {
		return fmt.Errorf("communityplus: audit action is required")
	}
	if e.Resource == "" {
		return fmt.Errorf("communityplus: audit resource is required")
	}
	if err := e.Scope.Validate(); err != nil {
		return err
	}
	return nil
}

// AuditSink persists audit events. Database-backed sinks can implement this
// interface without coupling the recorder to Fleet's datastore package.
type AuditSink interface {
	RecordAuditEvent(context.Context, AuditEvent) error
}

// AuditRecorder validates and stamps events before handing them to a sink.
type AuditRecorder struct {
	sink AuditSink
	now  func() time.Time
	seq  atomic.Uint64
}

func NewAuditRecorder(sink AuditSink) (*AuditRecorder, error) {
	if sink == nil {
		return nil, fmt.Errorf("communityplus: audit sink is required")
	}
	return &AuditRecorder{sink: sink, now: time.Now}, nil
}

func (r *AuditRecorder) Record(ctx context.Context, event AuditEvent) error {
	if r == nil || r.sink == nil {
		return fmt.Errorf("communityplus: audit recorder is not configured")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = r.now().UTC()
	}
	if event.ID == "" {
		event.ID = fmt.Sprintf("cp-audit-%d-%d", event.OccurredAt.UnixNano(), r.seq.Add(1))
	}
	return r.sink.RecordAuditEvent(ctx, event)
}

// MemoryAuditSink is useful for tests and local development. Production code
// can swap this for a SQL-backed implementation.
type MemoryAuditSink struct {
	mu     sync.RWMutex
	events []AuditEvent
}

func (s *MemoryAuditSink) RecordAuditEvent(_ context.Context, event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.Metadata = cloneStringMap(event.Metadata)
	s.events = append(s.events, event)
	return nil
}

func (s *MemoryAuditSink) Events() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]AuditEvent, len(s.events))
	for i, event := range s.events {
		event.Metadata = cloneStringMap(event.Metadata)
		result[i] = event
	}
	return result
}

func cloneStringMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
