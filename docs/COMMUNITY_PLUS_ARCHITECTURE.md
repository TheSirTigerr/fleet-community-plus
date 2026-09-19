# Community+ architecture

Community+ is an independently implemented extension layer for the Fleet Community codebase.
It is designed to provide equivalent operational capabilities without copying or depending on
Fleet's restricted Enterprise Edition server implementation.

## Rules

1. `server/communityplus` must never import code from an `ee/` package or require an Enterprise license key.
2. Public documentation, public API contracts and MIT-licensed Community interfaces may be used as specifications.
3. A capability is exposed only when its runtime status is `experimental` or `available`.
4. Security-sensitive operations are scoped explicitly to either `global` or one Fleet.
5. Cross-Fleet access must be denied by default and covered by tests.
6. Every mutating administrative operation should emit an audit event when integrated into Fleet services.
7. Automations are represented as generic triggers and actions so policy remediation, patching and software deployment share one execution model.

## Foundation

The initial foundation lives in `server/communityplus`:

- `features.go` — capability registry and implementation maturity.
- `rbac.go` — global/Fleet scopes, permissions, roles and authorization.
- `audit.go` — validated audit events plus a pluggable persistence sink.
- `automation.go` — scoped event/rule engine for remediation and orchestration.
- `sqlstore.go` — MySQL persistence for audit events and automation rules.
- `httpapi.go` — authenticated, scope-aware REST API for capabilities, audit and automation management.

This layer intentionally has no dependency on Fleet's datastore or service packages. Integration is
performed through adapters so Community+ remains testable and upstream Fleet changes remain mergeable.

## Integration plan

### Phase 1 — shared platform

- Capability registry
- Fleet scoping
- RBAC
- Audit logging
- Automation engine
- SQL persistence adapters
- REST capability endpoint

### Phase 2 — policies and software

- Fleet-scoped policy CRUD
- Policy-failure remediation
- Script execution actions
- Software installation actions
- Patch policy scheduler
- Maintenance windows
- Self-service software metadata

### Phase 3 — device management

- Enrollment workflows
- Zero-touch/setup experience orchestration
- Disk-encryption key escrow adapters
- OS update enforcement
- Remote lock/wipe actions
- Certificate deployment
- Device naming and assignment rules

### Phase 4 — identity and access

- SCIM provisioning
- JIT provisioning
- IdP group-to-Fleet mappings
- Conditional-access evaluation
- Account synchronization adapters

### Phase 5 — visibility and operations

- Vulnerability enrichment
- Reports and exports
- Custom query/table controls
- Agent version controls
- GitOps configuration
- External orchestration integrations

## Security model

A Fleet-scoped permission never contains another Fleet. Global permissions can operate on Fleet targets,
but Fleet permissions cannot elevate to global scope. The automation engine applies the same containment
rule before an action can execute.

Persistent adapters and HTTP handlers must keep that invariant rather than trusting user-provided Fleet IDs.

## Upstream build boundary

The initial bootstrap removed upstream's complete `ee/` directory, but the imported Community server still
contains production imports of packages below that path. As a result, the full Fleet server is not buildable
until those imports are replaced with independently implemented Community+ adapters. Restricted upstream EE
implementations must not be copied back to repair the build.

The Community+ package is deliberately isolated and independently testable while this compatibility work is
completed. An HTTP API being implemented here is not considered integrated until the complete Fleet server
build succeeds and the handler is mounted behind Fleet authentication.

## Feature maturity

The capability registry uses three states:

- `planned` — implementation is incomplete and must not be presented as usable.
- `experimental` — usable for development/testing and explicitly enabled by Community+.
- `available` — implementation is considered production-ready by this project.

This replaces license-gated behavior with implementation maturity; it is not a replacement or bypass for
Fleet Enterprise licensing.
