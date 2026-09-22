package communityplus

import "errors"

// ErrScopeConflict is returned when an existing globally unique resource ID is
// reused with a different scope. Scope is immutable once an ID is persisted so
// one Fleet can never take ownership of another Fleet's resource by guessing an
// ID and upserting it. SQL persistence enforces the invariant even when several
// Fleet server instances race on the same resource ID.
var ErrScopeConflict = errors.New("communityplus: resource scope must not change")
