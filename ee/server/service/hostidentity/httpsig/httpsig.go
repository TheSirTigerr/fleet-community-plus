// Package httpsig is a compatibility facade for Community+ HTTP message
// signature verification. It contains no Fleet Enterprise implementation.
package httpsig

import (
	"context"
	"log/slog"
	"net/http"

	communityhttpsig "github.com/fleetdm/fleet/v4/server/communityplus/hostidentity/httpsig"
	communitytypes "github.com/fleetdm/fleet/v4/server/communityplus/hostidentity/types"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

type certificateStore interface {
	GetHostIdentityCertBySerialNumber(context.Context, uint64) (*communitytypes.HostIdentityCertificate, error)
}

func Middleware(store certificateStore, require bool, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	return communityhttpsig.Middleware(store, require, logger)
}

func NewContext(ctx context.Context, certificate communitytypes.HostIdentityCertificate) context.Context {
	return communityhttpsig.NewContext(ctx, certificate)
}

func FromContext(ctx context.Context) (communitytypes.HostIdentityCertificate, bool) {
	return communityhttpsig.FromContext(ctx)
}

func IsSigAuthEndpoint(path string) bool {
	return communityhttpsig.IsSigAuthEndpoint(path)
}

func VerifyHostIdentity(ctx context.Context, _ certificateStore, host *fleet.Host) error {
	if host == nil {
		return communityhttpsig.VerifyHostIdentity(ctx, 0)
	}
	return communityhttpsig.VerifyHostIdentity(ctx, host.ID)
}
