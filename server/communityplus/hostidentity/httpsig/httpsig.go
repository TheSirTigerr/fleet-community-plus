// Package httpsig verifies Fleet agent HTTP message signatures using host
// identity certificates stored in the Community database.
package httpsig

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/fleethttpsig"
	hostidentity "github.com/fleetdm/fleet/v4/server/communityplus/hostidentity/types"
	remitlyhttpsig "github.com/remitly-oss/httpsig-go"
)

type contextKey struct{}

type certificateStore interface {
	GetHostIdentityCertBySerialNumber(context.Context, uint64) (*hostidentity.HostIdentityCertificate, error)
}

type certificateKey struct {
	certificate hostidentity.HostIdentityCertificate
	spec        remitlyhttpsig.KeySpec
}

func (k *certificateKey) KeySpec() (remitlyhttpsig.KeySpec, error) { return k.spec, nil }

type keyFetcher struct{ store certificateStore }

func (f keyFetcher) FetchByKeyID(ctx context.Context, _ http.Header, keyID string) (remitlyhttpsig.KeySpecer, error) {
	serial, err := strconv.ParseUint(keyID, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("communityplus: invalid host identity key id: %w", err)
	}
	certificate, err := f.store.GetHostIdentityCertBySerialNumber(ctx, serial)
	if err != nil {
		return nil, fmt.Errorf("communityplus: load host identity certificate: %w", err)
	}
	publicKey, err := certificate.UnmarshalPublicKey()
	if err != nil {
		return nil, err
	}
	var algorithm remitlyhttpsig.Algorithm
	switch publicKey.Curve {
	case elliptic.P256():
		algorithm = remitlyhttpsig.Algo_ECDSA_P256_SHA256
	case elliptic.P384():
		algorithm = remitlyhttpsig.Algo_ECDSA_P384_SHA384
	default:
		return nil, fmt.Errorf("communityplus: unsupported host identity curve")
	}
	return &certificateKey{
		certificate: *certificate,
		spec: remitlyhttpsig.KeySpec{
			KeyID: keyID, Algo: algorithm, PubKey: publicKey,
		},
	}, nil
}

func (f keyFetcher) Fetch(context.Context, http.Header, remitlyhttpsig.MetadataProvider) (remitlyhttpsig.KeySpecer, error) {
	return nil, fmt.Errorf("communityplus: host identity signature requires keyid metadata")
}

// Middleware verifies signatures when present and can require them for agent
// authentication endpoints. Unsigned human-facing API routes remain available
// for normal Fleet session authentication.
func Middleware(store certificateStore, require bool, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	if store == nil {
		return nil, fmt.Errorf("communityplus: host identity certificate store is required")
	}
	verifier, err := fleethttpsig.Verifier(keyFetcher{store: store})
	if err != nil {
		return nil, fmt.Errorf("communityplus: create HTTP signature verifier: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hasSignature := r.Header.Get("Signature-Input") != "" || r.Header.Get("Signature") != ""
			if !hasSignature {
				if require && IsSigAuthEndpoint(r.URL.Path) {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			result, err := verifier.Verify(r)
			if err != nil || !result.Verified {
				logger.WarnContext(r.Context(), "host identity HTTP signature verification failed", "err", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			key, ok := result.KeySpecer.(*certificateKey)
			if !ok {
				logger.ErrorContext(r.Context(), "host identity verifier returned an unexpected key type")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := NewContext(r.Context(), key.certificate)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

func NewContext(ctx context.Context, certificate hostidentity.HostIdentityCertificate) context.Context {
	return context.WithValue(ctx, contextKey{}, certificate)
}

func FromContext(ctx context.Context) (hostidentity.HostIdentityCertificate, bool) {
	certificate, ok := ctx.Value(contextKey{}).(hostidentity.HostIdentityCertificate)
	return certificate, ok
}

// IsSigAuthEndpoint reports whether an endpoint accepts host identity instead
// of a user session. Prefix checks intentionally cover versioned subroutes.
func IsSigAuthEndpoint(path string) bool {
	return strings.HasPrefix(path, "/osquery/") ||
		strings.HasPrefix(path, "/api/fleet/orbit/") ||
		(strings.HasPrefix(path, "/api/") && strings.Contains(path, "/fleet/certificate_authorities/") && strings.HasSuffix(path, "/request_certificate"))
}

// VerifyHostIdentity binds the verified request certificate to the loaded host.
func VerifyHostIdentity(ctx context.Context, hostID uint) error {
	if hostID == 0 {
		return fmt.Errorf("communityplus: host ID is required")
	}
	certificate, ok := FromContext(ctx)
	if !ok {
		return fmt.Errorf("missing HTTP signature")
	}
	if !certificate.NotValidAfter.After(time.Now()) {
		return fmt.Errorf("host identity certificate expired")
	}
	if certificate.HostID == nil {
		return fmt.Errorf("identity certificate is not linked to a specific host")
	}
	if *certificate.HostID != hostID {
		return fmt.Errorf("identity certificate belongs to a different host")
	}
	return nil
}
