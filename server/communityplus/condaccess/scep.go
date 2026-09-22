package condaccess

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/assets"
	scepdepot "github.com/fleetdm/fleet/v4/server/mdm/scep/depot"
	scepserver "github.com/fleetdm/fleet/v4/server/mdm/scep/server"
	"github.com/fleetdm/fleet/v4/server/service/middleware/otel"
	"github.com/smallstep/scep"
)

const (
	conditionalAccessSCEPPath         = "/api/fleet/conditional_access/scep"
	conditionalAccessCertValidityDays = 398
	conditionalAccessCACaps           = "SHA-256\nAES\nPOSTPKIOperation"
)

// RegisterSCEP mounts Community+'s conditional-access certificate enrollment
// endpoint. Certificates are issued only when a global Fleet enrollment secret
// is supplied as the SCEP challenge password. Renewal is intentionally omitted:
// clients must re-enroll with a valid challenge for each replacement cert.
func RegisterSCEP(
	ctx context.Context,
	mux *http.ServeMux,
	storage scepdepot.Depot,
	ds fleet.Datastore,
	logger *slog.Logger,
	fleetConfig *config.FleetConfig,
) error {
	if ctx == nil {
		return errors.New("conditional access context is nil")
	}
	if mux == nil {
		return errors.New("conditional access HTTP mux is nil")
	}
	if storage == nil {
		return errors.New("conditional access SCEP storage is nil")
	}
	if ds == nil {
		return errors.New("conditional access datastore is nil")
	}
	if logger == nil {
		return errors.New("conditional access logger is nil")
	}
	if fleetConfig == nil {
		return errors.New("conditional access Fleet config is nil")
	}
	if err := ensureAssets(ctx, ds); err != nil {
		return err
	}

	pair, err := assets.KeyPair(
		ctx,
		ds,
		fleet.MDMAssetConditionalAccessCACert,
		fleet.MDMAssetConditionalAccessCAKey,
	)
	if err != nil {
		return fmt.Errorf("load conditional access CA: %w", err)
	}
	if pair == nil || pair.Leaf == nil {
		return errors.New("conditional access CA is incomplete")
	}
	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok || key == nil {
		return errors.New("conditional access CA private key is not RSA")
	}

	var signer scepserver.CSRSignerContext = scepserver.SignCSRAdapter(scepdepot.NewSigner(
		storage,
		scepdepot.WithValidityDays(conditionalAccessCertValidityDays),
	))
	signer = requireGlobalEnrollSecret(ds, signer)

	core, err := scepserver.NewService(
		pair.Leaf,
		key,
		signer,
		scepserver.WithLogger(logger.With("component", "conditional-access-scep-core")),
	)
	if err != nil {
		return fmt.Errorf("create conditional access SCEP service: %w", err)
	}
	svc := noRenewalSCEPService{Service: core}

	httpLogger := logger.With("component", "http-conditional-access-scep")
	endpoints := scepserver.MakeServerEndpoints(svc)
	endpoints.GetEndpoint = scepserver.EndpointLoggingMiddleware(httpLogger)(endpoints.GetEndpoint)
	endpoints.PostEndpoint = scepserver.EndpointLoggingMiddleware(httpLogger)(endpoints.PostEndpoint)
	handler := scepserver.MakeHTTPHandler(endpoints, svc, httpLogger)
	handler = otel.WrapHandler(handler, conditionalAccessSCEPPath, *fleetConfig)
	mux.Handle(conditionalAccessSCEPPath, handler)
	return nil
}

// noRenewalSCEPService reuses Fleet's hardened SCEP parsing/response engine but
// deliberately changes the protocol surface needed by conditional access.
type noRenewalSCEPService struct {
	scepserver.Service
}

func (noRenewalSCEPService) GetCACaps(context.Context) ([]byte, error) {
	return []byte(conditionalAccessCACaps), nil
}

func (noRenewalSCEPService) GetNextCACert(context.Context) ([]byte, error) {
	return nil, errors.New("conditional access SCEP renewal is not supported")
}

func requireGlobalEnrollSecret(ds fleet.Datastore, next scepserver.CSRSignerContext) scepserver.CSRSignerContextFunc {
	return func(ctx context.Context, message *scep.CSRReqMessage) (*x509.Certificate, error) {
		if message == nil || message.ChallengePassword == "" {
			return nil, errors.New("missing challenge")
		}
		secret, err := ds.VerifyEnrollSecret(ctx, message.ChallengePassword)
		if err != nil {
			if fleet.IsNotFound(err) {
				return nil, errors.New("invalid challenge")
			}
			return nil, fmt.Errorf("verify enrollment secret: %w", err)
		}
		if secret == nil || secret.TeamID != nil {
			return nil, errors.New("invalid challenge")
		}
		return next.SignCSRContext(ctx, message)
	}
}
