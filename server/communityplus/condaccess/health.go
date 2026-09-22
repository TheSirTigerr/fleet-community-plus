package condaccess

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/crewjam/saml"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/google/uuid"
)

const (
	conditionalAccessRemediationFallback = "https://fleetdm.com/remediate"
	deviceAuthTokenTTL                   = time.Hour
)

type deviceHealthSessionProvider struct {
	ds     fleet.Datastore
	logger *slog.Logger
	hostID uint
}

func samlRequestNameID(req *saml.IdpAuthnRequest) string {
	if req == nil || req.Request.Subject == nil || req.Request.Subject.NameID == nil {
		return ""
	}
	return req.Request.Subject.NameID.Value
}

func (p *deviceHealthSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	ctx := r.Context()
	host, err := p.ds.HostLite(ctx, p.hostID)
	if err != nil {
		p.logger.ErrorContext(ctx, "conditional access host lookup failed", "host_id", p.hostID, "err", err)
		http.Error(w, "conditional access device unavailable", http.StatusForbidden)
		return nil
	}

	teamID := uint(0)
	if host.TeamID != nil {
		teamID = *host.TeamID
	}
	protectedPolicyIDs, err := p.ds.GetPoliciesForConditionalAccess(ctx, teamID, host.Platform)
	if err != nil {
		p.internalError(w, ctx, "load conditional access policy selection", err)
		return nil
	}
	protected := make(map[uint]struct{}, len(protectedPolicyIDs))
	for _, id := range protectedPolicyIDs {
		protected[id] = struct{}{}
	}

	results, err := p.ds.ListPoliciesForHost(ctx, &fleet.Host{ID: p.hostID, Platform: host.Platform})
	if err != nil {
		p.internalError(w, ctx, "load device policy results", err)
		return nil
	}

	failing := 0
	critical := 0
	for _, result := range results {
		if _, ok := protected[result.ID]; !ok || result.Response != "fail" {
			continue
		}
		failing++
		if result.Critical {
			critical++
		}
	}

	if failing > 0 {
		appConfig, cfgErr := p.ds.AppConfig(ctx)
		if cfgErr != nil {
			p.internalError(w, ctx, "load conditional access config", cfgErr)
			return nil
		}

		remediationURL, urlErr := p.remediationURL(ctx, appConfig.ServerSettings.ServerURL)
		if urlErr != nil {
			p.logger.ErrorContext(ctx, "build conditional access remediation URL", "host_id", p.hostID, "err", urlErr)
			http.Redirect(w, r, conditionalAccessRemediationFallback, http.StatusSeeOther)
			return nil
		}

		bypassAllowed := appConfig.ConditionalAccess == nil || appConfig.ConditionalAccess.BypassEnabled()
		if bypassAllowed && critical == 0 {
			consumedAt, bypassErr := p.ds.ConditionalAccessConsumeBypass(ctx, p.hostID)
			if bypassErr != nil {
				p.logger.ErrorContext(ctx, "consume conditional access bypass", "host_id", p.hostID, "err", bypassErr)
				http.Redirect(w, r, remediationURL, http.StatusSeeOther)
				return nil
			}
			if consumedAt != nil {
				p.logger.InfoContext(ctx, "conditional access bypass consumed", "host_id", p.hostID)
				return p.session(req)
			}
		}

		p.logger.InfoContext(ctx, "conditional access remediation required", "host_id", p.hostID, "failing", failing, "critical", critical)
		http.Redirect(w, r, remediationURL, http.StatusSeeOther)
		return nil
	}

	return p.session(req)
}

func (p *deviceHealthSessionProvider) session(req *saml.IdpAuthnRequest) *saml.Session {
	nameID := samlRequestNameID(req)
	if nameID == "" {
		nameID = fmt.Sprintf("host-%d", p.hostID)
	}
	return &saml.Session{NameID: nameID}
}

func (p *deviceHealthSessionProvider) remediationURL(ctx context.Context, serverURL string) (string, error) {
	token, err := p.validOrNewDeviceToken(ctx)
	if err != nil {
		return "", err
	}
	if serverURL == "" {
		return "", fmt.Errorf("Fleet server URL is empty")
	}
	return fmt.Sprintf("%s/device/%s/policies", trimTrailingSlash(serverURL), token), nil
}

func (p *deviceHealthSessionProvider) validOrNewDeviceToken(ctx context.Context) (string, error) {
	token, err := p.ds.GetDeviceAuthToken(ctx, p.hostID)
	switch {
	case err == nil:
		if _, validateErr := p.ds.LoadHostByDeviceAuthToken(ctx, token, deviceAuthTokenTTL); validateErr == nil {
			return token, nil
		} else if !fleet.IsNotFound(validateErr) {
			return "", fmt.Errorf("validate device auth token: %w", validateErr)
		}
	case fleet.IsNotFound(err):
		// Create a short-lived remediation token below.
	default:
		return "", fmt.Errorf("load device auth token: %w", err)
	}

	token = uuid.NewString()
	if err := p.ds.SetOrUpdateDeviceAuthToken(ctx, p.hostID, token); err != nil {
		return "", fmt.Errorf("store device auth token: %w", err)
	}
	return token, nil
}

func (p *deviceHealthSessionProvider) internalError(w http.ResponseWriter, ctx context.Context, operation string, err error) {
	p.logger.ErrorContext(ctx, operation, "host_id", p.hostID, "err", err)
	http.Error(w, "conditional access check failed", http.StatusInternalServerError)
}

func trimTrailingSlash(value string) string {
	for len(value) > 0 && value[len(value)-1] == '/' {
		value = value[:len(value)-1]
	}
	return value
}
