// Package mdmmigration implements Community+ macOS migration-to-Fleet workflows.
package mdmmigration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/fleetdm/fleet/v4/server"
	hostctx "github.com/fleetdm/fleet/v4/server/contexts/host"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

// Service implements the server-side parts of macOS MDM migration without
// depending on Fleet's Premium service wrapper.
type Service struct {
	ds     fleet.Datastore
	logger *slog.Logger
	now    func() time.Time
}

func New(ds fleet.Datastore, logger *slog.Logger) (*Service, error) {
	if ds == nil {
		return nil, errors.New("MDM migration datastore is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{ds: ds, logger: logger, now: time.Now}, nil
}

// Trigger validates migration eligibility, calls the configured migration
// webhook, then temporarily accelerates critical-query refetches so fleetd can
// detect when the previous MDM has released the host.
func (s *Service) Trigger(ctx context.Context, host *fleet.Host) error {
	if host == nil {
		return &fleet.BadRequestError{Message: "host is required for MDM migration"}
	}

	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("load app config: %w", err)
	}
	if !appConfig.MDM.EnabledAndConfigured {
		return fleet.ErrMDMNotConfigured
	}

	now := s.now()
	if host.RefetchCriticalQueriesUntil != nil && host.RefetchCriticalQueriesUntil.After(now) {
		return nil
	}

	connected, err := s.ds.IsHostConnectedToFleetMDM(ctx, host)
	if err != nil {
		return fmt.Errorf("check Fleet MDM connection: %w", err)
	}

	if !appConfig.MDM.MacOSMigration.Enable {
		return &fleet.BadRequestError{Message: "macOS MDM migration is not enabled"}
	}
	if appConfig.MDM.MacOSMigration.WebhookURL == "" {
		return &fleet.BadRequestError{Message: "macOS MDM migration webhook URL is not configured"}
	}

	mdmInfo, err := s.ds.GetHostMDM(ctx, host.ID)
	if err != nil {
		return fmt.Errorf("load host MDM information: %w", err)
	}
	manualEligible, err := fleet.IsEligibleForManualMigration(host, mdmInfo, connected)
	if err != nil {
		return fmt.Errorf("check manual MDM migration eligibility: %w", err)
	}
	if !fleet.IsEligibleForDEPMigration(host, mdmInfo, connected) && !manualEligible {
		return &fleet.BadRequestError{Message: "host is not eligible for macOS MDM migration"}
	}

	payload := fleet.MigrateMDMDeviceWebhookPayload{Timestamp: now.UTC()}
	payload.Host.ID = host.ID
	payload.Host.UUID = host.UUID
	payload.Host.HardwareSerial = host.HardwareSerial
	if err := server.PostJSONWithTimeout(ctx, appConfig.MDM.MacOSMigration.WebhookURL, payload, s.logger); err != nil {
		return fmt.Errorf("post macOS MDM migration webhook: %w", err)
	}

	refetchUntil := now.Add(fleet.RefetchMDMUnenrollCriticalQueryDuration)
	if err := s.ds.UpdateHostRefetchCriticalQueriesUntil(ctx, host.ID, &refetchUntil); err != nil {
		return fmt.Errorf("save migration critical-query refetch deadline: %w", err)
	}
	host.RefetchCriticalQueriesUntil = &refetchUntil
	return nil
}

// DesktopSummary exposes the migration notification/configuration needed by
// Fleet Desktop. Other premium-only Desktop features are intentionally not
// fabricated here; Community+ layers those independently as they are added.
func (s *Service) DesktopSummary(ctx context.Context) (fleet.DesktopSummary, error) {
	var summary fleet.DesktopSummary
	host, ok := hostctx.FromContext(ctx)
	if !ok || host == nil {
		return summary, fleet.NewAuthRequiredError("internal error: missing host from request context")
	}

	appConfig, err := s.ds.AppConfig(ctx)
	if err != nil {
		return summary, fmt.Errorf("load app config: %w", err)
	}

	summary.AlternativeBrowserHost = appConfig.FleetDesktop.AlternativeBrowserHost
	summary.Config.OrgInfo.OrgName = appConfig.OrgInfo.OrgName
	summary.Config.OrgInfo.OrgLogoURL = appConfig.OrgInfo.OrgLogoURL
	summary.Config.OrgInfo.OrgLogoURLLightBackground = appConfig.OrgInfo.OrgLogoURLLightBackground
	summary.Config.OrgInfo.OrgLogoURLDarkMode = appConfig.OrgInfo.OrgLogoURLDarkMode
	summary.Config.OrgInfo.OrgLogoURLLightMode = appConfig.OrgInfo.OrgLogoURLLightMode
	summary.Config.OrgInfo.ContactURL = appConfig.OrgInfo.ContactURL
	summary.Config.MDM.MacOSMigration.Mode = appConfig.MDM.MacOSMigration.Mode

	if !appConfig.MDM.EnabledAndConfigured || !appConfig.MDM.MacOSMigration.Enable {
		return summary, nil
	}

	connected, err := s.ds.IsHostConnectedToFleetMDM(ctx, host)
	if err != nil {
		return summary, fmt.Errorf("check Fleet MDM connection: %w", err)
	}
	mdmInfo, err := s.ds.GetHostMDM(ctx, host.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !fleet.IsNotFound(err) {
		return summary, fmt.Errorf("load host MDM information: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) || fleet.IsNotFound(err) {
		mdmInfo = nil
	}

	if mdmInfo != nil && !mdmInfo.Enrolled && host.IsDEPAssignedToFleet() {
		summary.Notifications.RenewEnrollmentProfile = true
	}
	manualEligible, err := fleet.IsEligibleForManualMigration(host, mdmInfo, connected)
	if err != nil {
		return summary, fmt.Errorf("check manual MDM migration eligibility: %w", err)
	}
	if fleet.IsEligibleForDEPMigration(host, mdmInfo, connected) || manualEligible {
		summary.Notifications.NeedsMDMMigration = true
	}
	return summary, nil
}
