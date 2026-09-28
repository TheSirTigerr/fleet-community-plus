package mdmmigration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	hostctx "github.com/fleetdm/fleet/v4/server/contexts/host"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
)

func eligibleManualMigrationHost() *fleet.Host {
	osqueryID := "osquery-host-id"
	return &fleet.Host{
		ID:             42,
		UUID:           "host-uuid",
		HardwareSerial: "SERIAL42",
		Platform:       "darwin",
		OSVersion:      "macOS 15.0.1",
		OsqueryHostID:  &osqueryID,
	}
}

func migrationAppConfig(webhookURL string, mode fleet.MacOSMigrationMode) *fleet.AppConfig {
	return &fleet.AppConfig{
		MDM: fleet.MDM{
			EnabledAndConfigured: true,
			MacOSMigration: fleet.MacOSMigration{
				Enable:     true,
				Mode:       mode,
				WebhookURL: webhookURL,
			},
		},
	}
}

func eligibleThirdPartyMDM() *fleet.HostMDM {
	return &fleet.HostMDM{Name: "Third Party MDM", Enrolled: true}
}

func TestTriggerPostsWebhookAndStartsCriticalQueryRefetchWindow(t *testing.T) {
	fixedNow := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	var payload fleet.MigrateMDMDeviceWebhookPayload
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode webhook payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	ds := &mock.DataStore{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return migrationAppConfig(webhook.URL, fleet.MacOSMigrationModeVoluntary), nil
	}
	ds.IsHostConnectedToFleetMDMFunc = func(context.Context, *fleet.Host) (bool, error) { return false, nil }
	ds.GetHostMDMFunc = func(context.Context, uint) (*fleet.HostMDM, error) { return eligibleThirdPartyMDM(), nil }
	var persistedUntil *time.Time
	ds.UpdateHostRefetchCriticalQueriesUntilFunc = func(_ context.Context, hostID uint, until *time.Time) error {
		if hostID != 42 {
			t.Fatalf("expected host ID 42, got %d", hostID)
		}
		persistedUntil = until
		return nil
	}

	svc, err := New(ds, nil)
	if err != nil {
		t.Fatalf("new migration service: %v", err)
	}
	svc.now = func() time.Time { return fixedNow }
	host := eligibleManualMigrationHost()
	if err := svc.Trigger(context.Background(), host); err != nil {
		t.Fatalf("trigger migration: %v", err)
	}

	if payload.Timestamp != fixedNow {
		t.Fatalf("expected timestamp %v, got %v", fixedNow, payload.Timestamp)
	}
	if payload.Host.ID != host.ID || payload.Host.UUID != host.UUID || payload.Host.HardwareSerial != host.HardwareSerial {
		t.Fatalf("unexpected webhook host payload: %+v", payload.Host)
	}
	expectedUntil := fixedNow.Add(fleet.RefetchMDMUnenrollCriticalQueryDuration)
	if persistedUntil == nil || !persistedUntil.Equal(expectedUntil) {
		t.Fatalf("expected persisted refetch deadline %v, got %v", expectedUntil, persistedUntil)
	}
	if host.RefetchCriticalQueriesUntil == nil || !host.RefetchCriticalQueriesUntil.Equal(expectedUntil) {
		t.Fatalf("expected host refetch deadline %v, got %v", expectedUntil, host.RefetchCriticalQueriesUntil)
	}
}

func TestTriggerIsIdempotentDuringCriticalQueryRefetchWindow(t *testing.T) {
	fixedNow := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	future := fixedNow.Add(time.Minute)
	host := eligibleManualMigrationHost()
	host.RefetchCriticalQueriesUntil = &future

	ds := &mock.DataStore{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{MDM: fleet.MDM{EnabledAndConfigured: true}}, nil
	}
	svc, err := New(ds, nil)
	if err != nil {
		t.Fatalf("new migration service: %v", err)
	}
	svc.now = func() time.Time { return fixedNow }

	if err := svc.Trigger(context.Background(), host); err != nil {
		t.Fatalf("idempotent trigger: %v", err)
	}
	if ds.IsHostConnectedToFleetMDMFuncInvoked || ds.GetHostMDMFuncInvoked || ds.UpdateHostRefetchCriticalQueriesUntilFuncInvoked {
		t.Fatal("migration should return before eligibility checks and persistence during the active refetch window")
	}
}

func TestDesktopSummaryAdvertisesEligibleMigration(t *testing.T) {
	host := eligibleManualMigrationHost()
	ds := &mock.DataStore{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		cfg := migrationAppConfig("https://example.test/migrate", fleet.MacOSMigrationModeForced)
		cfg.OrgInfo.OrgName = "Community+"
		return cfg, nil
	}
	ds.IsHostConnectedToFleetMDMFunc = func(context.Context, *fleet.Host) (bool, error) { return false, nil }
	ds.GetHostMDMFunc = func(context.Context, uint) (*fleet.HostMDM, error) { return eligibleThirdPartyMDM(), nil }

	svc, err := New(ds, nil)
	if err != nil {
		t.Fatalf("new migration service: %v", err)
	}
	ctx := hostctx.NewContext(context.Background(), host)
	summary, err := svc.DesktopSummary(ctx)
	if err != nil {
		t.Fatalf("desktop summary: %v", err)
	}
	if !summary.Notifications.NeedsMDMMigration {
		t.Fatal("expected Fleet Desktop to advertise MDM migration")
	}
	if summary.Config.MDM.MacOSMigration.Mode != fleet.MacOSMigrationModeForced {
		t.Fatalf("expected forced migration mode, got %q", summary.Config.MDM.MacOSMigration.Mode)
	}
	if summary.Config.OrgInfo.OrgName != "Community+" {
		t.Fatalf("expected org information to be preserved, got %q", summary.Config.OrgInfo.OrgName)
	}
}

func TestDesktopSummarySkipsEligibilityChecksWhenMigrationDisabled(t *testing.T) {
	host := eligibleManualMigrationHost()
	ds := &mock.DataStore{}
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{MDM: fleet.MDM{EnabledAndConfigured: true}}, nil
	}
	svc, err := New(ds, nil)
	if err != nil {
		t.Fatalf("new migration service: %v", err)
	}

	summary, err := svc.DesktopSummary(hostctx.NewContext(context.Background(), host))
	if err != nil {
		t.Fatalf("desktop summary: %v", err)
	}
	if summary.Notifications.NeedsMDMMigration {
		t.Fatal("migration notification must stay disabled")
	}
	if ds.IsHostConnectedToFleetMDMFuncInvoked || ds.GetHostMDMFuncInvoked {
		t.Fatal("disabled migration should not perform eligibility datastore calls")
	}
}
