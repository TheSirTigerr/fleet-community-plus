package service

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/fleetdm/fleet/v4/server/dev_mode"
	"github.com/fleetdm/fleet/v4/server/mdm/android/service/androidmgmt"
)

func TestCommunityPlusAMAPIClientSelection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	t.Run("production credentials select direct Google client", func(t *testing.T) {
		env := map[string]string{
			communityPlusAndroidGoogleCredentialsEnv: `{"project_id":"community-plus-project"}`,
			"FLEET_DEV_ANDROID_GOOGLE_CLIENT":        "OFF",
		}
		getEnv := dev_mode.GetEnv(func(name string) string { return env[name] })
		selected := ""
		google := func(_ context.Context, _ *slog.Logger, mappedEnv dev_mode.GetEnv) androidmgmt.Client {
			selected = "google"
			if got := mappedEnv("FLEET_DEV_ANDROID_GOOGLE_SERVICE_CREDENTIALS"); got != env[communityPlusAndroidGoogleCredentialsEnv] {
				t.Fatalf("mapped credentials = %q, want production credentials", got)
			}
			return nil
		}
		proxy := func(context.Context, *slog.Logger, string, dev_mode.GetEnv) androidmgmt.Client {
			selected = "proxy"
			return nil
		}

		_ = selectAMAPIClient(ctx, logger, "license", getEnv, google, proxy)
		if selected != "google" {
			t.Fatalf("selected %q, want google", selected)
		}
	})

	t.Run("legacy dev direct client remains supported", func(t *testing.T) {
		env := map[string]string{"FLEET_DEV_ANDROID_GOOGLE_CLIENT": "ON"}
		getEnv := dev_mode.GetEnv(func(name string) string { return env[name] })
		selected := ""
		google := func(context.Context, *slog.Logger, dev_mode.GetEnv) androidmgmt.Client {
			selected = "google"
			return nil
		}
		proxy := func(context.Context, *slog.Logger, string, dev_mode.GetEnv) androidmgmt.Client {
			selected = "proxy"
			return nil
		}

		_ = selectAMAPIClient(ctx, logger, "license", getEnv, google, proxy)
		if selected != "google" {
			t.Fatalf("selected %q, want google", selected)
		}
	})

	t.Run("proxy remains fallback", func(t *testing.T) {
		getEnv := dev_mode.GetEnv(func(string) string { return "" })
		selected := ""
		google := func(context.Context, *slog.Logger, dev_mode.GetEnv) androidmgmt.Client {
			selected = "google"
			return nil
		}
		proxy := func(_ context.Context, _ *slog.Logger, licenseKey string, _ dev_mode.GetEnv) androidmgmt.Client {
			selected = "proxy"
			if licenseKey != "license" {
				t.Fatalf("license key = %q, want license", licenseKey)
			}
			return nil
		}

		_ = selectAMAPIClient(ctx, logger, "license", getEnv, google, proxy)
		if selected != "proxy" {
			t.Fatalf("selected %q, want proxy", selected)
		}
	})
}
