package servicecompat

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
)

func TestCommunityPlusOverridesAreCompleteAndPreserveHostFeatures(t *testing.T) {
	ds := new(mock.Store)
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{
			Features: fleet.Features{EnableSoftwareInventory: true},
		}, nil
	}

	overrides := newCommunityPlusOverrides(nil, ds)

	value := reflect.ValueOf(overrides)
	typeOf := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Func && field.IsNil() {
			t.Fatalf("override callback %s must never be nil", typeOf.Field(i).Name)
		}
	}

	features, err := overrides.HostFeatures(context.Background(), &fleet.Host{})
	if err != nil {
		t.Fatalf("host features: %v", err)
	}
	if features == nil || !features.EnableSoftwareInventory {
		t.Fatalf("expected Community host features from AppConfig, got %#v", features)
	}

	if _, err := overrides.SetupExperienceNextStep(context.Background(), &fleet.Host{}); !errors.Is(err, fleet.ErrMissingLicense) {
		t.Fatalf("unsupported override should return ErrMissingLicense, got %v", err)
	}
}
