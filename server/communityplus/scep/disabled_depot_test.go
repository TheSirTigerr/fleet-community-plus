package scep

import (
	"errors"
	"testing"
)

func TestDisabledDepotFailsClosed(t *testing.T) {
	d := DisabledDepot{}
	if _, _, err := d.CA(nil); !errors.Is(err, ErrFeatureUnavailable) {
		t.Fatalf("CA error = %v", err)
	}
	if _, err := d.Serial(); !errors.Is(err, ErrFeatureUnavailable) {
		t.Fatalf("Serial error = %v", err)
	}
	if ok, err := d.HasCN("host", 0, nil, false); ok || !errors.Is(err, ErrFeatureUnavailable) {
		t.Fatalf("HasCN = %v, %v", ok, err)
	}
}
