package communityplus

import "testing"

func TestComparePatchVersions(t *testing.T) {
	tests := []struct {
		current   string
		candidate string
		want      int
		ok        bool
	}{
		{"1.2.3", "1.2.4", -1, true},
		{"1.2", "1.2.0", 0, true},
		{"2.0", "1.99", 1, true},
		{"v1.02.003", "1.2.4", -1, true},
		{"1.2-beta", "1.3", 0, false},
		{"1.2", "1.3+vendor", 0, false},
	}
	for _, tt := range tests {
		got, ok := comparePatchVersions(tt.current, tt.candidate)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("comparePatchVersions(%q, %q) = (%d, %v), want (%d, %v)", tt.current, tt.candidate, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSafePatchUpgradeRejectsDowngradeAndInstallerSwitch(t *testing.T) {
	current := CatalogEntry{Provider: CatalogProviderWinget, PackageIdentifier: "Vendor.App", Version: "1.2.3", InstallerType: "msi"}
	candidate := current
	candidate.Version = "1.2.4"
	if !safePatchUpgrade(current, candidate) {
		t.Fatal("expected newer compatible version to be accepted")
	}
	candidate.Version = "1.2.2"
	if safePatchUpgrade(current, candidate) {
		t.Fatal("downgrade must be rejected")
	}
	candidate.Version = "1.2.4"
	candidate.InstallerType = "msix"
	if safePatchUpgrade(current, candidate) {
		t.Fatal("installer type switch must be rejected")
	}
}
