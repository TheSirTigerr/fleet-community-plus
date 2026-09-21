package communityplus

import (
	"strings"
	"testing"
	"time"
)

func TestWindowsInstallPlanIsPinnedAndIdempotent(t *testing.T) {
	entry := validCatalogEntry()
	deployment := Deployment{ID: "deployment-1", CatalogEntryID: entry.ID, Scope: FleetScope(7), Automatic: true, CreatedAt: time.Now().UTC(), CreatedBy: "admin"}
	plan, err := NewWindowsInstallPlan(deployment, entry)
	if err != nil { t.Fatal(err) }
	script, err := plan.PowerShell()
	if err != nil { t.Fatal(err) }
	for _, expected := range []string{"Get-FileHash", "Installer SHA-256 mismatch", "DisplayVersion", "msiexec.exe", entry.InstallerSHA256} {
		if !strings.Contains(script, expected) { t.Fatalf("script missing %q: %s", expected, script) }
	}
}
