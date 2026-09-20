package maintainedapps

import (
	"encoding/json"
	"testing"
)

func TestManifestJSONAndPlatform(t *testing.T) {
	input := []byte(`{
		"refs":{"install":"echo install"},
		"versions":[{
			"version":"1.2.3",
			"installer_url":"https://example.test/app.pkg",
			"sha256":"abc",
			"install_script_ref":"install",
			"uninstall_script_ref":"uninstall",
			"queries":{"exists":"select 1","patched":"select 2","open":"select 3"},
			"default_categories":["Productivity"],
			"upgrade_code":"code"
		}]
	}`)
	var manifest ManifestFile
	if err := json.Unmarshal(input, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Versions) != 1 || manifest.Versions[0].Queries.Open != "select 3" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	manifest.Versions[0].Slug = "example/darwin"
	if got := manifest.Versions[0].Platform(); got != "darwin" {
		t.Fatalf("platform=%q", got)
	}
	manifest.Versions[0].Slug = "example/../../secret"
	if got := manifest.Versions[0].Platform(); got != "" {
		t.Fatalf("unsafe platform=%q", got)
	}
}
