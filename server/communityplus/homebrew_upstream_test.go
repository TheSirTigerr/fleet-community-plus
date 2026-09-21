package communityplus

import (
	"encoding/json"
	"testing"
)

const testSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestHomebrewDirectPKG(t *testing.T) {
	base := homebrewCask{
		Token:     "example",
		Name:      []string{"Example"},
		Version:   "1.2.3",
		URL:       "https://example.invalid/example.pkg",
		SHA256:    testSHA256,
		Artifacts: []map[string]json.RawMessage{{"pkg": json.RawMessage(`"Example.pkg"`)}},
	}
	if !homebrewDirectPKG(base) {
		t.Fatal("expected architecture-neutral direct PKG cask to be deployable")
	}

	cases := []struct {
		name   string
		mutate func(*homebrewCask)
	}{
		{"no-check hash", func(c *homebrewCask) { c.SHA256 = "no_check" }},
		{"disabled", func(c *homebrewCask) { c.Disabled = true }},
		{"deprecated", func(c *homebrewCask) { c.Deprecated = true }},
		{"variation", func(c *homebrewCask) {
			c.Variations = map[string]json.RawMessage{"arm64_sonoma": json.RawMessage(`{}`)}
		}},
		{"dmg url", func(c *homebrewCask) { c.URL = "https://example.invalid/example.dmg" }},
		{"non https", func(c *homebrewCask) { c.URL = "http://example.invalid/example.pkg" }},
		{"no pkg artifact", func(c *homebrewCask) {
			c.Artifacts = []map[string]json.RawMessage{{"app": json.RawMessage(`"Example.app"`)}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			candidate.Name = append([]string(nil), base.Name...)
			candidate.Artifacts = append([]map[string]json.RawMessage(nil), base.Artifacts...)
			tc.mutate(&candidate)
			if homebrewDirectPKG(candidate) {
				t.Fatalf("expected %s cask to be rejected", tc.name)
			}
		})
	}
}

func TestHomebrewDisplayNameFallsBackToToken(t *testing.T) {
	if got := homebrewDisplayName(homebrewCask{Token: "example"}); got != "example" {
		t.Fatalf("display name = %q, want example", got)
	}
}

func TestHomebrewCatalogEntryIDIsStable(t *testing.T) {
	a := homebrewCatalogEntryID("Example", "1.2.3", testSHA256)
	b := homebrewCatalogEntryID("example", "1.2.3", testSHA256)
	if a != b {
		t.Fatalf("catalog entry IDs should be case-insensitive: %q != %q", a, b)
	}
	if a == homebrewCatalogEntryID("example", "1.2.4", testSHA256) {
		t.Fatal("version must contribute to catalog entry ID")
	}
}
