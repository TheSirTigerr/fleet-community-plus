# Community+ maintained-app catalog

This directory contains a self-managed software catalog. It does not download
or reuse Fleet's hosted maintained-app catalog.

Create one JSON file per app below either `inputs/winget` or `inputs/homebrew`.
The importer accepts a single app object or an object with an `apps` array.

```json
{
  "slug": "microsoft-windows-terminal/windows",
  "name": "Windows Terminal",
  "version": "1.22.10352.0",
  "installer_url": "https://downloads.example.invalid/WindowsTerminal.msi",
  "sha256": "64-character-lowercase-sha256-of-the-installer",
  "install_script": "msiexec /i $INSTALLER_PATH /qn /norestart",
  "uninstall_script": "msiexec /x {PRODUCT-CODE} /qn /norestart",
  "queries": {
    "exists": "SELECT 1 FROM programs WHERE name = 'Windows Terminal';",
    "patched": "SELECT 1 FROM programs WHERE name = 'Windows Terminal' AND version >= '1.22.10352.0';"
  },
  "default_categories": ["Developer tools"],
  "unique_identifier": "Windows Terminal"
}
```

Run `go run ./cmd/maintained-apps` from the repository root to create the
files under `outputs/`. Use `--check` in CI or before publishing; it validates
all entries without creating or changing files. `--input-root`, `--output-dir`
and `--slug` make the same generator usable from a release pipeline.

Publish the generated directory over HTTPS and configure Fleet with
`FLEET_COMMUNITYPLUS_MAINTAINED_APPS_BASE_URL`. An optional second URL can be
configured with `FLEET_COMMUNITYPLUS_MAINTAINED_APPS_FALLBACK_BASE_URL`.
Without the primary variable Fleet refuses the catalog sync instead of silently
using a third-party catalog.

The importer rejects non-HTTPS installer URLs, missing SHA-256 hashes, missing
scripts, and malformed platform slugs. Review catalog changes like code: they
define commands that run on managed endpoints.
