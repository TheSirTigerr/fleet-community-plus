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

## Public-source adapters

For WinGet, place a downloaded public installer manifest beside a reviewed
Community+ sidecar. The names must match:

```
inputs/winget/example.winget.yaml
inputs/winget/example.winget.json
```

The YAML provides `PackageVersion`, `InstallerUrl`, `InstallerSha256`, and
optionally `ProductCode`. The JSON sidecar contains `slug`, scripts, queries,
categories, and other local policy choices. Its `version`, `installer_url`,
and `sha256` fields are ignored and replaced with the values from the YAML.

For Homebrew, use the same approach with a Cask and sidecar:

```
inputs/homebrew/example.cask.rb
inputs/homebrew/example.cask.json
```

Only Casks with literal `name`, `version`, `sha256`, and HTTPS `url` values
are accepted. `#{version}` in the URL is supported; other Ruby interpolation,
dynamic URLs, and `sha256 :no_check` are rejected. This prevents a catalog
update from publishing an installer whose integrity cannot be verified.

### Automated source refresh

To download a source file reproducibly, add a declaration next to its sidecar:

```json
{
  "url": "https://raw.githubusercontent.com/<owner>/<repo>/<commit>/<path>",
  "sha256": "sha256-of-the-exact-downloaded-source-file"
}
```

Name it `example.winget.source.json` or `example.cask.source.json`, then run
`go run ./cmd/maintained-apps --fetch-sources`. It only permits HTTPS downloads
from `raw.githubusercontent.com`, refuses redirects, limits each file to 2 MiB,
and writes a downloaded file only after its SHA-256 matches. Use immutable
commit URLs and review updates to the declaration, source file, and generated
catalog together.

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
