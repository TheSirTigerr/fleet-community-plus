# Fleet Community Plus

Fleet Community Plus is an independent extension project built on the MIT-licensed parts of Fleet.

## Goal

Provide independently implemented, self-hostable equivalents for Fleet Premium capabilities without using Fleet's restricted Enterprise Edition backend code.

## Licensing boundary

- Upstream Fleet files imported outside `ee/` keep their upstream licenses.
- The upstream `ee/` directory is intentionally excluded.
- Premium-equivalent functionality added here must be implemented independently from public documentation, public APIs, standards, and observed behavior that is lawful to reproduce.
- Do not copy restricted Fleet EE backend code into this repository.

## Bootstrap

A GitHub Actions workflow at `.github/workflows/bootstrap-fleet-community.yml` imports the current Fleet Community tree and removes the upstream `ee/` directory.

Because commits created by GitHub Apps/tokens do not necessarily trigger further workflow runs, the first bootstrap may need to be started manually from the repository's **Actions** tab using **Bootstrap Fleet Community base → Run workflow**.

## Development direction

See `docs/FEATURE_PARITY.md` for the implementation plan and `docs/CLEAN_ROOM.md` for the project boundary.
