# Changelog

## v4.3.1

- Added a live terminal progress map for pull-request scans in Sentinel CLI.
- Fixed Sentinel Cloud mode to scan the full PR through Cloud Pulses, pinned to the GitHub head SHA; the API key is sent only to Sentinel Cloud.
- Kept Sentinel Lite as an independent local option that analyzes the PR diff without using Cloud Pulses.

## v4.3.0

- Added `sntnl hardening` with agile, strict, and CI preference profiles, independently configurable toggles, and an informational local audit of package scripts, `.npmrc`, and lockfile signals.
- Added the `sentinel-hardening` agent skill and detailed safety/coverage documentation.
- Added pnpm lockfile auto-detection to `audit-deps`, using the existing pnpm/Yarn Berry parser.
- Updated the PR audit action to build and use the CLI from the checked-out source.

## v4.2.0

- Added the `sentinel-cicd-guard` and `sentinel-disclosure-dossier` agent skills.
- Clarified that CLI scans run when invoked and may be scheduled through user-configured CI; installing the CLI does not create a persistent watcher.
- Aligned package manifest and lockfile identity/version with the published `sntnl-cli` package.
