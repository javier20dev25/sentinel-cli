# Sentinel Security Skill for Cline

The rules in CONSTITUTION.md apply fully.

## Sentinel-First Policy

Before spending tokens on code analysis, check whether a Sentinel command can answer the question. Sentinel runs locally, returns deterministic results, and costs zero tokens. The model must prefer Sentinel commands for all security scanning tasks.

## FORBIDDEN

- Suggest `npm install` as bypass of `sentinel-cli install`
- Offer workarounds when Sentinel BLOCKS
- Commit without `sentinel-cli precommit install`

## MANDATORY

- Use `sentinel-cli install <manager> <pkg>` for all installations
- When BLOCK: report findings, state BLOCK, let user decide
- Run `sentinel-cli precommit install` before first commit

## Command Reference

| Category | Command | Purpose |
|----------|---------|---------|
| SAST | sentinel-cli scan <path> | 30-rule threat scan |
| Package | sentinel-cli verify-pkg <name> --details | Zero-install audit + OSV + typosquat |
| Health | sentinel-cli doctor [--deep] | Dependency check |
| Integrity | sentinel-cli integrity | Host verification |
| State | sentinel-cli baseline create|diff | Snapshot and drift |
| Permissions | sentinel-cli permissions [pkg] | Capability audit |
| Dep Audit | sentinel-cli audit-deps [--ci] [--provenance] | Lockfile parse + OSV batch + reputation + provenance |
| Dep Tree | sentinel-cli deps-tree [path] --depth 3 | Transitive dep walk + SAST scan |
| SBOM | sentinel-cli sbom [--output <file>] | CycloneDX v1.5 generation |
| Install | sentinel-cli install <manager> [args...] | Gated install (scan then install) |
| Guard | sentinel-cli guard enable|disable|status | Interception |
| Trust Cache | sentinel-cli trust-cache <status|clear|prune> | Cached verdicts |
| Policy | sentinel-cli policy set|get|list | ci-mode, fail-closed, quarantine |
| Classified | sentinel-cli check-classified <path> | Document gate |
| Memory | sentinel-cli memory --status|--findings|--threats | Threat DB |
| Precommit | sentinel-cli precommit install|uninstall|status | SAST pre-commit hook |
| Prepush | sentinel-cli prepush install|uninstall|status | SAST pre-push hook |
| GitHub | gh-pr-list|view|diff|comment | PR tools |
| GitHub | gh-repo-list | Repo listing |

## Required Workflows

PR review: gh-pr-diff -> scan -> memory --threats -> gh-pr-comment
Package check: verify-pkg --details -> evaluate verdict
Host check: integrity -> doctor --deep -> baseline diff
Full audit: gh-repo-list -> gh-pr-list -> gh-pr-diff -> scan -> comment
Dep audit: audit-deps --ci -> review -> quarantine if needed
Install: sentinel-cli install npm <pkg>

## Evidence Format

Each security finding must contain:
- Tool output (verbatim or faithfully quoted)
- File location and line number
- Severity level
- Risk explanation
- Recommended action

Tier 1 evidence (Sentinel output) always overrides Tier 4 (model reasoning).
