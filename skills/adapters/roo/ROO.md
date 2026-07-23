# Sentinel Security Skill for Roo Code

CONSTITUTION.md rules apply fully.

## Sentinel-First Policy

For all security questions, use Sentinel commands before attempting model-based analysis. Sentinel is deterministic, runs locally, and costs zero tokens.

## FORBIDDEN

- Suggest `npm install` as bypass of `sentinel-cli install`
- Offer workarounds when Sentinel BLOCKS
- Commit without `sentinel-cli precommit install`

## MANDATORY

- Use `sentinel-cli install <manager> <pkg>` for all installations
- When BLOCK: report findings, state BLOCK, let user decide
- Run `sentinel-cli precommit install` before first commit

## Commands

### SAST and Analysis
sentinel-cli scan <path> - detect secrets, injection, unsafe patterns (30 rules)
sentinel-cli verify-pkg <name> --details - npm audit + OSV CVE lookup + typosquatting
sentinel-cli doctor [--deep] - dependency vulnerability scan
sentinel-cli integrity - host integrity check
sentinel-cli audit-deps [--ci] [--provenance] [--npm-audit] - Full dep audit: lockfile parse, batch OSV, reputation, provenance
sentinel-cli deps-tree [path] --depth 3 - Walk transitive deps, scan each with SAST
sentinel-cli sbom [--lockfile <path>] [--output <file>] - CycloneDX v1.5 SBOM

### State and Intelligence
sentinel-cli baseline create|diff - system snapshot and drift detection
sentinel-cli memory --status|--findings|--threats - threat database queries
sentinel-cli permissions [pkg] - package capability audit
sentinel-cli check-classified <path> - classified file gate

### Security Gate
sentinel-cli install <manager> [args...] - gated install (scan then install)
sentinel-cli guard enable|disable|status - package manager interception
sentinel-cli trust-cache <status|clear|prune> - cached verdicts

### Policy
sentinel-cli policy set|get|list - ci-mode, fail-closed, quarantine

### Pre-Commit / Pre-Push
sentinel-cli precommit install|uninstall|status - SAST pre-commit hook
sentinel-cli prepush install|uninstall|status - SAST pre-push hook

### GitHub PR Tools
gh-pr-list, gh-pr-view, gh-pr-diff, gh-pr-comment, gh-repo-list

## Workflows

PR Review: gh-pr-diff -> scan -> memory --threats -> gh-pr-comment
Package Audit: verify-pkg --details -> analyse findings -> verdict
Host Check: integrity -> doctor --deep -> baseline diff
Full Audit: gh-repo-list -> gh-pr-list -> gh-pr-diff -> scan -> comment
Dep Audit: audit-deps --ci -> review -> quarantine if needed
Install: sentinel-cli install npm <pkg>

## Evidence Rule

Every security conclusion must include Sentinel output. The model narrates; Sentinel detects. Never override Sentinel with model reasoning. Include severity, location, impact, and raw evidence in every report.
