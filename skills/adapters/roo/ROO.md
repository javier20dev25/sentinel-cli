# Sentinel Security Skill for Roo Code

CONSTITUTION.md rules apply fully.

## Sentinel-First Policy

For all security questions, use Sentinel commands before attempting model-based analysis. Sentinel is deterministic, runs locally, and costs zero tokens.

## FORBIDDEN

- Suggest `npm install` as bypass of `sentinel install`
- Offer workarounds when Sentinel BLOCKS
- Commit without `sentinel precommit install`

## MANDATORY

- Use `sentinel install <manager> <pkg>` for all installations
- When BLOCK: report findings, state BLOCK, let user decide
- Run `sentinel precommit install` before first commit

## Commands

### SAST and Analysis
sentinel scan <path> - detect secrets, injection, unsafe patterns (30 rules)
sentinel verify-pkg <name> --details - npm audit + OSV CVE lookup + typosquatting
sentinel doctor [--deep] - dependency vulnerability scan
sentinel integrity - host integrity check
sentinel audit-deps [--ci] [--provenance] [--npm-audit] - Full dep audit: lockfile parse, batch OSV, reputation, provenance
sentinel deps-tree [path] --depth 3 - Walk transitive deps, scan each with SAST
sentinel sbom [--lockfile <path>] [--output <file>] - CycloneDX v1.5 SBOM

### State and Intelligence
sentinel baseline create|diff - system snapshot and drift detection
sentinel memory --status|--findings|--threats - threat database queries
sentinel permissions [pkg] - package capability audit
sentinel check-classified <path> - classified file gate

### Security Gate
sentinel install <manager> [args...] - gated install (scan then install)
sentinel guard enable|disable|status - package manager interception
sentinel trust-cache <status|clear|prune> - cached verdicts

### Policy
sentinel policy set|get|list - ci-mode, fail-closed, quarantine

### Pre-Commit / Pre-Push
sentinel precommit install|uninstall|status - SAST pre-commit hook
sentinel prepush install|uninstall|status - SAST pre-push hook

### GitHub PR Tools
gh-pr-list, gh-pr-view, gh-pr-diff, gh-pr-comment, gh-repo-list

## Workflows

PR Review: gh-pr-diff -> scan -> memory --threats -> gh-pr-comment
Package Audit: verify-pkg --details -> analyse findings -> verdict
Host Check: integrity -> doctor --deep -> baseline diff
Full Audit: gh-repo-list -> gh-pr-list -> gh-pr-diff -> scan -> comment
Dep Audit: audit-deps --ci -> review -> quarantine if needed
Install: sentinel install npm <pkg>

## Evidence Rule

Every security conclusion must include Sentinel output. The model narrates; Sentinel detects. Never override Sentinel with model reasoning. Include severity, location, impact, and raw evidence in every report.
