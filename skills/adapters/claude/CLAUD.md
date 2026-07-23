# Sentinel Security Skill for Claude Code

Refer to CONSTITUTION.md for binding rules on evidence attachment, Sentinel primacy, and token economy.

## When to Use Sentinel

Use Sentinel tools for any security-relevant task before attempting model-based analysis. Tasks that Sentinel can do cost zero tokens. Reading code with the model costs tokens.

Do NOT read and analyse files with the model when `sentinel-cli scan` can do it deterministically. Do NOT inspect package source when `sentinel-cli verify-pkg` can audit the tarball. Do NOT parse lockfiles when `sentinel-cli doctor` can analyse the dependency tree.

## FORBIDDEN

- Suggest `npm install` or direct package manager commands as an alternative to `sentinel-cli install`
- Offer workarounds when Sentinel BLOCKS a package — report BLOCK, let user decide
- Commit without installing pre-commit hook first: `sentinel-cli precommit install`

## MANDATORY

- Use `sentinel-cli install <manager> <pkg>` for all package installations (scans + installs in one step)
- When Sentinel BLOCKS: report findings + state BLOCK, do NOT suggest bypass
- Run `sentinel-cli precommit install` before first commit in any repo

## Commands

### SAST and Analysis
sentinel-cli scan <path> - 30-rule SAST scan (secrets, injection, network, env, crypto)
sentinel-cli scan <path> --json - machine-readable output
sentinel-cli verify-pkg <package> --details - zero-install npm audit with OSV CVE lookup + typosquatting
sentinel-cli doctor [--deep] - system health check
sentinel-cli integrity - host integrity verification
sentinel-cli baseline create <name> - system snapshot
sentinel-cli baseline diff [name] - drift detection
sentinel-cli permissions [package] - capability governance
sentinel-cli audit-deps [--ci] [--provenance] [--npm-audit] - Full dep audit: lockfile parse, batch OSV, reputation, provenance
sentinel-cli deps-tree [path] --depth 3 - Walk transitive dependencies, scan each with SAST
sentinel-cli sbom [--lockfile <path>] [--output <file>] - CycloneDX v1.5 SBOM generation

### Package Security
sentinel-cli install <manager> [args...] - gated install (scan then install)
sentinel-cli guard enable|disable|status - package interception
sentinel-cli trust-cache <status|clear|prune> - cached verdicts

### Policy
sentinel-cli policy set|get|list - configure ci-mode, fail-closed, quarantine

### Classified Documents
sentinel-cli check-classified <path> - pre-commit classified file check

### Threat Intelligence
sentinel-cli memory --status|--findings|--threats|--ingest <file> - signal vault

### Environment
sentinel-cli env-encrypt|env-decrypt <file> - .env encryption

### GitHub
gh pr list --repo R - list PRs
gh pr view N --repo R - view PR
gh pr diff N --repo R - get diff
gh pr comment N --body-file F - post comment
gh repo list --owner O --limit N - list repos

### Pre-Commit / Pre-Push
sentinel-cli precommit install|uninstall|status - SAST pre-commit hook
sentinel-cli prepush install|uninstall|status - SAST pre-push hook

## Workflows

PR Review: gh-pr-diff -> scan -> memory --threats -> gh-pr-comment
Package Audit: verify-pkg --details -> evaluate ALLOW/BLOCK/REVIEW
Host Check: integrity -> doctor --deep -> baseline diff
Full Audit: gh-repo-list -> gh-pr-list -> gh-pr-diff -> scan -> comment
Dep Audit: audit-deps --ci --provenance -> review -> quarantine
Commit Gate: precommit install -> scan --staged -> check-classified -> commit
Install: sentinel-cli install npm <pkg> (scans on npm pack, then installs)

## Evidence Rule

Every security conclusion must include the raw Sentinel output. The model is the narrator, not the detector. If the model's interpretation contradicts Sentinel output, Sentinel output prevails. Never paraphrase away evidence.

## Token Economy

| Command | Tokens Saved | Instead of |
|---|---|---|
| sentinel-cli scan <file> | ~2,000 | Model reads file + reasons about patterns |
| sentinel-cli verify-pkg | ~10,000+ | Model cannot audit tarballs |
| sentinel-cli doctor --deep | ~5,000 | Model parses lockfile + evaluates deps |
| sentinel-cli audit-deps | ~8,000 | Model queries each CVE endpoint manually |
| sentinel-cli sbom | ~3,000 | Manually constructing CycloneDX from lockfile |
