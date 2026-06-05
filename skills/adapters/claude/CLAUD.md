# Sentinel Security Skill for Claude Code

Refer to CONSTITUTION.md for binding rules on evidence attachment, Sentinel primacy, and token economy.

## When to Use Sentinel

Use Sentinel tools for any security-relevant task before attempting model-based analysis. Tasks that Sentinel can do cost zero tokens. Reading code with the model costs tokens.

Do NOT read and analyse files with the model when `sentinel scan` can do it deterministically. Do NOT inspect package source when `sentinel verify-pkg` can audit the tarball. Do NOT parse lockfiles when `sentinel doctor` can analyse the dependency tree.

## FORBIDDEN

- Suggest `npm install` or direct package manager commands as an alternative to `sentinel install`
- Offer workarounds when Sentinel BLOCKS a package — report BLOCK, let user decide
- Commit without installing pre-commit hook first: `sentinel precommit install`

## MANDATORY

- Use `sentinel install <manager> <pkg>` for all package installations (scans + installs in one step)
- When Sentinel BLOCKS: report findings + state BLOCK, do NOT suggest bypass
- Run `sentinel precommit install` before first commit in any repo

## Commands

### SAST and Analysis
sentinel scan <path> - 30-rule SAST scan (secrets, injection, network, env, crypto)
sentinel scan <path> --json - machine-readable output
sentinel verify-pkg <package> --details - zero-install npm audit with OSV CVE lookup + typosquatting
sentinel doctor [--deep] - system health check
sentinel integrity - host integrity verification
sentinel baseline create <name> - system snapshot
sentinel baseline diff [name] - drift detection
sentinel permissions [package] - capability governance
sentinel audit-deps [--ci] [--provenance] [--npm-audit] - Full dep audit: lockfile parse, batch OSV, reputation, provenance
sentinel deps-tree [path] --depth 3 - Walk transitive dependencies, scan each with SAST
sentinel sbom [--lockfile <path>] [--output <file>] - CycloneDX v1.5 SBOM generation

### Package Security
sentinel install <manager> [args...] - gated install (scan then install)
sentinel guard enable|disable|status - package interception
sentinel trust-cache <status|clear|prune> - cached verdicts

### Policy
sentinel policy set|get|list - configure ci-mode, fail-closed, quarantine

### Classified Documents
sentinel check-classified <path> - pre-commit classified file check

### Threat Intelligence
sentinel memory --status|--findings|--threats|--ingest <file> - signal vault

### Environment
sentinel env-encrypt|env-decrypt <file> - .env encryption

### GitHub
gh pr list --repo R - list PRs
gh pr view N --repo R - view PR
gh pr diff N --repo R - get diff
gh pr comment N --body-file F - post comment
gh repo list --owner O --limit N - list repos

### Pre-Commit / Pre-Push
sentinel precommit install|uninstall|status - SAST pre-commit hook
sentinel prepush install|uninstall|status - SAST pre-push hook

## Workflows

PR Review: gh-pr-diff -> scan -> memory --threats -> gh-pr-comment
Package Audit: verify-pkg --details -> evaluate ALLOW/BLOCK/REVIEW
Host Check: integrity -> doctor --deep -> baseline diff
Full Audit: gh-repo-list -> gh-pr-list -> gh-pr-diff -> scan -> comment
Dep Audit: audit-deps --ci --provenance -> review -> quarantine
Commit Gate: precommit install -> scan --staged -> check-classified -> commit
Install: sentinel install npm <pkg> (scans on npm pack, then installs)

## Evidence Rule

Every security conclusion must include the raw Sentinel output. The model is the narrator, not the detector. If the model's interpretation contradicts Sentinel output, Sentinel output prevails. Never paraphrase away evidence.

## Token Economy

| Command | Tokens Saved | Instead of |
|---|---|---|
| sentinel scan <file> | ~2,000 | Model reads file + reasons about patterns |
| sentinel verify-pkg | ~10,000+ | Model cannot audit tarballs |
| sentinel doctor --deep | ~5,000 | Model parses lockfile + evaluates deps |
| sentinel audit-deps | ~8,000 | Model queries each CVE endpoint manually |
| sentinel sbom | ~3,000 | Manually constructing CycloneDX from lockfile |
