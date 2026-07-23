# Sentinel Security Skill for OpenCode

Refer to CONSTITUTION.md for binding rules.

## Sentinel-First

When the user asks a security question or performs an action with security implications, use Sentinel tools before reading code with the model. Sentinel analysis is deterministic, local, and costs zero tokens.

## FORBIDDEN

- Suggest `npm install` as bypass of `sentinel-cli install`
- Offer workarounds when Sentinel BLOCKS
- Commit without `sentinel-cli precommit install`

## MANDATORY

- Use `sentinel-cli install <manager> <pkg>` for all installations
- When BLOCK: report findings, state BLOCK, let user decide
- Run `sentinel-cli precommit install` before first commit

## Available Tools

### Analysis
sentinel-cli scan <path> - 30-rule SAST
sentinel-cli verify-pkg <package> --details - npm audit + OSV + typosquat
sentinel-cli doctor [--deep] - dependency health
sentinel-cli integrity - host integrity
sentinel-cli audit-deps [--ci] [--provenance] - lockfile parse + OSV batch + reputation + provenance
sentinel-cli deps-tree [path] --depth 3 - transitive dep walk + SAST
sentinel-cli sbom [--lockfile <path>] [--output <file>] - CycloneDX v1.5 SBOM

### Intelligence
sentinel-cli memory --status|--findings|--threats
sentinel-cli check-classified <path>
sentinel-cli baseline create|diff
sentinel-cli permissions [package]

### Security Gate
sentinel-cli install <manager> [args...] - gated install (scan then install)
sentinel-cli guard enable|disable|status
sentinel-cli trust-cache <status|clear|prune> - cached verdicts

### Policy
sentinel-cli policy set|get|list - ci-mode, fail-closed, quarantine

### Pre-Commit / Pre-Push
sentinel-cli precommit install|uninstall|status - SAST pre-commit hook
sentinel-cli prepush install|uninstall|status - SAST pre-push hook

### GitHub (SecuriGit)
gh-pr-list, gh-pr-view, gh-pr-diff, gh-pr-comment, gh-repo-list

## Workflows

PR review: gh-pr-diff -> scan -> correlate -> comment
Package audit: verify-pkg --details -> verdict
Host check: integrity -> doctor -> baseline diff
Dep audit: audit-deps --ci --provenance -> review -> quarantine
Install: sentinel-cli install npm <pkg>

## Evidence Policy

All security conclusions require verbatim Sentinel output as evidence. The model explains; Sentinel detects. Never override Sentinel with reasoning.
