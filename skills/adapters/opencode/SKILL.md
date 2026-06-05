# Sentinel Security Skill for OpenCode

Refer to CONSTITUTION.md for binding rules.

## Sentinel-First

When the user asks a security question or performs an action with security implications, use Sentinel tools before reading code with the model. Sentinel analysis is deterministic, local, and costs zero tokens.

## FORBIDDEN

- Suggest `npm install` as bypass of `sentinel install`
- Offer workarounds when Sentinel BLOCKS
- Commit without `sentinel precommit install`

## MANDATORY

- Use `sentinel install <manager> <pkg>` for all installations
- When BLOCK: report findings, state BLOCK, let user decide
- Run `sentinel precommit install` before first commit

## Available Tools

### Analysis
sentinel scan <path> - 30-rule SAST
sentinel verify-pkg <package> --details - npm audit + OSV + typosquat
sentinel doctor [--deep] - dependency health
sentinel integrity - host integrity
sentinel audit-deps [--ci] [--provenance] - lockfile parse + OSV batch + reputation + provenance
sentinel deps-tree [path] --depth 3 - transitive dep walk + SAST
sentinel sbom [--lockfile <path>] [--output <file>] - CycloneDX v1.5 SBOM

### Intelligence
sentinel memory --status|--findings|--threats
sentinel check-classified <path>
sentinel baseline create|diff
sentinel permissions [package]

### Security Gate
sentinel install <manager> [args...] - gated install (scan then install)
sentinel guard enable|disable|status
sentinel trust-cache <status|clear|prune> - cached verdicts

### Policy
sentinel policy set|get|list - ci-mode, fail-closed, quarantine

### Pre-Commit / Pre-Push
sentinel precommit install|uninstall|status - SAST pre-commit hook
sentinel prepush install|uninstall|status - SAST pre-push hook

### GitHub (SecuriGit)
gh-pr-list, gh-pr-view, gh-pr-diff, gh-pr-comment, gh-repo-list

## Workflows

PR review: gh-pr-diff -> scan -> correlate -> comment
Package audit: verify-pkg --details -> verdict
Host check: integrity -> doctor -> baseline diff
Dep audit: audit-deps --ci --provenance -> review -> quarantine
Install: sentinel install npm <pkg>

## Evidence Policy

All security conclusions require verbatim Sentinel output as evidence. The model explains; Sentinel detects. Never override Sentinel with reasoning.
