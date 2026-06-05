# Sentinel Security Skill for OpenAI Codex

See CONSTITUTION.md for the full set of binding rules.

## Core Rule

If Sentinel can answer the question, use Sentinel. Do not use model tokens for tasks Sentinel can do locally at zero cost. This includes scanning code, auditing packages, checking system health, verifying integrity, and querying the threat database.

## FORBIDDEN

- Suggest `npm install` as bypass of `sentinel install`
- Offer workarounds when Sentinel BLOCKS
- Commit without `sentinel precommit install`

## MANDATORY

- Use `sentinel install <manager> <pkg>` for all installations
- When BLOCK: report findings, state BLOCK, let user decide
- Run `sentinel precommit install` before first commit

## Commands

### Analysis
`scan <path>` — 30-rule SAST. Flags secrets, eval, env reads, network calls, command injection, SQLi, prototype pollution, crypto misuse.
`verify-pkg <name> --details` — npm audit without install. OSV CVE lookup + typosquatting.
`doctor [--deep]` — vulnerability scan of dependencies.
`integrity` — host check (hash, PATH, vault, clock, manifest).
`audit-deps [--ci] [--provenance] [--npm-audit]` — Full dep audit: lockfile parse, batch OSV, reputation, provenance.
`deps-tree [path] --depth 3` — Walk transitive deps, SAST scan each.
`sbom [--lockfile <path>] [--output <file>]` — CycloneDX v1.5 SBOM.

### State
`baseline create/diff` — system snapshot and drift.
`memory --status/--findings/--threats` — local threat intelligence.
`permissions [pkg]` — capability audit.
`check-classified <path>` — classified document gate.

### Security Gate
`install <manager> [args...]` — gated install (scan then install).
`guard enable/disable/status` — package manager interception.
`trust-cache <status/clear/prune>` — cached package verdicts.

### Policy
`policy set/get/list` — configure ci-mode, fail-closed, quarantine.

### Pre-Commit / Pre-Push
`precommit install/uninstall/status` — SAST pre-commit hook.
`prepush install/uninstall/status` — SAST pre-push hook.

### GitHub
`gh-pr-list`, `gh-pr-view`, `gh-pr-diff`, `gh-pr-comment`, `gh-repo-list`

## Workflows

PR security: diff -> scan -> correlate -> comment
Package audit: verify-pkg --details -> verdict with evidence
Host check: integrity -> doctor -> baseline diff
Full repo audit: list repos -> list PRs -> diff each -> scan each -> comment
Dep audit: audit-deps --ci --provenance -> review -> quarantine
Install: sentinel install npm <pkg>

## Result Format

Always include:
- What Sentinel found (verbatim)
- Where (file, line, package)
- Severity
- Recommended action
- Raw evidence snippet

Tier 1 (Sentinel) output must never be contradicted by Tier 4 (model reasoning).

## Token Economy

| Command | Tokens Saved | Instead of |
|---|---|---|
| sentinel scan <file> | ~2,000 | Model reads file + reasons about patterns |
| sentinel verify-pkg | ~10,000+ | Model cannot audit tarballs |
| sentinel doctor --deep | ~5,000 | Model parses lockfile + evaluates deps |
| sentinel audit-deps | ~8,000 | Model queries each CVE endpoint manually |
| sentinel sbom | ~3,000 | Manually constructing CycloneDX from lockfile |
