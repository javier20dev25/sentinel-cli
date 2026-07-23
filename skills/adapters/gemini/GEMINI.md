# Sentinel Security Skill for Gemini CLI

Constitution reference: CONSTITUTION.md (binding rules on evidence, primacy, trust tiers)
Mandatory: check sentinel-cli --help before reading code or writing scripts.

## Sentinel-First Rule

Before reading any file for security analysis, check if a Sentinel command can do it. Every local Sentinel command costs zero tokens. The model should not spend tokens on analysis that Sentinel can produce deterministically.

## FORBIDDEN

- Read source code directly to look for security issues — use `sentinel-cli scan` instead
- Write duplicate security scripts — Sentinel already has the tool
- Analyze diffs manually — use `sentinel-cli scan`, `sentinel-cli pr-audit`, or `sentinel-cli workflow`
- Call `npm install`, `pip install`, or any package manager directly without going through `sentinel-cli install <manager> <pkg>`
- Suggest `npm install` or any direct package manager command as an alternative to `sentinel-cli install`. The agent MUST NOT bypass Sentinel's gate.
- When Sentinel BLOCKS a package, suggest bypassing or workarounds. Report BLOCK as BLOCK. The user decides the exception, not the agent.
- Commit code without first installing the pre-commit hook: `sentinel-cli precommit install`
- Run `npm update` or `npm outdated` without first running `sentinel-cli verify-pkg` on each updated package

## MANDATORY

1. Always start with `sentinel-cli --help` to discover available commands before reading code or writing analysis scripts
2. Use `sentinel-cli scan <path>` instead of reading files to find security issues
3. Use `sentinel-cli workflow full-audit --repo <owner/repo>` for full repo PR auditing
4. Use `sentinel-cli pr-audit --repo <owner/repo> --pr <number>` for single PR auditing
5. Use `sentinel-cli verify-pkg <package> --details` for npm package auditing
6. Use `sentinel-cli doctor [--deep]` for system dependency health checks
7. Use `sentinel-cli integrity` for host integrity verification
8. Use `sentinel-cli memory --status|--findings|--threats` for threat intelligence
9. Use `sentinel-cli check-classified <path>` for classified document checking
10. Use `sentinel-cli guard enable|disable|status` for package interception management
11. Use `sentinel-cli permissions <package>` for capability auditing
12. When user wants to install a package: use `sentinel-cli install <manager> <pkg>`. Do NOT use `npm install` directly. Do NOT scan the package separately and then suggest `npm install` — use `sentinel-cli install` which does both in one step.
13. When Sentinel BLOCKS a package: report the findings and state the BLOCK. Do NOT suggest bypassing, do NOT suggest `npm install` as an alternative. Let the user decide exceptions.
14. Before first commit in any repo: run `sentinel-cli precommit install` to install the SAST pre-commit hook
15. Before updating packages: run `sentinel-cli verify-pkg <pkg>` first to check for threats

## Intent Map — Activation Triggers

| Trigger Keywords | Sentinel Action |
|---|---|
| install, add, package | `sentinel-cli install npm <pkg>` |
| hack, malware, threat, peligroso, inseguro | `sentinel-cli scan <path>` |
| audit, analiza, revisa, PR, pull request | `sentinel-cli pr-audit --repo R --pr N` or `sentinel-cli workflow full-audit` |
| commit, precommit, pre-commit | `sentinel-cli precommit install`, `sentinel-cli scan --staged` |
| push, prepush, pre-push | `sentinel-cli prepush install` |
| verify, trust, confianza | `sentinel-cli verify-pkg <pkg>` |
| health, status, integridad | `sentinel-cli doctor --deep`, `sentinel-cli integrity` |
| secrets, token, password, key | `sentinel-cli scan <path>`, `sentinel-cli verify-pkg <pkg>` |
| memory, signal, threat, historial | `sentinel-cli memory --threats` |
| intercept, guard, bloqueo | `sentinel-cli guard status`, `sentinel-cli guard enable` |
| MCP, tool, integrate | `sentinel-cli mcp` |
| help, menu, info | `sentinel-cli --help`, `sentinel-cli hub` |
| all dependencies, lockfile, sbom | `sentinel-cli audit-deps`, `sentinel-cli sbom` |
| transitive, nested deps, tree | `sentinel-cli deps-tree <path>` |
| cache, trust, whitelist | `sentinel-cli trust-cache status` |
| policy, ci-mode, fail-closed | `sentinel-cli policy set|get|list` |

## Available Commands

### SAST and Analysis
sentinel-cli scan <path> - SAST with 30 rules (secrets, eval, env access, network, injection)
sentinel-cli verify-pkg <package> --details - npm package audit (zero-install, SAST on tarball, OSV CVE lookup, typosquatting)
sentinel-cli doctor [--deep] - system health + dependency vulnerability check
sentinel-cli integrity - host integrity (code hash, PATH, vault, clock, manifest)
sentinel-cli baseline create|diff - snapshot + drift detection
sentinel-cli permissions [package] - capability audit for packages
sentinel-cli audit-deps - Comprehensive dependency audit: parses lockfile, batch OSV CVE lookup, registry reputation scoring, npm provenance verification (--provenance, --quarantine, --json, --ci, --npm-audit)
sentinel-cli deps-tree [path] --depth 3 - Walk transitive dependencies from node_modules, scan each with SAST
sentinel-cli sbom [--lockfile <path>] [--output <file>] - Generate CycloneDX v1.5 SBOM from lockfile

### Pre-Commit / Pre-Push Hooks
sentinel-cli precommit install|uninstall|status - SAST pre-commit hook
sentinel-cli prepush install|uninstall|status - SAST pre-push hook

### Classified Documents
sentinel-cli check-classified <path> - pre-commit classified file check
sentinel-cli classify - manage classified document database

### Package Security
sentinel-cli install <manager> [args...] - scan then install (npm, pip, yarn, pnpm, cargo, docker)
sentinel-cli guard enable|disable|status - OS-level package interception (3-layer: PATH wrapper + alias)
sentinel-cli trust-cache <status|clear|prune> - Manage cached package analysis results

### Policy Management
sentinel-cli policy set <key> <value> - Configure ci-mode, fail-closed, quarantine policies
sentinel-cli policy get <key> - Show a specific policy value
sentinel-cli policy list - Show all configured policies

### Threat Intelligence
sentinel-cli memory --status|--findings|--threats|--ingest|--wipe - Signal Vault queries

### GitHub (SecuriGit PR tools)
gh-pr-list, gh-pr-view, gh-pr-diff, gh-pr-comment, gh-repo-list

### Workflows
sentinel-cli workflow full-audit --repo R - complete multi-repo audit
sentinel-cli workflow pr-review --repo R --pr N - single PR pipeline
sentinel-cli workflow package-audit --pkg P - zero-install audit
sentinel-cli workflow host-integrity - full host check

### Environment
sentinel-cli env-encrypt <file> - AES-256-CBC .env encryption
sentinel-cli env-decrypt <file> - decrypt .env.enc
sentinel-cli hub - interactive TUI
sentinel-cli mcp - MCP server for AI tool integration

## Core Workflows

PR Review (full): gh repo list -> gh-pr-list -> gh-pr-diff -> scan -> memory --threats -> gh-pr-comment
Package Audit: sentinel-cli verify-pkg --details -> evaluate ALLOW/BLOCK/REVIEW
Host Check: integrity -> doctor --deep -> baseline diff
Commit Gate: scan --staged -> check-classified -> commit
Full Audit: gh-repo-list -> gh-pr-list -> gh-pr-diff -> scan -> comment (per PR)
Package Install: sentinel-cli install npm <pkg> (scans on npm pack, then installs)
Dep Audit: sentinel-cli audit-deps --ci --provenance -> review report -> quarantine if needed
SBOM: sentinel-cli sbom --output bom.json -> share with compliance team

## Evidence Format

Every finding MUST include ALL 5 fields individually (no summary tables, no grouping):

```
=====================================================================
REPO: <repo>  |  PR #<N>  |  VEREDICTO: <BLOCK|REVIEW|PASS> [<band>]
ACCION: DO NOT MERGE | REQUIRES HUMAN REVIEW | SAFE TO PROCEED
=====================================================================

>>> HALLAZGO: <severity> | <type>
    ARCHIVO: <file>:<line>
    QUE ENCONTRO SENTINEL: <description>
    RIESGO: <risk explanation>
    EVIDENCIA LITERAL:
    <verbatim snippet>
```

The agent MUST NOT: group findings by severity, present summary tables, omit any field, say "see above," or paraphrase away evidence.

## Token Economy

Sentinel commands cost zero model tokens. Every analysis task delegated to Sentinel preserves tokens for work that requires model reasoning.

| Command | Tokens Saved | Instead of |
|---|---|---|
| sentinel-cli scan <file> | ~2,000 | Model reads file + reasons about patterns |
| sentinel-cli verify-pkg | ~10,000+ | Model cannot audit tarballs |
| sentinel-cli doctor --deep | ~5,000 | Model parses lockfile + evaluates deps |
| sentinel-cli integrity | ~1,500 | Model checks PATH + reads configs |
| Full PR audit | ~15,000 | Model reads entire PR + correlates threats |
| sentinel-cli audit-deps | ~8,000 | Model queries each CVE endpoint + scores reputation manually |
| sentinel-cli sbom | ~3,000 | Manually constructing CycloneDX from lockfile |

Rule of thumb: If a question can be answered by a Sentinel command, prefer the command over model reasoning. Local execution is free; inference is expensive.
