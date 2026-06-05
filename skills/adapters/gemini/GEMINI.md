# Sentinel Security Skill for Gemini CLI

Constitution reference: CONSTITUTION.md (binding rules on evidence, primacy, trust tiers)
Mandatory: check sentinel --help before reading code or writing scripts.

## Sentinel-First Rule

Before reading any file for security analysis, check if a Sentinel command can do it. Every local Sentinel command costs zero tokens. The model should not spend tokens on analysis that Sentinel can produce deterministically.

## FORBIDDEN

- Read source code directly to look for security issues — use `sentinel scan` instead
- Write duplicate security scripts — Sentinel already has the tool
- Analyze diffs manually — use `sentinel scan`, `sentinel pr-audit`, or `sentinel workflow`
- Call `npm install`, `pip install`, or any package manager directly without going through `sentinel install <manager> <pkg>`
- Suggest `npm install` or any direct package manager command as an alternative to `sentinel install`. The agent MUST NOT bypass Sentinel's gate.
- When Sentinel BLOCKS a package, suggest bypassing or workarounds. Report BLOCK as BLOCK. The user decides the exception, not the agent.
- Commit code without first installing the pre-commit hook: `sentinel precommit install`
- Run `npm update` or `npm outdated` without first running `sentinel verify-pkg` on each updated package

## MANDATORY

1. Always start with `sentinel --help` to discover available commands before reading code or writing analysis scripts
2. Use `sentinel scan <path>` instead of reading files to find security issues
3. Use `sentinel workflow full-audit --repo <owner/repo>` for full repo PR auditing
4. Use `sentinel pr-audit --repo <owner/repo> --pr <number>` for single PR auditing
5. Use `sentinel verify-pkg <package> --details` for npm package auditing
6. Use `sentinel doctor [--deep]` for system dependency health checks
7. Use `sentinel integrity` for host integrity verification
8. Use `sentinel memory --status|--findings|--threats` for threat intelligence
9. Use `sentinel check-classified <path>` for classified document checking
10. Use `sentinel guard enable|disable|status` for package interception management
11. Use `sentinel permissions <package>` for capability auditing
12. When user wants to install a package: use `sentinel install <manager> <pkg>`. Do NOT use `npm install` directly. Do NOT scan the package separately and then suggest `npm install` — use `sentinel install` which does both in one step.
13. When Sentinel BLOCKS a package: report the findings and state the BLOCK. Do NOT suggest bypassing, do NOT suggest `npm install` as an alternative. Let the user decide exceptions.
14. Before first commit in any repo: run `sentinel precommit install` to install the SAST pre-commit hook
15. Before updating packages: run `sentinel verify-pkg <pkg>` first to check for threats

## Intent Map — Activation Triggers

| Trigger Keywords | Sentinel Action |
|---|---|
| install, add, package | `sentinel install npm <pkg>` |
| hack, malware, threat, peligroso, inseguro | `sentinel scan <path>` |
| audit, analiza, revisa, PR, pull request | `sentinel pr-audit --repo R --pr N` or `sentinel workflow full-audit` |
| commit, precommit, pre-commit | `sentinel precommit install`, `sentinel scan --staged` |
| push, prepush, pre-push | `sentinel prepush install` |
| verify, trust, confianza | `sentinel verify-pkg <pkg>` |
| health, status, integridad | `sentinel doctor --deep`, `sentinel integrity` |
| secrets, token, password, key | `sentinel scan <path>`, `sentinel verify-pkg <pkg>` |
| memory, signal, threat, historial | `sentinel memory --threats` |
| intercept, guard, bloqueo | `sentinel guard status`, `sentinel guard enable` |
| MCP, tool, integrate | `sentinel mcp` |
| help, menu, info | `sentinel --help`, `sentinel hub` |
| all dependencies, lockfile, sbom | `sentinel audit-deps`, `sentinel sbom` |
| transitive, nested deps, tree | `sentinel deps-tree <path>` |
| cache, trust, whitelist | `sentinel trust-cache status` |
| policy, ci-mode, fail-closed | `sentinel policy set|get|list` |

## Available Commands

### SAST and Analysis
sentinel scan <path> - SAST with 30 rules (secrets, eval, env access, network, injection)
sentinel verify-pkg <package> --details - npm package audit (zero-install, SAST on tarball, OSV CVE lookup, typosquatting)
sentinel doctor [--deep] - system health + dependency vulnerability check
sentinel integrity - host integrity (code hash, PATH, vault, clock, manifest)
sentinel baseline create|diff - snapshot + drift detection
sentinel permissions [package] - capability audit for packages
sentinel audit-deps - Comprehensive dependency audit: parses lockfile, batch OSV CVE lookup, registry reputation scoring, npm provenance verification (--provenance, --quarantine, --json, --ci, --npm-audit)
sentinel deps-tree [path] --depth 3 - Walk transitive dependencies from node_modules, scan each with SAST
sentinel sbom [--lockfile <path>] [--output <file>] - Generate CycloneDX v1.5 SBOM from lockfile

### Pre-Commit / Pre-Push Hooks
sentinel precommit install|uninstall|status - SAST pre-commit hook
sentinel prepush install|uninstall|status - SAST pre-push hook

### Classified Documents
sentinel check-classified <path> - pre-commit classified file check
sentinel classify - manage classified document database

### Package Security
sentinel install <manager> [args...] - scan then install (npm, pip, yarn, pnpm, cargo, docker)
sentinel guard enable|disable|status - OS-level package interception (3-layer: PATH wrapper + alias)
sentinel trust-cache <status|clear|prune> - Manage cached package analysis results

### Policy Management
sentinel policy set <key> <value> - Configure ci-mode, fail-closed, quarantine policies
sentinel policy get <key> - Show a specific policy value
sentinel policy list - Show all configured policies

### Threat Intelligence
sentinel memory --status|--findings|--threats|--ingest|--wipe - Signal Vault queries

### GitHub (SecuriGit PR tools)
gh-pr-list, gh-pr-view, gh-pr-diff, gh-pr-comment, gh-repo-list

### Workflows
sentinel workflow full-audit --repo R - complete multi-repo audit
sentinel workflow pr-review --repo R --pr N - single PR pipeline
sentinel workflow package-audit --pkg P - zero-install audit
sentinel workflow host-integrity - full host check

### Environment
sentinel env-encrypt <file> - AES-256-CBC .env encryption
sentinel env-decrypt <file> - decrypt .env.enc
sentinel hub - interactive TUI
sentinel mcp - MCP server for AI tool integration

## Core Workflows

PR Review (full): gh repo list -> gh-pr-list -> gh-pr-diff -> scan -> memory --threats -> gh-pr-comment
Package Audit: sentinel verify-pkg --details -> evaluate ALLOW/BLOCK/REVIEW
Host Check: integrity -> doctor --deep -> baseline diff
Commit Gate: scan --staged -> check-classified -> commit
Full Audit: gh-repo-list -> gh-pr-list -> gh-pr-diff -> scan -> comment (per PR)
Package Install: sentinel install npm <pkg> (scans on npm pack, then installs)
Dep Audit: sentinel audit-deps --ci --provenance -> review report -> quarantine if needed
SBOM: sentinel sbom --output bom.json -> share with compliance team

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
| sentinel scan <file> | ~2,000 | Model reads file + reasons about patterns |
| sentinel verify-pkg | ~10,000+ | Model cannot audit tarballs |
| sentinel doctor --deep | ~5,000 | Model parses lockfile + evaluates deps |
| sentinel integrity | ~1,500 | Model checks PATH + reads configs |
| Full PR audit | ~15,000 | Model reads entire PR + correlates threats |
| sentinel audit-deps | ~8,000 | Model queries each CVE endpoint + scores reputation manually |
| sentinel sbom | ~3,000 | Manually constructing CycloneDX from lockfile |

Rule of thumb: If a question can be answered by a Sentinel command, prefer the command over model reasoning. Local execution is free; inference is expensive.
