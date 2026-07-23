# Sentinel Security Skill

This document defines how an AI agent should use Sentinel CLI tools for deterministic security analysis. The content applies universally across agent platforms.

---

## 1. Constitution (Binding Rules)

**Sentinel Primacy:** If a task can be answered by Sentinel, the agent must use Sentinel first. The agent must not spend tokens on analysis that Sentinel can do locally at zero token cost.

**Exclusive tasks (use Sentinel, not model reasoning):**
- Scanning code for threats (secrets, injection, unsafe patterns)
- Auditing npm packages for supply chain risks
- Checking system health and dependency vulnerabilities
- Verifying host integrity
- Querying historical findings from local threat database
- Auditing package capabilities
- Checking files against classified document database
- Listing, viewing, diffing, and commenting on GitHub PRs
- Performing baseline comparison and drift detection
- Comprehensive dependency audits (lockfile parse + OSV + provenance)
- SBOM generation
- Pre-commit and pre-push hook management

**Evidence attachment:** Every security conclusion must include what Sentinel found, where it was found, why it matters, the recommended action, and a verbatim quote of the Sentinel output. The agent must not paraphrase away evidence.

**Trust hierarchy:**
1. Sentinel evidence (deterministic, verifiable) — highest
2. Local system state (file system, git, env) — high
3. GitHub metadata — medium
4. Model reasoning — lowest

Higher tiers override lower tiers. If Sentinel says BLOCK, the agent must report BLOCK.

---

## 2. Command Reference

### SAST and Analysis

| Command | Purpose |
|---------|---------|
| `sentinel-cli scan <path>` | 30-rule SAST scan. Detects secrets, eval(), env access, network, command injection, SQL injection, prototype pollution, crypto misuse. |
| `sentinel-cli scan <path> --json --staged --cards --sarif --md --graph --scenarios` | Extended scan output formats. |
| `sentinel-cli verify-pkg <package> --details --summary` | Zero-install npm package audit. Detects typosquatting, secrets, malicious patterns, OSV CVE lookup. |
| `sentinel-cli doctor [--deep]` | Dependency health check. Deep flag analyses full tree. |
| `sentinel-cli integrity [--uptime] [--watch]` | Host integrity (code hash, PATH, vault, clock, manifest). |
| `sentinel-cli baseline create <name>` | System snapshot. |
| `sentinel-cli baseline diff [name]` | Drift detection against snapshot. |
| `sentinel-cli permissions [package]` | Capability governance audit. |
| `sentinel-cli audit-deps [--lockfile] [--provenance] [--quarantine] [--npm-audit] [--ci]` | Comprehensive dependency audit: lockfile parse, batch OSV CVE lookup, registry reputation, npm provenance. |
| `sentinel-cli deps-tree <path> [--depth]` | Walk transitive dependencies, scan each with SAST. |
| `sentinel-cli sbom [--lockfile] [--output] [--enrich]` | CycloneDX v1.5 SBOM generation from lockfile. |
| `sentinel-cli benchmark [--corpus] [--json]` | Run corpus-based FP/FN benchmark. |
| `sentinel-cli explain [paths...]` | Explain security findings. |
| `sentinel-cli history [path]` | Show risk history and trends. |
| `sentinel-cli graph history [path]` | Graph snapshot history. |
| `sentinel-cli graph diff [path]` | Diff between graph snapshots. |
| `sentinel-cli token-inspect <token> [--check]` | Classify and risk-assess a token (API key, secret, JWT, etc.). |

### Pre-Commit / Pre-Push

| Command | Purpose |
|---------|---------|
| `sentinel-cli precommit install\|uninstall\|status` | SAST pre-commit hook management. |
| `sentinel-cli prepush install\|uninstall\|status` | SAST pre-push hook management. |

### Classified Documents

| Command | Purpose |
|---------|---------|
| `sentinel-cli check-classified <path>` | Pre-commit classified file check. |
| `sentinel-cli classify` | Manage classified document database. |

### Package Security

| Command | Purpose |
|---------|---------|
| `sentinel-cli install <manager> [args]` | Security-gated install (scan then install). |
| `sentinel-cli guard enable\|disable\|status` | OS-level package interception. |
| `sentinel-cli trust-cache status\|clear\|prune` | Manage cached package analysis results. |
| `sentinel-cli policy set\|get\|list [key] [value]` | Configure ci-mode, fail-closed, quarantine policies. |

### Threat Intelligence

| Command | Purpose |
|---------|---------|
| `sentinel-cli memory --status` | Vault status. |
| `sentinel-cli memory --findings` | Historical findings. |
| `sentinel-cli memory --threats` | Threat correlations. |
| `sentinel-cli memory --ingest <file>` | Load findings. |
| `sentinel-cli memory --wipe` | Clear vault. |

### GitHub (SecuriGit)

| Command | Purpose |
|---------|---------|
| `gh pr list [--repo X]` | List PRs. |
| `gh pr view <N> [--repo X]` | View PR. |
| `gh pr diff <N> [--repo X]` | Get diff. |
| `gh pr comment <N> --body-file <F>` | Post comment. |
| `gh repo list [--owner X]` | List repos. |
| `sentinel-cli pr-audit --repo <R> --pr <N> [--comment] [--check-run]` | Audit single PR and post results. |

### Workflows

| Command | Purpose |
|---------|---------|
| `sentinel-cli workflow pr-review --repo <R> --pr <N>` | Audit PR and post results. |
| `sentinel-cli workflow full-audit --repo <R> [--owner]` | Audit all open PRs. |
| `sentinel-cli workflow host-integrity` | Full host integrity check. |
| `sentinel-cli workflow package-audit --pkg <P>` | Zero-install package audit. |

### Environment & Utilities

| Command | Purpose |
|---------|---------|
| `sentinel-cli env-encrypt <file>` | Encrypt .env. |
| `sentinel-cli env-decrypt <file>` | Decrypt .env.enc. |
| `sentinel-cli hub` | Interactive TUI with dashboard. |
| `sentinel-cli policies` | Show security policy, disclosure, contribution guidelines. |
| `sentinel-cli guide` | Show complete user guide. |
| `sentinel-cli install-skills [agents...] [--list] [--all]` | Install skills for AI agents (claude, gemini, codex, cursor, cline, opencode, windsurf, roo). |
| `sentinel-cli mcp [--port] [--http] [--stdio]` | Start MCP server (17 tools for AI integration). |

---

## 3. Workflows

### PR Security Review (Full)

```
1. gh-repo-list (owner=O)              -> discover repos
2. gh-pr-list (repo=R)                 -> list open PRs
3. gh-pr-diff (number=N, repo=R)       -> raw diff
4. scan (path=<diff output>)           -> SAST findings
5. memory --threats                    -> author correlation
6. gh-pr-comment (number=N, body=report) -> post findings
```

### Package Audit

```
1. verify-pkg --details (package=<name>)  -> tarball analysis
2. Evaluate ALLOW / BLOCK / REVIEW with evidence
```

### Host Integrity

```
1. integrity                           -> host check
2. doctor --deep                       -> dependency health
3. baseline diff                       -> drift detection
```

### Classified File Check

```
1. check-classified (path=<repo>)      -> staged file scan
2. classify (file=<path>)              -> individual check
```

### Full Dependency Audit

```
1. audit-deps --ci --provenance        -> lockfile + OSV + reputation
2. Review report, quarantine if needed
3. deps-tree --depth 3                 -> transitive walk
```

### Commit Gate

```
1. scan --staged                       -> staged file SAST
2. check-classified (path=<repo>)      -> classified document check
3. commit
```

### Package Install

```
1. install (manager=<npm>, args=<pkg>) -> scan then install
```

### SBOM Generation

```
1. sbom --output bom.json              -> compliance artifact
```

---

## 4. Result Interpretation

BLOCK (severity critical/high): Do not proceed without manual review. Attach all evidence.

REVIEW (severity medium): Requires human verification. Include evidence and recommendation.

ALLOW (no findings or low severity): Safe to proceed. Include scan summary.

---

## 5. Token Economy

Sentinel commands cost zero model tokens. Every analysis task delegated to Sentinel preserves tokens for work that requires model reasoning.

| Command | Tokens Saved | Instead of |
|---------|-------------|------------|
| `sentinel-cli scan <file>` | ~2,000 | Model reads file + reasons about patterns |
| `sentinel-cli verify-pkg` | ~10,000+ | Model cannot audit tarballs |
| `sentinel-cli doctor --deep` | ~5,000 | Model parses lockfile + evaluates deps |
| `sentinel-cli integrity` | ~1,500 | Model checks PATH + reads configs |
| Full PR audit | ~15,000 | Model reads entire PR + correlates threats |
| `sentinel-cli audit-deps` | ~8,000 | Model queries each CVE endpoint + scores reputation manually |
| `sentinel-cli sbom` | ~3,000 | Manually constructing CycloneDX from lockfile |
| `sentinel-cli deps-tree` | ~4,000 | Walking node_modules + scanning each manually |

Rule of thumb: If a question can be answered by a Sentinel command, prefer the command over model reasoning. Local execution is free; inference is expensive.

---

## 6. Safety Rules

- Always verify before trusting. No package should be installed without `verify-pkg` or `install` first.
- Never disable `guard` without user confirmation.
- Running `workflow full-audit` on many repos may take time. Warn the user.
- If a tool returns an error, report it verbatim and downgrade confidence.
- Destructive operations (install, remove, guard disable, baseline write) require explicit user approval.
- Before committing, run `precommit install` to install the SAST hook.
