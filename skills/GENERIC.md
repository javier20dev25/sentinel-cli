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
| `sentinel scan <path>` | 30-rule SAST scan. Detects secrets, eval(), env access, network, command injection, SQL injection, prototype pollution, crypto misuse. |
| `sentinel scan <path> --json` | Machine-readable JSON output. |
| `sentinel verify-pkg <package>` | Zero-install npm package audit. Detects typosquatting, secrets, malicious patterns. |
| `sentinel doctor [--deep]` | Dependency health check. Deep flag analyses full tree. |
| `sentinel integrity [--uptime] [--watch]` | Host integrity (code hash, PATH, vault, clock, manifest). |
| `sentinel baseline create <name>` | System snapshot. |
| `sentinel baseline diff [name]` | Drift detection against snapshot. |
| `sentinel permissions [package]` | Capability governance audit. |

### Classified Documents

| Command | Purpose |
|---------|---------|
| `sentinel check-classified <path>` | Pre-commit classified file check. |
| `sentinel classify` | Manage classified document database. |

### Package Security

| Command | Purpose |
|---------|---------|
| `sentinel install <manager> [args]` | Security-gated install. |
| `sentinel guard enable\|disable\|status` | OS-level package interception. |

### Threat Intelligence

| Command | Purpose |
|---------|---------|
| `sentinel memory --status` | Vault status. |
| `sentinel memory --findings` | Historical findings. |
| `sentinel memory --threats` | Threat correlations. |
| `sentinel memory --ingest <file>` | Load findings. |

### GitHub (SecuriGit)

| Command | Purpose |
|---------|---------|
| `gh pr list [--repo X]` | List PRs. |
| `gh pr view <N> [--repo X]` | View PR. |
| `gh pr diff <N> [--repo X]` | Get diff. |
| `gh pr comment <N> --body-file <F>` | Post comment. |
| `gh repo list [--owner X]` | List repos. |

### Utilities

| Command | Purpose |
|---------|---------|
| `sentinel env-encrypt <file>` | Encrypt .env. |
| `sentinel env-decrypt <file>` | Decrypt .env. |
| `sentinel hub` | Interactive TUI. |
| `sentinel policies` | Show policy. |

---

## 3. Workflows

### PR Security Review

```
1. gh-pr-diff (number=N, repo=R)          -> raw diff
2. scan (path=<diff output>)              -> SAST findings
3. memory (action=--threats)              -> author correlation
4. gh-pr-comment (number=N, body=<report>) -> post findings
```

### Package Audit

```
1. verify-pkg (package=<name>)            -> tarball analysis
2. Report ALLOW / BLOCK / REVIEW with evidence
```

### Host Integrity

```
1. integrity                              -> host check
2. doctor (deep=--deep)                   -> dependency health
3. baseline diff                          -> drift detection
```

### Classified File Check

```
1. check-classified (path=<repo>)         -> staged file scan
2. classify (file=<path>)                 -> individual check
```

### Full Repository Audit

```
1. gh-repo-list (owner=O, limit=N)        -> repos
2. For each repo: gh-pr-list -> PRs
3. For each PR: gh-pr-diff + scan        -> analysis
4. gh-pr-comment per PR                  -> report
```

---

## 4. Result Interpretation

BLOCK (severity critical/high): Do not proceed without manual review. Attach all evidence.

REVIEW (severity medium): Requires human verification. Include evidence and recommendation.

ALLOW (no findings or low severity): Safe to proceed. Include scan summary.

---

## 5. Safety Rules

- Always verify before trusting. No package should be installed without `verify-pkg` first.
- Never disable `guard` without user confirmation.
- Running `gh-full-audit` on many repos may take time. Warn the user.
- If a tool returns an error, report it verbatim and downgrade confidence.
- Destructive operations (install, remove, guard disable, baseline write) require explicit user approval.
