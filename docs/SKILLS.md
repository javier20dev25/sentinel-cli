# Sentinel Skills System

Architecture, installation, and reference for integrating Sentinel into any AI coding agent.

---

## Architecture

```
skills/
  CONSTITUTION.md      # Shared rules (referenced by all adapters)
  GENERIC.md           # Universal skill for any agent

  adapters/
    claude/CLAUDE.md
    gemini/GEMINI.md
    codex/CODEX.md
    cursor/sentinel.mdc
    cline/CLINE.md
    opencode/SKILL.md
    windsurf/.windsurfrules
    roo/ROO.md

src/
  mcp/
    server.ts          # MCP server (standalone, no external dependency)
  cli/
    install-skills.ts  # sentinel install-skills command

install-skills.sh      # Bootstrap for Unix
install-skills.ps1     # Bootstrap for Windows
```

Each adapter contains the same core content (constitution rules, command reference, workflows, evidence policy) formatted for the target agent platform. Only the file format and syntax differ.

---

## Installation

### Via Sentinel CLI

```bash
sentinel install-skills             # Interactive: select agent
sentinel install-skills --agent claude
sentinel install-skills --agent all  # Install for all detected agents
sentinel install-skills --list       # List supported agents
sentinel install-skills --detect     # Auto-detect installed agents
```

### Standalone script

```bash
# Unix
bash install-skills.sh

# Windows
powershell -File install-skills.ps1
```

The standalone script is a fallback for environments where the full Sentinel CLI is not available.

### Agent detection

`install-skills --detect` checks for these binaries in PATH:

- `claude` (Claude Code)
- `gemini` (Gemini CLI)
- `codex` (OpenAI Codex CLI)
- `cursor` (Cursor)
- `cline` (Cline)
- `opencode` (OpenCode)
- `windsurf` (Windsurf)
- `roo` (Roo Code)

It also checks for configuration directories like `~/.cursor/rules/`, `~/.config/opencode/`, and project-local `.claude/` directories.

---

## Agent Integration Points

| Agent | File | Location |
|-------|------|----------|
| Claude Code | `CLAUD.md` | Project root or `.claude/CLAUDE.md` |
| Gemini CLI | `GEMINI.md` | Project root |
| OpenAI Codex | `CODEX.md` | `.reference/CODEX.md` |
| Cursor | `sentinel.mdc` | `.cursor/rules/sentinel.mdc` |
| Cline | `CLINE.md` | Project root |
| OpenCode | `SKILL.md` | `.opencode/skills/SKILL.md` |
| Windsurf | `.windsurfrules` | Project root |
| Roo Code | `ROO.md` | Project root |
| Any MCP client | MCP protocol | Connects to `sentinel mcp` (stdio or HTTP) |

---

## MCP Integration

Sentinel exposes its full tool set through the Model Context Protocol (MCP). Any MCP-compatible agent (Claude Desktop, Cursor, Cline, OpenCode) can connect directly without needing a static skill file.

```bash
# Start MCP server (stdio mode)
sentinel mcp

# Start MCP server (HTTP mode)
sentinel mcp --http --port 3003
```

### MCP Tools

The MCP server exposes the same tools available in the CLI:

- `scan` — SAST scan with 30 rules
- `verify-pkg` — npm package audit (zero-install)
- `doctor` — system health check
- `integrity` — host integrity verification
- `check-classified` — classified file check
- `memory` — signal vault query
- `threat-query` — threat intelligence lookup by author
- `threat-correlate` — correlate findings with threat database
- `gh-pr-list`, `gh-pr-view`, `gh-pr-diff`, `gh-repo-list` — GitHub PR tools
- `install-pkg`, `remove-pkg` — package management tools

---

## Token Economy

Sentinel commands cost **zero model tokens**. Every analysis task delegated to Sentinel preserves tokens for work that requires model reasoning. The token savings are substantial:

| Command | Tokens Saved | Model Alternative |
|---------|-------------|-------------------|
| `sentinel scan <file>` | ~2,000 | Model reads file + reasons about security patterns |
| `sentinel scan <dir>` | ~8,000+ | Model walks directory + reads every file |
| `sentinel verify-pkg <pkg>` | ~10,000+ | Model cannot audit tarballs; best effort is guessing |
| `sentinel doctor [--deep]` | ~5,000 | Model parses lockfile + evaluates each dependency |
| `sentinel integrity` | ~1,500 | Model checks PATH + reads config files |
| `sentinel permissions <pkg>` | ~3,000 | Model reads package source + classifies capabilities |
| `sentinel memory --threats` | ~2,000 | Model has no access to local threat history |
| `sentinel check-classified <path>` | ~1,000 | Model reads staged files + compares to rules |
| `sentinel baseline diff` | ~4,000 | Model reads both snapshots + computes diff |
| `gh-pr-diff + scan` (full PR audit) | ~10,000+ | Model reads entire PR diff + analyzes each hunk |

### Cost Per Workflow

| Workflow | Tokens Saved | Notes |
|----------|-------------|-------|
| PR Security Review | ~15,000 | gh-pr-diff + scan + memory + gh-pr-comment |
| Package Audit | ~12,000 | verify-pkg + memory correlation |
| Host Integrity | ~8,000 | integrity + doctor + baseline |
| Full Repo Audit | ~50,000+ | Scales with number of PRs |

### What 50,000 Tokens Buys

At typical AI coding agent pricing:
- **Claude Code**: ~$0.50 saved per full repo audit
- **Cursor**: ~$0.30 saved per PR review
- **OpenCode**: ~$0.20 saved per package audit

More importantly, tokens are a **context window budget**. Using Sentinel for deterministic analysis leaves the model's context window free for:
- Understanding the business logic of findings
- Generating remediation code
- Explaining attack chains in human terms
- Handling novel security patterns not covered by static rules

### Rule of Thumb

If a question can be answered by running a shell command, the agent should prefer the command over model reasoning. This is the core of the token economy: **local execution is free; inference is expensive.**

---

## Trust Model

Evidence is ranked by four tiers. Higher tiers override lower tiers. See `docs/TRUST_MODEL.md` for full details.

1. **Sentinel Evidence** — deterministic tool output (highest)
2. **Local System State** — observable facts from the environment
3. **GitHub Metadata** — externally sourced repository data
4. **Model Reasoning** — AI model inference (lowest)

The agent must never use model reasoning to override Sentinel evidence. If Sentinel says BLOCK, the agent must report BLOCK.

---

## Workflows

### PR Security Review

```
1. gh-pr-diff (number)         → get raw diff
2. scan (path: <diff>)         → analyse for threats
3. memory (action: --threats)  → correlate with historical threats
4. gh-pr-comment (number, body) → post structured report
```

### Package Audit

```
1. verify-pkg (package)        → analyse tarball
2. memory (action: --threats)  → check author history
3. Report ALLOW/BLOCK/REVIEW   → decision with evidence
```

### Host Integrity Check

```
1. integrity                   → verify host
2. doctor (deep: --deep)       → dependency health
3. baseline (action: diff)     → compare with known snapshot
```

### Classified Document Protection

```
1. check-classified (path)     → verify staged files
2. classify (file)             → check specific file
```

### Full Repository Audit

```
1. gh-repo-list (owner)        → list repositories
2. gh-pr-list (repo)           → list open PRs
3. gh-pr-diff (number)         → get diff for each PR
4. scan (path)                 → analyse each diff
5. gh-pr-comment (number, body) → post findings
```

---

## CLI Command Reference

### SAST and Analysis

| Command | Description |
|---------|-------------|
| `sentinel scan <path>` | SAST scan with 30 rules. Detects secrets, eval(), env access, network requests, command injection, SQL injection, prototype pollution, crypto misuse, and more. |
| `sentinel scan <path> --json` | Machine-readable JSON output. |
| `sentinel verify-pkg <package>` | Audit npm package without installing. Detects typosquatting, secret leaks, malicious patterns. |
| `sentinel verify-pkg <package> --details` | Full analysis breakdown. |
| `sentinel doctor [--deep]` | System health check for npm dependencies. Deep flag analyses full dependency tree. |
| `sentinel integrity [--uptime] [--watch]` | Host integrity verification. Checks code hash, PATH, vault, clock, manifest. |
| `sentinel baseline create <name>` | Create system snapshot. |
| `sentinel baseline diff [name]` | Compare current state against snapshot. |
| `sentinel permissions [package]` | Audit package capabilities and governance. |

### Classified Document Management

| Command | Description |
|---------|-------------|
| `sentinel check-classified <repoPath>` | Pre-commit hook. Blocks if classified files staged. |
| `sentinel classify` | Manage classified document database. |

### Package Management (Security-Gated)

| Command | Description |
|---------|-------------|
| `sentinel install <manager> [args...]` | Install packages through security gate (npm, pip, yarn, etc.). |
| `sentinel guard enable` | Enable OS-level package interception. |
| `sentinel guard disable` | Disable interception. |
| `sentinel guard status` | Show guard state. |

### Memory and Threat Intelligence

| Command | Description |
|---------|-------------|
| `sentinel memory --status` | Signal vault status summary. |
| `sentinel memory --findings` | List historical findings. |
| `sentinel memory --threats` | Show threat correlations. |
| `sentinel memory --ingest <file>` | Load findings into vault. |
| `sentinel memory --wipe` | Clear vault data. |

### GitHub Integration (SecuriGit)

| Command | Description |
|---------|-------------|
| `gh pr list [--repo owner/repo]` | List open PRs. |
| `gh pr view <number> [--repo owner/repo]` | View PR details. |
| `gh pr diff <number> [--repo owner/repo]` | Get PR diff. |
| `gh pr comment <number> --body-file <file>` | Post comment on PR. |
| `gh repo list [--owner user] [--limit N]` | List repositories. |

### Environment and Configuration

| Command | Description |
|---------|-------------|
| `sentinel env-encrypt <file>` | Encrypt .env file (AES-256-CBC). Requires `SENTINEL_ENV_KEY`. |
| `sentinel env-decrypt <file>` | Decrypt .env.enc file. |
| `sentinel hub` | Interactive TUI. |
| `sentinel policies` | Show security policy. |
| `sentinel guide` | Complete user guide. |

---

## Workflow Definitions

### pr-review

Complete pipeline: list PRs in a repo, fetch each diff, scan with SAST, correlate with threat database, and post structured report as a PR comment.

**Steps:**
1. `gh-pr-list --repo <name> --limit <N>` — get open PRs
2. For each PR: `gh-pr-diff --repo <name> --number <N>` — get diff
3. `scan` on each diff — detect threats
4. `memory --threats` — correlate author with historical threats
5. `gh-pr-comment` — post finding report

**Output:** structured security report per PR with severity, location, evidence snippet, and recommendation.

**Token cost:** 0 (all analysis is local).

### package-audit

Zero-install package audit with author threat correlation.

**Steps:**
1. `verify-pkg --package <name>` — analyse tarball
2. `gh-pr-list` or direct query for author context (if available)
3. Cross-reference findings with threat database

**Output:** ALLOW / BLOCK / REVIEW verdict with evidence.

**Token cost:** 0.

### host-integrity

Host and environment security verification.

**Steps:**
1. `integrity` — check code hash, PATH, vault, clock
2. `doctor --deep` — dependency vulnerability analysis
3. `baseline diff` — detect drift from known-good state

**Output:** integrity level (TRUSTED / WARNING / COMPROMISED) with issue list.

**Token cost:** 0.

### classified-check

Prevent classified data leakage through git.

**Steps:**
1. `check-classified --path <repo>` — verify staged files
2. If blocked: `classify` to inspect specific file

**Output:** pass/fail with matched file list.

**Token cost:** 0.

### full-audit

Complete multi-repository security audit.

**Steps:**
1. `gh-repo-list --owner <name>` — list repos
2. For each repo: `gh-pr-list` — get open PRs
3. For each PR: `gh-pr-diff` + `scan` — analyse
4. `gh-pr-comment` — report per PR

**Output:** summary across all repositories with per-PR findings.

**Token cost:** 0 (all analysis is local; only final report generation uses the model).

---

## Evidence Format (MANDATORY)

Every security conclusion MUST include ALL 5 fields for EACH finding individually — no summaries, no tables, no grouping:

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

The agent MUST NOT: group by severity, present summary tables, omit any field, say "see above," or paraphrase away evidence. The verdict IS the action. For BLOCK, do NOT suggest fixes — rejection means rejection.

---

## Integration Example (Claude Code)

Place `CLAUD.md` in your project root. Claude Code reads it automatically on project context load. The skill teaches Claude:

- When to call `sentinel scan` instead of reading files
- How to interpret BLOCK / REVIEW / ALLOW
- To attach evidence verbatim to every security claim
- To chain tools for complete workflows

Other agents follow the same pattern with their respective skill file name and location.
