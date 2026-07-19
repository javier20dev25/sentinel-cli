# Sentinel — Security Intelligence for AI Coding Agents

> SAST Scanner · Supply Chain Shield · Skills System · MCP Server · Sentinel Oracle

Sentinel provides a security intelligence layer that any AI coding agent can use: deterministic local analysis (SAST, package audit, threat intelligence) exposed as installable skills for Claude, Cursor, Cline, Windsurf, OpenCode, Roo, Gemini, and Codex.

## The Problem

AI coding agents don't know what's safe. They parse lockfiles with model reasoning (expensive, unreliable), guess at threat patterns, and produce plausible-sounding but wrong security answers. Every token spent on security analysis is wasted — Sentinel does it deterministically, locally, at zero token cost.

## The Solution

Two integration surfaces:

**Skills** — Agent-specific instruction files that teach agents to call Sentinel tools for all security-relevant tasks. One canonical specification (CONSTITUTION.md + GENERIC.md) adapted for every major coding agent platform.

**MCP Server** — Model Context Protocol server (`sentinel mcp`) that exposes all Sentinel tools (scan, verify-pkg, doctor, integrity, memory, GitHub PR tools) as standard MCP tool calls. Connect Claude Desktop, Cursor, Cline, or any MCP-compatible agent.

## Quick Start

```bash
# Install globally
npm install -g @sentinel/cli

# Install skills for detected agents
sentinel install-skills

# Start MCP server (stdio mode, for AI agent connection)
sentinel mcp

# Quick scan
sentinel scan ./src
```

## Skills System

Install skills for your AI coding agent:

```bash
sentinel install-skills           # auto-detect agents
sentinel install-skills --list    # show detected agents
sentinel install-skills --all     # install for all platforms
sentinel install-skills --agent claude --agent cursor
```

Each skill teaches the agent:
- **Sentinel primacy** — call `sentinel scan` before reading code with the model (0 tokens vs. expensive model analysis)
- **Evidence attachment** — every security claim must include verbatim Sentinel output
- **Trust hierarchy** — Sentinel evidence (Tier 1) overrides model reasoning (Tier 4)
- **Workflows** — PR review, package audit, host integrity, full audit pipelines

See [docs/SKILLS.md](./docs/SKILLS.md), [docs/TRUST_MODEL.md](./docs/TRUST_MODEL.md), and [skills/](./skills/) for details.

## MCP Server

```bash
sentinel mcp                      # stdio mode (default, for MCP clients)
sentinel mcp --http --port 3003   # HTTP/SSE mode for web clients
```

Exposes 17 tools: scan, verify-pkg, doctor, integrity, memory, threat-query, threat-correlate, audit-deps, deps-tree, trust-cache, sbom, policy, check-classified, gh-pr-list, gh-pr-view, gh-pr-diff, gh-repo-list.

Connect from any MCP-compatible agent (Claude Desktop, Cursor, Cline, etc.).

## Core CLI Commands

| Command | Description |
|---------|-------------|
| `sentinel scan <path>` | SAST scan with 30 rules |
| `sentinel verify-pkg <package>` | Audit npm package (zero-install) |
| `sentinel doctor [--deep]` | System health check |
| `sentinel integrity` | Verify host integrity |
| `sentinel baseline create\|diff` | System snapshot and drift detection |
| `sentinel permissions [package]` | Capability audit |
| `sentinel check-classified <path>` | Check files against classified DB |
| `sentinel memory --status` | Query local threat intelligence |
| `sentinel guard enable\|disable\|status` | Package interception guard |
| `sentinel hub` | Interactive operations menu |
| `sentinel install-skills` | Install skills for AI coding agents |
| `sentinel mcp` | Start MCP server (17 tools) for agent integration |

## Network Auditor

The Network Auditor subsystem monitors AI agent activity to detect repository exfiltration, data collection, and evasion behaviors. It operates as a local audit pipeline with zero telemetry transmission.

### Capabilities

- **Process monitoring** — Detects AI coding agents (Claude Code, Cursor, Copilot, etc.) and suspicious process chains
- **Git command detection** — Continuous monitoring of git operations (clone, fetch, push, bundle, archive, pack-objects, rev-list, log, grep, etc.)
- **File access analysis** — Mass read detection, embedding pattern identification, secret file access monitoring
- **Anti-evasion detection** — 8 signal types: artificial rhythm, fragmented traffic, protocol hopping, custom compression, monitor awareness, memory-only operations, distributed chains, no temporary files
- **Evidence chain correlation** — 4 chain types: repository exfiltration, pre-operational snapshot, full snapshot transfer, AI embedding
- **Canary system** — Decoy files, fake secrets, contaminated git history with unique markers
- **Risk assessment** — Configurable weights, contextual multipliers, 4-level scoring (LOW / MEDIUM / HIGH / CRITICAL)

### CLI Usage

```
sentinel network start                     Start a live audit session
sentinel network stop                      Stop and produce verdict
sentinel network status                    Current session status
sentinel network history -l <N>            Last N sessions
sentinel network session <id>              Full session detail
sentinel network export <id> --format fmt  Export session (json|markdown)
```

Full reference: [docs/NETWORK_AUDITOR.md](./docs/NETWORK_AUDITOR.md)

## Session Recording and Replay

Sentinel can record real OS sessions (process events, git commands, file accesses) and replay them through the detection pipeline for benchmarking and regression testing.

### Recording

```bash
# Record a 30-second session
node scripts/record-session.js git-clone 30 "cd /tmp && git clone https://github.com/expressjs/express"

# Record using canonical profile
sentinel network record 30 --profile git-clone
```

Recorded sessions are saved as `replay-corpus/recorded/session-<id>.json` with companion `.ground-truth.json` files containing expected risk level and behaviors.

### Replay

```bash
# Replay a single session
sentinel network replay run replay-corpus/recorded/session-<id>.json

# Run full campaign on all recorded sessions
sentinel network replay campaign replay-corpus/recorded

# Compare baseline vs current results
sentinel network replay diff replay-corpus/recorded-baseline replay-corpus/recorded
```

### Architecture

```
record-session.js
  └── Starts PowerShell process monitor + git detector
       └── Runs target workload (git clone, npm install, etc.)
            └── Saves session + ground truth
                 └── ReplayEngine replays through NetworkAuditPipeline
                      └── Verdict: risk score, behaviors, confidence
```

## Canonical Corpus

Sentinel defines 31 canonical session profiles spanning 4 categories:

| Category    | Count | Profiles |
|-------------|-------|----------|
| Benign      | 16    | git-clone, git-fetch, git-pull, git-rebase, git-push, git-log, git-status, git-diff, npm-install, npm-test, cargo-build, go-mod-download, docker-build, docker-pull, terraform-plan, terraform-apply |
| IA          | 4     | cursor-edit, cursor-refactor, copilot-chat, claude-code |
| Suspicious  | 5     | grep-secrets, read-env, read-git, read-ssh, mass-file-read |
| Malicious   | 6     | exfil-pastebin, exfil-gist, exfil-discord, exfil-dns, exfil-git-bundle, exfil-tar-git |

Profiles that require specific tools (Docker, Go, Terraform) are marked with `requires` metadata and excluded from effective coverage when the tool is unavailable.

### Corpus Coverage

```bash
sentinel network corpus coverage replay-corpus
```

Reports captured vs missing profiles, environment-dependent profiles, effective coverage, and category breakdown.

## CI Gate

The CI gate (`src/ci-gate.ts`) runs a full evaluation across 5 validation layers:

1. **Calibrated corpus** — 39 synthetic scenarios (threshold: 100%)
2. **Blind corpus #1** — 15 independent scenarios (threshold: 60%)
3. **Blind corpus #2** — 14 frozen-engine scenarios (threshold: 60%)
4. **Blind corpus #3** — 14 policy-frozen scenarios (threshold: 60%)
5. **Replay corpus** — Recorded sessions with ground truth (thresholds: accuracy >= 75%, recall >= 95%, FPR <= 70%, FNR <= 5%)

```bash
node dist/ci-gate.js
```

Exit code 0 = all gates pass. Exit code 1 = regression detected.

## Benchmark History

Each CI gate run records a benchmark entry to `benchmark-history.json`:

```
sentinel network benchmark history
```

Benchmark entries include per-corpus pass rates, replay metrics (accuracy, precision, recall, F1, FPR, FNR), and latency distribution (P50, P95, P99, max, standard deviation). A delta table compares the current entry against the previous version across all metrics.

## Sentinels Core

- **LiteScanner** — 30 SAST rules: secrets, eval, network, env access, command injection, SQLi, prototype pollution, crypto misuse
- **Supply Chain Shield** — npm package audit without installing (typosquatting, embedded secrets, malicious patterns)
- **System Doctor** — dependency vulnerability scan, behavioral analysis
- **Integrity Manager** — chain-of-trust integrity verification (hash, PATH, vault, clock, manifest)
- **Signal Vault** — local SQLite threat intelligence, author correlation, pattern matching
- **Baseline Manager** — system snapshots and drift detection

## Architecture

```
sentinel/
├── skills/               # Canonical skill specifications
│   ├── CONSTITUTION.md   # Binding rules (all agents)
│   ├── GENERIC.md        # Universal adapter-agnostic skill
│   └── adapters/          # Per-platform skill files
│       ├── claude/       # CLAUDE.md
│       ├── cursor/       # sentinel.mdc
│       ├── cline/        # CLINE.md
│       ├── windsurf/     # .windsurfrules
│       ├── opencode/     # SKILL.md
│       ├── roo/          # ROO.md
│       ├── gemini/       # GEMINI.md
│       └── codex/        # CODEX.md
├── docs/
│   ├── NETWORK_AUDITOR.md  # Network auditor full documentation
│   ├── SKILLS.md           # Skills system documentation
│   └── TRUST_MODEL.md      # Evidence trust hierarchy
├── src/
│   ├── cli/              # CLI commands + intelligence modules
│   │   ├── main.ts       # Commander entry point
│   │   ├── install-skills.ts  # Skills installer
│   │   ├── intelligence/ # Signal vault, integrity, baselines
│   │   └── network/      # Network auditor CLI layer
│   │       ├── auditor.ts # Session lifecycle, orchestration
│   │       ├── process-monitor.ts
│   │       ├── git-detector.ts
│   │       ├── corpus-coverage.ts
│   │       └── session-recorder.ts
│   ├── mcp/              # Standalone MCP server (extracted from Oracle)
│   │   └── server.ts     # 17-tool MCP protocol server
│   ├── core/lite/        # LiteScanner SAST engine
│   ├── core/network/     # Network auditor core
│   │   ├── pipeline.ts         # Event orchestration
│   │   ├── behavior-engine.ts  # 8 classifiers
│   │   ├── risk-engine.ts      # Risk scoring
│   │   ├── anti-evasion-engine.ts
│   │   ├── evidence-chain.ts
│   │   ├── canary-system.ts
│   │   ├── replay-engine.ts    # Deterministic replay
│   │   ├── evaluator.ts        # Benchmark evaluation
│   │   ├── benchmark-history.ts
│   │   ├── canonical-sessions.ts # 31 profiles
│   │   └── types.ts            # 35+ interfaces
│   ├── ci-gate.ts        # Regression gate (5 layers)
│   ├── install-skills.sh # Unix standalone installer
│   └── install-skills.ps1 # Windows standalone installer
├── replay-corpus/        # Session corpus
│   ├── corpus-version.json   # Version metadata
│   ├── recorded/             # Real recorded sessions
│   └── synthetic/            # Synthetic scenarios + ground truth
├── benchmark-history.json    # Versioned benchmark entries
└── scripts/
    └── record-session.js     # Session acquisition script
```

## Sentinel Oracle

Sentinel Oracle is a physically isolated merge authorization server. It runs on a separate device (Raspberry Pi, NUC, mini PC) and enforces multi-factor approval before any pull request is merged — implementing Merge Authority Isolation.

See [sentinel-oracle](https://github.com/javier20dev25/sentinel-oracle) for the dedicated repository with full architecture documentation, setup guides, and device management.

Key features:
- **Physical isolation** — Oracle runs on a separate device, no cloud dependency
- **Three-device trust model** — workstation (untrusted), oracle server (trusted), phone (identity)
- **QR + WebAuthn** — phone-based biometric confirmation for merge approval
- **Emergency lockdown** — global kill switch for all pending merges

## Requirements

- **Node.js** >= 18.0.0
- **npm** >= 9
- **gh** CLI (for GitHub PR tools — optional)

## License

**Business Source License 1.1** — see [LICENSE](./LICENSE).

---

*Built for developers who take security seriously.*
