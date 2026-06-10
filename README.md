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
│   ├── SKILLS.md         # Skills system documentation
│   └── TRUST_MODEL.md    # Evidence trust hierarchy
├── src/
│   ├── cli/              # CLI commands + intelligence modules
│   │   ├── main.ts       # Commander entry point
│   │   ├── install-skills.ts  # Skills installer
│   │   └── intelligence/ # Signal vault, integrity, baselines
│   ├── mcp/              # Standalone MCP server (extracted from Oracle)
│   │   └── server.ts     # 17-tool MCP protocol server
│   ├── core/lite/        # LiteScanner SAST engine
│   ├── install-skills.sh # Unix standalone installer
│   └── install-skills.ps1 # Windows standalone installer
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
