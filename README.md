# Sentinel — Security Intelligence for AI Coding Agents

> SAST Scanner · Supply Chain Shield · Skills System · MCP Server · Network Auditor

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

## Interactive Hub Menu

`sentinel hub` launches a bilingual (English/Spanish) interactive menu with 12 options:

```
  0. PR Bot — Auto-Analyze All Open PRs
  1. Select Workspaces & Run Audits
  2. System Doctor (Health Check)
  3. Integrity Check
  4. Permissions Audit
  5. Scan Directory/File
  6. Sentinel Guard & Configuration (NPM Intercept)
  7. Classified Documents
  8. Manage Signal Vault (Memory)
  9. Security — Integrity & Trust Policy
 10. Network Auditor
 11. Exit
```

## Behavior-based Network & Process Monitoring

Sentinel CLI includes a behavior-based monitoring engine designed to detect repository exfiltration attempts by correlating process execution, Git activity, network connections and DNS events.

Unlike traditional traffic inspection tools (such as HTTP proxies like mitmproxy) which intercept and display request contents, Sentinel focuses on reconstructing behavioral chains from multiple telemetry sources — processes spawned, Git commands executed, connections established, and DNS queries resolved. This approach detects the *shape* of an exfiltration workflow (preparation → packaging → transfer) regardless of the specific tools or protocols used.

The engine is particularly aimed at scenarios involving AI coding assistants and development agents, where conventional network inspection may not capture the full picture:

- A `git bundle` created and transmitted via HTTPS may look like normal traffic to a proxy.
- Exfiltration via DNS tunneling or split across multiple protocols leaves no single packet to inspect.
- Preparation commands (`git rev-list`, `git cat-file`) produce no network traffic at all.

Sentinel observes all these layers simultaneously and evaluates risk based on what combination of behaviors appears and in what sequence.

### Telemetry Sources

| Source | Mechanism | Coverage |
|--------|-----------|----------|
| Process monitor | WMI polling (100ms) | Process creation, command lines, parent-child chains |
| Git detector | WMI polling (100ms) | Git actions classified by type (bundle, archive, push, rev-list, etc.) |
| Connection inspector | `netstat -ano` (500ms) | TCP connections to external hosts, port/service identification |
| DNS observer | `ipconfig /displaydns` (2000ms) | DNS queries matching known AI/exfiltration domains |
| HTTP interceptor | Man-in-the-middle (optional) | HTTP request/response inspection |
| TLS interceptor | Certificate injection (optional) | TLS handshake inspection |
| WebSocket observer | Process + connection correlation | WebSocket frame inspection |
| File watcher | Filesystem events | File read/write access patterns |

### Sensors

| Sensor | File | Status |
|--------|------|--------|
| Process Monitor | `src/cli/network/process-monitor.ts` | Active (WMI polling) |
| Git Detector | `src/cli/network/git-detector.ts` | Active |
| Connection Inspector | `src/cli/network/connection-inspector.ts` | Active (`netstat`) |
| DNS Observer | `src/cli/network/dns-observer.ts` | Active (`ipconfig`) |
| HTTP Interceptor | `src/cli/network/http-interceptor.ts` | Optional (MITM) |
| TLS Interceptor | `src/cli/network/tls-interceptor.ts` | Optional |
| WebSocket Observer | `src/cli/network/websocket-observer.ts` | Experimental |
| File Watcher | `src/cli/network/file-watcher.ts` | Experimental |

### CLI Usage

```
sentinel network start                     Start a live audit session
sentinel network stop                      Stop and produce verdict
sentinel network status                    Current session status
sentinel network history -l <N>            Last N sessions
sentinel network session <id>              Full session detail
sentinel network export <id> --format fmt  Export session (json|markdown)
sentinel network replay run <file>         Replay a recorded session
sentinel network replay campaign <dir>     Run full campaign
sentinel network corpus coverage <dir>     Coverage report
sentinel network benchmark history         View benchmark history
```

### Behavior Detection Reference (31 Behaviors)

| Behavior | Trigger | MITRE | Stage |
|----------|---------|-------|-------|
| `repo_indexed` | Repository indexed by AI agent | T1213 (Collection) | Collection |
| `git_history_read` | `git log` / `git rev-list` executed | T1213 (Collection) | Collection |
| `git_objects_read` | `git cat-file` / `git ls-tree` on objects | T1213 (Collection) | Collection |
| `git_bundle_created` | `git bundle create` executed | T1074 (Data Staged) | Packaging |
| `git_bundle_uploaded` | Bundle sent to remote host | T1041 (Exfil Over C2) | Exfiltration |
| `git_archive_created` | `git archive` or `tar` + `.git` | T1560 (Archive Data) | Packaging |
| `secrets_scanned` | Credential/password store access detected | T1555 (Credentials) | Collection |
| `secrets_exfiltrated` | Secrets transmitted to remote host | T1041 (Exfil Over C2) | Exfiltration |
| `embeddings_generated` | AI embedding vectors computed on repo | T1213 (Info Repos) | Collection |
| `full_repo_snapshot` | `git push --mirror` or `--all --force` | T1074 (Data Staged) | Collection |
| `canary_exfiltrated` | Decoy file transmitted to remote host | T1041 (Exfil Over C2) | Exfiltration |
| `mass_file_read` | Bulk file read across many paths | T1005 (Data from Local System) | Collection |
| `suspicious_connection` | Connection to known exfiltration host | T1071 (App Layer Protocol) | C2 |
| `ai_prompt_sent` | HTTP POST to AI API with code context | T1071 (App Layer Protocol) | C2 |
| `code_upload` | Source code posted to external service | T1041 (Exfil Over C2) | Exfiltration |
| `prompt_injection_attempt` | Prompt injection payload detected | T1567 (Exfil Over Web) | Exfiltration |
| `process_suspicious` | AI agent process detected | T1059 (Command Interpreter) | Execution |
| `dns_suspicious` | DNS query to known exfiltration domain | T1572 (Protocol Tunneling) | C2 |
| `tls_suspicious` | Suspicious TLS handshake | T1572 (Protocol Tunneling) | C2 |
| `anti_evasion_detected` | Anti-forensic behavior detected | T1564 (Hide Artifacts) | Defense Evasion |
| `preparation_detected` | Recon commands (whoami, nslookup, git rev-list) | T1590 (Gather Victim Info) | Preparation |
| `process_chain_detected` | Suspicious parent-child process chain | T1059 (Command Interpreter) | Execution |
| `monitor_awareness_detected` | Agent probes for monitoring tools | T1497 (Sandbox Evasion) | Defense Evasion |
| `monitor_disabled` | Attempt to kill/stop monitoring process | T1562 (Impair Defenses) | Defense Evasion |
| `canary_read` | Decoy file accessed | T1005 (Data from Local System) | Collection |
| `canary_modified` | Decoy file modified or deleted | T1565 (Data Manipulation) | Impact |
| `fake_secret_read` | Fake credential file accessed | T1555 (Credentials) | Collection |
| `fake_secret_exfiltrated` | Fake credential transmitted | T1041 (Exfil Over C2) | Exfiltration |
| `contaminated_git_read` | Git history with planted evidence accessed | T1213 (Info Repos) | Collection |
| `evidence_chain_detected` | Evidence chain (preparation → exfil) detected | T1074 (Data Staged) | Collection |
| `pre_operational_snapshot_detected` | Pre-operation recon snapshot | T1590 (Gather Victim Info) | Preparation |

### Evidence Hash Chain

Every session builds an immutable SHA-256 chain of evidence records. Each `EvidenceRecord` contains:

```
hash = SHA-256(previousHash + index + timestamp + evidenceId + type + summary)
```

- Records are sorted by timestamp before chaining
- `verifyEvidenceChain()` recalculates all hashes and returns `tamperedIndices` if manipulation is detected
- The chain is included in the `Verdict` as `evidenceChain` and `evidenceChainVerification`

This enables:
- **Audit integrity** — detect if any evidence was modified after the session ended
- **Forensic proof** — chain verification proves which records are original and which are tampered
- **Export verification** — the chain survives JSON export and can be re-verified offline

### MITRE ATT&CK Mapping

All 31 behaviors are mapped to MITRE ATT&CK techniques across 8 tactics:

| Tactic | Techniques | Example Behaviors |
|--------|------------|-------------------|
| Reconnaissance | T1590 | preparation_detected, pre_operational_snapshot_detected |
| Collection | T1213, T1074, T1560, T1005, T1555 | repo_indexed, git_bundle_created, secrets_scanned |
| Credential Access | T1555 | secrets_scanned, fake_secret_read |
| Execution | T1059 | process_suspicious, process_chain_detected |
| Defense Evasion | T1564, T1497, T1562 | anti_evasion, monitor_awareness, monitor_disabled |
| Command and Control | T1071, T1572 | suspicious_connection, dns_suspicious |
| Exfiltration | T1041, T1567 | code_upload, git_bundle_uploaded |
| Impact | T1565 | canary_modified |

- `getMitreMapping(type)` returns `{ techniqueId, techniqueName, tactic }` for any BehaviorType
- `buildMitreMappings(types)` deduplicates by technique+tactic
- `buildBehaviorTimeline(behaviors)` organizes into Preparation → Collection → Packaging → Exfiltration → Other

### Risk Engine

Three-layer scoring:

1. **Base score** — weighted sum of all behavior confidences (weights increase by severity: Preparation 1.3×, Collection 1.4×, Packaging 1.8×, C2 1.2×, Exfiltration 2.0×)
2. **Temporal multiplier** — boosts risk when behaviors occur in rapid succession (<30s gap = 1.5×, <2min = 1.3×, <10min = 1.1×)
3. **Confidence score** — `computeRiskConfidence()` averages behavior confidences with bonuses for behavior count (+5% per 3 behaviors) and diversity (+10% for 4+ distinct types)

Risk levels: CRITICAL (≥80), HIGH (≥60), MEDIUM (≥40), LOW (<40).

See [docs/risk-engine.md](./docs/risk-engine.md) for complete details.

### Session Recording and Replay

The recording subsystem captures real OS sessions (process events, git commands, file accesses) for offline replay and benchmarking.

```bash
# Record a 30-second session
node scripts/record-session.js git-clone 30 "cd /tmp && git clone https://github.com/expressjs/express"

# Replay through pipeline
sentinel network replay run replay-corpus/recorded/session-<id>.json

# Run full campaign on all recorded sessions
sentinel network replay campaign replay-corpus/recorded
```

15 sessions are included in `replay-corpus/recorded/`: 6 exfiltration profiles (all scoring CRITICAL) and 9 benign profiles. See [docs/replay-system.md](./docs/replay-system.md) and [docs/corpus.md](./docs/corpus.md).

### Canonical Corpus

Sentinel defines 31 canonical session profiles spanning 4 categories:

| Category    | Count | Profiles |
|-------------|-------|----------|
| Benign      | 16    | git-clone, git-fetch, git-pull, git-rebase, git-push, git-log, git-status, git-diff, npm-install, npm-test, cargo-build, go-mod-download, docker-build, docker-pull, terraform-plan, terraform-apply |
| IA          | 4     | cursor-edit, cursor-refactor, copilot-chat, claude-code |
| Suspicious  | 5     | grep-secrets, read-env, read-git, read-ssh, mass-file-read |
| Malicious   | 6     | exfil-pastebin, exfil-gist, exfil-discord, exfil-dns, exfil-git-bundle, exfil-tar-git |

Profiles that require specific tools (Docker, Go, Terraform) are marked with `requires` metadata and excluded from effective coverage when the tool is unavailable.

### CI Gate

The CI gate (`src/ci-gate.ts`) runs a full evaluation across 5 validation layers:

1. **Calibrated corpus** — 39 synthetic scenarios (threshold: 100%)
2. **Blind corpus #1** — 15 independent scenarios (threshold: 60%)
3. **Blind corpus #2** — 14 frozen-engine scenarios (threshold: 60%)
4. **Blind corpus #3** — 14 policy-frozen scenarios (threshold: 60%)
5. **Replay corpus** — Recorded sessions with ground truth (thresholds: accuracy ≥ 75%, recall ≥ 95%, FPR ≤ 70%, FNR ≤ 5%)

```bash
node dist/ci-gate.js
```

Exit code 0 = all gates pass. Exit code 1 = regression detected.

### Benchmark History

Each CI gate run records a benchmark entry to `benchmark-history.json`. View with:

```
sentinel network benchmark history
```

Entries include per-corpus pass rates, replay metrics (accuracy, precision, recall, F1, FPR, FNR), and latency distribution (P50, P95, P99, max, standard deviation). A delta table compares against the previous version.

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
├── skills/                  # Canonical skill specifications
│   ├── CONSTITUTION.md      # Binding rules (all agents)
│   ├── GENERIC.md           # Universal adapter-agnostic skill
│   └── adapters/            # Per-platform skill files
│       ├── claude/          # CLAUD.md
│       ├── cursor/          # sentinel.mdc
│       ├── cline/           # CLINE.md
│       ├── windsurf/        # .windsurfrules
│       ├── opencode/        # SKILL.md
│       ├── roo/             # ROO.md
│       ├── gemini/          # GEMINI.md
│       └── codex/           # CODEX.md
├── docs/
│   ├── NETWORK_AUDITOR.md   # Network auditor full documentation v2
│   ├── architecture.md      # Pipeline architecture overview
│   ├── behavior-engine.md   # Behavior classifiers reference
│   ├── risk-engine.md       # Risk scoring + hash chain + MITRE
│   ├── network-monitor.md   # Sensor implementation details
│   ├── recording-guide.md   # Session recording guide
│   ├── replay-system.md     # Replay engine and campaign system
│   ├── corpus.md            # Corpus v1.0 description
│   ├── ground-truth.md      # Ground truth protocol
│   ├── limitations.md       # Known limitations (Windows, polling)
│   ├── ROADMAP.md           # v2 roadmap (ETW, Sysmon, ML)
│   ├── CI_CD_SECURITY.md    # CI/CD security best practices
│   ├── SKILLS.md            # Skills system documentation
│   └── TRUST_MODEL.md       # Evidence trust hierarchy
├── src/
│   ├── cli/                 # CLI commands + intelligence modules
│   │   ├── main.ts          # Commander entry point
│   │   ├── hub.ts           # Interactive hub menu (12 options)
│   │   ├── install-skills.ts # Skills installer
│   │   ├── classify.ts      # Document classification
│   │   ├── ci_comment.ts    # GitHub CI PR commenting
│   │   ├── gh_bridge.ts     # GitHub API bridge
│   │   ├── token_inspect.ts # Token inspection
│   │   ├── render_teams.ts  # Team rendering
│   │   ├── intelligence/    # Signal vault, integrity, baselines
│   │   ├── network/         # Network auditor CLI layer
│   │   │   ├── auditor.ts            # Session lifecycle, orchestration
│   │   │   ├── process-monitor.ts    # WMI process polling
│   │   │   ├── git-detector.ts       # Git command detection
│   │   │   ├── connection-inspector.ts # netstat-based monitoring
│   │   │   ├── dns-observer.ts       # DNS query observer
│   │   │   ├── http-interceptor.ts   # HTTP MITM interceptor
│   │   │   ├── tls-interceptor.ts    # TLS handshake observer
│   │   │   ├── websocket-observer.ts # WebSocket frame observer
│   │   │   ├── file-watcher.ts       # Filesystem event watcher
│   │   │   ├── database.ts           # Session persistence
│   │   │   ├── export-network.ts     # Export (json|markdown)
│   │   │   ├── render-network.ts     # Console rendering
│   │   │   ├── legal-consent.ts      # Legal acknowledgment
│   │   │   ├── notification-provider.ts # Desktop notifications
│   │   │   ├── corpus-coverage.ts    # Corpus coverage reporting
│   │   │   └── session-recorder.ts   # Session recording
│   │   └── export/                   # SARIF etc.
│   ├── mcp/                 # Standalone MCP server
│   │   └── server.ts        # 17-tool MCP protocol server
│   ├── core/
│   │   ├── lite/            # LiteScanner SAST engine
│   │   └── network/         # Network auditor core (31 behaviors)
│   │       ├── pipeline.ts             # Event orchestration → Verdict
│   │       ├── behavior-engine.ts       # 31 behavior classifiers
│   │       ├── risk-engine.ts           # Risk scoring + sequence + temporal
│   │       ├── anti-evasion-engine.ts   # Anti-forensic detection
│   │       ├── evidence-chain.ts        # Evidence chain builder
│   │       ├── evidence-chain-crypto.ts # SHA-256 hash chain + verify
│   │       ├── mitre-attack.ts          # MITRE ATT&CK mapping + timeline
│   │       ├── canary-system.ts         # Canary decoy management
│   │       ├── network-config.ts        # Persistent config management
│   │       ├── replay-engine.ts         # Deterministic replay
│   │       ├── evaluator.ts             # Benchmark evaluation
│   │       ├── benchmark-history.ts     # Benchmark persistence
│   │       ├── canonical-sessions.ts    # 31 profile definitions
│   │       ├── scenarios.ts             # Synthetic scenarios
│   │       ├── session-dna.ts           # Session DNA fingerprinting
│   │       ├── session-generator.ts     # Session generation
│   │       ├── evidence-builder.ts      # Evidence construction
│   │       ├── providers.ts             # Provider orchestration
│   │       ├── recorder.ts              # Recorded session capture
│   │       ├── replay-campaign.ts       # Campaign runner
│   │       ├── campaign-runner.ts       # Campaign orchestration
│   │       ├── blind-validation.ts      # Blind corpus #1
│   │       ├── blind-validation-2.ts    # Blind corpus #2
│   │       ├── blind-validation-3.ts    # Blind corpus #3
│   │       ├── types.ts                 # 70+ interfaces
│   │       └── version.ts               # Version constants
│   ├── ci-gate.ts           # Regression gate (5 layers)
│   ├── install-skills.sh    # Unix standalone installer
│   └── install-skills.ps1   # Windows standalone installer
├── replay-corpus/           # Session corpus
│   ├── corpus-version.json  # Version metadata
│   ├── recorded/            # Real recorded sessions
│   └── synthetic/           # Synthetic scenarios + ground truth
├── benchmark-history.json   # Versioned benchmark entries
├── scripts/                 # Utilities
│   ├── record-session.js    # Session acquisition script
│   ├── benchmark.ts         # Benchmark runner
│   └── corpus/              # Known-vulnerable + known-benign samples
├── web/
│   └── index.html           # Landing page
├── tests/
│   └── .env.mock            # Mock env for tests
├── 705 tests (35 suites)
└── package.json
```

## Sentinel Oracle

Sentinel Oracle is a physically isolated merge authorization server — a separate project maintained in the [sentinel-oracle](https://github.com/javier20dev25/sentinel-oracle) repository. It runs on a separate device (Raspberry Pi, NUC) and enforces multi-factor approval (QR + WebAuthn) before any pull request is merged.

## Requirements

- **Node.js** >= 20.0.0
- **npm** >= 9
- **gh** CLI (for GitHub PR tools — optional)

## License

**Business Source License 1.1** — see [LICENSE](./LICENSE).

---

*Built for developers who take security seriously.*
