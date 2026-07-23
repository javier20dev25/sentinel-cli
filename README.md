# Sentinel — Security Intelligence Platform

> SAST Scanner · Supply Chain Shield · Network Auditor · Skills System · MCP Server

Sentinel is a deterministic, local-first security intelligence platform. It scans source code for vulnerabilities, audits software supply chains, monitors network behavior for exfiltration attempts, and verifies system integrity — all without sending data to third-party services.

It also integrates with AI coding agents (Claude, Cursor, Cline, Windsurf, OpenCode, Roo, Gemini, Codex) via platform-specific skills and a Model Context Protocol (MCP) server, but Sentinel works standalone as a CLI security tool for any development workflow.

## Quick Start

```bash
# Install globally
npm install -g @sentinel/cli

# Scan a project for vulnerabilities
sentinel scan ./src

# Audit all dependencies
sentinel audit-deps

# Start network monitoring
sentinel network start

# Install skills for AI coding agents (optional)
sentinel install-skills
```

## Core Capabilities

### Static Analysis (SAST)

30 deterministic rules covering: secrets detection, eval() usage, network access, environment variable exposure, command injection, SQL injection, prototype pollution, crypto misuse, obfuscation, and workflow poisoning.

```bash
sentinel scan <path>
```

### Supply Chain Security

Multi-layer package auditing without installing anything:

| Layer | Mechanism |
|-------|-----------|
| CVE lookup | OSV.dev batch query (up to 1,000 packages) |
| Typosquat detection | Damerau-Levenshtein + homoglyph detection |
| Provenance verification | SLSA attestation via `npm attestation verify` |
| Registry reputation | 6-factor scoring (age, maintainers, versions, deprecation, description, homepage) |
| Malicious patterns | Embedded secrets, suspicious install scripts |

```bash
sentinel audit-deps           # Full dependency audit
sentinel verify-pkg <name>    # Single package check
sentinel sbom                 # CycloneDX v1.5 SBOM generation
```

### Network Auditor (Behavior-based Exfiltration Detection)

Monitors process execution, Git activity, network connections, and DNS queries to detect repository exfiltration patterns. Unlike traditional tools that inspect packet contents, Sentinel reconstructs behavioral chains (preparation → collection → packaging → exfiltration) to detect the *shape* of an attack regardless of the tools used.

**31 behavior classifiers** mapped to MITRE ATT&CK, with SHA-256 evidence chaining and timeline reconstruction.

```bash
sentinel network start         # Start a live audit session
sentinel network stop          # Stop and produce verdict
sentinel network status        # Current session status
sentinel network history -l N  # Last N sessions
sentinel network session <id>  # Session detail
sentinel network export <id>   # Export (json|markdown)
```

See [Network Auditor Documentation](./docs/NETWORK_AUDITOR.md).

### Build Flight Recorder

Captures a complete forensic record of any build command: process tree (filtered to build descendants), file artifacts created during the build, and a SHA-256 integrity chain. Outputs a `CLEAN`/`REVIEW` verdict based on anomalous processes.

```bash
sentinel build "npm run build"
sentinel build "make -j4" --timeout 60000
sentinel build "go build ./..." --provenance   # full report
sentinel build "gcc -O2 *.c -o app" --save     # save for diff
sentinel build "gcc -O2 *.c -o app" --provenance --save  # second run shows diff
```

See [Build Flight Recorder Documentation](./docs/build-flight-recorder.md).

### System Integrity

| Command | Description |
|---------|-------------|
| `sentinel integrity` | Chain-of-trust host verification (hash, PATH, vault, clock, manifest) |
| `sentinel doctor` | Dependency health and system diagnostics |
| `sentinel baseline create\|diff` | System snapshots and drift detection |
| `sentinel permissions <pkg>` | Capability audit of installed packages |

### Interactive Hub

`sentinel hub` launches a bilingual (English/Spanish) operations menu:

```
  0. PR Bot — Auto-Analyze All Open PRs
  1. Select Workspaces & Run Audits
  2. System Doctor (Health Check)
  3. Integrity Check
  4. Permissions Audit
  5. Scan Directory/File
  6. Sentinel Guard & Configuration
  7. Classified Documents
  8. Manage Signal Vault (Memory)
  9. Security — Integrity & Trust Policy
 10. Network Auditor
 11. Exit
```

---

## AI Coding Agent Integration (Optional)

Sentinel integrates with AI coding agents through two mechanisms:

### Skills System

Platform-specific instruction files that teach AI agents to call Sentinel for all security-relevant tasks. Available for 8 agent platforms:

```bash
sentinel install-skills           # auto-detect agents
sentinel install-skills --list    # show detected agents
sentinel install-skills --all     # install for all platforms
```

Each skill teaches the agent:
- **Sentinel primacy** — call `sentinel scan` before reading code with the model (0 tokens vs. expensive model analysis)
- **Evidence attachment** — every security claim must include verbatim Sentinel output
- **Trust hierarchy** — Sentinel evidence (Tier 1) overrides model reasoning (Tier 4)
- **Workflows** — PR review, package audit, host integrity, full audit pipelines

| Agent | Format | File |
|-------|--------|------|
| Claude Code | Markdown | `skills/adapters/claude/CLAUD.md` |
| Cursor | YAML + MDC | `skills/adapters/cursor/sentinel.mdc` |
| Cline | Markdown | `skills/adapters/cline/CLINE.md` |
| Windsurf | Flat rules | `skills/adapters/windsurf/.windsurfrules` |
| OpenCode | Markdown | `skills/adapters/opencode/SKILL.md` |
| Roo Code | Markdown | `skills/adapters/roo/ROO.md` |
| Gemini CLI | YAML + triple-file | `skills/adapters/gemini/GEMINI.md` |
| OpenAI Codex | Markdown | `skills/adapters/codex/CODEX.md` |

See [docs/SKILLS.md](./docs/SKILLS.md) for skill authoring guide.

### MCP Server

Model Context Protocol server (`sentinel mcp`) exposing 17 tools as standard MCP tool calls:

| Category | Tools |
|----------|-------|
| SAST + Analysis | scan, verify-pkg, doctor, integrity, audit-deps, deps-tree, sbom |
| Security Gate | install, guard, trust-cache, policy |
| Intelligence | memory, check-classified, baseline, permissions |
| GitHub PR Tools | gh-pr-list, gh-pr-view, gh-pr-diff, gh-repo-list |

```bash
sentinel mcp                      # stdio mode (default)
sentinel mcp --http --port 3003   # HTTP/SSE mode
```

Connect from any MCP-compatible agent (Claude Desktop, Cursor, Cline, etc.).

---

## Network Auditor (in detail)

### Telemetry Sources

| Source | Mechanism | Coverage |
|--------|-----------|----------|
| Process monitor | WMI polling (100ms) | Process creation, command lines, parent-child chains |
| Git detector | WMI polling (100ms) | Git actions classified by type |
| Connection inspector | `netstat -ano` (500ms) | TCP connections to external hosts |
| DNS observer | `ipconfig /displaydns` (2000ms) | DNS queries to known exfiltration domains |
| HTTP interceptor | MITM (optional) | HTTP request/response inspection |
| TLS interceptor | Certificate injection (optional) | TLS handshake inspection |
| WebSocket observer | Process + connection correlation | WebSocket frame inspection |
| File watcher | Filesystem events | File read/write access patterns |

### Behavior Detection (31 Behaviors)

| Behavior | Trigger | MITRE | Stage |
|----------|---------|-------|-------|
| `repo_indexed` | Repository indexed by AI agent | T1213 | Collection |
| `git_history_read` | `git log` / `git rev-list` | T1213 | Collection |
| `git_objects_read` | `git cat-file` / `git ls-tree` | T1213 | Collection |
| `git_bundle_created` | `git bundle create` | T1074 | Packaging |
| `git_bundle_uploaded` | Bundle sent to remote host | T1041 | Exfiltration |
| `git_archive_created` | `git archive` or `tar` + `.git` | T1560 | Packaging |
| `secrets_scanned` | Credential store access | T1555 | Collection |
| `secrets_exfiltrated` | Secrets transmitted remotely | T1041 | Exfiltration |
| `embeddings_generated` | AI embedding vectors on repo | T1213 | Collection |
| `full_repo_snapshot` | `git push --mirror` | T1074 | Collection |
| `canary_exfiltrated` | Decoy file transmitted | T1041 | Exfiltration |
| `mass_file_read` | Bulk file read | T1005 | Collection |
| `suspicious_connection` | Connection to exfiltration host | T1071 | C2 |
| `ai_prompt_sent` | HTTP POST to AI API | T1071 | C2 |
| `code_upload` | Source code posted externally | T1041 | Exfiltration |
| `prompt_injection_attempt` | Prompt injection payload | T1567 | Exfiltration |
| `process_suspicious` | AI agent process | T1059 | Execution |
| `dns_suspicious` | DNS to exfiltration domain | T1572 | C2 |
| `tls_suspicious` | Suspicious TLS handshake | T1572 | C2 |
| `anti_evasion_detected` | Anti-forensic behavior | T1564 | Defense Evasion |
| `preparation_detected` | Recon commands (whoami, git rev-list) | T1590 | Preparation |
| `process_chain_detected` | Suspicious parent-child chain | T1059 | Execution |
| `monitor_awareness_detected` | Probes for monitoring tools | T1497 | Defense Evasion |
| `monitor_disabled` | Attempt to kill monitoring | T1562 | Defense Evasion |
| `canary_read` | Decoy file accessed | T1005 | Collection |
| `canary_modified` | Decoy file modified | T1565 | Impact |
| `fake_secret_read` | Fake credential accessed | T1555 | Collection |
| `fake_secret_exfiltrated` | Fake credential transmitted | T1041 | Exfiltration |
| `contaminated_git_read` | Planted evidence accessed | T1213 | Collection |
| `evidence_chain_detected` | Evidence chain detected | T1074 | Collection |
| `pre_operational_snapshot_detected` | Pre-operation snapshot | T1590 | Preparation |

### Evidence Hash Chain

Every session builds an immutable SHA-256 chain of evidence records:

```
hash = SHA-256(previousHash + index + timestamp + evidenceId + type + summary)
```

- `verifyEvidenceChain()` recalculates all hashes and reports tampered indices
- The chain survives JSON export and can be re-verified offline
- Enables audit integrity, forensic proof, and export verification

### MITRE ATT&CK Coverage

| Tactic | Techniques | Example Behaviors |
|--------|------------|-------------------|
| Reconnaissance | T1590 | preparation_detected |
| Collection | T1213, T1074, T1560, T1005, T1555 | repo_indexed, secrets_scanned |
| Credential Access | T1555 | secrets_scanned, fake_secret_read |
| Execution | T1059 | process_suspicious |
| Defense Evasion | T1564, T1497, T1562 | anti_evasion, monitor_disabled |
| Command and Control | T1071, T1572 | suspicious_connection, dns_suspicious |
| Exfiltration | T1041, T1567 | code_upload, git_bundle_uploaded |
| Impact | T1565 | canary_modified |

### Risk Engine

Three-layer scoring:
1. **Base score** — weighted sum with sequence multipliers (Preparation 1.3× → Exfiltration 2.0×)
2. **Temporal multiplier** — boosts risk on rapid succession (<30s = 1.5×)
3. **Confidence** — `computeRiskConfidence()` with behavior count + diversity bonuses

Risk levels: CRITICAL (≥80), HIGH (≥60), MEDIUM (≥40), LOW (<40).

### Session Recording and Replay

```bash
# Record a real OS session
node scripts/record-session.js git-clone 30 "cd /tmp && git clone ..."

# Replay through pipeline
sentinel network replay run replay-corpus/recorded/session-<id>.json

# Run full campaign
sentinel network replay campaign replay-corpus/recorded
```

15 recorded sessions (6 exfiltration, 9 benign) + 31 synthetic profiles in `replay-corpus/`.

### Corpus Coverage

```bash
sentinel network corpus coverage replay-corpus
```

Reports captured vs missing profiles, environment-dependent profiles, effective coverage.

---

## Benchmarks

Sentinel includes two independent benchmark systems:

### 1. SAST Benchmark (`sentinel benchmark`)

Measures LiteScanner precision and recall against a curated corpus of known-vulnerable and known-benign fixtures:

| Fixture Type | Count | Examples |
|-------------|-------|----------|
| Known-vulnerable | 10 | malware.js, ast-threat.js, secrets.env, supply-chain.yml |
| Known-benign | 8 | normal.js, normal.py, normal.rs, normal.go |

```bash
sentinel benchmark
```

Reports per-fixture findings, precision, recall, and worst FP/FN offenders.

### 2. Network CI Gate (`sentinel network benchmark history`)

Runs the full detection pipeline against 5 validation layers, recording results to `benchmark-history.json`:

| Layer | Scenarios | Last Run |
|-------|-----------|----------|
| Calibrated corpus | 39 scenarios | 79.5% pass (31/39) |
| Blind corpus #1 | 15 scenarios | 60.0% pass (9/15) |
| Blind corpus #2 | 14 scenarios | 92.9% pass (13/14) |
| Blind corpus #3 | 14 scenarios | 85.7% pass (12/14) |
| Replay corpus | 200 sessions | 80.0% accuracy, 77.8% precision, 100% recall |

```bash
sentinel network benchmark history
```

Displays a versioned delta table comparing metrics (pass rates, accuracy, precision, recall, F1, FPR, FNR, latency percentiles) against the previous engine version.

### CI Gate

```bash
node dist/ci-gate.js
```

Exit code 0 = all gates pass. Exit code 1 = regression detected. Thresholds: calibrated 100%, blind 60%, replay accuracy ≥75%, recall ≥95%, FPR ≤70%, FNR ≤5%.

---

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
│   │   ├── benchmark.ts     # SAST benchmark runner
│   │   ├── classify.ts      # Document classification
│   │   ├── ci_comment.ts    # GitHub CI PR commenting
│   │   ├── gh_bridge.ts     # GitHub API bridge
│   │   ├── token_inspect.ts # Token inspection
│   │   ├── render_benchmark.ts  # SAST benchmark renderer
│   │   ├── render_teams.ts  # Team rendering
│   │   ├── intelligence/    # Signal vault, integrity, baselines
│   │   │   ├── signal_vault.ts         # SQLite threat intel
│   │   │   ├── supply_chain_shield.ts  # Multi-layer package audit
│   │   │   ├── integrity_manager.ts    # Chain-of-trust verification
│   │   │   ├── baseline_manager.ts     # System snapshots
│   │   │   ├── osv_integrator.ts       # OSV.dev CVE batch query
│   │   │   ├── typosquat_detector.ts   # Levenshtein + homoglyph
│   │   │   ├── provenance_verifier.ts  # SLSA attestation
│   │   │   ├── registry_reputation.ts  # 6-factor scoring
│   │   │   ├── lockfile_parser.ts      # Lockfile dependency extract
│   │   │   ├── sbom_generator.ts       # CycloneDX v1.5
│   │   │   ├── npm_audit_parser.ts     # npm audit result parser
│   │   │   ├── caps_analyzer.ts        # Capability audit
│   │   │   ├── behavioral_drift.ts     # Behavioral monitoring
│   │   │   ├── homoglyph_detector.ts   # Unicode squat detection
│   │   │   ├── quarantine.ts           # Filesystem isolation
│   │   │   ├── trust_cache.ts          # Cached verdicts
│   │   │   └── memory_manager.ts       # Threat intel memory
│   │   ├── network/         # Network auditor CLI layer
│   │   │   ├── auditor.ts            # Session lifecycle
│   │   │   ├── process-monitor.ts    # WMI process polling
│   │   │   ├── git-detector.ts       # Git command detection
│   │   │   ├── connection-inspector.ts # netstat monitoring
│   │   │   ├── dns-observer.ts       # DNS query observer
│   │   │   ├── http-interceptor.ts   # HTTP MITM
│   │   │   ├── tls-interceptor.ts    # TLS handshake observer
│   │   │   ├── websocket-observer.ts # WebSocket frames
│   │   │   ├── file-watcher.ts       # Filesystem events
│   │   │   ├── database.ts           # Session persistence
│   │   │   ├── export-network.ts     # Export (json|markdown)
│   │   │   ├── render-network.ts     # Console rendering
│   │   │   ├── legal-consent.ts      # Legal acknowledgment
│   │   │   ├── notification-provider.ts # Desktop notifications
│   │   │   ├── corpus-coverage.ts    # Coverage reporting
│   │   │   └── session-recorder.ts   # Session recording
│   │   └── export/           # Export formats
│   │       ├── json.ts, markdown.ts, pdf.ts, policy.ts, sarif.ts
│   ├── mcp/                 # Standalone MCP server
│   │   └── server.ts        # 17-tool MCP protocol server
│   ├── core/
│   │   ├── lite/            # LiteScanner SAST engine
│   │   │   ├── lite_scanner.ts         # 30-rule SAST engine
│   │   │   ├── multi_ast.ts            # Multi-language AST parser
│   │   │   ├── sandbox.ts              # Safe code evaluation
│   │   │   └── fixtures/               # Test fixtures
│   │   │       ├── agents/             # Agent config samples
│   │   │       └── workflows/          # CI workflow samples
│   │   ├── network/         # Network auditor core
│   │   │   ├── pipeline.ts             # Event orchestration
│   │   │   ├── behavior-engine.ts       # 31 classifiers
│   │   │   ├── risk-engine.ts           # 3-layer scoring
│   │   │   ├── anti-evasion-engine.ts   # Anti-forensic detection
│   │   │   ├── evidence-chain.ts        # Evidence chain builder
│   │   │   ├── evidence-chain-crypto.ts # SHA-256 hash chain
│   │   │   ├── mitre-attack.ts          # MITRE ATT&CK + timeline
│   │   │   ├── canary-system.ts         # Canary decoy management
│   │   │   ├── network-config.ts        # Config persistence
│   │   │   ├── replay-engine.ts         # Deterministic replay
│   │   │   ├── evaluator.ts             # Full evaluation suite
│   │   │   ├── benchmark-history.ts     # Benchmark persistence
│   │   │   ├── canonical-sessions.ts    # 31 profile definitions
│   │   │   ├── scenarios.ts             # 39 synthetic scenarios
│   │   │   ├── blind-validation.ts      # Blind corpus #1
│   │   │   ├── blind-validation-2.ts    # Blind corpus #2
│   │   │   ├── blind-validation-3.ts    # Blind corpus #3
│   │   │   ├── session-dna.ts           # Session fingerprint
│   │   │   ├── session-generator.ts     # Session generation
│   │   │   ├── evidence-builder.ts      # Evidence construction
│   │   │   ├── providers.ts             # Provider orchestration
│   │   │   ├── recorder.ts              # Session capture
│   │   │   ├── replay-campaign.ts       # Campaign runner
│   │   │   ├── campaign-runner.ts       # Campaign orchestration
│   │   │   ├── types.ts                 # 70+ interfaces
│   │   │   └── version.ts               # Version constants
│   │   ├── agency_graph.ts             # Capability graph
│   │   ├── agency_score.ts             # Capability scoring
│   │   ├── attack_scenario.ts          # Attack scenario modeling
│   │   ├── evidence_card.ts            # Evidence card format
│   │   ├── evidence_pack.ts            # Evidence packaging
│   │   ├── graph_persistence.ts        # Graph storage
│   │   ├── ownership_graph.ts          # Code ownership graph
│   │   ├── pr_delta.ts                 # PR diff analysis
│   │   ├── risk_history.ts             # Risk history tracking
│   │   ├── token_classifier.ts         # Token classification
│   │   └── vault.ts                    # Encrypted secret store
│   ├── ci-gate.ts           # Regression gate (5 layers)
│   ├── install-skills.sh    # Unix standalone installer
│   └── install-skills.ps1   # Windows standalone installer
├── replay-corpus/           # Session corpus
│   ├── corpus-version.json  # Version metadata
│   ├── recorded/            # Real recorded sessions (15)
│   └── synthetic/           # Synthetic scenarios + ground truth
├── scripts/                 # Utilities
│   ├── record-session.js    # Session acquisition script
│   ├── benchmark.ts / .test.ts  # Benchmark runner + tests
│   └── corpus/              # Known-vulnerable + known-benign fixtures
│       ├── known-vulnerable/    # 10 malicious samples
│       └── known-benign/        # 8 benign samples
├── benchmark-history.json   # Network CI gate benchmark history
├── 705 tests (35 suites)
└── package.json
```

## Sentinel Oracle

Sentinel Oracle is a physically isolated merge authorization server — maintained in the [sentinel-oracle](https://github.com/javier20dev25/sentinel-oracle) repository.

## Requirements

- **Node.js** >= 20.0.0
- **npm** >= 9
- **gh** CLI (for GitHub PR tools — optional)

## License

**Business Source License 1.1** — see [LICENSE](./LICENSE).

---

*Built for developers who take security seriously.*
