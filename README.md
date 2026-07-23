# Sentinel — Security Intelligence Platform

> SAST Scanner · Supply Chain Shield · Network Auditor · Build Intelligence · Skills System · MCP Server

Sentinel is a deterministic, local-first security intelligence platform. It scans source code for vulnerabilities, audits software supply chains, monitors network behavior for exfiltration attempts, observes build processes, and verifies system integrity — all without sending data to third-party services.

It also integrates with AI coding agents (Claude, Cursor, Cline, Windsurf, OpenCode, Roo, Gemini, Codex) via platform-specific skills and a Model Context Protocol (MCP) server, but Sentinel works standalone as a CLI security tool for any development workflow.

---

## Contents

| I want to... | Go to |
|--------------|-------|
| Install and try it | [Quick Start](#quick-start) |
| Understand what it does | [Core Capabilities](#core-capabilities) |
| See a real output | [Demo](#demo) |
| Understand the architecture | [Architecture](#architecture) |
| Read the design principles | [Design Philosophy](#design-philosophy) |
| Compare with other tools | [How Sentinel Compares](#how-sentinel-compares) |
| Find a use case | [Use Cases](#use-cases) |
| Learn the CLI commands | [CLI Commands](#cli-commands-70) |
| See benchmark numbers | [Benchmarks](#benchmarks) |
| Understand maturity level | [Current Maturity](#current-maturity) |
| Read the full documentation | [Documentation](#documentation) |
| Contribute | [Contributing](./CONTRIBUTING.md) |
| Report a vulnerability | [Security](./SECURITY.md) |
| See the roadmap | [Roadmap](./ROADMAP.md) |

---

## Current Maturity

| Area | Status |
|------|--------|
| **SAST (30 rules)** | Production-ready |
| **Supply chain audit** | Production-ready |
| **Network auditor** | Production-ready |
| **GitHub integration** | Production-ready |
| **Build intelligence** | Production-ready |
| **Red Team emulation** | Research-grade (simulated) |
| **Replay & regression** | Implemented, needs external validation |
| **Atomic RT validation** | Pending (requires isolated VM) |
| **CALDERA campaigns** | Pending |
| **External benchmarking** | Pending |

**1,040 automated regression and unit tests** covering implemented functionality. CI runs on Node 20 + 22.

---

## Quick Start

```bash
# Install globally
npm install -g @sentinel/cli

# Scan a project for vulnerabilities
sentinel-cli scan ./src

# Audit all dependencies
sentinel-cli audit-deps

# Start network monitoring
sentinel-cli network start

# Observe a build
sentinel-cli build observe "npm run build"

# Install skills for AI coding agents (optional)
sentinel-cli install-skills
```

---

## Core Capabilities

### 1. Static Analysis (SAST)

30 deterministic rules covering: secrets detection, eval() usage, network access, environment variable exposure, command injection, SQL injection, prototype pollution, crypto misuse, obfuscation, and workflow poisoning.

```bash
sentinel-cli scan <path>
```

### 2. Supply Chain Security

Multi-layer package auditing without installing anything:

| Layer | Mechanism |
|-------|-----------|
| CVE lookup | OSV.dev batch query (up to 1,000 packages) |
| Typosquat detection | Damerau-Levenshtein + homoglyph detection |
| Provenance verification | SLSA attestation via `npm attestation verify` |
| Registry reputation | 6-factor scoring (age, maintainers, versions, deprecation, description, homepage) |
| Malicious patterns | Embedded secrets, suspicious install scripts |

```bash
sentinel-cli audit-deps           # Full dependency audit
sentinel-cli verify-pkg <name>    # Single package check
sentinel-cli sbom                 # CycloneDX v1.5 SBOM generation
sentinel-cli deps-tree <path>     # Transitive dependency scan
```

### 3. Network Auditor (Behavior-based Exfiltration Detection)

Monitors process execution, Git activity, network connections, and DNS queries to detect repository exfiltration patterns. Unlike traditional tools that inspect packet contents, Sentinel reconstructs behavioral chains (preparation → collection → packaging → exfiltration) to detect the *shape* of an attack regardless of the tools used.

**31 behavior classifiers** mapped to MITRE ATT&CK, with SHA-256 evidence chaining and timeline reconstruction.

```bash
sentinel-cli network start         # Start a live audit session
sentinel-cli network stop          # Stop and produce verdict
sentinel-cli network status        # Current session status
sentinel-cli network history -l N  # Last N sessions
sentinel-cli network session <id>  # Session detail
sentinel-cli network export <id>   # Export (json|markdown)
```

### 4. Build Flight Recorder

Captures a complete forensic record of any build command: process tree (filtered to build descendants), file artifacts created during the build, and a SHA-256 integrity chain. Outputs a `CLEAN`/`REVIEW` verdict based on anomalous processes.

```bash
sentinel-cli build observe "npm run build"
sentinel-cli build observe "make -j4" --verbose
sentinel-cli build observe "go build ./..." --json
sentinel-cli build explain              # Why the score is what it is
sentinel-cli inspect                    # Evidence graph, centrality, dominators
```

### 5. GitHub Integration

```bash
sentinel-cli pr-audit --repo R --pr N     # Audit a single PR
sentinel-cli workflow full-audit --repo R # Audit ALL PRs in one repo
```

PR Bot auto-analyzes all open PRs across your repos, posts findings as PR comments with Check Run status.

### 6. System Integrity

| Command | Description |
|---------|-------------|
| `sentinel-cli integrity` | Chain-of-trust host verification (hash, PATH, vault, clock, manifest) |
| `sentinel-cli doctor` | Dependency health and system diagnostics |
| `sentinel-cli baseline create\|diff` | System snapshots and drift detection |
| `sentinel-cli permissions <pkg>` | Capability audit of installed packages |

### 7. Security Guard

OS-level package manager interception and git hooks:

```bash
sentinel-cli guard enable            # Intercept npm/yarn/pip installs
sentinel-cli guard status            # Check guard status
sentinel-cli precommit install       # Block commits with threats
sentinel-cli prepush install         # Block pushes with threats
sentinel-cli install npm <pkg>       # Scan then install
```

### 8. Threat Intelligence Memory

```bash
sentinel-cli memory --status         # View vault status
sentinel-cli memory --ingest <file>  # Ingest cloud report
sentinel-cli memory --findings       # Query past findings
sentinel-cli memory --threats        # Threat correlations
```

### 9. Red Team & Validation

```bash
sentinel-cli redteam --list          # 26 attack scenarios, 10 campaigns
sentinel-cli redteam --coverage      # Coverage matrix
sentinel-cli atomic --list           # 30+ Atomic RT tests mapped
sentinel-cli atomic --dry-run        # Preview without executing
sentinel-cli coverage                # MITRE ATT&CK matrix
sentinel-cli replay list             # Replay datasets
sentinel-cli regression list         # Regression suites
```

### 10. Interactive Hub

`sentinel-cli hub` launches a bilingual (English/Spanish) operations menu:

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

## What Sentinel Does NOT Do

- **Replace EDR** — Sentinel observes builds and monitors networks, not runtime
- **Replace SAST tools** — it complements them with build-time context
- **Replace DAST** — no dynamic testing of running applications
- **Replace SCA** — uses OSV for CVE lookup, not a full SCA replacement
- **Block builds** — it reports, not prevents (no auto-remediation)
- **Detect zero-days** — relies on observable patterns, not vulnerability research
- **Analyze firmware/hypervisor** — out of scope

---

## AI Coding Agent Integration (Optional)

### Skills System

Platform-specific instruction files that teach AI agents to call Sentinel for all security-relevant tasks. Available for 8 agent platforms:

```bash
sentinel-cli install-skills           # auto-detect agents
sentinel-cli install-skills --list    # show detected agents
sentinel-cli install-skills --all     # install for all platforms
```

Each skill teaches the agent:
- **Sentinel primacy** — call `sentinel-cli scan` before reading code with the model
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

### MCP Server

Model Context Protocol server (`sentinel-cli mcp`) exposing 17 tools as standard MCP tool calls:

| Category | Tools |
|----------|-------|
| SAST + Analysis | scan, verify-pkg, doctor, integrity, audit-deps, deps-tree, sbom |
| Security Gate | install, guard, trust-cache, policy |
| Intelligence | memory, check-classified, baseline, permissions |
| GitHub PR Tools | gh-pr-list, gh-pr-view, gh-pr-diff, gh-repo-list |

```bash
sentinel-cli mcp                      # stdio mode (default)
sentinel-cli mcp --http --port 3003   # HTTP/SSE mode
```

---

## Demo

```
$ sentinel-cli build observe "npm run build"

  ══════════════════════════════════════════════
   SENTINEL BUILD OBSERVATION
  ══════════════════════════════════════════════

  CLEAN   90/100  9.0s

  What happened
  ──────────────
  Tools:     none detected
  Processes: 0 observed

  Build Identity
  ──────────────
  Hermetic:      95/100
  Reproducible:  0/100
  Confidence:    0

  Why this score
  ──────────────
  -5  [MEDIUM] 235 named pipe(s) detected (inter-process communication not tracked)
  -15  No build tools detected (may not be a build)
  +5  Hermetic build (95/100)
  +5  No network activity during build

  Nothing requires immediate action.
```

```
$ sentinel-cli pr-audit --repo javier20dev25/sentinel-cli --pr 42

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✔ CLEAN  │  PR #42  │  javier20dev25/sentinel-cli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Title:    feat: add new detection rule
  Author:   contributor123
  Files:    3 changed
  Lines:    +45/-12
  Rules:    30 SAST rules (code + secrets + filenames)
  Status:   CLEAN BILL OF HEALTH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Design Philosophy

Sentinel exists because of six convictions:

1. **Evidence over signatures.** Observe what happened, not what matches a pattern.
2. **Explainability over opaque scoring.** Every verdict traces to observed evidence.
3. **Deterministic before probabilistic.** 30 SAST rules before Bayesian inference.
4. **Replay before repetition.** Capture once, validate many times.
5. **Observable systems produce better security.** If you can't see it, you can't secure it.
6. **Offensive thinking improves defensive validation.** Red Team validates Blue Team.

---

## How Sentinel Compares

| Tool | What it does | Sentinel's approach |
|------|-------------|-------------------|
| CodeQL | Static analysis (source code patterns) | Observes build behavior, not just code patterns |
| Snyk | Dependency vulnerability scanning | Multi-layer supply chain + behavioral analysis |
| Trivy | Container image scanning | Build-time observation, not image scanning |
| Falco | Runtime security (syscall monitoring) | Build-scoped observation with forensic detail |
| Sysmon | System telemetry collection | Reconstructs causal chains from telemetry |
| Sigstore | Artifact signing/verification | Captures provenance during build, verifies post-build |

**Sentinel is not better than these tools.** It does something different: it observes builds, monitors networks, and explains trust. It complements SAST, SCA, and EDR — it doesn't replace them.

---

## Use Cases

| When | How |
|------|-----|
| **Pull Request review** | `sentinel-cli pr-audit` posts findings as PR comment |
| **Release pipeline** | `sentinel-cli build observe` as quality gate |
| **Incident investigation** | `sentinel-cli build explain` for causal analysis |
| **Supply chain audit** | `sentinel-cli audit-deps` for dependency trust |
| **Red Team validation** | `sentinel-cli redteam` for attack simulation |
| **Regression detection** | `sentinel-cli regression` for automated validation |
| **AI agent integration** | `sentinel-cli mcp` for 17 tool calls via MCP protocol |
| **System integrity** | `sentinel-cli integrity` for chain-of-trust verification |
| **Package interception** | `sentinel-cli guard enable` for OS-level npm/pip blocking |
| **Threat history** | `sentinel-cli memory` for local threat intelligence vault |

---

## CLI Commands (70+)

### Security Scanning
```bash
sentinel-cli scan <path>               # SAST findings by severity
sentinel-cli audit-deps                # Dependency audit (lockfile + OSV)
sentinel-cli verify-pkg <name>         # Single package check
sentinel-cli sbom                      # CycloneDX v1.5 SBOM
sentinel-cli deps-tree <path>          # Transitive dependency scan
```

### Build Intelligence
```bash
sentinel-cli build observe <cmd>       # Verdict + trust + explanation
sentinel-cli build explain             # Why the score is what it is
sentinel-cli inspect                   # Evidence graph, centrality, dominators
sentinel-cli top                       # Top findings from recent builds
```

### Network & Red Team
```bash
sentinel-cli network start             # Start live monitoring
sentinel-cli network stop              # Stop and get verdict
sentinel-cli redteam --list            # 26 attacks, 10 campaigns
sentinel-cli atomic --list             # 30+ Atomic RT tests mapped
sentinel-cli coverage                  # MITRE ATT&CK matrix
```

### GitHub Integration
```bash
sentinel-cli pr-audit --repo R --pr N  # Audit a single PR
sentinel-cli workflow full-audit       # Audit ALL PRs in a repo
```

### Security Guard & Hooks
```bash
sentinel-cli guard enable              # Intercept npm/yarn/pip
sentinel-cli precommit install         # Block commits with threats
sentinel-cli prepush install           # Block pushes with threats
sentinel-cli install npm <pkg>         # Scan then install
```

### Validation
```bash
sentinel-cli replay list               # Replay datasets
sentinel-cli regression list           # Regression suites
sentinel-cli baseline-pro list         # Baseline profiles
sentinel-cli stress config             # Stress testing
```

### AI Integration
```bash
sentinel-cli mcp                       # MCP server (17 tools)
sentinel-cli hub                       # Interactive operations menu
sentinel-cli install-skills            # Install for 8 AI agents
```

### System
```bash
sentinel-cli integrity                 # Chain-of-trust verification
sentinel-cli doctor                    # System health check
sentinel-cli baseline create|diff      # System snapshots
sentinel-cli permissions <pkg>         # Capability audit
sentinel-cli memory --status           # Threat vault status
sentinel-cli token-inspect <token>     # Classify and risk-assess a token
```

---

## Benchmarks

```bash
sentinel-cli benchmark                 # SAST precision/recall
sentinel-cli network benchmark history # Detection pipeline metrics
```

| Layer | Scenarios | Pass Rate |
|-------|-----------|-----------|
| Calibrated corpus | 39 | 79.5% |
| Blind corpus #1 | 15 | 60.0% |
| Blind corpus #2 | 14 | 92.9% |
| Blind corpus #3 | 14 | 85.7% |
| Replay corpus | 200 | 80.0% accuracy, 100% recall |

---

## Evidence Trust Hierarchy

| Tier | Source | Confidence |
|------|--------|------------|
| Tier 1 | Sentinel telemetry (ETW, eBPF, auditd) | High |
| Tier 2 | Sentinel inference (graph, Bayesian, trust) | Medium |
| Tier 3 | External feeds (OSV, MITRE, registry) | Variable |
| Tier 4 | Model reasoning (when used via MCP/skills) | Lowest |

Sentinel evidence (Tier 1) overrides model reasoning (Tier 4).

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](./ARCHITECTURE.md) | 938-line technical architecture |
| [Build Intelligence](./docs/BUILD_INTELLIGENCE.md) | Complete feature reference |
| [Network Auditor](./docs/NETWORK_AUDITOR.md) | Behavior-based detection |
| [Trust Model](./docs/TRUST_MODEL.md) | Evidence hierarchy and calibration |
| [Skills](./docs/SKILLS.md) | AI agent integration guide |
| [Classification Policy](./CLASSIFICATION_POLICY.md) | Detection policy contract |
| [Technical Report](./INFORME_TECNICO_v2.md) | 801-line technical report |
| [Contributing](./CONTRIBUTING.md) | Development guide |
| [Security](./SECURITY.md) | Vulnerability reporting |
| [Roadmap](./ROADMAP.md) | Direction without dates |

---

## Requirements

- **Node.js** >= 20.0.0
- **npm** >= 9
- **gh** CLI (for GitHub PR tools — optional)

---

## License

**Business Source License 1.1** — see [LICENSE](./LICENSE).

Changes to GPL v2.0 on 2030-05-20.

---

*Built for developers who take security seriously.*
