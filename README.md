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

### Option 1: npm (recommended)

```bash
npm install -g sntnl-cli
```

### Option 2: npx (no install required)

```bash
npx sntnl-cli scan ./src
```

### Option 3: Clone and build

```bash
git clone https://github.com/javier20dev25/sentinel-cli.git
cd sentinel-cli
npm install
npm run build
node dist/cli/main.js scan ./src
```

### Usage

```bash
# Scan a project for vulnerabilities
sntnl scan ./src

# Audit all dependencies
sntnl audit-deps

# Start network monitoring
sntnl network start

# Observe a build
sntnl build observe "npm run build"

# Install skills for AI coding agents (optional)
sntnl install-skills
```

---

## Core Capabilities

### 1. Static Analysis (SAST)

30 deterministic rules covering: secrets detection, eval() usage, network access, environment variable exposure, command injection, SQL injection, prototype pollution, crypto misuse, obfuscation, and workflow poisoning.

```bash
sntnl scan <path>
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
sntnl audit-deps           # Full dependency audit
sntnl verify-pkg <name>    # Single package check
sntnl sbom                 # CycloneDX v1.5 SBOM generation
sntnl deps-tree <path>     # Transitive dependency scan
```

### 3. Network Auditor (Behavior-based Exfiltration Detection)

Monitors process execution, Git activity, network connections, and DNS queries to detect repository exfiltration patterns. Unlike traditional tools that inspect packet contents, Sentinel reconstructs behavioral chains (preparation → collection → packaging → exfiltration) to detect the *shape* of an attack regardless of the tools used.

**31 behavior classifiers** mapped to MITRE ATT&CK, with SHA-256 evidence chaining and timeline reconstruction.

```bash
sntnl network start         # Start a live audit session
sntnl network stop          # Stop and produce verdict
sntnl network status        # Current session status
sntnl network history -l N  # Last N sessions
sntnl network session <id>  # Session detail
sntnl network export <id>   # Export (json|markdown)
```

### 4. Build Flight Recorder

Captures a complete forensic record of any build command: process tree (filtered to build descendants), file artifacts created during the build, and a SHA-256 integrity chain. Outputs a `CLEAN`/`REVIEW` verdict based on anomalous processes.

```bash
sntnl build observe "npm run build"
sntnl build observe "make -j4" --verbose
sntnl build observe "go build ./..." --json
sntnl build explain              # Why the score is what it is
sntnl inspect                    # Evidence graph, centrality, dominators
```

### 5. GitHub Integration

```bash
sntnl pr-audit --repo R --pr N     # Audit a single PR
sntnl workflow full-audit --repo R # Audit ALL PRs in one repo
```

PR Bot auto-analyzes all open PRs across your repos, posts findings as PR comments with Check Run status.

### 6. System Integrity

| Command | Description |
|---------|-------------|
| `sntnl integrity` | Chain-of-trust host verification (hash, PATH, vault, clock, manifest) |
| `sntnl doctor` | Dependency health and system diagnostics |
| `sntnl baseline create\|diff` | System snapshots and drift detection |
| `sntnl permissions <pkg>` | Capability audit of installed packages |

### 7. Security Guard

OS-level package manager interception and git hooks:

```bash
sntnl guard enable            # Intercept npm/yarn/pip installs
sntnl guard status            # Check guard status
sntnl precommit install       # Block commits with threats
sntnl prepush install         # Block pushes with threats
sntnl install npm <pkg>       # Scan then install
```

### 8. Threat Intelligence Memory

```bash
sntnl memory --status         # View vault status
sntnl memory --ingest <file>  # Ingest cloud report
sntnl memory --findings       # Query past findings
sntnl memory --threats        # Threat correlations
```

### 9. Token Intelligence

Classifies and risk-assesses any token string — GitHub PATs, AWS keys, Stripe secrets, Slack tokens, and more. Produces risk scores, scope analysis, and actionable recommendations.

```bash
sntnl token-inspect <token>    # Full classification + risk assessment
```

### 10. Export (JSON, Markdown, PDF, SARIF)

Export scan findings and reports in multiple formats for integration with external tools, CI pipelines, and compliance systems.

```bash
sntnl export json              # Machine-readable JSON
sntnl export markdown          # Human-readable Markdown
sntnl export pdf               # Printable PDF report
sntnl export sarif             # SARIF for GitHub Code Scanning
sntnl export policy            # Policy configuration export
```

### 11. Data Protection

```bash
sntnl check-classified <path>  # Pre-commit classified data check
sntnl env-encrypt <file>       # AES-256-CBC encryption for .env files
sntnl env-decrypt <file>       # Decrypt .env.enc back to plaintext
```

### 12. Policy & Drift Detection

Configure security policies and track behavioral drift of package capabilities across versions.

```bash
sntnl policy                   # ci-mode, fail-closed, quarantine settings
sntnl drift                    # Track capability drift across versions
sntnl baseline create|diff     # System snapshots and drift detection
```

### 13. Graph Analytics

Advanced analysis of build process graphs: centrality measures, dominator trees, Bayesian inference shifts, and critical path detection.

```bash
sntnl graph history            # Snapshot history with chain count trend
sntnl graph diff               # Diff between latest two snapshots
sntnl graph analytics          # Centrality, dominators, Bayesian, critical path
sntnl inspect                  # Evidence graph investigation
```

### 14. Network Intelligence Deep Dive

Extended network auditor capabilities for advanced threat analysis:

```bash
sntnl network trusted          # Manage trusted agent allowlist
sntnl network doctor           # Health check, coverage, sensor drift
sntnl network blindspots       # Record and manage detection failures
sntnl network campaign         # Run validation campaigns
sntnl network benchmark        # Benchmark history across engine versions
sntnl network replay           # Replay sessions through detection pipeline
sntnl network record           # Record real OS session
sntnl network corpus           # Inspect corpus coverage
```

### 15. Red Team & Validation

```bash
sntnl redteam --list          # 26 attack scenarios, 10 campaigns
sntnl redteam --coverage      # Coverage matrix
sntnl atomic --list           # 30+ Atomic RT tests mapped
sntnl atomic --dry-run        # Preview without executing
sntnl coverage                # MITRE ATT&CK matrix
sntnl replay list             # Replay datasets
sntnl regression list         # Regression suites
```

### 10. Interactive Hub

`sntnl hub` launches a bilingual (English/Spanish) operations menu:

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
- **Auto-remediate** — it reports and blocks (via guard/precommit), but does not fix code
- **Detect zero-days** — relies on observable patterns, not vulnerability research
- **Analyze firmware/hypervisor** — out of scope

---

## AI Coding Agent Integration (Optional)

### Skills System

Platform-specific instruction files that teach AI agents to call Sentinel for all security-relevant tasks. Available for 8 agent platforms:

```bash
sntnl install-skills           # auto-detect agents
sntnl install-skills --list    # show detected agents
sntnl install-skills --all     # install for all platforms
```

Each skill teaches the agent:
- **Sentinel primacy** — call `sntnl scan` before reading code with the model
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

Model Context Protocol server (`sntnl mcp`) exposing 17 tools as standard MCP tool calls:

| Category | Tools |
|----------|-------|
| SAST + Analysis | scan, verify-pkg, doctor, integrity, audit-deps, deps-tree, sbom |
| Security Gate | check-classified, trust-cache, policy |
| Intelligence | memory, threat-query, threat-correlate |
| GitHub PR Tools | gh-pr-list, gh-pr-view, gh-pr-diff, gh-repo-list |

```bash
sntnl mcp                      # stdio mode (default)
sntnl mcp --http --port 3003   # HTTP/SSE mode
```

---

## Demo

```
$ sntnl build observe "npm run build"

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
$ sntnl pr-audit --repo javier20dev25/sntnl --pr 42

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
| **Pull Request review** | `sntnl pr-audit` posts findings as PR comment |
| **Release pipeline** | `sntnl build observe` as quality gate |
| **Incident investigation** | `sntnl build explain` for causal analysis |
| **Supply chain audit** | `sntnl audit-deps` for dependency trust |
| **Red Team validation** | `sntnl redteam` for attack simulation |
| **Regression detection** | `sntnl regression` for automated validation |
| **AI agent integration** | `sntnl mcp` for 17 tool calls via MCP protocol |
| **System integrity** | `sntnl integrity` for chain-of-trust verification |
| **Package interception** | `sntnl guard enable` for OS-level npm/pip blocking |
| **Threat history** | `sntnl memory` for local threat intelligence vault |
| **Token risk assessment** | `sntnl token-inspect` to classify any token |
| **Data protection** | `sntnl env-encrypt` for .env file encryption |
| **Graph analysis** | `sntnl graph analytics` for build process insights |
| **Network forensics** | `sntnl network record` + `replay` for session analysis |
| **Policy enforcement** | `sntnl policy` for ci-mode, fail-closed, quarantine |
| **SARIF integration** | `sntnl export sarif` for GitHub Code Scanning |

---

## CLI Commands (90+)

### Security Scanning
```bash
sntnl scan <path>               # SAST findings by severity
sntnl scan --staged             # Scan staged git changes
sntnl audit-deps                # Dependency audit (lockfile + OSV)
sntnl verify-pkg <name>         # Single package check
sntnl sbom                      # CycloneDX v1.5 SBOM
sntnl deps-tree <path>          # Transitive dependency scan
```

### Build Intelligence
```bash
sntnl build observe <cmd>       # Verdict + trust + explanation
sntnl build explain             # Why the score is what it is
sntnl build mark-release        # Mark current build as release baseline
sntnl build release             # Show current release baseline info
sntnl build trust               # Trust calibration: corpus stats, model state
sntnl build learning            # Continuous learning pipeline, model versions
```

### Graph Analytics
```bash
sntnl graph history             # Graph snapshot history with chain count trend
sntnl graph diff                # Diff between latest two graph snapshots
sntnl graph analytics           # Centrality, dominators, Bayesian shifts, critical path
sntnl inspect                   # Evidence graph, centrality, dominators
sntnl top                       # Top findings from recent builds
```

### Network & Red Team
```bash
sntnl network start             # Start live monitoring
sntnl network stop              # Stop and get verdict
sntnl network status            # Current session status
sntnl network history -l N      # Last N sessions
sntnl network session <id>      # Session detail
sntnl network export <id>       # Export session (json|markdown)
sntnl network trusted           # Manage trusted agents
sntnl network doctor            # Health check, coverage, sensor drift
sntnl network blindspots        # Record detection failures
sntnl network campaign          # Run validation campaigns
sntnl network benchmark         # Benchmark history across engine versions
sntnl network replay            # Replay recorded sessions
sntnl network record            # Record real OS session for replay
sntnl network corpus            # Inspect corpus coverage vs canonical profiles
sntnl redteam --list            # 26 attacks, 10 campaigns
sntnl atomic --list             # 30+ Atomic RT tests mapped
sntnl coverage                  # MITRE ATT&CK matrix
```

### GitHub Integration
```bash
sntnl pr-audit --repo R --pr N  # Audit a single PR
sntnl workflow full-audit       # Audit ALL PRs in a repo
sntnl workflow pr-review        # Audit + post results as PR comment
```

### Security Guard & Hooks
```bash
sntnl guard enable              # Intercept npm/yarn/pip
sntnl guard status              # Check guard status
sntnl precommit install         # Block commits with threats
sntnl prepush install           # Block pushes with threats
sntnl install npm <pkg>         # Scan then install
```

### Data Protection
```bash
sntnl check-classified <path>   # Verify files for classified data
sntnl env-encrypt <file>        # Encrypt .env with AES-256-CBC
sntnl env-decrypt <file>        # Decrypt .env.enc back to plaintext
```

### Token Intelligence
```bash
sntnl token-inspect <token>     # Classify and risk-assess any token
                                      # (GitHub PAT, AWS key, Stripe, Slack, etc.)
```

### Export
```bash
sntnl export json               # Export findings as JSON
sntnl export markdown           # Export findings as Markdown
sntnl export pdf                # Export findings as PDF
sntnl export sarif              # Export findings as SARIF
sntnl export policy             # Export policy configuration
```

### Validation
```bash
sntnl replay list               # Replay datasets
sntnl regression list           # Regression suites
sntnl baseline-pro list         # Baseline profiles
sntnl stress config             # Stress testing
```

### Policy & Drift
```bash
sntnl policy                    # Configure security policies
                                      # (ci-mode, fail-closed, quarantine)
sntnl drift                     # Track behavioral drift across versions
sntnl baseline create|diff      # System snapshots and drift detection
```

### AI Integration
```bash
sntnl mcp                       # MCP server (17 tools)
sntnl hub                       # Interactive operations menu
sntnl install-skills            # Install for 8 AI agents
sntnl guide                     # Interactive user guide
sntnl policies                  # Show security policy & guidelines
```

### System
```bash
sntnl integrity                 # Chain-of-trust verification
sntnl doctor                    # System health check
sntnl permissions <pkg>         # Capability audit
sntnl memory --status           # Threat vault status
```

---

## Benchmarks

```bash
sntnl benchmark                 # SAST precision/recall
sntnl network benchmark history # Detection pipeline metrics
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
| [Build Flight Recorder](./docs/build-flight-recorder.md) | Build observation system |
| [Network Auditor](./docs/NETWORK_AUDITOR.md) | Behavior-based detection |
| [Behavior Engine](./docs/behavior-engine.md) | 31 behavior classifiers |
| [Risk Engine](./docs/risk-engine.md) | Risk scoring methodology |
| [Trust Model](./docs/TRUST_MODEL.md) | Evidence hierarchy and calibration |
| [Skills](./docs/SKILLS.md) | AI agent integration guide |
| [CI/CD Security](./docs/CI_CD_SECURITY.md) | CI pipeline security |
| [Corpus](./docs/corpus.md) | Canonical profile system |
| [Replay System](./docs/replay-system.md) | Session replay architecture |
| [Recording Guide](./docs/recording-guide.md) | How to record sessions |
| [Ground Truth](./docs/ground-truth.md) | Validation methodology |
| [Limitations](./docs/limitations.md) | Known limitations |
| [Classification Policy](./CLASSIFICATION_POLICY.md) | Detection policy contract |
| [Technical Report](./INFORME_TECNICO_v2.md) | 801-line technical report |
| [Legal](./LEGAL.md) | Legal notices and attributions |
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
