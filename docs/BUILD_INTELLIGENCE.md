# Sentinel CLI — Build Intelligence & Red Team Framework

**Version:** 2.3.0
**Date:** July 22, 2026

---

## Overview

Sentinel CLI is a **build observation system with integrated validation and offensive emulation capabilities**. It's not a vulnerability scanner or linter. It answers four questions about each build:

1. **What happened?** (observed evidence)
2. **Why should I care?** (inference + heuristics)
3. **How would an attacker break it?** (offensive emulation)
4. **How do I validate without re-executing?** (replay + regression)

---

## Design Principles

Sentinel follows five fundamental principles:

1. **Observe before concluding.** Capture telemetry before generating inferences.
2. **Every verdict must be explainable.** Each point of the score traces to specific features, which trace to observed evidence.
3. **Evidence is immutable.** Once captured, events are not modified.
4. **Confidence is calibrated.** The Trust Score is calibrated against a corpus of known builds.
5. **Inference is separated from observation.** Sentinel explicitly distinguishes between observed, inferred, simulated, and mapped data.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Layer (70+ commands)                  │
├─────────────────────────────────────────────────────────────┤
│                   Core Network Layer                        │
│  EvidenceGraph │ TemporalGraph │ BayesianNetwork │ Trust    │
│  ReplaySystem │ RegressionSuite │ AttackCoverage │ Baseline │
├─────────────────────────────────────────────────────────────┤
│                  Detection & Analysis Layer                 │
│  15 Detection Rules │ 26 Attack Scenarios │ Graph Diff      │
├─────────────────────────────────────────────────────────────┤
│                    Data Layer                               │
│  BuildRecord │ EvidenceRelation │ TrustFeatureVector         │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Evidence Graph

**30 Evidence Types:**

| Category | Types | Source |
|----------|-------|--------|
| Processes | ProcessSpawned, ProcessTerminated, ProcessForked, ProcessInjected | ETW/procfs |
| Files | FileCreated, FileModified, FileDeleted, FileRenamed, FileRead, FileWritten | inotify/polling |
| Network | NetworkConnection, DnsQuery, HttpsRequest, TcpConnection | eBPF/auditd |
| Memory | MemoryAllocated, MemoryProtect, MemoryWrite | ETW/procfs |
| Registry | RegistryKeyCreated, RegistryValueSet, RegistryKeyDeleted | ETW |
| Services | ServiceInstalled, ServiceStarted, ServiceModified | CIM/WMI |
| DLLs | DllLoaded, DllInjected | ETW |
| Tokens | TokenImpersonated, TokenCreated | ETW |
| Modules | ModuleLoaded, ModuleUnloaded | ETW/procfs |
| Scripts | ScriptExecuted, ScriptBlockLogged | ETW/auditd |

**19 Evidence Relations:**

Relations are **inferred**, not directly observed. Sentinel constructs the graph from temporal and process correlations.

### 2. Trust Engine

**Score (0-100):**

```
CLEAN (≥80)  │  REVIEW (≥50)  │  BLOCK (<50)
```

**Feature Model:**

```
Observed Telemetry
        ↓
Feature Extraction (69 features)
        ↓
Normalization (0-1 per feature)
        ↓
Weighted Aggregation (calibrated weights)
        ↓
Calibration (reference corpus)
        ↓
Trust Score (0-100)
        ↓
Verdict (CLEAN/REVIEW/BLOCK)
```

**Feature Categories:**

| Category | Features | Type | Description |
|----------|----------|------|-------------|
| Hermeticity | 12 | Observed + Inferred | Isolated environment, no network, no secrets |
| Processes | 15 | Observed | Known tools, no LOLBins |
| Files | 10 | Observed | Only sources, no binaries |
| Network | 8 | Observed | No activity, no DoH |
| Dependencies | 12 | Observed + Inferred | Lock files, verified hashes |
| Behavior | 12 | Inferred | Reproducible build, no drift |

**Important:** The Trust Score is an *estimation*, not a measurement. Real confidence depends on the quality of the underlying telemetry.

### 3. Red Team Framework

**Philosophy:**

```
Atomic Red Team (stimulus)
        ↓
Sentinel observes (protagonist)
        ↓
Evidence Graph is built
        ↓
Trust Engine evaluates
        ↓
Red Team Report generates
```

**Sentinel is the protagonist**, not the tool that executes attacks. Attack scenarios are *simulations* of what an attacker could do, not real executions.

**26 Attack Scenarios (10 Campaigns):**

| # | Campaign | Attacks | Real Priority | Status |
|---|----------|---------|---------------|--------|
| 1 | Supply Chain | ATK-016 to ATK-020 | P1 | Simulated |
| 2 | Identity Evasion | ATK-003, ATK-004 | P2 | Simulated |
| 3 | Secret Exfiltration | ATK-005 to ATK-007 | P3 | Simulated |
| 4 | Git Attacks | ATK-021 to ATK-023 | P4 | Simulated |
| 5 | CI/CD Attacks | ATK-024 to ATK-026 | P5 | Simulated |
| 6 | Toolchain Hijack | ATK-008, ATK-009 | P6 | Simulated |
| 7 | Graph Poisoning | ATK-010, ATK-011 | P7 | Simulated |
| 8 | Sensor Evasion | ATK-001, ATK-002 | P8 | Simulated |
| 9 | Timeline Confusion | ATK-014, ATK-015 | P9 | Simulated |
| 10 | ML Poisoning | ATK-012, ATK-013 | P10 | Future |

**15 Detection Rules:**

| ID | Rule | Severity |
|----|------|----------|
| DR-001 | Unknown Tool Execution | medium |
| DR-002 | LOLBin Usage | high |
| DR-003 | Network During Build | critical |
| DR-004 | File System Tampering | high |
| DR-005 | Registry Modification | high |
| DR-006 | Service Installation | critical |
| DR-007 | DLL Injection | critical |
| DR-008 | Token Impersonation | critical |
| DR-009 | Memory Protection Change | high |
| DR-010 | DNS over HTTPS | medium |
| DR-011 | Named Pipe Creation | medium |
| DR-012 | Response File Poisoning | high |
| DR-013 | Process Hollowing | critical |
| DR-014 | ETW Health | low |
| DR-015 | Fileless Execution | critical |

---

## New Features v2.0

### 1. Replay System

**Purpose:** Save attack telemetry for reuse without re-executing.

```bash
sentinel-cli replay list                    # List datasets
sentinel-cli replay run <dataset-id>        # Run replay
```

**Data Structure:**

```
datasets/
├── windows/
│   └── replay-1234/
│       ├── dataset.json        # Metadata
│       ├── build.json          # Build record (OBSERVED)
│       ├── events.json         # Events (OBSERVED)
│       ├── graph.json          # Evidence graph (INFERRED)
│       └── trust.json          # Trust result (INFERRED)
├── linux/
├── macos/
├── atomic/
└── caldera/
```

### 2. Regression Suite

**Purpose:** Automatically validate that detections don't break.

```bash
sentinel-cli regression list                # List suites
sentinel-cli regression coverage            # View coverage
```

**Default Suite (12 tests):**

| Test | Attack | Severity | Expected Verdict | Status |
|------|--------|----------|------------------|--------|
| DLL Injection | ATK-008 | critical | BLOCK | Implemented |
| ETW Patching | ATK-002 | critical | BLOCK | Implemented |
| LD_PRELOAD | ATK-005 | critical | BLOCK | Implemented |
| Named Pipes | ATK-006 | medium | REVIEW | Implemented |
| DoH Exfil | ATK-007 | high | BLOCK | Implemented |
| Process Hollowing | ATK-013 | critical | BLOCK | Implemented |
| LOLBins | ATK-010 | high | REVIEW | Implemented |
| npm postinstall | ATK-016 | critical | BLOCK | Implemented |
| Git Hooks | ATK-021 | high | REVIEW | Implemented |
| GitHub Actions | ATK-024 | critical | BLOCK | Implemented |
| Clean Build | — | info | CLEAN | Implemented |
| Hermetic Build | — | info | CLEAN | Implemented |

### 3. ATT&CK Coverage Matrix

**Purpose:** Visualize mapping coverage vs MITRE ATT&CK.

```bash
sentinel-cli coverage                       # View matrix
sentinel-cli coverage --save                # Save to file
```

**28 MITRE Techniques Mapped:**

| Tactic | Techniques | Mapping | Status |
|--------|------------|---------|--------|
| defense-evasion | T1055, T1055.001, T1055.012, T1562.001, T1562.006, T1218, T1218.011, T1070.004 | 100% | Mapped |
| execution | T1059.004, T1059.006, T1059.007, T1204.002 | 75% | Mapped |
| persistence | T1574.006, T1574.007, T1546 | 67% | Mapped |
| credential-access | T1552.001 | 100% | Mapped |
| exfiltration | T1071.004, T1570 | 100% | Mapped |
| supply-chain | T1195.002 | 100% | Mapped |
| collection | T1005 | 50% | Partial |
| discovery | T1082, T1083 | 0% | Not covered |
| impact | T1565.001 | 0% | Planned |

**Important:** This table shows **mapping coverage**, not **detection efficacy**. It means there are detection rules associated with each technique, not that Sentinel detects 100% of implementations of that technique.

### 4. Baseline System

**Purpose:** Detect anomalies by comparing against known good builds.

```bash
sentinel-cli baseline-pro list              # List profiles
sentinel-cli baseline-pro create <id>       # Create profile
sentinel-cli baseline-pro show <id>         # View details
```

**Statistics:**

| Metric | Type | Description |
|--------|------|-------------|
| meanTrustScore | Inferred | Average trust score |
| stdTrustScore | Inferred | Standard deviation |
| meanDurationMs | Observed | Average build duration |
| meanProcesses | Observed | Average process count |
| typicalTools | Observed | Typical tools (>70%) |
| typicalHosts | Observed | Typical network hosts |

**Anomaly Detection:**

| Type | Threshold | Severity |
|------|-----------|----------|
| Trust score outlier | >2 std devs | warning/critical |
| Duration outlier | >2 std devs | warning |
| Process count outlier | >2 std devs | info |
| New tools | Not in baseline | warning |
| New network hosts | Not in baseline | critical |

### 5. Stress Testing

**Purpose:** Framework prepared to measure performance, accuracy, and stability under load.

```bash
sentinel-cli stress config                  # Configure test
sentinel-cli stress results <config-id>     # View results
sentinel-cli stress compare <config-id>     # Compare runs
```

**Metrics Prepared to Measure:**

| Category | Metrics | Type | Status |
|----------|---------|------|--------|
| Throughput | builds/sec, total builds | Observed | Ready |
| Accuracy | TP, FP, TN, FN, Precision, Recall, F1 | Observed | Pending* |
| Performance | avg, P50, P95, P99, max analysis time | Observed | Ready |
| Memory | heap used, RSS, peak memory | Observed | Ready |

*Note on Accuracy:* Accuracy metrics (Precision, Recall, F1) will be calculated when a labeled dataset with ground truth exists. Currently the framework is prepared to measure them, but doesn't report them without a validated corpus.

---

## CLI Commands (70+)

### Level 1 (Normal User)

```
sentinel-cli build observe <cmd>            # Verdict + trust + highlights
sentinel-cli scan <path>                    # findings by severity
sentinel-cli top                            # top findings
```

**Output:** Verdict, Trust Score, 3-5 highlights, what to do.

### Level 2 (Analyst)

```
sentinel-cli build explain                  # Why the score is what it is
sentinel-cli inspect                        # Graph, centrality, dominators
sentinel-cli trust                          # Trust calibration
```

### Level 3 (Researcher)

```
sentinel-cli build observe --verbose        # Full technical details
sentinel-cli build graph                    # Evidence graph
sentinel-cli atomic --list                  # Atomic RT tests mapped
```

### Level 4 (Pipeline)

```
sentinel-cli build observe --json           # JSON for pipelines
sentinel-cli scan --json                    # findings JSON
sentinel-cli regression list                # regression suites
```

### Red Team

```
sentinel-cli redteam --list                 # 26 attacks, 10 campaigns
sentinel-cli redteam --coverage             # Coverage matrix
sentinel-cli atomic --priority P1 --dry-run # Preview without executing
sentinel-cli atomic --script                # Generate script
```

### Testing & Validation

```
sentinel-cli replay list                    # Replay datasets
sentinel-cli replay run <id>                # Run replay
sentinel-cli regression coverage            # Test coverage
sentinel-cli coverage                       # MITRE ATT&CK matrix
sentinel-cli stress config                  # Configure stress test
sentinel-cli stress results <id>            # Results
```

### Baseline & Performance

```
sentinel-cli baseline-pro list              # Baseline profiles
sentinel-cli baseline-pro show <id>         # Details
sentinel-cli stress compare <id>            # Compare runs
```

### Integrations

```
sentinel-cli mcp                            # MCP server
sentinel-cli hub                            # Interactive menu
sentinel-cli guide                          # 22 sections
```

---

## Assumptions

Sentinel assumes that:

- The operating system telemetry has not been manipulated.
- The system clock is sufficiently precise to correlate events.
- Observed events represent the actual build behavior.
- The attacker does not have kernel privileges.
- The execution environment is not compromised (isolated VM for testing).
- Build tools are the ones the user declares to use.
- Verified hashes and signatures have not been falsified.

If any of these assumptions don't hold, Sentinel's results may be incorrect or incomplete.

---

## Threat Model

### Covered Actors

| Actor | Covered | Limitations |
|-------|---------|-------------|
| Malicious developer | Yes | Only if modifying observed files/processes |
| Compromised dependency | Yes | Detects supply chain changes |
| Malicious Git Hooks | Yes | Detects hooks executing code |
| Malicious GitHub Actions | Yes | Detects secret exfiltration |
| Supply chain attack | Yes | Detects postinstall scripts, init scripts |
| PATH hijacking | Partial | Detects non-standard tools |
| DLL injection | Yes | Detects process injection |
| ETW patching | Yes | Detects logging disabling |
| Insider with limited access | Partial | Depends on available telemetry |
| Kernel rootkit | No | Sentinel has no kernel access |
| Compromised hypervisor | No | Out of scope |
| Firmware malware | No | Out of scope |

### Not Covered

- Kernel memory inspection
- EDR replacement
- SAST replacement
- DAST replacement
- CodeQL or static analysis tool replacement
- Logical vulnerability detection
- Dependency vulnerability analysis (uses OSV as external source)
- Typosquatting beyond basic heuristics

---

## Capabilities

| Capability | Status | Description |
|------------|--------|-------------|
| **Observation** | ✔ | Captures build telemetry |
| **Detection** | ✔ | Identifies anomalous behavior |
| **Explanation** | ✔ | Generates causal explanations |
| **Replay** | ✔ | Reuses telemetry without re-executing |
| **Regression** | ✔ | Validates detections don't break |
| **Coverage** | ✔ | Maps MITRE ATT&CK coverage |
| **Baseline** | ✔ | Detects anomalies vs known good builds |
| **Stress** | ✔ | Measures performance under load |
| **Prevention** | No | Sentinel doesn't block builds |
| **Automatic remediation** | No | Sentinel doesn't fix issues |
| **Execution blocking** | No | Sentinel doesn't stop processes |

**Note:** Sentinel is an **observation and analysis** tool, not a **prevention or remediation** tool. Its outputs are recommendations that a human or external system must implement.

---

## Limitations

- Does not inspect kernel memory.
- Does not replace an EDR (Endpoint Detection and Response).
- Does not replace SAST (Static Application Security Testing).
- Does not replace DAST (Dynamic Application Security Testing).
- Does not replace CodeQL or static analysis tools.
- Does not detect logical vulnerabilities in code.
- Depends on the quality of the underlying telemetry.
- Does not detect attacks that leave no trace in observable telemetry.
- Does not cover hypervisor or firmware level attacks.
- Does not detect malware resident in memory without process changes.
- Does not analyze dependency vulnerabilities (uses OSV as external source).
- Does not detect typosquatting beyond basic heuristics.

---

## Out of Scope

Sentinel currently does not attempt to:

- Detect malware resident in firmware.
- Detect hypervisor rootkits.
- Analyze source code vulnerabilities (uses external tools).
- Replace SAST tools.
- Replace DAST tools.
- Replace SCA (Software Composition Analysis) tools.
- Detect zero-day vulnerabilities.
- Analyze real-time network behavior (only during builds).
- Monitor production systems (only builds).
- Execute automatic remediation.
- Generate patches or fixes.
- Integrate directly with CI/CD pipelines without configuration.

---

## Validation Methodology

Sentinel uses a layered validation approach:

### Level 1: Unit Tests

- **53 test suites**
- **1,040 unit tests**
- Core component coverage
- Business logic validation

### Level 2: Regression Testing

- **12 predefined tests** in default suite
- Automatic detection validation
- Regression detection on each commit

### Level 3: Replay Testing

- Telemetry reuse from captured data
- Validation without re-executing attacks
- Comparison against expected results

### Level 4: Synthetic Attacks

- 26 simulated attack scenarios
- 10 Red Team campaigns
- Detection logic validation

### Level 5: Atomic Red Team (Pending)

- Real technique execution
- Isolated VM environment
- End-to-end validation

### Level 6: MITRE CALDERA (Pending)

- Complete adversary campaigns
- Multi-phase correlation validation

### Level 7: External Benchmarking (Pending)

- Comparison against existing tools
- Industry standard metrics
- Independent validation

---

## External Validation Planned

### Comparison Tools

| Tool | Type | Comparison |
|------|------|------------|
| CodeQL | Static SAST | Source code analysis |
| Semgrep | Static SAST | Custom rules |
| Snyk | SCA + SAST | Dependencies + code |
| Microsoft Defender | EDR | Runtime detection |
| Falco | Runtime security | System monitoring |
| Sysmon | Telemetry | System events |

### Comparison Metrics

| Metric | Description |
|--------|-------------|
| Detection Rate | % of attacks detected |
| False Positive Rate | % of false positives |
| Time to Detect | Average detection time |
| Coverage | % of MITRE techniques covered |
| Explainability | Ability to explain verdicts |

### Validation Plan

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | Completed | Unit tests + regression |
| Phase 2 | Completed | Synthetic attacks + replay |
| Phase 3 | In progress | Atomic Red Team in VM |
| Phase 4 | Pending | CALDERA campaigns |
| Phase 5 | Pending | External benchmarking |
| Phase 6 | Pending | Results publication |

---

## Data Classification

| Component | Type | Confidence | Description |
|-----------|------|------------|-------------|
| Processes | Observed | High | OS telemetry |
| Files | Observed | High | inotify/polling |
| Network | Observed | Medium-High | eBPF/auditd |
| Evidence Graph | Inferred | Medium | Graph built from observations |
| Trust Score | Inferred | Medium | 69 features, calibrated model |
| Bayesian Network | Inferred | Low-Medium | Noisy-OR propagation |
| Temporal Analysis | Inferred | Medium | Sequence analysis |
| Dominator Analysis | Inferred | Medium | Graph algorithm |
| Red Team Report | Simulated | Low | Attack scenarios, not executed |
| Coverage Matrix | Mapped | High | Static technique→detection mapping |
| Baseline Deviation | Inferred | Medium | Statistical comparison |
| Stress Metrics | Observed | High | Direct performance measurement |

**Important:** The Trust Score is an *estimation*, not a measurement. Real confidence depends on the quality of the underlying telemetry.

---

## File Structure

```
sentinel-cli/
├── src/
│   ├── cli/
│   │   ├── main.ts                    70+ commands
│   │   ├── build/
│   │   │   ├── build-summary.ts       Level 1-4 (6 questions)
│   │   │   ├── build-story.ts         Evidence graph, temporal, Bayesian
│   │   │   └── explain.ts             Build explanation
│   │   ├── scan/                      Security scanning
│   │   ├── inspect/                   Graph analysis
│   │   └── redteam/                   Red Team UI
│   ├── core/
│   │   ├── network/
│   │   │   ├── build-types.ts         30 EvidenceTypes, 19 Relations
│   │   │   ├── evidence-graph.ts      Graph construction & queries
│   │   │   ├── temporal-graph.ts      Temporal & Bayesian analysis
│   │   │   ├── graph-analytics.ts     Diff, centrality, correlation
│   │   │   ├── trust-calibration.ts   69-feature Trust Engine
│   │   │   ├── evidence-reliability.ts Confidence propagation
│   │   │   ├── process-timeline.ts    Build process timelines
│   │   │   ├── redteam-types.ts       26 attacks, 10 campaigns
│   │   │   ├── redteam-attacks.ts     Attack implementations
│   │   │   ├── redteam-runner.ts      Runner + 15 detection rules
│   │   │   ├── atomic-redteam-map.ts  30+ mapped tests (P1-P8)
│   │   │   ├── atomic-redteam-runner.ts Atomic RT integration
│   │   │   ├── replay-system.ts       Save/replay telemetry
│   │   │   ├── regression-suite.ts    12 regression tests
│   │   │   ├── attack-coverage.ts     MITRE ATT&CK matrix
│   │   │   ├── baseline-system.ts     Anomaly detection
│   │   │   └── stress-testing.ts      Performance benchmarks
│   │   └── ...
│   └── ...
├── tests/
│   └── ... (53 suites, 1,040 tests)
├── datasets/                          Replay datasets
├── baselines/                         Baseline profiles
├── regression-suites/                 Regression suites
├── stress-tests/                      Stress test results
├── lab/
│   └── setup.ps1                      Lab setup script
└── package.json
```

---

## Verification

| Verification | Status | Type |
|--------------|--------|------|
| TypeScript compilation | ✅ 0 errors | Observed |
| Unit tests | ✅ 53 suites, 1,040 passed | Observed |
| `build observe` | ✅ Score 80, Verdict CLEAN | Observed |
| `redteam --list` | ✅ 26 attacks, 10 campaigns | Observed |
| `atomic --list` | ✅ 30+ tests, P1-P8 | Observed |
| `replay list` | ✅ Functional | Observed |
| `regression list` | ✅ 12 tests default | Observed |
| `coverage` | ✅ 28 MITRE techniques | Observed |
| `baseline-pro list` | ✅ Functional | Observed |
| `stress config` | ✅ Default config | Observed |
| `scan` | ✅ Functional | Observed |
| `inspect` | ✅ Functional | Observed |
| `top` | ✅ Functional | Observed |

**Status:** Smoke tests passed. Scientific validation pending.

---

## What's Missing for Production

| Area | Status | Requirement |
|------|--------|-------------|
| **Real Atomic Red Team** | Pending | Execute in isolated VM |
| **Caldera integration** | Pending | Complete campaigns |
| **External validation** | Pending | Compare with other tools |
| **API documentation** | Pending | For integrators |
| **Comparative benchmark** | Pending | vs Snyk, CodeQL, etc. |
| **ML Poisoning** | Future | When learning model exists |

---

## Conclusion

Sentinel CLI is a **build observation system with integrated validation and offensive emulation capabilities**. The difference from traditional tools isn't "compiles or doesn't compile"; it's that Sentinel attempts to answer **what happened, why, with what confidence, and how an attacker would break it**.

The system is in research-grade / ops-ready with controlled lab validation phase. Analysis capabilities are validated with unit tests. External validation capabilities require real execution with Atomic Red Team in an isolated VM environment.

The next step is **real execution** of Atomic Red Team tests to validate end-to-end detection.

---

*Generated automatically by Sentinel CLI v2.3.0*
