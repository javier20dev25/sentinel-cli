# Sentinel CLI (v4.0 "Oracle Lite")

**Sentinel Security Oracle -- Unified Terminal Security Interface.**

A supply-chain enforcement layer and static analysis suite that intercepts dependency installation, audits pull requests, and maintains a local signal vault for temporal drift detection. This is the deliberately degraded ("Lite") distribution of the proprietary Sentinel Cloud engine. The rule set, correlation logic, and integrity verification subsystems are intentionally reduced to protect the Cloud engine's reasoning IP while retaining high-utility local scanning.

## Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [CLI Reference](#cli-reference)
- [Threat Detection Model](#threat-detection-model)
- [PR Scanning Pipeline](#pr-scanning-pipeline)
- [Supply Chain Analysis](#supply-chain-analysis)
- [Signal Vault & Temporal Correlation](#signal-vault--temporal-correlation)
- [Integrity Verification](#integrity-verification)
- [Baseline & Drift Detection](#baseline--drift-detection)
- [OS-Level Guard](#os-level-guard)
- [Classified Document Protection](#classified-document-protection)
- [GitHub Actions Integration](#github-actions-integration)
- [License](#license)

## Architecture

The CLI is organized into two source trees under `src/`:

```
src/
  cli/                          -- Command entry points and orchestration
    main.ts                       Commander-based CLI dispatcher
    pr_scan.ts                    Standalone PR scanner for CI/CD pipelines
    hub.ts                        Interactive TUI menu system
    gh_bridge.ts                  GitHub API abstraction layer (via gh CLI)
    guard.ts                      OS-level package manager interception
    classify.ts                   Classified document pre-commit hook
    telemetry.ts                  Performance telemetry output
    intelligence/
      signal_vault.ts               SQLite-backed signal persistence
      memory_manager.ts             High-level vault operations
      supply_chain_shield.ts        npm tarball extraction + SAST scanning
      capability_analyzer.ts        Finding-to-capability mapper
      system_auditor.ts             "doctor" command -- local node_modules audit
      integrity_manager.ts          Host integrity verification
      integrity_chain.ts            Merkle-chain of CLI boot sessions
      baseline_manager.ts           System snapshot creation and diffing
  core/
    lite/
      lite_scanner.ts              Core SAST engine (30 rules, patch parsing)
```

### Engine Architecture

`LiteScanner` is the central detection primitive. It operates on unified diff patches rather than full file trees, making it suitable for both local directory scanning and CI/CD pull request analysis. The scanner applies a deterministic rule set of 30 regular expressions across five detection intents:

| Intent | Description |
|--------|-------------|
| `MALICIOUS` | Deliberately obfuscated or destructive code patterns |
| `SUSPICIOUS` | Capabilities commonly abused in supply-chain attacks |
| `VULNERABILITY` | Accidentally introduced security weaknesses (XSS, injection) |
| `EXFILTRATION` | Secret, credential, or key exposure in plaintext |
| `NEUTRAL` | Benign but observable behavior (network calls, logging) |

Rules are categorized by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and include pattern groups for:
- Dynamic code execution (`eval`, `new Function`, obfuscated access)
- OS process spawning (`child_process`, `exec`, `spawn`)
- Network outbound communication
- Environment variable access
- Base64 decoding / potential obfuscation
- DOM injection (XSS)
- Sandbox escape (`vm.runInNewContext`)
- Cloud provider secrets (AWS, GitHub, Stripe, SendGrid, Slack)
- Private keys and JWT tokens
- Database credentials, encryption keys, API keys
- Darknet address references
- Hardcoded passwords and authentication tokens

## Installation

```bash
npm install -g @sentinel/cli
```

Requires Node.js >= 18.0.0. The package bundles `better-sqlite3` for local persistence, `commander` for CLI parsing, `picocolors` for terminal output, and `acorn`/`acorn-walk` for AST-level analysis (proprietary rules not included in Lite distribution).

## CLI Reference

### `sentinel scan [path] [--json]`

Scans a local file or directory using LiteScanner's SAST rule set. Without `--json`, outputs human-readable findings grouped by severity. With `--json`, produces a structured output containing host integrity status and all findings.

The scanner treats the entire target as a single unified diff patch where every line is an addition. This allows the same `scanPatch` codepath to serve both local and PR contexts.

```bash
sentinel scan ./src/myfile.js
sentinel scan . --json
```

### `sentinel verify-pkg <package> [--details] [--summary]`

Downloads a package tarball from the npm registry via `npm pack` (no installation), extracts it to a temporary directory, and runs LiteScanner on all `.js`, `.ts`, `.mjs`, and `.cjs` files inside the extracted `package/` directory.

The command outputs:
- Package metadata (name, file count, size, scan time, memory usage)
- npm registry information (description, author, maintainers)
- A verdict classification: `SAFE`, `SUSPICIOUS`, or `MALICIOUS`
- Finding distribution by capability type with severity histograms
- Evidence lines for HIGH/CRITICAL findings

```bash
sentinel verify-pkg dotenv --details
sentinel verify-pkg utilz --summary
```

### `sentinel doctor [--deep]`

Performs a system health audit. Without `--deep`, scans only `package.json` for configuration-level threats. With `--deep`, walks all installed dependencies in `node_modules/` (up to 20 files per package, 2 levels deep) and scans each with LiteScanner.

### `sentinel integrity`

Runs a six-point host integrity verification:
1. **Ruleset hash**: SHA-256 of the compiled LiteScanner and SignalVault modules
2. **PATH poisoning**: checks whether suspicious directories (`temp`, `downloads`, `desktop`) appear in the top 3 PATH entries
3. **Vault integrity**: verifies the Signal Vault SQLite file is non-zero and its modification time precedes system clock
4. **Signed manifest**: compares `integrity.json` rulesHash against computed hash of the current code
5. **Environment check**: respects `SENTINEL_UNTRUSTED` flag
6. **Integrity chain**: verifies the Merkle chain of previous boot sessions

Accepts `--uptime` (show accumulated verified uptime) and `--watch` (live counter, updates every second).

### `sentinel permissions [package]`

Maps LiteScanner findings to high-level capability categories: `NETWORK`, `FILESYSTEM`, `PROCESS_EXEC`, `ENV_ACCESS`, `DYNAMIC_EXEC`, `DOM_MANIPULATION`, `CREDENTIAL_LEAK`. Without arguments, audits all installed dependencies. With a package name, audits only that package.

The mapping is performed by `CapabilityAnalyzer` which applies a risk escalation rule: findings with `MALICIOUS` intent are elevated to `CRITICAL`; findings with `VULNERABILITY` intent are downgraded from `CRITICAL` to `HIGH`.

### `sentinel memory`

Manages the local Signal Vault (SQLite database at `~/.sentinel/vault.db`).

| Option | Behavior |
|--------|----------|
| `--status` | Prints metrics (scans, findings, signals, repos, authors) plus threshold drift analysis and multi-author correlation |
| `--ingest <file>` | Ingests a Sentinel Cloud JSON report from file |
| `--ingest-dir <dir>` | Batch ingests all JSON reports from a directory |
| `--stdin` | Pipe mode -- accepts JSON via stdin |
| `--paste` | Interactive JSON paste mode (terminate with Ctrl+D/Ctrl+Z on empty line) |
| `--wipe` | Deletes all local history |
| `--threshold <n>` | Sets signal threshold for drift reports (default 5) |

### `sentinel hub`

Launches an interactive TUI with 11 main operations:
1. PR Bot -- batch analysis of all open pull requests across all repositories
2. Workspace selection with per-repo auditing (baseline context scan, PR inspection)
3. System doctor
4. Integrity check
5. Permissions audit
6. Local directory scan
7. Guard management (enable/disable/trust-cache)
8. Classified documents management
9. Signal Vault management
10. Donation page
11. Security policy display

### `sentinel guard <status|enable|disable|trust-cache>`

Injects shell aliases into the user's PowerShell or POSIX profile that intercept `npm`, `pip`, `pip3`, `yarn`, `pnpm`, `cargo`, and `docker` commands. Intercepted commands first route through `supply_chain_shield.scanInstallation()` before proceeding to the native binary. Can be disabled by removing the alias block from the profile.

### `sentinel baseline <create|diff> [name]`

Creates or diffs system snapshots. A baseline captures dependency versions, SHA-256 hashes of each package's main entry point, and capability fingerprints. `diff` compares the current state against the saved baseline and reports added, removed, modified, or code-drifted packages.

### `sentinel install <manager> [args...]`

Security-gated installation path. Routes dependency installation requests through `SupplyChainShield.analyzeBatch()` before delegating to the native package manager. Intended to be the backend of the OS-level Guard intercept.

### `sentinel env-encrypt <file>` / `sentinel env-decrypt <file>`

Encrypts or decrypts `.env` files using AES-256-CBC. The key is derived via SHA-256 of the `SENTINEL_ENV_KEY` environment variable (fallback: hostname). Outputs to `file.enc` or `file.decrypted`.

### `sentinel check-classified <repoPath>`

Pre-commit hook entry point. Reads the local classified database (`~/.sentinel/classified.json`), compares staged files against the classified list, and blocks the commit if any classified files are detected.

### `sentinel policies`

Displays security policy, responsible disclosure procedures, contribution guidelines, code of conduct, versioning policy, and privacy statement.

### `sentinel guide`

Displays a comprehensive command reference with tested examples.

## Threat Detection Model

### Patch Parsing

The parser in `pr_scan.ts` splits a unified diff on `diff --git` boundaries. Each file segment is passed to `LiteScanner.scanPatch(filename, patch)` which iterates lines, incrementing a line counter on `+` lines and context lines. Only added lines (`+` prefix) are tested against rules. Deletion lines are ignored -- the scanner models only what a PR introduces, not what it removes.

### Inline Bypass

Any line ending with `// sentinel-disable-line RULE_NAME` is exempted from that specific rule. Without a rule name, all 30 rules are bypassed for that line. The directive is parsed after the line is trimmed; the comment `// sentinel-disable-line UNSAFE_EVAL` suppresses the UNSAFE_EVAL rule for that line only. This mechanism is implemented directly in `LiteScanner.scanPatch()` before the rule loop.

### Verdict Calculation

Given the set of findings from all files in a PR or scan:

```
CRITICAL severity present  -> riskBand = "CRITICAL", decision = "BLOCK", score >= 90
HIGH severity present      -> riskBand = "SUSPICIOUS", decision = "REVIEW", score >= 60
No HIGH/CRITICAL findings  -> riskBand = "SAFE", decision = "PASS", score = 10
```

The verdict is computed in `LiteScanner.auditPR()` and persists alongside the scan record in the Signal Vault.

### Truth Maintenance

The `integrity.json` manifest stores a `rulesHash` that must match the computed SHA-256 of the compiled LiteScanner and SignalVault modules. If the CLI binary is modified, the `sentinel integrity` command detects the hash mismatch and flags the runtime as `SUSPECT` or `COMPROMISED`. This is a read-only check; the manifest is only updated by the build process.

## PR Scanning Pipeline

The system supports two scanning modalities:

### Interactive (via `hub.ts`)

The TUI uses `GitHubBridge` to list repositories and their open PRs, fetch diffs via `gh pr diff`, and run `LiteScanner.scanPatch()` on the aggregated diff. Findings are displayed inline with severity, type, description, and a snippet. Results are persisted to the local Signal Vault for historical tracking.

### CI/CD (via `pr_scan.ts`)

The `pr_scan.ts` script is invoked in GitHub Actions:

1. The workflow checks out the repository, installs dependencies, and compiles TypeScript.
2. `gh pr diff <number>` fetches the multi-file unified diff.
3. `pr_scan.ts` parses the diff into per-file patches, runs `LiteScanner.auditPR()` across all files, and separately parses the diff for `package.json` changes to identify new dependencies.
4. New dependencies are batch-analyzed via `SupplyChainShield.analyzeBatch()` (max 5 per scan to avoid timeout).
5. Results are emitted as a single JSON object containing the scan ID, all findings (with file, line, type, severity, description, and truncated snippet), supply chain results, and the verdict.
6. The workflow reads the JSON output and posts a formatted comment to the pull request via `gh pr comment`.

Deep links in the comment use the format `{serverUrl}/{owner}/{repo}/blob/{headSha}/{file}#L{line}` to provide one-click navigation to each finding's exact location.

## Supply Chain Analysis

`SupplyChainShield` performs static analysis on npm packages without installing them:

1. `npm pack <spec> --pack-destination <tmp>` downloads the tarball
2. `tar -xzf` extracts to a temporary directory
3. All `.js`/`.ts`/`.mjs`/`.cjs` files are collected via recursive directory walk (skipping hidden files and `node_modules`)
4. Each file is scanned with `LiteScanner.scanPatch()` using the same 30-rule SAST engine
5. Composite verdict: `MALICIOUS` if any `CRITICAL` finding exists, `SUSPICIOUS` if any `HIGH` or `SECRET_*` finding exists, `SAFE` otherwise

Temporary files are cleaned up in a `finally` block. The `analyzeBatch()` method iterates sequentially (not parallel) to avoid resource contention on GitHub runners.

## Signal Vault & Temporal Correlation

The `SignalVault` (backed by SQLite via `better-sqlite3`) persists three entity types:

- **scans**: Scan session records with repo name, PR number, author, risk score, and risk band
- **findings**: Individual SAST findings linked to a scan via foreign key
- **signals**: Lightweight signal records (repo, author, signal type, weight, file path) also linked to scans

### Schema

```sql
scans (id TEXT PRIMARY KEY, repo_name TEXT, pr_number INTEGER, author TEXT,
       risk_score REAL, risk_band TEXT, created_at DATETIME)

findings (id INTEGER PK, scan_id TEXT FK -> scans.id, rule_name TEXT,
          severity INTEGER, file_path TEXT, line_number INTEGER, description TEXT)

signals (id INTEGER PK, repo TEXT, author TEXT, signal_type TEXT, weight REAL,
         file_path TEXT, source_scan TEXT FK -> scans.id, created_at DATETIME)
```

### Temporal Correlation

When a new scan runs, its finding `type` values are compared against historical signals from the same author over the last 90 days. Correlated signals (same author, same signal type, within the lookback window) are returned alongside the scan verdict. This enables detection of behavioral drift across multiple PRs.

### Drift Thresholds

`getThresholdAnalysis()` groups signals by repository and filters those exceeding a configurable threshold (default 5). Each group is classified as `MONITOR` (at threshold), `ELEVATED` (2x threshold), or `ESCALATING` (3+ critical signal types).

### Multi-Author Correlation

`getMultiAuthorSignals()` reports repositories where multiple distinct GitHub accounts have contributed signals of the same type, indicating coordinated supply-chain infiltration attempts.

## Integrity Verification

The `IntegrityManager` computes a SHA-256 hash of the LiteScanner and SignalVault compiled modules at runtime and compares against the signed `integrity.json` manifest. Additional checks:

- **PATH poisoning**: Extracts the first 3 PATH entries and tests them against a list of suspicious directory name patterns
- **Clock anomaly**: Compares system clock against SQLite vault file modification time to detect time-drift attacks
- **Signal Vault state**: Flags zero-byte vault files as compromised

### Integrity Chain

`IntegrityChain` maintains a Merkle-linked list of boot sessions in the same SQLite database:

```
link_hash = SHA256(JSON.stringify({
  session_id, link_number, code_hash, previous_link_hash, started_at, accumulated_seconds
}))
```

Each new boot record includes the hash of the previous record (`previous_link_hash`), forming a chain that can be verified in either direction. If the code hash changes between boots or the link hash computation does not match the stored value, the chain status is `BROKEN`.

Accumulated uptime is the sum of all session durations across the entire chain, providing an integrity-gated "verified uptime" counter.

## Baseline & Drift Detection

`BaselineManager` serializes to `~/.sentinel/baselines/<name>.json`:

```json
{
  "timestamp": "ISO 8601",
  "dependencies": { "pkg": "version" },
  "capabilities": { "pkg": ["NETWORK"] },
  "hashes": { "pkg": "sha256" }
}
```

`diffBaseline()` compares the current `package.json` dependencies against the baseline and reports three drift classes:

| Class | Detection Mechanism |
|-------|-------------------|
| New package | Entry in current deps not in baseline |
| Version drift | Version string differs |
| Shadow drift | Version matches but SHA-256 hash differs |

Shadow drift triggers an escalation: the system labels it as potential code integrity violation and recommends `sentinel doctor --deep`.

## OS-Level Guard

`guard.ts` injects into the shell profile (PowerShell or POSIX) a set of function definitions that shadow native package manager commands. Each function:

1. Calls `SupplyChainShield.scanInstallation()` with the manager name and arguments
2. Only proceeds to the native binary if the scan returns `success: true`
3. Returns the exit code from the native binary

On Windows PowerShell, the resolution uses `.exe`/`.cmd` suffixes because native executables cannot be shadowed by PowerShell functions without explicit extension. Each function calls the native binary via `& "npm.cmd" $args` after the Sentinel scan gate passes.

## Classified Document Protection

`classify.ts` maintains a JSON database (`~/.sentinel/classified.json`) mapping repository paths to arrays of classified file paths (relative to repo root). The pre-commit hook (`installPreCommitHook`) appends to the existing `.git/hooks/pre-commit` script, preserving any pre-existing hook logic. At commit time, `checkClassifiedHook()` runs `git diff --cached --name-only`, cross-references against the classified list, and exits with code 1 (blocking the commit) if any classified file is staged.

## GitHub Actions Integration

The workflow at `.github/workflows/sentinel-pr-bot.yml` triggers on `pull_request: [opened, synchronize, reopened]`. Execution flow:

1. Checkout the merge commit (not the PR head)
2. Set up Node.js 20
3. Install dependencies (`npm ci`)
4. Compile TypeScript (`npx tsc`)
5. Fetch the diff: `gh pr diff <number>` piped to a file
6. Run `node dist/cli/pr_scan.js <diff_file>` with environment variables `SENTINEL_REPO`, `SENTINEL_PR`, `SENTINEL_AUTHOR`
7. Parse the JSON output with `fromJson`
8. Post a formatted comment using `gh pr comment`

Findings are hyperlinked to the exact file and line via deep links constructed from `github.server_url`, `github.repository`, and the PR head SHA. The workflow uses only GitHub-provided infrastructure and consumes zero external API resources.

## Contributing (Pull Requests)

This repository accepts external contributions subject to the following rules:

1. Open an issue describing the proposed change before submitting a PR. Unprompted PRs may be closed without review.
2. All PRs are scanned by Sentinel's PR Bot (SAST + supply chain analysis) before human review. Malicious or obfuscated submissions will be blocked and the author reported.
3. TypeScript code must compile with zero errors under `tsc --strict`. The codebase targets ES6 with CommonJS modules.
4. SAST rule additions must be submitted to `src/core/lite/lite_scanner.ts` alongside a test file in `tests/` that triggers the new rule.
5. Supply chain analysis features must include a `verify-pkg` test against a known-safe package and a known-suspicious package.
6. Do not include `dist/` build artifacts in PRs (already gitignored).
7. No emoji, no marketing language, no ASCII art in code or documentation.

## Reporting Bugs

Open an issue at https://github.com/javier20dev25/sentinel-cli/issues with the following information:

- CLI version (`sentinel --version`)
- Node.js version
- Operating system
- The exact command that produced the error
- Full terminal output (including the integrity check preamble)
- If the bug is a false positive: the file content or code pattern that triggered it, and why the detection is incorrect

## Reporting Security Vulnerabilities

Sentinel is a security tool; its own security is treated as critical infrastructure. Vulnerabilities in Sentinel CLI itself must be reported privately:

- Open a GitHub issue with the label `security` for private disclosure
- Do NOT open a public GitHub issue for security vulnerabilities.
- Acknowledgment within 48 hours. Fix target: 7 days for critical issues, 30 days for moderate issues.
- Scope: CLI binary, SAST rules in `lite_scanner.ts`, Signal Vault persistence logic, Supply Chain Shield tarball extraction, Integrity Manager, and OS-level Guard injection.
- Out of scope: third-party npm dependencies (report those to their respective maintainers).

## Self-Scan Results

Sentinel can scan its own source tree. Running `sentinel scan ./src --json` on the current codebase produces zero SAST findings -- the scanner does not flag any of its own patterns as malicious. The integrity manager will report `COMPROMISED` if the code hash stored in `integrity.json` does not match the runtime hash, which is expected when the source has been modified after the manifest was generated. This is the integrity system functioning as designed, not a vulnerability.

## License

BUSSL-1.1 -- Business Source License 1.1. See [LICENSE](LICENSE).

Free for non-production and personal use. Production use for security tools requires a license. Changes to GPL v2.0 after 2030-05-20.
