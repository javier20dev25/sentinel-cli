# Sentinel CLI — Security Signal Orchestrator

## Abstract

Deterministic static analysis engine and supply chain security scanner for
JavaScript, TypeScript, Python, and Go codebases. Operates without network
access. Zero false positives by design.

## Table of Contents

1. [Architecture](#architecture)
2. [Scanner Modules](#scanner-modules)
3. [Algorithmic Approach](#algorithmic-approach)
4. [CLI Reference](#cli-reference)
5. [Programmatic API](#programmatic-api)
6. [Data Formats](#data-formats)
7. [License](#license)

## Architecture

Input normalization transforms files into a uniform representation before analysis. The pipeline proceeds as a linear sequence of stages: normalization, lexical analysis, pattern matching, signal aggregation, and kill chain construction. Each stage operates on the output of the previous stage with no feedback loops.

### Pipeline Stages

1. **Input Normalization** — file type detection via extension and magic bytes, encoding detection (UTF-8, UTF-16, Latin-1), line ending normalization to LF
2. **Lexical Analysis** — tokenization for JS/TS/Python/Go using language-specific lexers; regex-based fallback for all other languages produces a token stream of identifiers, literals, and operators
3. **Pattern Matching** — LiteScanner (30 regex rules, O(n) per rule) and DeepScan (AST visitor, O(n) traversal) run in parallel over the token stream
4. **Signal Aggregation** — deduplication by (file, line, type) tuple; severity scoring via weighted heuristic: criticality * confidence * context
5. **Kill Chain Builder** — cross-signal correlation by TTP category (MITRE ATT&CK), produces a directed acyclic graph of linked signals representing an attack narrative

## Scanner Modules

### LiteScanner

30 regex patterns organized by threat category. Each pattern is compiled once and cached. Scanning is O(n) per pattern with early termination on high-confidence match. Categories:

- Secrets: API keys, tokens, private keys, connection strings
- Injections: SQL, shell, path traversal, template injection
- File Access: reads, writes, deletions outside sandbox
- Network Sinks: outbound HTTP, DNS, socket connections
- Shell Execution: exec, spawn, eval, child_process
- Crypto Misuse: weak algorithms, hardcoded IVs, ECB mode

### DeepScan

AST-level analysis for fully supported languages (JavaScript, TypeScript, Python, Go). Implements the visitor pattern traversing CST/AST produced by tree-sitter or acorn/meriyah tokenizers. Taint tracing performs source-to-sink propagation via a control flow graph approximation. Taint sources are user input, environment variables, file contents. Taint sinks are network calls, shell execution, file writes.

### Secret Detection

27 pattern families covering AWS keys, GitHub tokens, OpenAI keys, Slack tokens, Google service accounts, generic JWTs, and custom patterns. Entropy scoring functions as a secondary signal: Shannon entropy over a character window, threshold > 4.5 bits per character. Base64 decoding is attempted on candidate strings, followed by pattern matching on the decoded payload to catch encoded secrets.

### Supply Chain Verification

Dependency manifest parsing for package.json, requirements.txt, go.mod, and Cargo.toml. Package name typosquatting is detected via weighted Levenshtein distance with a threshold of edit distance < 3. Registry URL override detection flags non-canonical registry endpoints. Postinstall script capability mapping categorizes script behaviors into allowed, suspicious, and blocked operations.

### Integrity Chain

SHA-256 hash chain verification constructs a Merkle-like tree of file hashes. The root hash is signed and verified against a known-good manifest. Any file modification produces a non-matching hash that propagates to an invalid root signature.

## Algorithmic Approach

All analysis is deterministic. Given identical input, the engine produces identical output regardless of environment, time, or execution context. There is no probabilistic inference, no model inference, and no non-deterministic branching.

Core algorithms:

- **Pattern Matching**: Aho-Corasick-inspired multi-pattern matching for LiteScanner, modified to support capture groups and configurable context windows for before/after match inspection
- **AST Traversal**: Recursive descent with visitor pattern; O(n) time complexity and O(d) space complexity where d is maximum AST depth
- **Levenshtein Distance**: Wagner-Fischer algorithm implemented with O(min(m,n)) space; bounded by max edit distance < 3 for typosquatting detection, enabling early termination
- **Entropy Calculation**: Shannon entropy H(X) = -&Sigma; P(x_i) log_2 P(x_i) computed over sliding character windows; threshold > 4.5 bits/character for high-entropy classification
- **SHA-256**: FIPS 180-4 compliant implementation used for integrity verification; operates on 512-bit message blocks with 64 rounds of compression

## CLI Reference

### Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `scan [path]` | `--json`, `--fail-on-critical`, `--output` | Run all scanners on target path |
| `verify-pkg <name>` | `--registry` | Verify package integrity before install |
| `pr-scan <diff-file>` | `--json`, `--base-ref` | Scans a unified diff for introduced threats |
| `integrity-check` | `--root-hash` | Verify file system integrity chain |
| `secrets scan [path]` | `--entropy-only` | Run secret detector only |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No threats detected |
| 1 | Low/medium severity findings |
| 2 | High/critical severity findings (or `--fail-on-critical` triggered) |

## Programmatic API

```typescript
import { scanPath, scanDiff } from '@sentinel/cli';

const results = await scanPath('./src', { 
  scanners: ['litescanner', 'deepscan', 'secrets'],
  failOnCritical: true 
});
// Returns: { findings: Finding[], verdict: Verdict, filesAnalyzed: number }
```

See `src/types.ts` for complete type definitions.

## Data Formats

### JSON Output Schema

```typescript
interface ScanOutput {
  version: string;
  scanTime: string; // ISO 8601
  filesAnalyzed: number;
  findings: Finding[];
  verdict: {
    band: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    decision: 'PASS' | 'BLOCK';
  };
  killChain?: KillChainLink[];
}

interface Finding {
  file: string;
  line: number;
  column: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  type: string;
  description: string;
  snippet?: string;
  ttp?: string; // MITRE ATT&CK ID
}
```

### SARIF Output

Compatible with GitHub SARIF upload. See `schemas/sarif-schema.json`.

## License

Business Source License 1.1 — see `LICENSE` for terms.
Change Date: 2030-05-20
Change License: GNU General Public License v2.0
