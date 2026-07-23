# Build Flight Recorder

Instrument a build command and capture a forensic record of every process, file artifact, network interaction, and environment variable that participates in the build. Outputs a signed SHA-256 hash chain, per-artifact digests, a CLEAN/REVIEW verdict, and — optionally — a human-readable Build Provenance Report with cross-build diff.

## Usage

```bash
sentinel-cli build "<command>" [--provenance] [--save]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--cwd <path>` | `process.cwd()` | Working directory for the build |
| `--timeout <ms>` | `300000` | Kill the build after this many milliseconds |
| `--provenance` | off | Print full Build Provenance Report (human-readable) |
| `--save` | off | Save build record to `~/.sentinel/builds/` for cross-build diff |

### Examples

```bash
sentinel-cli build "npm run build"
sentinel-cli build "make -j4" --timeout 60000
sentinel-cli build "go build ./..." --provenance
sentinel-cli build "gcc -O2 main.c -o app" --provenance --save
sentinel-cli build "gcc -O2 main.c -o app" --provenance --save   # second run shows diff
```

## What It Captures

### 1. Process Graph

Every process spawned during the build is recorded via OS polling (200 ms interval). On Windows the recorder uses `Get-CimInstance Win32_Process`; on Linux/macOS it uses `ps`. After the build finishes, processes are filtered to only those that descend from the build command's PID, producing a clean tree with full command-line arguments (`argv`).

**Detection criteria:**
- **Dangerous tools** (`curl`, `wget`, `openssl`, `base64`, `gdb`, `nc`, etc.) spawn a `Suspicious process` anomaly
- **Unrecognized processes** (not in the system, build-tool, or known-safe lists) spawn an `Unrecognized build process` anomaly

### 2. File Artifacts with Change Tracking

A baseline of all files under the working directory is captured before the build starts (recursive, depth 4, excluding hidden files, `node_modules`, and `.git`). During the build (1 s polling interval) and after the build finishes, the recorder compares the current state against the baseline and classifies each change:

| Operation | Detection |
|-----------|-----------|
| `created` | File exists in current but not in baseline |
| `modified` | File exists in both but `size` or `mtime` changed (>100 ms tolerance) |
| `deleted` | File existed in baseline but not in current |

Every created or modified file receives a SHA-256 digest. Files with compiler-like extensions (`.o`, `.so`, `.exe`, `.wasm`, `.jar`, `.rlib`, etc.) are tagged as **artifacts** and hashed separately.

### 3. Network Connections

TCP connections and DNS queries are polled every 2 seconds via:
- **Windows**: `Get-NetTCPConnection` + `Get-DnsClientCache`
- **Linux/macOS**: `ss -tunp`

Connections to localhost (`127.0.0.1`, `::1`) are filtered out. Suspicious destinations (pastebin, transfer.sh, ngrok, webhook services, `.ru`/`.cn`/`.tk` TLDs) generate anomalies.

### 4. Environment Snapshot

Relevant build environment variables are captured at process start:

`CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS`, `LD_LIBRARY_PATH`, `LD_PRELOAD`, `PKG_CONFIG_PATH`, `PATH`, `HOME`, `CMAKE_PREFIX_PATH`, `CPATH`, `LIBRARY_PATH`, `INCLUDE`, `npm_config_registry`, `NODE_ENV`, `PYTHONPATH`, `CARGO_HOME`, `GOPATH`, `GOROOT`, `RUSTUP_HOME`

### 5. Integrity Chain

Every event (process start, file create/modify/delete, TCP connection, DNS query) produces a SHA-256 hash link that chains to the previous link:

```
linkHash = SHA256(eventType | eventFingerprint | previousHash)
```

The chain begins with a genesis link: `SHA256("genesis")`. The terminal hash and link count are displayed in every output mode.

### 6. Per-Artifact Hashes

Files with artifact extensions (`.o`, `.obj`, `.a`, `.lib`, `.so`, `.dll`, `.dylib`, `.exe`, `.out`, `.bin`, `.elf`, `.wasm`, `.jar`, `.war`, `.apk`, `.aab`, `.rlib`, `.rmeta`, `.pyc`) receive individual SHA-256 digests displayed in the summary and provenance report.

## Build Provenance Report

Use `--provenance` to produce a human-readable document instead of the terminal summary:

```
============================================================
  BUILD PROVENANCE REPORT
============================================================

  Build #20260720171044
  Command:   gcc -O2 main.c -o app
  Started:   2026-07-20T17:10:44.245Z
  Duration:  8s
  Exit code: 0
  Platform:  win32 v24.13.1
  CWD:       /home/user/project

  ── Environment ──
    CC=gcc
    CFLAGS=-O2 -march=x86-64
    ...

  ── Toolchain ──
    gcc

  ── Process Tree ──
    gcc (pid 14060) — gcc -O2 main.c -o app

  ── Artifacts ──
    a1b2c3d4e5f6    32.0 KB  dist/app
    f6e5d4c3b2a1    8.0 KB   dist/app.o
    2 artifacts (40.0 KB)

  ── File Changes ──
    Created:  2
    Modified: 1
    Deleted:  0
      + dist/app (32.0 KB)
      + dist/app.o (8.0 KB)
      ~ src/main.c (4.2 KB)

  ── Network ──
    DNS  debian.example.com
    TCP  93.184.216.34:443

  ── Diff vs Previous Build ──
    Files created: 1 → 2
    Artifacts: 1 → 2
    New artifacts:
      + f6e5d4c3b2a1  dist/app.o
    New anomalies: yes

  ── Integrity ──
    Hash chain links: 14
    Terminal hash:    431238cff0d437410291356875b78c2a16778e9f5a59ad50ebe6b173383d52c9

  Verdict: CLEAN
============================================================
```

## Build-to-Build Diff

When `--save` is used, the build record is written to `~/.sentinel/builds/<tool>_<cwd>_prev.json`. A subsequent `--save` run loads the previous record and produces a `Diff vs Previous Build` section showing:

- Process count delta
- File operation deltas (created, modified, deleted)
- New and removed artifact hashes
- New anomaly detection

## Verdict Logic

| Condition | Verdict |
|-----------|---------|
| No anomalies, build tools detected | `CLEAN` |
| No anomalies, no build tools | `REVIEW` (maybe not a build) |
| One or more anomalies | `REVIEW` |

## Exit Codes

The recorder exits with the build's exit code. Anomalies do not change the exit code; they are advisory.

## Data Types

Defined in `src/core/network/build-types.ts`.

```typescript
interface BuildRecord {
  command: string
  args: string[]
  cwd: string
  startTime: string
  durationMs: number
  exitCode: number | null
  platform: string
  nodeVersion: string
  env: Record<string, string>
  processes: BuildProcessEvent[]
  files: BuildFileEvent[]
  network: BuildNetEvent[]
  artifactHashes: ArtifactHash[]
  summary: BuildSummary
  hashChain: BuildChainLink[]
}
```

## Architecture

```
CLI (main.ts)
  └─ build command
       ├─ recordBuild()           ← src/cli/build/build-recorder.ts
       │    ├─ spawn()            ← child process with shell (Windows) or direct exec
       │    ├─ pollProcesses()    ← 200 ms interval, baseline + ancestry filter
       │    ├─ pollFiles()        ← 1 s interval, mtime/size diff + post-build final scan
       │    ├─ pollNetwork()      ← 2 s interval, TCP + DNS
       │    └─ BuildRecord        ← includes env snapshot + per-artifact hashes
       ├─ renderBuildSummary()    ← src/cli/build/build-summary.ts
       └─ renderBuildProvenance() ← src/cli/build/build-provenance.ts
            └─ BuildDiff          ← cross-build SHA-256 comparison
```

## Classification Sets

### `BUILD_TOOLS`
gcc, g++, clang, clang++, cl.exe, link.exe, ld, ar, lib.exe, make, cmake, ninja, nmake, msbuild, cargo, rustc, go, javac, kotlinc, node, tsc, esbuild, webpack, rollup, vite, python, pip, cc, c++

### `DANGEROUS_BUILD_TOOLS`
curl, wget, fetch, axel, aria2c, perl, ruby, lua, openssl, base64, telnet, nc, ncat, socat, gdb, lldb, objdump, readelf, strings

### `SYSTEM_PROCESSES`
Excludes 28+ Windows system processes (svchost, lsass, dwm, etc.) and equivalent on Linux/macOS.

### `KNOWN_BUILD_PROCESSES`
node, cmd.exe, powershell, bash, sh, zsh, make, nmake, gcc, clang, rustc, cargo, go, python, java, javac, mvn, gradle, npm, npx, yarn, pnpm, tsc, esbuild, webpack, rollup, vite, babel
