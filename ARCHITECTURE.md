# Sentinel Architecture — Build Trust Platform

## Overview

Sentinel es una **Build Trust Platform**: analiza no solo el código, sino el ecosistema completo que lo produjo. Workspace, scripts, toolchain, PATH, CI, artifacts, red, inputs, grafo de procesos, historial, tendencias, identidad del builder, contratos y confianza.

**Versión:** 4.0.0  
**Stack:** TypeScript + Node.js ≥20 + Vitest  
**Estructura:** `src/cli/` (frontend CLI) + `src/core/` (lógica principal) + `src/core/network/` (build trust modules)

---

## Tabla de Contenidos

1. [Arquitectura General](#1-arquitectura-general)
2. [Build Flight Recorder](#2-build-flight-recorder)
3. [Chain of Build Trust (10 módulos)](#3-chain-of-build-trust)
   - 3.1 File Read Provenance
   - 3.2 Build Input Identity
   - 3.3 PATH Resolution
   - 3.4 Trust Engine
   - 3.5 Process Lifetime
   - 3.6 Build Intent
   - 3.7 Build Contract
    - 3.8 Secret Flow
    - 3.9 Hermetic Build Score
    - 3.10 Compiler Invocation Identity
4. [Build Identity](#4-build-identity)
5. [Build DNA & Multi-DNA](#5-build-dna--multi-dna)
5. [Build DNA & Multi-DNA](#5-build-dna--multi-dna)
6. [Provenance Graph](#6-provenance-graph)
7. [Build Baseline & Normality](#7-build-baseline--normality)
8. [Trend Engine](#8-trend-engine)
9. [Build Explain](#9-build-explain)
10. [Evidence Chain](#10-evidence-chain)
11. [Risk Engine](#11-risk-engine)
12. [Anti-Evasion Engine](#12-anti-evasion-engine)
13. [Behavior Engine](#13-behavior-engine)
14. [Canary System](#14-canary-system)
15. [Native Event System](#15-native-event-system)
16. [Network Audit Pipeline](#16-network-audit-pipeline)
17. [CLI Commands](#17-cli-commands)
18. [Tipos (build-types.ts)](#18-tipos-build-typests)
19. [Testing](#19-testing)
20. [Configuración](#20-configuración)
21. [External Validation](#21-external-validation)
22. [Evidence Reliability Engine](#22-evidence-reliability-engine)
23. [Evasion Detection](#23-evasion-detection)
24. [Build Serializer](#24-build-serializer)
25. [Roadmap](#25-roadmap)

---

## 1. Arquitectura General

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI (commander)                        │
│  src/cli/main.ts — scan, build, explain, history, policy...  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                    Build Recorder                           │
│        src/cli/build/build-recorder.ts                     │
│  recordBuild() → BuildRecord completo                      │
│  Polling: processes, files, network, reads, contracts       │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Core Network Modules                           │
│  src/core/network/                                          │
│                                                             │
│  ┌─────────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ File Read       │  │ Build Input  │  │ PATH          │  │
│  │ Provenance      │  │ Identity     │  │ Resolution    │  │
│  └────────┬────────┘  └──────┬───────┘  └──────┬────────┘  │
│           │                  │                  │           │
│  ┌────────▼──────────────────▼──────────────────▼────────┐  │
│  │                  Trust Engine                         │  │
│  │  7 dimensiones ponderadas → Score 0-100 + breakdown  │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                           │                                  │
│  ┌────────────────────────▼──────────────────────────────┐  │
│  │  Process    │  Build     │  Build     │  Build        │  │
│  │  Lifetime   │  Intent    │  Contract  │  Identity     │  │
│  └─────────────┴────────────┴────────────┴───────────────┘  │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Build DNA   │  │ Provenance   │  │ Trend Engine     │   │
│  │ + Multi-DNA │  │ Graph        │  │ (EWMA/CUSUM)     │   │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Risk Engine │  │ Anti-Evasion │  │ Canary System    │   │
│  │ (behavior)  │  │ Engine       │  │ (decoy files)    │   │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐                           │
│  │ Evidence    │  │ Behavior     │                           │
│  │ Chain       │  │ Engine       │                           │
│  └─────────────┘  └──────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Build Flight Recorder

**Archivo:** `src/cli/build/build-recorder.ts` (527 líneas)

### Flujo completo de recordBuild():

```
Pre-build
  ├─ capturePathState()         → PATH + 22 tools resueltas
  ├─ capturePreBuildInventory() → mtime/size de todos los archivos
  ├─ buildInputIdentity()       → scan + fingerprint SHA256 de inputs
  ├─ baselinePids               → snapshot de PIDs pre-existentes
  └─ fileBaseline               → snapshot de archivos

Durante (polling cada N ms)
  ├─ pollProcesses (200ms)
  │   ├─ trackProcessExits()    → detecta PIDs desaparecidos
  │   ├─ captureScriptIdentity()→ scripts con imports
  │   └─ hash chain link
  ├─ pollFiles (1000ms)
  │   ├─ detect created/modified/deleted
  │   └─ hash chain link
  ├─ pollNetwork (2000ms)
  │   ├─ TCP connections
  │   └─ DNS queries
  ├─ pollReads (1500ms)
  │   ├─ pollProcessOpenFiles() → archivos abiertos por PID
  │   └─ dedup

Post-build
  ├─ detectReadFilesPostBuild() → inferencia por mtime
  ├─ deduplicateReadEvents()
  ├─ capturePathState()         → post-build PATH snapshot
  ├─ computeTrust()             → Trust Score 0-100
  ├─ buildIntentFlow()          → flujo esperado vs observado
  ├─ loadContract() / updateContract() / saveContract()
  ├─ findEphemeralProcesses()   → <100ms
  ├─ Anomalías:
  │   ├─ dangerousSeen          → curl/wget/perl/etc
  │   ├─ unknown processes
  │   ├─ suspicious network     → pastebin, .ru, .cn
  │   ├─ intent deviations
  │   ├─ contract violations
  │   └─ ephemeral processes
  └─ BuildRecord completo
```

### Políticas de polling:
- `POLL_PROCESS_MS = 200`
- `POLL_FILE_MS = 1000`
- `POLL_NET_MS = 2000`
- `POLL_READ_MS = 1500`

### BuildRecord (build-types.ts):

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
  identity?: BuildIdentity
  readFiles?: FileReadEvent[]
  inputIdentity?: BuildInputIdentity
  scriptIdentities?: ScriptIdentity[]
  pathResolutions?: PathState[]
  trustResult?: TrustResult
  buildIntent?: BuildIntentStep[]
  buildContractViolations?: BuildContractViolation[]
  secretFlow?: SecretFlow
  compilerInvocations?: CompilerInvocationIdentity
  hermetricScore?: number
  reproducibilityScore?: number
}
```

---

## 3. Chain of Build Trust (10 módulos)

### 3.1 File Read Provenance

**Archivo:** `src/core/network/file-read-provenance.ts` (209 líneas)  
**Tests:** `file-read-provenance.test.ts` (16 tests)

**Propósito:** Rastrear qué archivos lee cada proceso del build.

**3 estrategias:**
1. **Pre-build inventory** (`capturePreBuildInventory`): Camina el directorio, captura size + mtimeMs de cada archivo (excluye `.`, `node_modules`, `.git`).
2. **Poll en vivo** (`pollProcessOpenFiles`): Por cada PID en el build:
   - Linux: `/proc/<pid>/fd/` → `readlink()` → filtra por cwd
   - Windows: `Get-Process -Id <pid> | Select-Object Modules` + `Handle`
3. **Post-build detection** (`detectReadFilesPostBuild`): Compara mtime post-build vs pre-build inventory. Asigna el proceso más cercano temporalmente como responsable.

**Deduplicación:** Clave compuesta `filePath:pid`.

**Rendering:** Agrupa por proceso, muestra hasta 5 archivos por proceso, máximo 20 líneas.

**Integración:** `pollReads` cada 1500ms en recorder. `readFiles` se almacena en `BuildRecord.readFiles`. Aristas `read` en `provenance-graph.ts:addReadEdges()`.

### 3.2 Build Input Identity

**Archivo:** `src/core/network/build-input-identity.ts` (353 líneas)  
**Tests:** `build-input-identity.test.ts` (42 tests)

**Propósito:** Identificar, categorizar y fingerprintear todos los archivos de entrada del build.

**Categorías:**
- `build_system`: Makefile, CMakeLists.txt, meson.build, SConstruct, build.ninja, WORKSPACE, BUILD.bazel (12 patrones)
- `language_config`: Cargo.toml, go.mod, package.json, pom.xml, build.gradle, pyproject.toml, requirements.txt, etc. (22 patrones)
- `ci_config`: `.github/workflows/`, `.gitlab-ci.yml`, azure-pipelines.yml, .circleci/, Jenkinsfile, .woodpecker/, .drone.yml (8 patrones)
- `shell_script`: `.sh`, `.ps1`, `.bat`, `.cmd`, `.bash`, `.zsh`, `.fish`
- Excluye: README*, LICENSE*, .gitignore, node_modules/, .git/, docs/, etc.

**Input fingerprint:** SHA256 determinístico de todos los inputs ordenados por path → `${path}:${sha256}:${size}:${permissions}\n`

**Diff:** Detecta `new`, `removed`, `modified`, `permission_changed`, `owner_changed`, `symlink_changed`.

**Input Stability:** `(current/previous)*100` — porcentaje de inputs mantenidos vs baseline.

**Script Identity:** Captura intérprete + SHA256 + realpath + imports extraídos por lenguaje (Python: `import`/`from`, JS/TS: `require`/`import`, Shell: `source`/`.`).

**Toolchain Purity:** `expectedOnly / max(expected.length, 1) * 100`.

### 3.3 PATH Resolution

**Archivo:** `src/core/network/path-resolution.ts` (197 líneas)

**Propósito:** Capturar estado completo de PATH + resolución de 22 herramientas de compilación.

**Herramientas resueltas:**
- Compiladores: gcc, g++, clang, clang++, cc, c++
- Linkers/binutils: ld, ld.lld, ar, ranlib, strip, objcopy, nm, readelf
- Build systems: make, cmake, ninja, meson
- Runtimes: python, python3, node, rustc, cargo, go, javac, java
- Network: curl, wget, git

**Por cada tool:** `which` → `realpath` → `fs.readFileSync` + SHA256 → `--version`

**Diff entre dos estados:**
- `reordered` (warning): Misma longitud, entries cambiaron de posición
- `prepended` (critical): Entry nueva al inicio
- `appended` (warning): Entry nueva al final
- `removed` (warning): Entry eliminada
- `shadowed` (critical): Misma tool resuelve a distinto realpath

**Integración:** `capturePathState()` pre-build + post-build. Se guarda como `pathResolutions: PathState[]`.

### 3.4 Trust Engine

**Archivo:** `src/core/network/build-trust-engine.ts` (279 líneas)

**Propósito:** Ponderar 7 dimensiones de confianza → score 0-100 completamente explicable.

| Dimensión | Peso | Score base | Penalizaciones |
|-----------|------|------------|----------------|
| toolchain_identity | 0.18 | 100 | -20 sin toolchain, -15/SHA cambiado |
| input_identity | 0.18 | 100 | -8/modified, -5/new, -5/removed (máx -40) |
| artifact_integrity | 0.15 | 100 | -10/artifact cambiado (máx -40) |
| behavior | 0.15 | 100 | -15/anomalía (máx -45) |
| network | 0.12 | 100 | -5/conn (máx -25), -25 destinos sospechosos |
| graph | 0.12 | 100 | -5/unrecognized process (máx -20) |
| trend | 0.10 | 80 | +10 hash links, +10 duración estable, -10 cambio >50% |

**Score global:** `round(sum(score_i * weight_i))`

**Métricas adicionales:**
- `inputStability`: delega a `BuildInputIdentity.inputStability`
- `toolchainPurity`: % de herramientas esperadas que están presentes
- `buildDeterminism`: boolean — mismos inputs + mismos artifacts = true

**Rendering:** Barra visual `█░` por dimensión + evidencia textual con `+N`/`-N`.

### 3.5 Process Lifetime

**Archivo:** `src/core/network/process-lifetime.ts` (88 líneas)  
**Tests:** `build-lifetime.test.ts` (21 tests)

**Propósito:** Trackear startTime y exitTime por proceso; detectar efímeros <100ms.

**Mecanismo:** `trackProcessExits()` compara `currentPids` vs `previousPollPids`. PIDs desaparecidos se marcan con `exitTime = now`.

**Efímeros:** `findEphemeralProcesses(thresholdMs=100)` — procesos con duración positiva <100ms. Se reportan como anomalía.

### 3.6 Build Intent

**Archivo:** `src/core/network/build-intent.ts` (148 líneas)

**Propósito:** Clasificar cada proceso en 10 intenciones + comparar flujo observado vs esperado.

**Intenciones (ProcessIntent):**
`configure` | `compile` | `link` | `archive` | `download` | `script` | `package` | `test` | `install` | `unknown`

**Mapeo de 30+ herramientas:** gcc/clang → compile, ld → link, curl/wget → download, make/ninja/cargo → package, npm/pip → install, etc.

**Orden canónico esperado:** `configure → compile → archive → link → download → package → script → test → install`

**Desviaciones detectadas:**
- Orden inesperado: etapa posterior antes que anterior
- Etapa no esperada: observada pero no en flujo esperado
- Etapa esperada faltante: si hay build_system inputs, configure es esperado

### 3.7 Build Contract

**Archivo:** `src/core/network/build-contract.ts` (116 líneas)

**Propósito:** Persistir herramientas vistas por proyecto; detectar herramientas nuevas como violaciones.

**Almacenamiento:** `~/.sentinel/builds/contracts/<command>_<cwd_sanitized>.json`

**Violaciones:**
- **Tool nueva** (warning): Aparece después de `threshold=5` builds
- **Tool faltante** (info): Tool con count≥threshold no aparece en este build
- **Downloader temprano** (critical): curl/wget/fetch con count < threshold (proyecto joven descargando)

### 3.8 Secret Flow

**Archivo:** `src/core/network/secret-flow.ts` (187 líneas)

**Propósito:** Rastrear qué secretos lee cada proceso del build y si esos secretos terminan en conexiones de red (exfiltration risk).

**Detección de secretos (20 patrones):**
- `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_` (Stripe)
- `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` (GitHub tokens)
- `AKIA` + 20 chars (AWS access key)
- `-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----`
- `eyJ` (JWT), `mongodb.*:([^@]+)@` (Mongo connection strings)
- `xox[abposr]-` (Slack tokens), `AIza[0-9A-Za-z_-]` (GCP API)
- `sq0atp-`, `sq0csp-` (Square), `sk-[0-9a-fA-F]{32,}` (OpenAI)
- `pk-[0-9a-fA-F]{32,}`, `da2-[a-z0-9]{26}` (AppSync)
- `ghr_[0-9a-zA-Z]{35,}`, `npm_[a-zA-Z0-9]{36}`, `pat-[a-zA-Z0-9]{22,}`
- `pypi-[A-Za-z0-9]`, `rubygems_[A-Za-z0-9]`

**Detección por archivos sensibles (por nombre):**
- `.env*`, `credentials`, `.netrc`, `*.pem`, `*.key`, `id_rsa`, `id_dsa`, `id_ed25519`, `id_ecdsa`
- `kubeconfig`, `service-account*`, `secrets.yml`, `tokens`, `oauth*`

**Detección por variables de entorno (38 vars):**
- `AWS_SECRET_*`, `AWS_SESSION_TOKEN`, `AZURE_*`, `GCP_PROJECT`, `GOOGLE_*`
- `GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_*`, `BITBUCKET_*`
- `STRIPE_*`, `SLACK_*`, `DOCKER_*`, `NPM_TOKEN`, `PYPI_TOKEN`
- `DATABASE_URL`, `REDIS_URL`, `MONGODB_URI`, `PG*`, `MYSQL_*`, `MONGO_*`

**Chain de Exfiltración:**
- `buildSecretFlowChains()`: Procesa todas las lecturas de archivos sensibles + variables de entorno del build, detecta si algún proceso que leyó secretos también hizo conexiones de red, asigna severidad (CRITICAL si exfiltración detectada, HIGH si hay secretos críticos, MEDIUM si hay secretos).

**API pública:**
- `scanFileForSecrets(filePath, content)` — escanea contenido de archivo contra 20 patrones, retorna `SecretAccess[]`
- `scanProcessReadsForSecrets(readEvents)` — cruza eventos de lectura de archivos contra archivos sensibles por nombre
- `scanEnvForSecrets()` — escanea `process.env` contra 38 vars sensibles, retorna `SecretAccess[]`
- `buildSecretFlowChains(processes, netEvents, fileReadEvents)` — construye cadenas secreto → PID → red
- `computeHermeticScore(netConns, unknownTools, pathChanges, buildSteps, ...)` — métrica 0-100 de hermeticidad
- `computeReproducibilityScore(...)` — métrica 0-100 de reproducibilidad
- `renderSecretFlowChains(chains)` — renderizado ASCII de cadenas de secretos
- `renderHermeticScore(score)` — renderizado ASCII con barra visual
- `renderReproducibilityScore(result)` — renderizado ASCII con check/x

### 3.9 Hermetic Build Score

**Implementado en:** `src/core/network/secret-flow.ts` (como parte de Secret Flow)

**Fórmula:** `score = 100 - sum(penalizaciones)`

**Penalizaciones (cada una tiene un máximo):**
| Factor | Penalización base | Máx |
|--------|-------------------|-----|
| Conexiones de red | `min(count * 8, 30)` | 30 |
| Herramientas desconocidas | `min(count * 5, 20)` | 20 |
| Cambios de PATH | `min(count * 10, 20)` | 20 |
| Etapas inesperadas | 5 c/u | 20 |
| Contract violations | 10 c/u | 40 |
| Build ephemeral (sin baseline) | 15 | 15 |
| Secretos encontrados | 8 c/u | 30 |

**Interpretación:**
- 90–100: Hermetic ✅
- 70–89: Mostly hermetic
- 50–69: Partial hermetic
- <50: Non-hermetic ⚠️

### 3.10 Compiler Invocation Identity

**Archivo:** `src/core/network/compiler-invocation.ts` (171 líneas)

**Propósito:** Capturar el argv exacto + response files + environment de cada invocación de compilador/linker para identificar builds, detectar flags sospechosos y permitir reproducibilidad.

**Compiladores detectados (14):**
`gcc`, `g++`, `cc`, `c++`, `clang`, `clang++`, `cc1`, `cc1plus`, `collect2`, `rustc`, `go`, `javac`, `kotlinc`, `ghc`

**Linkers detectados (5):**
`ld`, `ld.lld`, `ld.gold`, `lld-link`, `link`

**Flags sospechosos detectados (en argv y response files):**
- `-fno-stack-protector`, `-z execstack`: deshabilitar protecciones de seguridad
- `-fplugin`, `-fplugin-arg-*`: plugins de compilador (potencialmente maliciosos)
- `-Wl,--enable-new-dtags`, `-Wl,-rpath`: manipulación de RPATH
- `--no-crypto`, `--no-verify`: deshabilitar verificación criptográfica (en rustc/go)

**API pública:**
- `isCompilerOrLinker(name)` — detecta si un nombre de proceso es compilador/linker conocido
- `extractCompilerInvocation(process, cwd)` — parsea argv completo, extrae inputFiles, outputFiles, flags, defines, includeDirs, responseFiles con contenido, envSnapshot
- `analyzeCompilerInvocations(processes)` — agrega todas las invocaciones de compiladores del build, detecta invocaciones sospechosas
- `renderCompilerInvocations(invocations)` — renderizado ASCII de invocaciones

---

## 4. Build Identity

**Archivo:** `src/core/network/build-identity.ts` (173 líneas)

**Propósito:** Capturar identidad completa del entorno de compilación.

**Campos:**
- Hostname, platform, arch, kernel, kernelVersion, OS version
- Container detection (Docker, containerd, kubepods)
- CI provider detection: GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps
- toolVersions: 15 herramientas con `--version`
- toolIdentities: 15 herramientas con `which` → `realpath` → SHA256 → size → mtime
- builderProcess, cpus, memoryGb, uptimeHours

---

## 5. Build DNA & Multi-DNA

**Archivo:** `src/core/network/build-dna.ts` (369 líneas)

**Build DNA:** Fingerprint de una build con 7 dimensiones:
- `toolchain`: uniqueProcesses ordenados
- `envVector`: environment keys ordenados
- `artifactHashes`: SHA256 de artifacts ordenados
- `processGraphSignature`: SHA256 del árbol de procesos serializado
- `networkProfile`: count TCP + hosts ordenados
- `totalFileOps`: created + modified + deleted
- `durationMs`, `anomalyCount`

**Multi-DNA:** 6 fingerprints cortos (SHA256 truncados a 16 chars):
- `toolchain`, `environment`, `artifact`, `network`, `graph`, `behavior`

**Similaridad:**
- `computeDnaSimilarity()`: Jaccard + numericSim con pesos [0.25, 0.25, 0.2, 0.1, 0.1, 0.05, 0.05]
- `computeMultiDnaSimilarity()`: Coincidencia exacta con pesos [0.2, 0.1, 0.25, 0.1, 0.2, 0.15]

**Build Graph Edges:** `inferBuildGraph()` produce aristas `spawned`, `produced` desde procesos y archivos.

**Behavior Chain:** `deriveBehaviorChain()` — secuencia de comportamientos observados (configure → compile → link → ...).

---

## 6. Provenance Graph

**Archivo:** `src/core/network/provenance-graph.ts` (285 líneas)

**Propósito:** Construir un grafo de procedencia del build con nodos (tool, source, intermediate, artifact) y aristas (compiled, linked, archived, generated, downloaded, configured, read).

**Nodos:**
- `tool`: gcc, ld, make, etc.
- `source`: .c, .cc, .cpp, .h, .rs, .go, .java, .ts, .js, .py, .s, .S, .asm
- `intermediate`: .o, .obj, .lo, .lib, .a, .rlib, .class
- `artifact`: .so, .dll, .exe, .out, .wasm, .node, .dylib, .bin, .elf

**Aristas:** Inferidas por proximidad temporal entre procesos y archivos creados.

**Stages:** `configure → compile → archive → link → download → package → finalize`

**Read edges:** `addReadEdges()` conecta tools con archivos leídos vía `FileReadEvent[]`.

---

## 7. Build Baseline & Normality

**Archivo:** `src/core/network/build-baseline.ts` (121 líneas)

**Propósito:** Mantener baseline estadístico de builds para detectar outliers.

**Baseline stats:** mean + std de duration, artifact count, file ops. Typical toolchain (tools presentes en ≥80% de builds). Typical graph signature.

**Normality (z-score):** `z = (value - mean) / std`. Outlier si |z| > 3 en cualquier dimensión.

**Almacenamiento:** `~/.sentinel/baselines/<command>_<cwd>.json` (máx 50 builds).

---

## 8. Trend Engine

**Archivo:** `src/core/network/trend-engine.ts` (197 líneas)

**Propósito:** Análisis de tendencias históricas con EWMA, CUSUM y slope.

**Métricas trackeadas (10):** duration_ms, process_count, artifact_count, file_creations, file_modifications, file_deletions, file_ops_total, network_connections, tool_count, unique_processes.

**Algoritmos:**
- **Slope:** regresión lineal simple sobre índices
- **EWMA:** suavizado exponencial con α=0.3
- **CUSUM:** detección de cambio acumulado con k=0.5σ

**Drift:** `none` (<3%), `low` (<10%), `medium` (<20%), `high` (≥20%). Alert si high o medium con CUSUM > 3σ.

**Almacenamiento:** `~/.sentinel/builds/<command>_<cwd>/<timestamp>.json` (máx 200 builds).

---

## 9. Build Explain

**Archivo:** `src/core/network/build-explain.ts` (374 líneas)

**Propósito:** Explicar por qué un build difiere del anterior o del release baseline.

**Eventos detectados:**
- `process_spawn`: procesos nuevos (con severidad según peligrosidad)
- `file_create`: archivos nuevos
- `artifact_hash`: artifacts con SHA256 cambiado (severidad high)
- `network_conn`: conexiones TCP nuevas
- `dns_query`: DNS queries nuevas

**Causal chain:** Construye cadena causal desde el evento raíz (primero en timeline o primer high severity).

**Confidence breakdown:** toolchain, environment, artifact, network, graph, behavior con pesos.

---

## 10. Evidence Chain

**Archivo:** `src/core/network/evidence-chain.ts` (285 líneas)

**Propósito:** Correlacionar eventos en cadenas de evidencia (exfiltration, preparation, snapshot, embedding).

**Cadenas detectadas:**
- **Exfiltration chain:** file reads → git bundle → network upload
- **Preparation chain:** git commands → system preparation
- **Snapshot chain:** mass file reads → git history → full repo snapshot
- **Embedding chain:** file reads → AI embeddings

---

## 11. Risk Engine

**Archivo:** `src/core/network/risk-engine.ts` (269 líneas)

**Propósito:** Evaluar riesgo basado en comportamientos observados con pesos y multiplicadores.

**Behavior weights (37 tipos):** desde `repo_indexed` (25) hasta `canary_exfiltrated` (99).

**Multiplicadores:**
- `bundle_plus_upload`: 2.0x
- `secret_plus_exfil`: 2.5x
- `anti_evasion_plus_exfil`: 2.5x
- `canary_triggered`: 3.0x
- `multiple_behaviors`: 1.3x
- Temporal: 1.1x–1.5x según avg gap entre comportamientos

**Score normalizado 0-100.** Thresholds: CRITICAL ≥80, HIGH ≥50, MEDIUM ≥20, LOW <20.

---

## 12. Anti-Evasion Engine

**Archivo:** `src/core/network/anti-evasion-engine.ts` (437 líneas)

**Propósito:** Detectar técnicas de evasión de monitoreo.

**Señales (9 tipos):**
- `artificial_rhythm`, `fragmented_traffic`, `protocol_hopping`, `custom_compression`
- `monitor_awareness`, `memory_only_ops`, `distributed_chain`, `no_temp_files`, `preparation_phase`, `process_chain`

**Pesos:** 15–40 según severidad.

---

## 13. Behavior Engine

**Archivo:** `src/core/network/behavior-engine.ts`

**Propósito:** Clasificar eventos individuales (flows, procesos, file accesses, git commands) en comportamientos.

**Comportamientos clasificados:**
- Flows: AI prompts, code upload, suspicious connections
- Procesos: monitor disable, preparation commands
- File accesses: mass read, embedding, secrets scan
- Git: bundle, archive, history read, objects read, push

---

## 14. Canary System

**Archivo:** `src/core/network/canary-system.ts` (235 líneas)

**Propósito:** Sistema de señuelos (decoy files + fake secrets) para detectar exfiltración.

**15 decoy files:** customer_data_2026_q2.csv, api_keys_internal.json, aws_credentials_prod.json, etc.

**14 fake secret patterns:** `sk-live-`, `ghp_`, `AKIA`, `-----BEGIN RSA PRIVATE KEY-----`, etc.

**Marker:** `SENTINEL_CANARY_TOKEN_` en contenido de señuelos.

---

## 15. Native Event System

**Archivo:** `src/core/network/native-events.ts` (129 líneas)

**Propósito:** Abstracción unificada para recibir eventos del sistema operativo en tiempo real, reemplazando el polling periódico de procesos.

**Interfaz común (`NativeEventProvider`):**
```typescript
interface NativeEventProvider {
  name: string
  start(): void
  stop(): void
  onProcessEvent(callback): void
  onFileEvent(callback): void
  onNetEvent(callback): void
}
```

**Implementaciones:**
| Provider | OS | Mecanismo | Funcionalidad |
|----------|----|-----------|---------------|
| `EtwEventProvider` | Windows | ETW via `wevtutil` + `Get-WinEvent` | ProcessStart, ProcessStop, TcpIp (connect/disconnect) |
| `EBpfEventProvider` | Linux | eBPF via `execsnoop`/`opensnoop`/`tcptracer` (BCC) | Process exec, File open, TCP connect |
| `PollingEventProvider` | Any | `ps`/`Get-CimInstance` a intervalos | Procesos, archivos, red |

**Factory:** `createEventProvider()` selecciona automáticamente: ETW en Windows, eBPF en Linux (si BCC disponible), polling como fallback.

---

## 16. Network Audit Pipeline

**Archivo:** `src/core/network/pipeline.ts` (499 líneas)

**Propósito:** Orquestar el pipeline completo de auditoría de red.

**Flujo completo:**
1. Recibir eventos (flows, procesos, file accesses, git)
2. Clasificar cada evento en comportamientos
3. Anti-evasion signals
4. Preparation detection
5. Process chain correlation
6. Logical correlation rules (bundle+upload → upload, canary+exfil → exfiltrated)
7. Risk assessment
8. Build evidence chain + verify
9. MITRE ATT&CK mapping
10. Behavior timeline (Preparation → Collection → Packaging → Exfiltration)
11. Build verdict (session DNA + confidence score)

---

## 17. CLI Commands

**Archivo:** `src/cli/main.ts`

| Comando | Descripción |
|---------|-------------|
| `scan [path]` | SAST scan con múltiples formatos de salida |
| `build run <command>` | Build Flight Recorder + Trust Report |
| `build explain [id]` | Explicar diferencias entre builds |
| `build mark-release <id>` | Marcar build como release baseline |
| `build release` | Mostrar release actual |
| `explain [paths]` | Explicar hallazgos de seguridad |
| `history [path]` | Risk history + trends |
| `graph history/diff` | Graph snapshot management |
| `verify-pkg <package>` | Supply chain audit |
| `audit-deps` | Dependency audit (lockfile, OSV, provenance) |
| `deps-tree` | Transitive dependency scan |
| `trust-cache` | Trust cache management |
| `permissions [package]` | Capability audit |
| `policy` | Policy management |
| `baseline create/diff` | System baseline |
| `doctor` | System health check |
| `drift <pkg> <ver> <path>` | Behavioral drift |
| `benchmark` | FP/FN corpus benchmark |
| `integrity` | Sentinel self-integrity check |

---

## 18. Tipos (build-types.ts)

**Archivo:** `src/core/network/build-types.ts` (525 líneas)

### Core:
- `BuildRecord`, `BuildProcessEvent`, `BuildFileEvent`, `BuildNetEvent`
- `BuildSummary`, `BuildChainLink`, `ArtifactHash`, `BuildStep`
- `BuildIdentity`, `ToolIdentity`

### Input Identity:
- `BuildInputCategory`, `BuildInput`, `BuildInputIdentity`, `InputChange`, `ScriptIdentity`

### PATH Resolution:
- `ToolResolution`, `PathState`

### Trust Engine:
- `TrustDimension`, `TrustResult`

### Process Intent:
- `ProcessIntent`, `BuildIntentStep`, `BuildIntentFlow`

### Build Contract:
- `BuildContractEntry`, `BuildContractViolation`

### File Read:
- `FileReadEvent`

### Secret Flow:
- `SecretAccess`, `SecretFlowChain`, `SecretFlow`

### Compiler Invocation:
- `CompilerInvocation`, `CompilerInvocationIdentity`

### DNA & Explain:
- `BuildDna`, `MultiDna`, `MultiDnaSimilarity`, `BuildExplanation`, `ConfidenceBreakdown`
- `CausalNode`, `BuildGraphEdge`, `ExplainEvent`, `ExplainResult`

### Provenance:
- `ProvenanceNode`, `ProvenanceEdge`, `ProvenanceGraph`, `ProvenanceNodeType`

### Baseline:
- `BuildBaselineStats`, `BuildNormalityResult`

### Trend:
- `TrendMetric`, `TrendResult`

### Constants:
- `BUILD_TOOLS` (40+ tools), `DANGEROUS_BUILD_TOOLS` (10+), `BUILD_ENV_KEYS` (18 keys)

---

## 19. Testing

**Framework:** Vitest (v4.1.7)  
**Config:** `vitest.config.ts` con `testTimeout: 30000`

**Ubicación:** `src/**/*.test.ts` y `src/**/*.spec.ts`

**Tests del Build Trust:**
| Archivo | Tests |
|---------|-------|
| `file-read-provenance.test.ts` | 16 |
| `build-input-identity.test.ts` | 42 |
| `build-lifetime.test.ts` | 21 |
| `secret-flow.test.ts` | 23 |
| `compiler-invocation.test.ts` | 10 |
| `evidence-reliability.test.ts` | 16 |
| `evasion-detection.test.ts` | 10 |
| `build-serializer.test.ts` | 7 |
| `build-explain.test.ts` | — |
| `build-adv-features.test.ts` | — |

**Total suite:** 901 tests, 47 test files, 0 fallos.

---

## 20. Configuración

**Variables de entorno relevantes:**
- `PATH`: capturado pre/post build
- `NODE_OPTIONS`: `--no-deprecation` para el proceso hijo
- `DOCKER_IMAGE`, `IMAGE_NAME`, `CONTAINER_ID`: detección de contenedor
- Envars CI: `GITHUB_*`, `GITLAB_*`, `JENKINS_*`, `CIRCLE_*`, `TF_BUILD`

**Archivos de almacenamiento:**
| Propósito | Ruta |
|-----------|------|
| Build records | `~/.sentinel/builds/<key>/<timestamp>.json` |
| Baselines | `~/.sentinel/baselines/<key>.json` |
| Contracts | `~/.sentinel/builds/contracts/<key>.json` |
| Release store | `~/.sentinel/builds/<key>_release.json` |
| Session history | `~/.sentinel/history/` |
| Graph history | `~/.sentinel/graphs/` |

**Políticas:** `~/.sentinel/policy.json` — ci-mode, fail-closed, quarantine.

---

## 21. External Validation

**Archivo:** `scripts/validate-projects.ts` (150 líneas)

**Propósito:** Framework para validar Sentinel contra proyectos reales, midiendo FP/FN y asegurando que las detecciones sean correctas.

**Proyectos validados:**
| Proyecto | Lenguaje | Build system | Expected tools |
|----------|----------|-------------|---------------|
| `hello-node` | JavaScript | node/npm | node, npm |
| `libsodium` | C | autotools | gcc/cc, ld, libtool, make |
| `busybox` | C | make | gcc/cc, ld, make, gzip |
| `redis` | C | make | gcc/cc, ld, make |

**Flujo de validación:**
1. `git clone --depth=1` en `~/.sentinel/validation-sources/`
2. Ejecuta `recordBuild()` para cada proyecto
3. Reporta hermetic score, trust score, tools esperados vs detectados, artifacts esperados vs encontrados
4. Detecta anomalías (tools faltantes, artifacts extra, etc.)
5. Guarda resultados en `~/.sentinel/validation-results/`

## 22. Evidence Reliability Engine

**Archivo:** `src/core/network/evidence-reliability.ts` (155 líneas)
**Tests:** `evidence-reliability.test.ts` (16 tests)

**Propósito:** Asignar nivel de confianza a cada señal de evidencia según su fuente, permitiendo que el Trust Score no solo mida el build, sino también la **calidad de la evidencia**.

### Fuentes y su confianza:
| Fuente | Confianza | Plataforma |
|--------|-----------|------------|
| ETW | 98 | Windows |
| eBPF | 97 | Linux |
| Endpoint Security | 96 | macOS |
| auditd | 95 | Linux |
| ftrace | 94 | Linux |
| procfs | 85 | Linux |
| CIM Query | 82 | Windows |
| Handle API | 78 | Windows |
| ps | 72 | Linux/Unix |
| Polling | 65 | Any |
| mtime heuristic | 42 | Any |

### API pública:
- `evidenceConfidence(source)` — retorna confianza para una fuente
- `processConfidence(proc)` — computa confianza de un proceso (source + start/exit times)
- `fileReadConfidence(event)` — computa confianza de lectura de archivo
- `netEventConfidence(event)` — computa confianza de evento de red
- `fileEventConfidence(event)` — computa confianza de evento de archivo
- `computeObservationConfidence(processes, files, network, reads)` — agrega todo en un `ObservationConfidence` con overall, signals, coverage, sources, weakest/strongest signal
- `renderObservationConfidence(oc)` — renderizado ASCII

### ObservationConfidence:
```typescript
interface ObservationConfidence {
  overall: number        // 0-100
  signals: Record<string, number>  // por tipo de señal
  coverage: number       // % de señales con confianza ≥50
  sources: EvidenceSource[]
  weakestSignal: number
  strongestSignal: number
}
```

**Uso:** Se almacena en `BuildRecord.observationConfidence`. Permite distinguir entre:
- "Trust 93 + Observation Confidence 91" → evidencia sólida
- "Trust 93 + Observation Confidence 41" → build parece confiable pero la evidencia es débil

---

## 23. Evasion Detection

**Archivo:** `src/core/network/evasion-detection.ts` (243 líneas)
**Tests:** `evasion-detection.test.ts` (10 tests)

**Propósito:** Detectar técnicas de evasión de monitoreo, cubriendo 10 vectores de ataque identificados en threat model.

### Casos cubiertos:

| # | Vector | Detección | Severidad |
|---|--------|-----------|-----------|
| 1 | Compilación desde stdin | `CompilerInvocation.fromStdin` | MEDIUM |
| 2 | Ejecución vía memfd_create | `CompilerInvocation.fromMemfd` + `detectFilelessExecution()` | HIGH |
| 3 | Plugin LLVM desde memoria | `captureProcessMaps()` → regiones anónimas rwx | CRITICAL |
| 4 | Procesos <25ms (evaden polling) | `classifyEphemeralProcesses()` con threshold 25ms | HIGH |
| 5 | Response file cambia post-lectura | `detectResponseFileChanges()` en compiler-invocation | HIGH |
| 6 | Wrapper renombrado como gcc | `ToolIdentity.realPath` + SHA256 en build-identity | MEDIUM |
| 7 | LD_PRELOAD post-snapshot | `captureProcessMaps()` → `/proc/*/maps` + environ | HIGH |
| 8 | DNS-over-HTTPS (bypass DNS audit) | `detectDnsOverHttps()` contra 15+ proveedores conocidos | MEDIUM |
| 9 | Named pipes (IPC no trackeado) | `detectNamedPipes()` vía `\\.\\pipe\\` o FIFOs | MEDIUM |
| 10 | ptrace injection (procesos sin padre) | `detectOrphanProcesses()` → ppid no está en build set | CRITICAL |

### API pública:
- `detectOrphanProcesses(processes)` — detecta procesos cuyo ppid no está en el set
- `detectNamedPipes(processes, cwd)` — enumera named pipes/fifos activos
- `detectDnsOverHttps(netEvents)` — detecta conexiones a DoH providers
- `captureProcessMaps(processes)` — lee `/proc/*/maps`, detecta regiones rwx/memfd, captura LD_PRELOAD
- `detectEphemeralProcesses(processes, thresholds)` — clustering multithreshold
- `detectFilelessExecution(processes)` — detecta /dev/fd, pipe:[], socket:[] en cmdline
- `inferEvidenceSource(platform, options?)` — selecciona mejor fuente disponible

---

## 24. Build Serializer

**Archivo:** `src/core/network/build-serializer.ts` (120 líneas)
**Tests:** `build-serializer.test.ts` (7 tests)

**Propósito:** Serialización eficiente de BuildRecord para builds grandes, con truncamiento inteligente de arrays y strings.

### Límites de serialización:
| Campo | Máximo |
|-------|--------|
| Procesos | 500 |
| Archivos | 2000 |
| Eventos de red | 500 |
| Reads | 500 |
| Hash chain | 100 |
| Anomalías | 200 |
| Artefactos | 200 |
| Compiler invocations | 50 |
| Secretos | 100 |
| Cadenas de secretos | 50 |
| String length | 500 chars |

### API pública:
- `compactRecord(record)` — retorna BuildRecord truncado con reporte de serialización
- `renderSerializationReport(report)` — renderizado ASCII con bytes original/compactado/ahorrado

---

## 25. Roadmap

### Corto plazo:
- Seasonality en Trend Engine (weekly/release/CI cycles)
- Dependency Provenance (crates, hashes, mirrors, registry, lockfile)
- Validación contra Linux kernel, LLVM, OpenSSL, PostgreSQL

### Medio plazo:
- **Evidence Reliability Engine v2**: Confidence scoring dinámico basado en consistencia cross-source
- **Evasion Detection v2**: Detección de time-of-check/time-of-use (TOCTOU) en response files y PATH
- **macOS Endpoint Security**: Implementar `NativeEventProvider` para ESF
- **eBPF real-time**: Migrar EBpfEventProvider de polling ps a suscripción BCC/libbpf

### Largo plazo:
- Build Story narrative generada por LLM
- Trust Score exportable como SBOM (CycloneDX)
- FP/FN corpus automation con benchmark CI
- Modo "air-gapped": operación sin conexión a Internet
