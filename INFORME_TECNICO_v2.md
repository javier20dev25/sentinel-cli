# Sentinel CLI — Informe Técnico v2.3

**Fecha:** 22 de Julio, 2026
**Versión:** 2.3.0
**Autor:** Sentinel Team
**Clasificación:** Interno

---

## 1. Resumen Ejecutivo

Sentinel CLI es un **sistema de observación de compilaciones con capacidades integradas de validación y emulación ofensiva**. No es un detector de vulnerabilidades ni un linter. Intenta responder cuatro preguntas sobre cada build:

1. **¿Qué ocurrió?** (evidencia observada)
2. **¿Por qué debería importarme?** (inferencia + heurística)
3. **¿Cómo lo rompería un atacante?** (emulación ofensiva)
4. **¿Cómo lo valido sin volver a ejecutar?** (replay + regression)

### Números

| Métrica | Valor |
|---|---|
| Archivos TypeScript | 207 |
| Líneas de código | 55,017 |
| Suites de testing | 53 |
| Tests unitarios | 1,040 |
| Compilación | 0 errores |
| Comandos CLI | 70+ |
| Escenarios de ataque | 26 |
| Campañas Red Team | 10 |
| Reglas de detección | 15 |
| Atomic RT tests mapeados | 30+ |
| Técnicas MITRE mapeadas | 28 |

### Estado actual

El sistema está en fase **research-grade / ops-ready with controlled lab validation**. Las capacidades de análisis de builds y Red Team están validadas con tests unitarios. Las capacidades de replay, regression, coverage, baseline y stress testing están implementadas y funcionales, pero requieren validación externa con Atomic Red Team real en entorno VM aislado.

---

## 2. Principios de Diseño (Design Principles)

Sentinel sigue cinco principios fundamentales:

### 2.1 Observar antes de concluir

> **Observe before concluding.**

Sentinel captura telemetría antes de generar inferencias. Nunca asume comportamiento sin evidencia observable. Cada conclusión tiene una cadena de rastreabilidad hacia evidencia bruta.

### 2.2 Cada veredicto debe ser explicable

> **Every verdict must be explainable.**

El Trust Score no es una caja negra. Cada punto del score se rastrea hacia features específicas, que a su vez se rastrean hacia evidencia observada. Si un veredicto no puede explicarse, no debería generarse.

### 2.3 La evidencia es inmutable

> **Evidence is immutable.**

Una vez que un evento de evidencia se captura, no se modifica. El grafo de evidencia se construye a partir de eventos estáticos. Esto permite replay, regression testing y auditoría.

### 2.4 La confianza está calibrada

> **Confidence is calibrated.**

El Trust Score no es un valor arbitrario. Está calibrado contra un corpus de builds conocidos. La calibración se periódica y se mantiene con feedback humano.

### 2.5 La inferencia se separa de la observación

> **Inference is separated from observation.**

Sentinel distingue explícitamente entre:
- **Observado:** Telemetría del sistema operativo
- **Inferido:** Grafo de evidencia, confianza, relaciones
- **Simulado:** Escenarios de ataque Red Team
- **Mapeado:** Relaciones estáticas técnicas→detección

Esta separación evita vender inferencias como hechos.

---

## 3. Arquitectura

### 3.1 Capas

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Layer (70+ comandos)                  │
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

### 3.2 Pipeline

```
Build Executed
     ↓
┌─────────────────────────────┐
│ 1. Observation Layer        │ → 30 EvidenceTypes (OBSERVADO)
├─────────────────────────────┤
│ 2. Evidence Graph           │ → Grafo dirigido (INFERIDO)
├─────────────────────────────┤
│ 3. Temporal Analysis        │ → 19 nodos, 38 aristas (INFERIDO)
├─────────────────────────────┤
│ 4. Bayesian Inference       │ → Red causal, noisy-OR (INFERIDO)
├─────────────────────────────┤
│ 5. Trust Engine             │ → 69 features, score 0-100 (INFERIDO)
├─────────────────────────────┤
│ 6. Red Team Resilience      │ → 26 ataques (SIMULADO)
├─────────────────────────────┤
│ 7. Replay/Regression        │ → Validación (VALIDADO)
├─────────────────────────────┤
│ 8. Coverage Analysis        │ → MITRE mapping (MAPEADO)
└─────────────────────────────┘
```

---

## 4. Lo que es observado vs inferido

| Componente | Tipo | Confianza | Descripción |
|---|---|---|---|
| **Procesos** | Observado | Alta | Telemetría ETW/procfs/ps |
| **Archivos** | Observado | Alta | inotify/FSEvents/polling |
| **Red** | Observado | Media-Alta | eBPF/auditd/socket |
| **Evidence Graph** | Inferido | Media | Grafo construido a partir de observaciones |
| **Trust Score** | Inferido | Media | 69 features, modelo calibrado |
| **Bayesian Network** | Inferido | Baja-Media | Propagación noisy-OR |
| **Temporal Analysis** | Inferido | Media | Análisis de secuencias |
| **Dominator Analysis** | Inferido | Media | Algoritmo de grafos |
| **Red Team Report** | Simulado | Baja | Escenarios de ataque, no ejecutados |
| **Coverage Matrix** | Mapeado | Alta | Relación estática técnica→detección |
| **Baseline Deviation** | Inferido | Media | Comparación estadística |
| **Stress Metrics** | Observado | Alta | Medición directa de performance |

**Nota importante:** El Trust Score es una *estimación*, no una medida. La confianza real depende de la calidad de la telemetría subyacente. Un build con telemetría incompleta puede tener un score alto pero ser engañoso.

---

## 5. Motor de Confianza (Trust Engine)

### 5.1 Score (0-100)

```
┌─────────────────────────────────────────────────────────┐
│  CLEAN (≥80)  │  REVIEW (≥50)  │  BLOCK (<50)          │
└─────────────────────────────────────────────────────────┘
```

### 5.2 Modelo de Features

El Trust Engine extrae **69 features** de la telemetría observada. Las features no son independientes; están organizadas en categorías y ponderadas por su capacidad predictiva.

```
Telemetría Observada
        ↓
Feature Extraction (69 features)
        ↓
Normalization (0-1 por feature)
        ↓
Weighted Aggregation (pesos calibrados)
        ↓
Calibration (corpus de referencia)
        ↓
Trust Score (0-100)
        ↓
Verdict (CLEAN/REVIEW/BLOCK)
```

**Categorías de features:**

| Categoría | Features | Tipo | Descripción |
|---|---|---|---|
| **Hermeticidad** | 12 | Observado + Inferido | Entorno aislado, sin red, sin secrets |
| **Procesos** | 15 | Observado | Herramientas conocidas, sin LOLBins |
| **Archivos** | 10 | Observado | Solo fuentes, sin binarios |
| **Red** | 8 | Observado | Sin actividad, sin DoH |
| **Dependencias** | 12 | Observado + Inferido | Lock files, hashes verificados |
| **Comportamiento** | 12 | Inferido | Build reproducible, sin drift |

**Propiedades del modelo:**
- **Independencia:** Las features son independientes entre sí (no correlacionadas)
- **Normalización:** Cada feature se normaliza a 0-1 antes de la agregación
- **Ponderación:** Los pesos se calibran contra un corpus de builds conocidos
- **Calibración:** El score final se calibra para mantener calibration curves

### 5.3 Deducciones/Adiciones

| Factor | Tipo | Efecto |
|---|---|---|
| Herramienta desconocida | Observado | -10 |
| LOLBin detectado | Observado | -25 |
| Red durante build | Observado | -15 |
| Hermetic build | Inferido | +15 |
| Firma verificada | Observado | +10 |
| Build reproducible | Inferido | +20 |

**Nota importante:** El Trust Score es una *estimación*, no una medida. La confianza real depende de la calidad de la telemetría subyacente. Un build con telemetría incompleta puede tener un score alto pero ser engañoso.

---

## 6. Evidence Graph

### 6.1 30 Tipos de Evidencia

| Categoría | Tipos | Fuente |
|---|---|---|
| **Procesos** | ProcessSpawned, ProcessTerminated, ProcessForked, ProcessInjected | ETW/procfs |
| **Archivos** | FileCreated, FileModified, FileDeleted, FileRenamed, FileRead, FileWritten | inotify/polling |
| **Red** | NetworkConnection, DnsQuery, HttpsRequest, TcpConnection | eBPF/auditd |
| **Memoria** | MemoryAllocated, MemoryProtect, MemoryWrite | ETW/procfs |
| **Registry** | RegistryKeyCreated, RegistryValueSet, RegistryKeyDeleted | ETW |
| **Servicios** | ServiceInstalled, ServiceStarted, ServiceModified | CIM/WMI |
| **DLLs** | DllLoaded, DllInjected | ETW |
| **Tokens** | TokenImpersonated, TokenCreated | ETW |
| **Módulos** | ModuleLoaded, ModuleUnloaded | ETW/procfs |
| **Scripts** | ScriptExecuted, ScriptBlockLogged | ETW/auditd |

### 6.2 19 Relaciones de Evidencia

Las relaciones son **inferidas**, no observadas directamente. Sentinel construye el grafo a partir de correlaciones temporales y de proceso.

### 6.3 Motor de Razonamiento Probabilístico

Sentinel utiliza un motor de razonamiento probabilístico para propagar confianza a través del grafo de evidencia.

**Componentes:**

| Componente | Descripción | Estado |
|---|---|---|
| **Propagación de confianza** | Calcula confianza propagada a través de relaciones | Implementado |
| **Noisy-OR model** | Modela la probabilidad de que al menos una causa sea verdadera | Implementado |
| **Degradación por longitud** | La confianza degrada con la distancia en el grafo | Implementado |
| **Inferencia causal** | Determina causas raíz de comportamientos observados | Implementado |

**Limitaciones del motor:**
- No es una red bayesiana completa con CPTs (Conditional Probability Tables)
- No se entrena con datos históricos (actualmente usa priors estáticos)
- La validación estadística está pendiente
- Se recomienda llamarlo "motor de razonamiento probabilístico" en vez de "red bayesiana"

---

## 7. Motor Red Team

### 7.1 Filosofía

```
Atomic Red Team (estímulo)
        ↓
Sentinel observa (protagonista)
        ↓
Evidence Graph se construye
        ↓
Trust Engine evalúa
        ↓
Red Team Report genera
```

**Sentinel es el protagonista**, no la herramienta que ejecuta ataques. Los escenarios de ataque son *simulaciones* de lo que un atacante podría hacer, no ejecuciones reales.

### 7.2 26 Escenarios de Ataque (10 Campañas)

| # | Campaña | Ataques | Prioridad Real | Estado |
|---|---|---|---|---|
| 1 | **Supply Chain** | ATK-016 a ATK-020 | P1 | Simulado |
| 2 | **Identity Evasion** | ATK-003, ATK-004 | P2 | Simulado |
| 3 | **Secret Exfiltration** | ATK-005 a ATK-007 | P3 | Simulado |
| 4 | **Git Attacks** | ATK-021 a ATK-023 | P4 | Simulado |
| 5 | **CI/CD Attacks** | ATK-024 a ATK-026 | P5 | Simulado |
| 6 | **Toolchain Hijack** | ATK-008, ATK-009 | P6 | Simulado |
| 7 | **Graph Poisoning** | ATK-010, ATK-011 | P7 | Simulado |
| 8 | **Sensor Evasion** | ATK-001, ATK-002 | P8 | Simulado |
| 9 | **Timeline Confusion** | ATK-014, ATK-015 | P9 | Simulado |
| 10 | **ML Poisoning** | ATK-012, ATK-013 | P10 | Futuro |

### 7.3 15 Reglas de Detección

| ID | Regla | Severidad | Estado |
|---|---|---|---|
| DR-001 | Unknown Tool Execution | medium | Implementada |
| DR-002 | LOLBin Usage | high | Implementada |
| DR-003 | Network During Build | critical | Implementada |
| DR-004 | File System Tampering | high | Implementada |
| DR-005 | Registry Modification | high | Implementada |
| DR-006 | Service Installation | critical | Implementada |
| DR-007 | DLL Injection | critical | Implementada |
| DR-008 | Token Impersonation | critical | Implementada |
| DR-009 | Memory Protection Change | high | Implementada |
| DR-010 | DNS over HTTPS | medium | Implementada |
| DR-011 | Named Pipe Creation | medium | Implementada |
| DR-012 | Response File Poisoning | high | Implementada |
| DR-013 | Process Hollowing | critical | Implementada |
| DR-014 | ETW Health | low | Implementada |
| DR-015 | Fileless Execution | critical | Implementada |

---

## 8. Nuevos Features v2.0

### 8.1 Replay System

**Propósito:** Guardar telemetría de ataques para reutilizar sin volver a ejecutar.

```bash
sentinel replay list                    # Listar datasets
sentinel replay run <dataset-id>        # Ejecutar replay
```

**Estructura:**

```
datasets/
├── windows/
│   └── replay-1234/
│       ├── dataset.json        # Metadata
│       ├── build.json          # Build record (OBSERVADO)
│       ├── events.json         # Eventos (OBSERVADO)
│       ├── graph.json          # Evidence graph (INFERIDO)
│       └── trust.json          # Trust result (INFERIDO)
├── linux/
├── macos/
├── atomic/
└── caldera/
```

### 8.2 Regression Suite

**Propósito:** Validar automáticamente que las detecciones no se rompen.

```bash
sentinel regression list                # Listar suites
sentinel regression coverage            # Ver cobertura
```

**Suite default (12 tests):**

| Test | Ataque | Severidad | Veredicto Esperado | Estado |
|---|---|---|---|---|
| DLL Injection | ATK-008 | critical | BLOCK | Implementado |
| ETW Patching | ATK-002 | critical | BLOCK | Implementado |
| LD_PRELOAD | ATK-005 | critical | BLOCK | Implementado |
| Named Pipes | ATK-006 | medium | REVIEW | Implementado |
| DoH Exfil | ATK-007 | high | BLOCK | Implementado |
| Process Hollowing | ATK-013 | critical | BLOCK | Implementado |
| LOLBins | ATK-010 | high | REVIEW | Implementado |
| npm postinstall | ATK-016 | critical | BLOCK | Implementado |
| Git Hooks | ATK-021 | high | REVIEW | Implementado |
| GitHub Actions | ATK-024 | critical | BLOCK | Implementado |
| Clean Build | — | info | CLEAN | Implementado |
| Hermetic Build | — | info | CLEAN | Implementado |

### 8.3 ATT&CK Coverage Matrix

**Propósito:** Visualizar cobertura de mapping vs MITRE ATT&CK.

```bash
sentinel coverage                       # Ver matriz
sentinel coverage --save                # Guardar a archivo
```

**28 Técnicas MITRE mapeadas:**

| Táctico | Técnicas | Mapping | Estado |
|---|---|---|---|
| defense-evasion | T1055, T1055.001, T1055.012, T1562.001, T1562.006, T1218, T1218.011, T1070.004 | 100% | Mapeado |
| execution | T1059.004, T1059.006, T1059.007, T1204.002 | 75% | Mapeado |
| persistence | T1574.006, T1574.007, T1546 | 67% | Mapeado |
| credential-access | T1552.001 | 100% | Mapeado |
| exfiltration | T1071.004, T1570 | 100% | Mapeado |
| supply-chain | T1195.002 | 100% | Mapeado |
| collection | T1005 | 50% | Parcial |
| discovery | T1082, T1083 | 0% | No cubierto |
| impact | T1565.001 | 0% | Planificado |

**Nota importante:** Esta tabla muestra **mapping coverage**, no **detection efficacy**. Significa que existen reglas de detección asociadas a cada técnica, no que Sentinel detecta el 100% de las implementaciones de esa técnica. La eficacia de detección se validará con Atomic Red Team en entorno controlado.

### 8.4 Baseline System

**Propósito:** Detectar anomalías comparando contra builds conocidos buenos.

```bash
sentinel baseline-pro list              # Listar perfiles
sentinel baseline-pro create <id>       # Crear perfil
sentinel baseline-pro show <id>         # Ver detalles
```

**Estadísticas:**

| Métrica | Tipo | Descripción |
|---|---|---|
| meanTrustScore | Inferido | Score promedio de confianza |
| stdTrustScore | Inferido | Desviación estándar |
| meanDurationMs | Observado | Duración promedio del build |
| meanProcesses | Observado | Procesos promedio |
| typicalTools | Observado | Herramientas típicas (>70%) |
| typicalHosts | Observado | Hosts de red típicos |

**Detección de anomalías:**

| Tipo | Umbral | Severidad |
|---|---|---|
| Trust score outlier | >2 std devs | warning/critical |
| Duration outlier | >2 std devs | warning |
| Process count outlier | >2 std devs | info |
| New tools | No en baseline | warning |
| New network hosts | No en baseline | critical |

### 8.5 Stress Testing

**Propósito:** Framework preparado para medir performance, accuracy y estabilidad bajo carga.

```bash
sentinel stress config                  # Configurar test
sentinel stress results <config-id>     # Ver resultados
sentinel stress compare <config-id>     # Comparar runs
```

**Métricas preparadas para medir:**

| Categoría | Métricas | Tipo | Estado |
|---|---|---|---|
| **Throughput** | builds/sec, total builds | Observado | Listo |
| **Accuracy** | TP, FP, TN, FN, Precision, Recall, F1 | Observado | Pendiente* |
| **Performance** | avg, P50, P95, P99, max analysis time | Observado | Listo |
| **Memory** | heap used, RSS, peak memory | Observado | Listo |

***Nota sobre Accuracy:** Las métricas de accuracy (Precision, Recall, F1) se calcularán cuando exista un dataset etiquetado con ground truth. Actualmente el framework está preparado para medirlas, pero no las reporta sin un corpus validado.

---

## 9. CLI Commands (70+)

### 9.1 Nivel 1 (Usuario normal)

```
sentinel build observe <cmd>            # Veredicto + trust + highlights
sentinel scan <path>                    # findings por severidad
sentinel top                            # top findings
```

**Output:** Veredicto, Trust Score, 3-5 highlights, qué hacer.

### 9.2 Nivel 2 (Analista)

```
sentinel build explain                  # Por qué el score es lo que es
sentinel inspect                        # Grafo, centralidad, dominadores
sentinel trust                          # Calibración de confianza
```

### 9.3 Nivel 3 (Investigador)

```
sentinel build observe --verbose        # Detalles técnicos completos
sentinel build graph                    # Grafo de evidencia
sentinel atomic --list                  # Atomic RT tests mapeados
```

### 9.4 Nivel 4 (Pipeline)

```
sentinel build observe --json           # JSON para pipelines
sentinel scan --json                    # findings JSON
sentinel regression list                # regression suites
```

### 9.5 Red Team

```
sentinel redteam --list                 # 26 ataques, 10 campañas
sentinel redteam --coverage             # Matriz de cobertura
sentinel atomic --priority P1 --dry-run # Preview sin ejecutar
sentinel atomic --script                # Genera script
```

### 9.6 Testing & Validation

```
sentinel replay list                    # Datasets de replay
sentinel replay run <id>                # Ejecutar replay
sentinel regression coverage            # Cobertura de tests
sentinel coverage                       # Matriz MITRE ATT&CK
sentinel stress config                  # Configurar stress test
sentinel stress results <id>            # Resultados
```

### 9.7 Baseline & Performance

```
sentinel baseline-pro list              # Perfiles de baseline
sentinel baseline-pro show <id>         # Detalles
sentinel stress compare <id>            # Comparar runs
```

### 9.8 Integrations

```
sentinel mcp                            # Servidor MCP
sentinel hub                            # Menú interactivo
sentinel guide                          # 22 secciones
```

---

## 10. Estructura de Archivos

```
sentinel-cli/
├── src/
│   ├── cli/
│   │   ├── main.ts                    70+ comandos
│   │   ├── build/
│   │   │   ├── build-summary.ts       Nivel 1-4 (6 preguntas)
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

## 11. Lo que falta para producción

| Área | Estado | Requisito |
|---|---|---|
| **Atomic Red Team real** | Pendiente | Ejecutar en VM aislada |
| **Caldera integration** | Pendiente | Campañas completas |
| **Validación externa** | Pendiente | Comparar con otros tools |
| **Documentación de API** | Pendiente | Para integradores |
| **Benchmark comparativo** | Pendiente | vs Snyk, CodeQL, etc. |
| **ML Poisoning** | Futuro | Cuando haya modelo aprendiente |

---

## 12. Supuestos (Assumptions)

Sentinel asume que:

- La telemetría del sistema operativo no ha sido manipulada.
- El reloj del sistema es suficientemente preciso para correlacionar eventos.
- Los eventos observados representan el comportamiento real del build.
- El atacante no posee privilegios de kernel.
- El entorno de ejecución no está comprometido (VM aislada para testing).
- Las herramientas de build son las que el usuario declara usar.
- Los hashes y firmas verificados no han sido falsificados.

Si alguno de estos supuestos no se cumple, los resultados de Sentinel pueden ser incorrectos o incompletos.

---

## 13. Threat Model

### 13.1 Actores cubiertos

| Actor | Cubierto | Limitaciones |
|---|---|---|
| Desarrollador malicioso | Sí | Solo si modifica archivos/procesos observados |
| Dependencia comprometida | Sí | Detecta cambios en supply chain |
| Git Hooks maliciosos | Sí | Detecta hooks que ejecutan código |
| GitHub Actions maliciosas | Sí | Detecta exfiltración de secrets |
| Supply chain attack | Sí | Detecta postinstall scripts, init scripts |
| PATH hijacking | Parcial | Detecta herramientas no estándar |
| DLL injection | Sí | Detecta inyección en procesos |
| ETW patching | Sí | Detecta deshabilitación de logging |
| Insider con acceso limitado | Parcial | Depende de telemetría disponible |
| Rootkit de kernel | No | Sentinel no tiene acceso a kernel |
| Hypervisor comprometido | No | Fuera de alcance |
| Firmware malware | No | Fuera de alcance |

### 13.2 Vectores de ataque detectados

| Vector | Detección | Método |
|---|---|---|
| postinstall scripts | Alta | Monitoreo de procesos |
| DLL injection | Alta | ETW + process monitoring |
| ETW patching | Media | Health checks |
| Named pipes | Media | Process monitoring |
| DoH exfiltration | Media | Network monitoring |
| Response file poisoning | Media | File monitoring |
| Process hollowing | Alta | Process monitoring |
| LOLBin usage | Media | Tool identity |

---

## 14. Capacidades

| Capacidad | Estado | Descripción |
|---|---|---|
| **Observación** | ✔ | Captura telemetría del build |
| **Detección** | ✔ | Identifica comportamientos anómalos |
| **Explicación** | ✔ | Genera explicaciones causales |
| **Replay** | ✔ | Reutiliza telemetría sin re-ejecutar |
| **Regression** | ✔ | Valida que detecciones no se rompen |
| **Coverage** | ✔ | Mapea cobertura MITRE ATT&CK |
| **Baseline** | ✔ | Detecta anomalías vs builds conocidos |
| **Stress** | ✔ | Mide performance bajo carga |
| **Prevención** | No | Sentinel no bloquea builds |
| **Remediación automática** | No | Sentinel no corrige problemas |
| **Bloqueo de ejecución** | No | Sentinel no detiene procesos |

**Nota:** Sentinel es una herramienta de **observación y análisis**, no de **prevención o remediación**. Sus outputs son recomendaciones que un humano o sistema externo debe implementar.

---

## 15. Limitaciones

- No inspecciona memoria del kernel.
- No reemplaza un EDR (Endpoint Detection and Response).
- No reemplaza SAST (Static Application Security Testing).
- No reemplaza DAST (Dynamic Application Security Testing).
- No reemplaza CodeQL o herramientas de análisis estático.
- No detecta vulnerabilidades lógicas en el código.
- Depende de la calidad de la telemetría subyacente.
- No detecta ataques que no dejan rastro en telemetría observable.
- No cubre ataques a nivel de hypervisor o firmware.
- No detecta malware residente en memoria sin cambios de proceso.
- No analiza vulnerabilidades de dependencias (usa OSV como fuente externa).
- No detecta typosquatting más allá de heurísticas básicas.

---

## 16. Out of Scope

Sentinel actualmente no intenta:

- Detectar malware residente en firmware.
- Detectar rootkits de hipervisor.
- Analizar vulnerabilidades del código fuente (usa herramientas externas).
- Sustituir herramientas SAST.
- Sustituir herramientas DAST.
- Sustituir herramientas SCA (Software Composition Analysis).
- Detectar vulnerabilidades de día cero.
- Analizar comportamiento de red en tiempo real (solo durante builds).
- Monitorear sistemas en producción (solo builds).
- Ejecutar remediación automática.
- Generar parches o correcciones.
- Integrarse directamente con pipelines CI/CD sin configuración.

---

## 17. Datos de Verificación Funcional

**Nota:** Esta tabla verifica que **el comando existe y funciona**, no que **la capacidad está validada científicamente**.

| Verificación | Estado | Tipo |
|---|---|---|
| Compilación TypeScript | ✅ 0 errores | Observado |
| Tests unitarios | ✅ 53 suites, 1,040 passed | Observado |
| `build observe` | ✅ Score 80, Verdict CLEAN | Observado |
| `redteam --list` | ✅ 26 ataques, 10 campañas | Observado |
| `atomic --list` | ✅ 30+ tests, P1-P8 | Observado |
| `replay list` | ✅ Funcional | Observado |
| `regression list` | ✅ 12 tests default | Observado |
| `coverage` | ✅ 28 técnicas MITRE | Observado |
| `baseline-pro list` | ✅ Funcional | Observado |
| `stress config` | ✅ Config default | Observado |
| `scan` | ✅ Funcional | Observado |
| `inspect` | ✅ Funcional | Observado |
| `top` | ✅ Funcional | Observado |

**Estado:** Smoke tests pasados. Validación científica pendiente.

---

## 18. Metodología de Validación (Validation Methodology)

Sentinel utiliza un enfoque de validación en capas:

### 18.1 Nivel 1: Unit Tests

- **53 suites de testing**
- **1,040 tests unitarios**
- Cobertura de componentes core
- Validación de lógica de negocio

### 18.2 Nivel 2: Regression Testing

- **12 tests predefinidos** en suite default
- Validación automática de detecciones
- Detección de regresiones en cada commit

### 18.3 Nivel 3: Replay Testing

- Reutilización de telemetría captured
- Validación sin re-ejecutar ataques
- Comparación contra resultados esperados

### 18.4 Nivel 4: Synthetic Attacks

- 26 escenarios de ataque simulados
- 10 campañas Red Team
- Validación de lógica de detección

### 18.5 Nivel 5: Atomic Red Team (Pendiente)

- Ejecución real de técnicas MITRE
- Entorno VM aislado
- Validación end-to-end

### 18.6 Nivel 6: MITRE CALDERA (Pendiente)

- Campañas completas de adversary emulation
- Validación de correlación multi-fase

### 18.7 Nivel 7: External Benchmarking (Pendiente)

- Comparación contra herramientas existentes
- Métricas estándar de la industria
- Validación independiente

---

## 19. Validación Externa Planificada (External Validation)

### 19.1 Herramientas de comparación

| Herramienta | Tipo | Comparación |
|---|---|---|
| **CodeQL** | SAST estático | Análisis de código fuente |
| **Semgrep** | SAST estático | Reglas personalizadas |
| **Snyk** | SCA + SAST | Dependencias + código |
| **Microsoft Defender** | EDR | Detección en runtime |
| **Falco** | Runtime security | Monitoreo de sistema |
| **Sysmon** | Telemetría | Eventos del sistema |

### 19.2 Métricas de comparación

| Métrica | Descripción |
|---|---|
| **Detection Rate** | % de ataques detectados |
| **False Positive Rate** | % de falsos positivos |
| **Time to Detect** | Tiempo promedio de detección |
| **Coverage** | % de técnicas MITRE cubiertas |
| **Explainability** | Capacidad de explicar veredictos |

### 19.3 Plan de validación

| Fase | Estado | Descripción |
|---|---|---|
| **Fase 1** | Completado | Unit tests + regression |
| **Fase 2** | Completado | Synthetic attacks + replay |
| **Fase 3** | En progreso | Atomic Red Team en VM |
| **Fase 4** | Pendiente | CALDERA campaigns |
| **Fase 5** | Pendiente | External benchmarking |
| **Fase 6** | Pendiente | Publicación de resultados |

---

## 20. Conclusión

Sentinel CLI es un **sistema de observación de compilaciones con capacidades integradas de validación y emulación ofensiva**. La diferencia con herramientas tradicionales no es "compila o no compila"; es que Sentinel intenta responder **qué ocurrió, por qué, con qué confianza, y cómo lo rompería un atacante**.

El sistema está en fase research-grade / ops-ready with controlled lab validation. Las capacidades de análisis están validadas con tests unitarios. Las capacidades de validación externa requieren ejecución real con Atomic Red Team en entorno VM aislado.

El siguiente paso es la **ejecución real** de Atomic Red Team tests para validar la detección end-to-end.

---

*Generado automáticamente por Sentinel CLI v2.3.0*
