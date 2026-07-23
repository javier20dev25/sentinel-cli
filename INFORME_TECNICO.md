# Sentinel CLI — Informe Técnico

**Fecha:** 22 de Julio, 2026
**Versión:** 1.0.0
**Autor:** Sentinel Team
**Clasificación:** Interno

---

## 1. Resumen Ejecutivo

Sentinel CLI es una plataforma de **Build Intelligence** que reconstruye y explica el *comportamiento* de un build, no solo pass/fail. Analiza 30 tipos de evidencia, evalúa 69 features de confianza, y ejecuta 26 escenarios de ataque Red Team contra su propio Evidence Graph.

| Métrica | Valor |
|---|---|
| Archivos TypeScript | 202 |
| Líneas de código | 52,901 |
| Suites de testing | 53 |
| Tests unitarios | 1,040 |
| Compilación | 0 errores |
| Comandos CLI | 62+ |
| Tipos de evidencia | 30 |
| Features de confianza | 69 |
| Escenarios de ataque | 26 |
| Campañas Red Team | 10 |
| Reglas de detección | 15 |
| Atomic RT tests mapeados | 30+ |

---

## 2. Arquitectura del Sistema

### 2.1 Capas de Abstracción

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Layer (62+ comandos)               │
│  build observe │ scan │ inspect │ redteam │ atomic │ top    │
├─────────────────────────────────────────────────────────────┤
│                   Core Network Layer                        │
│  EvidenceGraph │ TemporalGraph │ BayesianNetwork │ Trust    │
├─────────────────────────────────────────────────────────────┤
│                  Detection & Analysis Layer                 │
│  15 Detection Rules │ 26 Attack Scenarios │ Graph Diff      │
├─────────────────────────────────────────────────────────────┤
│                    Data Layer (44 archivos)                  │
│  BuildRecord │ EvidenceRelation │ TrustFeatureVector         │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Pipeline de Análisis

```
Build Executed
     ↓
┌─────────────────────────────┐
│ 1. Observation Layer        │ → 30 EvidenceTypes capturados
├─────────────────────────────┤
│ 2. Evidence Graph           │ → Grafo dirigido con 19 relaciones
├─────────────────────────────┤
│ 3. Temporal Analysis        │ → 19 nodos temporales, 38 aristas
├─────────────────────────────┤
│ 4. Bayesian Inference       │ → Red causal, noisy-OR propagation
├─────────────────────────────┤
│ 5. Trust Engine             │ → 69 features, score 0-100
├─────────────────────────────┤
│ 6. Red Team Resilience      │ → 26 ataques, 10 campañas
└─────────────────────────────┘
     ↓
Output (6 preguntas)
```

---

## 3. Las 6 Preguntas Fundamentales

| # | Pregunta | Implementación |
|---|---|---|
| 1 | **¿Está limpio?** | Trust Score + Verdict (CLEAN/REVIEW/BLOCK) |
| 2 | **¿Qué hizo?** | Evidence Graph + Temporal Timeline |
| 3 | **¿Qué cambió?** | Graph Diff + Dominators |
| 4 | **¿Qué debería preocuparme?** | Highlights por severidad |
| 5 | **¿Por qué?** | Bayesian Causal + Evidence Types |
| 6 | **¿Qué debería hacer?** | Recomendaciones accionables |

---

## 4. Motor de Confianza (Trust Engine)

### 4.1 Score (0-100)

```
┌─────────────────────────────────────────────────────────┐
│  CLEAN (≥80)  │  REVIEW (≥50)  │  BLOCK (<50)          │
└─────────────────────────────────────────────────────────┘
```

### 4.2 69 Features de Confianza

| Categoría | Features | Descripción |
|---|---|---|
| **Hermeticidad** | 12 | Entorno aislado, sin red, sin secrets |
| **Procesos** | 15 | Herramientas conocidas, sin LOLBins, sin inyección |
| **Archivos** | 10 | Solo fuentes, sin binarios, sin scripts ocultos |
| **Red** | 8 | Sin actividad, sin DoH, sin DNS anómalo |
| **Dependencias** | 12 | Lock files, hashes verificados, sin typosquatting |
| **Comportamiento** | 12 | Build reproducible, sin drift, sin anomalías |

### 4.3 Deducciones/Adiciones

| Factor | Deducción | Adición |
|---|---|---|
| Herramienta desconocida | -10 | — |
| LOLBin detectado | -25 | — |
| Red durante build | -15 | — |
| Hermetic build | — | +15 |
| Firma verificada | — | +10 |
| Build reproducible | — | +20 |

---

## 5. Evidence Graph

### 5.1 30 Tipos de Evidencia

| Categoría | Tipos |
|---|---|
| **Procesos** | ProcessSpawned, ProcessTerminated, ProcessForked, ProcessInjected |
| **Archivos** | FileCreated, FileModified, FileDeleted, FileRenamed, FileRead, FileWritten |
| **Red** | NetworkConnection, DnsQuery, HttpsRequest, TcpConnection |
| **Memoria** | MemoryAllocated, MemoryProtect, MemoryWrite |
| **Registry** | RegistryKeyCreated, RegistryValueSet, RegistryKeyDeleted |
| **Servicios** | ServiceInstalled, ServiceStarted, ServiceModified |
| **DLLs** | DllLoaded, DllInjected |
| **Tokens** | TokenImpersonated, TokenCreated |
| **Módulos** | ModuleLoaded, ModuleUnloaded |
| **Scripts** | ScriptExecuted, ScriptBlockLogged |

### 5.2 19 Relaciones de Evidencia

```
ProcessSpawned → ProcessCreated
ProcessSpawned → FileCreated
FileCreated → NetworkConnection
DllLoaded → ProcessSpawned
TokenImpersonated → ProcessSpawned
ProcessTerminated → ProcessSpawned
...
```

---

## 6. Análisis Temporal

### 6.1 19 Nodos Temporales

| Nodo | Descripción |
|---|---|
| PreBuild | Antes del build |
| BuildStart | Inicio del build |
| Compilation | Compilación |
| Linking | Vinculación |
| Packaging | Empaquetado |
| PostBuild | Después del build |
| ... | 13 más |

### 6.2 38 Aristas Temporales

```
PreBuild → BuildStart → Compilation → Linking → Packaging → PostBuild
```

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

**Sentinel es el protagonista**, no la herramienta que ejecuta ataques.

### 7.2 26 Escenarios de Ataque (10 Campañas)

| # | Campaña | Ataques | Prioridad Real |
|---|---|---|---|
| 1 | **Supply Chain** | ATK-016 a ATK-020 | P1 (más común) |
| 2 | **Identity Evasion** | ATK-003, ATK-004 | P2 |
| 3 | **Secret Exfiltration** | ATK-005 a ATK-007 | P3 |
| 4 | **Git Attacks** | ATK-021 a ATK-023 | P4 |
| 5 | **CI/CD Attacks** | ATK-024 a ATK-026 | P5 |
| 6 | **Toolchain Hijack** | ATK-008, ATK-009 | P6 |
| 7 | **Graph Poisoning** | ATK-010, ATK-011 | P7 |
| 8 | **Sensor Evasion** | ATK-001, ATK-002 | P8 |
| 9 | **Timeline Confusion** | ATK-014, ATK-015 | P9 |
| 10 | **ML Poisoning** | ATK-012, ATK-013 | P10 (futuro) |

### 7.3 15 Reglas de Detección

| ID | Regla | Severidad |
|---|---|---|
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

### 7.4 30+ Atomic RT Tests Mapeados

| Prioridad | Campaña | Tests |
|---|---|---|
| P1 | Supply Chain | 5 (npm, Gradle, Cargo, MSBuild, Maven) |
| P2 | Identity + Git + CI | 12 |
| P3 | Secret Exfiltration | 3 |
| P4 | Graph Poisoning | 2 |
| P5 | Toolchain Hijack | 2 |
| P6 | Sensor Evasion | 2 |
| P7 | Timeline Confusion | 2 |
| P8 | ML Poisoning | 2 |

---

## 8. CLI Commands (62+)

### 8.1 Build Analysis

| Comando | Nivel | Descripción |
|---|---|---|
| `build observe` | 1-4 | Análisis completo con 6 preguntas |
| `build explain` | 2 | Explicación detallada del score |
| `build graph` | 4 | Grafo de evidencia completo |
| `build run` | — | Alias de `build observe` |

### 8.2 Security Analysis

| Comando | Descripción |
|---|---|
| `scan` | Escaneo de seguridad con findings |
| `inspect` | Grafo de evidencia, centralidad, dominadores |
| `trust` | Calibración de confianza |
| `top` | Top findings por severidad |

### 8.3 Red Team

| Comando | Descripción |
|---|---|
| `redteam --list` | Lista 26 ataques y 10 campañas |
| `redteam --campaign <name>` | Ejecuta campaña específica |
| `redteam --coverage` | Matriz de cobertura |
| `atomic --list` | Lista Atomic RT tests mapeados |
| `atomic --dry-run` | Preview sin ejecutar |
| `atomic --priority <P1-P4>` | Filtra por prioridad |
| `atomic --script` | Genera script PowerShell |

### 8.4 Learning

| Comando | Descripción |
|---|---|
| `learning` | Entrena modelo de confianza |
| `learning --check` | Verifica si necesita retraining |

### 8.5 Integrations

| Comando | Descripción |
|---|---|
| `mcp` | Servidor MCP para herramientas AI |
| `hub` | Menú interactivo de operaciones |
| `guide` | 22 secciones de guía |

---

## 9. Estructura de Archivos

```
sentinel-cli/
├── src/
│   ├── cli/
│   │   ├── main.ts                    62+ comandos
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
│   │   │   └── atomic-redteam-runner.ts Atomic RT integration
│   │   └── ...
│   └── ...
├── tests/
│   ├── evidence-graph.test.ts
│   ├── temporal-graph.test.ts
│   ├── graph-analytics.test.ts
│   ├── redteam.test.ts
│   ├── atomic-redteam.test.ts
│   └── ... (53 suites, 1,040 tests)
├── lab/
│   └── setup.ps1                      Lab setup script
└── package.json
```

---

## 10. Datos de Verificación

| Verificación | Estado |
|---|---|
| Compilación TypeScript | ✅ 0 errores |
| Tests unitarios | ✅ 53 suites, 1,040 passed |
| `build observe` | ✅ Score 80, Verdict CLEAN |
| `redteam --list` | ✅ 26 ataques, 10 campañas |
| `atomic --list` | ✅ 30+ tests, P1-P8 |
| `scan` | ✅ Funcional |
| `inspect` | ✅ Funcional |
| `top` | ✅ Funcional |

---

## 11. Roadmap

| Fase | Estado | Descripción |
|---|---|---|
| **Nivel 1-4** | ✅ Completado | Output completo con 6 preguntas |
| **Red Team Framework** | ✅ Completado | 26 ataques, 10 campañas, 15 reglas |
| **Atomic RT Integration** | ✅ Completado | 30+ tests mapeados |
| **Supply Chain Attacks** | ✅ Completado | npm, Gradle, Cargo, MSBuild, Maven |
| **Git Attacks** | ✅ Completado | hooks, config poisoning, submodules |
| **CI/CD Attacks** | ✅ Completado | GitHub Actions, OIDC, composite actions |
| **Lab Setup** | ✅ Completado | Script de setup para testing |
| **Real-time Execution** | 🔲 Pendiente | Ejecutar Atomic tests reales |
| **Caldera Integration** | 🔲 Pendiente | Adversary emulation framework |
| **ML Poisoning** | 🔲 Futuro | Corpus poisoning, adversarial features |

---

## 12. Conclusión

Sentinel CLI está **listo para producción** en su capacidad de análisis de builds y Red Team framework. El sistema:

1. **Analiza** builds con 30 tipos de evidencia
2. **Evalúa** confianza con 69 features
3. **Ejecuta** 26 escenarios de ataque contra su propio grafo
4. **Genera** reportes con veredictos accionables
5. **Mapea** 30+ Atomic RT tests para testing real

El próximo paso es la **ejecución real** de Atomic Red Team tests en un entorno VM aislado para validar la detección end-to-end.

---

*Generado automáticamente por Sentinel CLI v1.0.0*
