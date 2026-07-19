# Roadmap — Sentinel Network Auditor v2

## v1.0 Corpus (Actual) ✅

- Pipeline funcional: 3 sensores + behavior engine + risk engine + replay
- 15 sesiones grabadas (6 exfil CRITICAL + 9 benignas)
- Detección 100% de perfiles de exfiltración
- Sesiones benignas separadas (HIGH/MEDIUM)

## v2.0 — Backends Nativos

### ETW for Windows
- `FileSystemWatcher` para eventos de archivos en tiempo real
- `EtwEventConsumer` para process creation (reemplaza polling WMI)
- Captura de procesos efímeros (<30ms)
- Activaría `mass_file_read`, `secrets_scanned`, `git_objects_read`

### eBPF for Linux
- `tracepoint/syscalls/sys_enter_read/write` para acceso a archivos
- `kprobe/tcp_connect` para conexiones en tiempo real

### Windows Filtering Platform (WFP)
- Captura de paquetes DNS en tiempo real (resuelve NXDOMAIN)
- Filtrado de tráfico por proceso
- Callout driver para inspección en kernel

## v2.0 — Correlación y ML

### Correlación Temporal
- Ventanas deslizantes configurables (5s, 30s, 5min)
- Secuencias: lectura → compresión → conexión → transmisión
- Grafos causales entre procesos

### Modelo de Secuencia
- Detección de patrones de exfiltración independientes de implementación
- Embeddings de sesiones para detección de anomalías

### Anti-Evasión
- Ritmo artificial (accesos perfectamente espaciados)
- Fragmentación de tráfico
- Protocol hopping
- Custom compression

### Explainability
- Descomposición del score de riesgo por factor
- Visualización de cadenas de evidencia
- Reportería forense

## Milestones propuestos

| Hito | Dependencia | Esfuerzo estimado |
|---|---|---|
| FileSystemWatcher en Windows | Ninguna | 1-2 semanas |
| ETW process events | Investigación ETW API | 2-4 semanas |
| WFP DNS capture | Driver signing | 3-6 semanas |
| Correlación temporal | Ninguna (solo lógica) | 2-3 semanas |
| Modelo de secuencia | Dataset grande (>1000 sesiones) | 4-8 semanas |

## Issues abiertos para v2

- [ ] ETW backend para eventos de proceso y archivo en Windows
- [ ] Sysmon integration como fuente de datos
- [ ] WFP backend para captura DNS en tiempo real
- [ ] Driver mode (MiniFilter para archivos)
- [ ] Streaming mode (procesamiento en tiempo real, no solo grabación)
- [ ] Sequence model para detección de patrones
- [ ] Temporal correlation entre eventos
- [ ] Behavioral graph (relaciones entre procesos)
- [ ] Explainability del score de riesgo
- [ ] Reducción de falsos positivos con ML
- [ ] Benchmark con >1000 sesiones
