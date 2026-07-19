# Arquitectura del Pipeline de Detección de Exfiltración

## Visión General

```
Sensores (CLI)
  ConnectionInspector → netstat -ano (500ms)
  DnsObserver         → ipconfig /displaydns (2000ms)
  ProcessMonitor      → Get-CimInstance Win32_Process (100ms)
       │
       ▼
Pipeline núcleo (Core)
  behavior-engine.ts  → classifyFlow, classifyProcess, classifyFileAccess,
                        classifyGitCommand, classifyPreparationCommands,
                        computeMassReadBehavior, computeEmbeddingBehavior
  risk-engine.ts      → assessRisk (pesos + multiplicadores → score 0–100)
       │
       ▼
Almacenamiento / Reporte
  Session JSON        → events + behaviors + risk
  Ground Truth        → expectedRisk + expectedBehaviors + forbiddenBehaviors
  Campaign            → corrida batch de N sesiones con métricas
```

## Flujo de detección

1. **Captura**: 3 sensores independientes muestrean el SO cada 100-2000ms
2. **Clasificación**: Cada evento crudo pasa por 1+ clasificadores → Behavior
3. **Acumulación**: Behaviors se agregan por tipo (deduplicación)
4. **Riesgo**: assessRisk() calcula score base + multiplicadores → nivel (LOW–CRITICAL)
5. **Replay**: Sesiones grabadas se re-ejecutan deterministicamente por el pipeline

## Principios de diseño

- **Auditar, no bloquear**: Solo observa y reporta, nunca interfiere
- **Comportamiento sobre firma**: Detecta intenciones, no comandos literales
- **Zero telemetría externa**: Todo es local
- **Determinístico**: El replay reproduce exactamente la misma clasificación

## Archivos clave

| Archivo | Rol |
|---|---|
| `src/cli/network/connection-inspector.ts` | Sensor TCP (netstat -ano) |
| `src/cli/network/dns-observer.ts` | Sensor DNS (ipconfig /displaydns) |
| `src/cli/network/process-monitor.ts` | Sensor procesos (WMI) |
| `src/core/network/behavior-engine.ts` | 8 clasificadores de comportamiento |
| `src/core/network/risk-engine.ts` | Cálculo de riesgo |
| `src/core/network/types.ts` | Interfaces y tipos compartidos |
| `src/core/network/replay-engine.ts` | Replay determinístico |
| `scripts/record-session.js` | Grabador de sesiones |
| `replay-corpus/recorded/` | Sesiones grabadas |
