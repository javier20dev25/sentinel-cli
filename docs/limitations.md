# Limitaciones Conocidas — v1.0 Corpus

## 1. Limitaciones del Sistema Operativo (Windows)

| Limitación | Causa | Impacto |
|---|---|---|
| NXDOMAIN no capturable | Windows no cachea respuestas DNS negativas en `ipconfig /displaydns` | DNS tunneling a dominios inexistentes es indetectable por DnsObserver (solo detectable por proceso: nslookup) |
| Procesos efímeros | Polling cada 100ms; procesos que viven <30ms no se capturan | Subestimación de actividad |
| Eventos de archivo inexistentes | Sin ETW/FileSystemWatcher; no hay FileAccessEvent en Windows | `mass_file_read`, `secrets_scanned`, `git_objects_read` no se activan |
| Conexiones post-mortem | `netstat` muestra conexiones que ya cerraron | Latencia en detección |
| Cache DNS persistente | Grabaciones consecutivas arrastran entradas de sesiones previas | Baseline contaminado; mitigado con `ipconfig /flushdns` |

## 2. Falsos Positivos Conocidos

| Escenario | Causa | Mitigación |
|---|---|---|
| Nombre de perfil con AI agent | `cursor-edit`, `claude-code` en command line → `process_suspicious` | No ocurre en uso real (el echo text no contiene nombres de IA) |
| `preparation_detected` en perfiles benignos | `ipconfig`, `netstat`, etc. aparecen en command lines del sistema | Aceptado; peso bajo |
| `suspicious_connection` en toda sesión con salida a Internet | Conexiones a puertos >1024 se marcan como sospechosas | Aceptado; peso 30 |

## 3. Brechas de Cobertura

| Vector | Estado | Alternativa |
|---|---|---|
| HTTP inspeccionable | Solo si pasa por proxy (no implementado) | Ninguna en v1 |
| TLS inspeccionable | Solo SNI visible | Ninguna en v1 |
| WebSocket | No implementado | Ninguna en v1 |
| RAM only exfiltration | Sin monitoreo de memoria | Ninguna en v1 |
| Fragmentación entre procesos | Sin correlación cross-process | Ninguna en v1 |

## 4. Bugs Conocidos

| Bug | Archivo | Status |
|---|---|---|
| Ground truth format no establece `format: "sentinel-session-v1"` | `record-session.js` | Cosmético |
| Verdict display muestra "LOW RISK" para scores CRITICAL | `replay-engine.ts` | Solo visual |
