# Sensores de Red (CLI)

## ConnectionInspector

**Archivo**: `src/cli/network/connection-inspector.ts`

- **Comando**: `cmd.exe /c netstat -ano`
- **Intervalo**: 500ms
- **Filtros**:
  - Solo conexiones `TCP` en estado `ESTABLISHED`, `TIME_WAIT`, o `CLOSE_WAIT`
  - Excluye IPs privadas: 10.x, 192.168.x, 172.16-31.x, 127.x, ::1
  - Solo puertos remotos considerados "sospechosos": 443, 80, 8443, 8080, 3000, 5000, y rango 1024–49151
- **Deduplicación**: Set de flowKeys `localAddr:localPort-remoteAddr:remotePort`
- **Latencia**: ~140ms por poll

## DnsObserver

**Archivo**: `src/cli/network/dns-observer.ts`

- **Comando**: `cmd.exe /c ipconfig /displaydns`
- **Intervalo**: 2000ms
- **Baseline**: Primer poll establece línea base (no emite eventos)
- **Deduplicación**: Set de queries vistas
- **Patrones detectados**:
  - Dominios de IA: `.grok.com`, `.x.ai`, `.openai.com`, `.anthropic.com`, etc.
  - Almacenamiento: `.googleapis.com`, `storage.googleapis.com`
  - Exfiltración: `pastebin.com`, `discord.com`, `gist.github.com`
  - Canarios: `beacon.this`, `canarytokens.com`
- **Latencia**: ~100ms por poll
- **Limitación**: NXDOMAIN no se cachea en Windows → indetectable

## ProcessMonitor

**Archivo**: `src/cli/network/process-monitor.ts`

- **Comando**: `powershell Get-CimInstance Win32_Process | Select-Object ... | ConvertTo-JSON`
- **Intervalo**: 100ms
- **Comportamiento**: Emite **todos** los procesos nuevos (no solo los que tienen risk indicators)
- **Indicadores de riesgo**:
  - Agentes IA: grok, cursor, copilot, claude, codex, gemini, etc.
  - Comandos peligrosos: git bundle, git archive, git rev-list --all, curl, wget, nslookup, whoami, ipconfig, netstat, etc.
- **Skip**: `\microsoft\copilot\` (proceso legítimo)
- **Latencia**: ~300-500ms por poll
