# Guía de Grabación de Sesiones

## Herramienta

```
node scripts/record-session.js <profileId> <duration_sec> [work_cmd]
```

## Funcionamiento

1. Inicia el recorder de Sentinel (`sentinel network record`): captura procesos, red, DNS
2. Si se especifica `work_cmd`, lo ejecuta en background via `cmd.exe /c`
3. Espera la duración especificada o hasta que termine el recorder
4. Guarda en `replay-corpus/recorded/session-<id>.json`
5. Genera `replay-corpus/recorded/session-<id>.ground-truth.json`

## Reglas críticas

### 1. Una sesión por invocación

Cada perfil debe grabarse en una invocación SEPARADA de bash/tool. Si se ponen múltiples perfiles en el mismo script, los comandos de trabajo de todos los perfiles aparecen en el command line del PowerShell padre, contaminando la detección.

### 2. Flush DNS entre grabaciones

El cache DNS de Windows persiste entre sesiones. Usar antes de grabar:

```powershell
Start-Process -WindowStyle Hidden -FilePath cmd -ArgumentList '/c ipconfig /flushdns'
```

### 3. Echo text sin nombres de IA

El texto del `echo` en el work command NO debe contener nombres de agentes IA (cursor, claude, etc.) porque el process monitor los detecta. Usar genéricos:

```
Bien:  echo editando fuente...
Mal:   echo cursor-edit editando fuente...
```

### 4. Duración suficiente

Mínimo 15-20 segundos para que los sensores (especialmente poll 100-2000ms) capturen eventos. Usar `ping -n 15 127.0.0.1 >nul` para mantener el proceso vivo.

### 5. Citas y escaping

Usar `"" ` (doble doble comilla) para nested quotes en PowerShell:

```
cmd.exe /c "echo profile running... & curl ""https://api.example.com"" & ping -n 4 127.0.0.1 >nul"
```

## Output

- `session-<random>.json`: Eventos crudos (process, git command, file access)
- `session-<random>.ground-truth.json`: Metadatos del perfil + riesgo esperado
