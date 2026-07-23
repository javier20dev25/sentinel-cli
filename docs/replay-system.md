# Sistema de Replay y Campañas

## Replay Engine

**Archivo**: `src/core/network/replay-engine.ts`

Replayea una sesión grabada a través del pipeline de detección de forma determinística.

### Flujo

```
replayFile(session.json)
  → Carga y valida formato
  → Crea pipeline
  → Procesa eventos cronológicamente:
      process → classifyProcess()
      git_command → classifyGitCommand()
      file_access → classifyFileAccess()
  → Genera veredicto (risk score, level, behaviors)
  → Compara contra ground truth
  → Retorna ReplayResult
```

## CLI

| Comando | Descripción |
|---|---|
| `sentinel-cli network replay run <file>` | Replay de una sesión |
| `sentinel-cli network replay campaign <dir>` | Replay de todas las sesiones en directorio |
| `sentinel-cli network replay diff <baseline> <current>` | Compara dos campañas |

## ReplayResult

```typescript
interface ReplayResult {
  sessionId: string;
  riskScore: number;
  riskLevel: string;
  behaviorsDetected: string[];
  errors: string[];
  passed: boolean;  // match contra ground truth?
}
```

## Campañas

Una campaña ejecuta replay sobre todas las sesiones en un directorio y produce:

```
ID: rc-<random>
Sessions: 15
Pass: 6
Flagged: 9

Risk distribution:
  CRITICAL   6
  HIGH       3
  MEDIUM     6
```

## Evaluación

Usa matriz de confusión estándar:

| | Should be non-LOW | Should be LOW |
|---|---|---|
| Engine flagged | True Positive | False Positive |
| Engine did not flag | False Negative | True Negative |

Métricas: accuracy, precision, recall, specificity, F1, FPR, FNR.
