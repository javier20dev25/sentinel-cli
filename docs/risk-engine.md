# Sistema de Evaluación de Riesgo (risk-engine.ts)

## Cálculo

```
score = Σ(weight × confidence) para cada tipo de behavior único
score *= multiplicadores contextuales
score *= multiplicadores de secuencia (exfiltration chain)
score *= multiplicador temporal (avg gap entre behaviors)
normalizado = min(round(score / maxPossibleScore × 100), 100)
confidence = computeRiskConfidence(behaviors)
```

## Pesos base

| Behavior | Peso |
|---|---|
| `repo_indexed` | 25 |
| `git_history_read` | 35 |
| `git_objects_read` | 40 |
| `git_bundle_created` | 60 |
| `git_bundle_uploaded` | 90 |
| `git_archive_created` | 50 |
| `secrets_scanned` | 30 |
| `secrets_exfiltrated` | 95 |
| `embeddings_generated` | 20 |
| `full_repo_snapshot` | 85 |
| `canary_exfiltrated` | 99 |
| `mass_file_read` | 15 |
| `suspicious_connection` | 30 |
| `ai_prompt_sent` | 10 |
| `code_upload` | 50 |
| `prompt_injection_attempt` | 70 |
| `process_suspicious` | 20 |
| `dns_suspicious` | 25 |
| `tls_suspicious` | 25 |
| `anti_evasion_detected` | 60 |
| `preparation_detected` | 40 |
| `process_chain_detected` | 50 |
| `monitor_awareness_detected` | 70 |
| `monitor_disabled` | 80 |
| `canary_read` | 70 |
| `canary_modified` | 75 |
| `fake_secret_read` | 80 |
| `fake_secret_exfiltrated` | 95 |
| `contaminated_git_read` | 75 |
| `evidence_chain_detected` | 65 |
| `pre_operational_snapshot_detected` | 60 |

## Multiplicadores contextuales

| Condición | Factor |
|---|---|
| `git_bundle_created` + `code_upload` simultáneos | 2.0× |
| `anti_evasion_detected` + `code_upload`/`canary_exfiltrated` | 2.5× |
| `canary_exfiltrated` o `fake_secret_read` | 3.0× |
| ≥3 tipos de behavior distintos | 1.3× |

## Multiplicadores de secuencia (exfiltration chain)

Si los behaviors forman una cadena de exfiltración completa, se aplican multiplicadores progresivos:

| Etapa | Condición | Factor |
|---|---|---|
| Preparation | `preparation_detected` presente | 1.3× |
| Collection | `git_history_read` + `git_objects_read` + `mass_file_read` | 1.4× |
| Packaging | `git_bundle_created` + `git_archive_created` | 1.8× |
| Channel | `dns_suspicious` + `tls_suspicious` | 1.2× |
| Exfiltration | `code_upload` + `git_bundle_uploaded` + `secrets_exfiltrated` + `canary_exfiltrated` | 2.0× |

Se aplican en cascada: si hay Preparation AND Collection, se multiplica `1.3 × 1.4 = 1.82×`.

## Multiplicador temporal

Cuan más cerca en el tiempo ocurren los behaviors, mayor el factor:

| Avg gap | Factor |
|---|---|
| `< 30s` | 1.5× |
| `< 2min` | 1.3× |
| `< 10min` | 1.1× |
| `≥ 10min` | 1.0× (sin cambio) |

## Confidence del riesgo

```
confidence = avgBehaviorConf × 0.75 + (n / 5 × 0.15) + (diversity / 3 × 0.1) + 0.1
```

Donde:
- `n` = cantidad de behaviors (capped at 5)
- `diversity` = cantidad de tipos distintos de behavior (capped at 3)

Más behaviors y más diversos → mayor confianza en la evaluación.

## Normalización

`maxPossibleScore = 120`. Un score ≥ 120 → 100%.

## Niveles

| Nivel | Score | Significado |
|---|---|---|
| LOW | 0–19 | Operación normal |
| MEDIUM | 20–49 | Actividad sospechosa aislada |
| HIGH | 50–79 | Múltiples indicadores |
| CRITICAL | 80–100 | Exfiltración activa confirmada |
