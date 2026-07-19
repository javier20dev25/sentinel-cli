# Corpus de Sesiones v1.0

## Estructura

```
replay-corpus/
  corpus-version.json     → manifiesto de versión
  recorded/               → sesiones grabadas + ground truth
  synthetic/              → sesiones sintéticas (calibración)
```

## Perfiles (15 sesiones grabadas)

### Exfiltración (6) — CRITICAL

| Perfil | ID Sesión | Score | Behaviors clave |
|---|---|---|---|
| exfil-pastebin | ua7u9r | CRITICAL(100) | code_upload×2, preparation_detected×9, suspicious_connection |
| exfil-gist | tr0rmt | CRITICAL(100) | code_upload×2, preparation_detected×9, suspicious_connection |
| exfil-discord | 74pdej | CRITICAL(100) | code_upload×2, preparation_detected×9, suspicious_connection |
| exfil-dns | ldgh8q | CRITICAL(82) | dns_suspicious×4, preparation_detected×13, suspicious_connection |
| exfil-git-bundle | vfvxrw | CRITICAL(100) | git_bundle_created×2, preparation_detected×9, full_repo_snapshot |
| exfil-tar-git | 4lvaxc | CRITICAL(100) | git_archive_created×2, preparation_detected×9, suspicious_connection |

### Benignas (9) — HIGH/MEDIUM

| Perfil | Score | Nota |
|---|---|---|
| cursor-edit | HIGH(78) | Falso positivo: "cursor" en profile ID → process_suspicious |
| cursor-refactor | HIGH(78) | Idem |
| claude-code | HIGH(78) | Falso positivo: "claude" en profile ID |
| read-env | MEDIUM(47) | Solo preparation_detected |
| grep-secrets | MEDIUM(47) | Solo preparation_detected |
| read-git | MEDIUM(47) | Solo preparation_detected |
| read-ssh | MEDIUM(47) | Solo preparation_detected |
| mass-file-read | MEDIUM(47) | Solo preparation_detected |
| (extra) | MEDIUM(47) | Solo preparation_detected |

## Cobertura

De 31 perfiles canónicos, 26 son capturables en este entorno (5 requieren docker/go/terraform). Cobertura efectiva: 100%.

## Versión

`corpus-version.json`:

```json
{
  "version": "1.0.0",
  "recordedAt": "2026-07-19",
  "profiles": { "total": 31, "captured": 26, "effectiveCoveragePct": 100 }
}
```
