# Motor de Comportamiento (behavior-engine.ts)

8 clasificadores que transforman eventos crudos en Behaviors tipificados.

## Clasificadores

### classifyFlow(flow: NetworkFlow): Behavior | null

Detecta en conexiones de red:

| Condición | Behavior |
|---|---|
| Host en SUSPICIOUS_HOST_PATTERNS + bytesSent > 1MB | `code_upload` |
| Host en patrones + path AI API | `ai_prompt_sent` |
| Host en patrones (sin lo anterior) | `suspicious_connection` |
| Host desconocido + path AI API + >50KB | `code_upload` |
| Host desconocido + path AI API | `ai_prompt_sent` |
| Body HTTP contiene "git bundle" | `git_bundle_uploaded` |
| DNS query matchea patrones | `dns_suspicious` |
| SNI matchea patrones | `tls_suspicious` |

### classifyProcess(event: ProcessEvent): Behavior | null

Detecta en procesos:

| Condición | Behavior |
|---|---|
| Nombre/cmdline contiene AI agent (grok, cursor, claude, etc.) | `process_suspicious` |
| cmdline matchea monitor detection commands | `monitor_awareness_detected` |
| cmdline contiene `git bundle create`, `git archive` | `git_bundle_created` / `git_archive_created` |
| cmdline contiene `git rev-list --all`, `git pack-objects`, etc. | `repo_indexed` |
| cmdline contiene `curl` + `--data-binary`/`-d`/`-F`/`-T`/`--upload-file` | `code_upload` |
| cmdline contiene `nslookup` + `-type=txt`/dominio `.attacker|.exfil|.tunnel` | `dns_suspicious` |
| cmdline contiene `tar` + `.git` + `-czf`/`-zcf`/`--create` | `git_archive_created` |

Skip rules (no generan behavior):
- `node.exe` ejecutando `dist/cli/main.js` o `scripts/record-session.js` (propia infraestructura)
- `mscopilot` o `\microsoft\copilot\` (proceso legítimo del SO)

### classifyFileAccess(access: FileAccessEvent): Behavior | null

| Condición | Behavior |
|---|---|
| Path contiene `.git` + `objects` | `git_objects_read` |
| Path contiene `.git` + `logs`/`index`/`config`/`head` | `git_history_read` |
| Path termina en `.bundle` o `.gitbundle` | `git_bundle_created` |
| Path contiene secret fragments (`.env`, `secrets`, `credentials`, etc.) | `secrets_scanned` |

### classifyGitCommand(cmd: GitCommandEvent): Behavior | null

| Acción git | Behavior |
|---|---|
| `bundle` | `git_bundle_created` |
| `archive` | `git_archive_created` |
| `rev-list`, `log` | `git_history_read` |
| `push --mirror/--all/--force` | `full_repo_snapshot` |
| `cat-file`, `ls-tree`, `show-ref`, `for-each-ref` | `git_objects_read` |
| `clone`, `fetch`, `pull` | No genera (normal) |
| `status`, `add`, `commit`, `diff`, etc. | No genera (normal) |

### classifyPreparationCommands(proc: ProcessEvent): Behavior | null

Comandos de preparación/reconocimiento:

| Comando | |
|---|---|
| `whoami`, `ipconfig`, `netstat`, `hostname` | |
| `arp`, `route`, `systeminfo` | |
| `nslookup` | |
| `git cat-file`, `git rev-list`, `git ls-tree` | |
| `git count-objects`, `git show-ref`, `git for-each-ref` | |
| `git diff --cached`, `git stash list`, `git stash` | |
| `git bundle list-heads` | |

### computeMassReadBehavior, computeEmbeddingBehavior

Requieren FileAccessEvent (no implementado en Windows actualmente).
