# Incidente: HOST INTEGRITY SUSPECT (Confidence LOW) — falso positivo del verificador

- **ID:** HOST_INTEGRITY_2026-08-09
- **Fecha de apertura:** 2026-08-09
- **Fecha de cierre:** 2026-08-09
- **Estado:** `CLOSED`
- **Clasificación definitiva:** `VERIFIER DEFECT — FALSE POSITIVE / LEGACY COMPATIBILITY GAP`
  (reemplaza la clasificación inicial `BASELINE DRIFT`, que era parcialmente incorrecta)
- **Componente afectado:** `src/cli/intelligence/integrity_chain.ts`
- **Impacto:** toda invocación del CLI reportaba `HOST INTEGRITY: SUSPECT` + `Confidence Level: LOW`,
  con la cadena de integridad en `BROKEN`. Señal falsa de compromiso para cualquier proceso que
  dependiera de `HOST INTEGRITY`.

---

## 1. Síntoma

Cada invocación del CLI emitía:

```text
⚠️  HOST INTEGRITY: SUSPECT
   Confidence Level: LOW
   - Integrity chain broken: code hash mismatch or link hash verification failed.
```

## 2. Hipótesis inicial (descartada como causa)

Se registró inicialmente como `BASELINE DRIFT` asociado a un manifest desactualizado.
El manifest (o `integrity.json`) **no era la causa inmediata del SUSPECT**: es un problema
independiente y queda como expediente separado. Mezclar ambos fenómenos habría llevado a
concluir erróneamente que "actualizar el manifest" resolvía la integridad del host. No fue así.

## 3. Causa raíz demostrada

Defecto determinista del verificador en `recordBoot()`:

```text
recordBoot()
    ↓
recomputación incompatible del link_hash
    ↓
hashOk = false
    ↓
integrity chain = BROKEN
    ↓
HOST INTEGRITY = SUSPECT
    ↓
Confidence = LOW
```

Dos defectos concretos en la recomputación:

1. **Material distinto entre creación y verificación.** `createLink()` hasheaba solo los
   6 campos canónicos (`session_id`, `link_number`, `code_hash`, `previous_link_hash`,
   `started_at`, `accumulated_seconds`), mientras que la verificación hasheaba la **fila
   completa** (9 claves, incluyendo `id`, `link_hash` y `created_at`).
2. **Doble SHA-256.** La verificación aplicaba `sha256(hashLink(lastLink))` y comparaba contra
   el `link_hash` almacenado, que era un único `sha256` del material canónico.

### Evidencia (reproducida contra `vault.db` real)

- `code_hash` almacenado == hash de reglas actual (`9b1a9605809f…`) → la rama
  "code hash mismatch" **no** se disparaba.
- Hash de campos-de-creación == `link_hash` almacenado → `true` (el registro es correcto).
- Recomputed del verificador == `link_hash` almacenado → `false` (el verificador estaba roto).
- La cadena contiene **dos generaciones de contrato criptográfico** (halladas empíricamente):

| Generación | Links | `link_hash` | `previous_link_hash` |
|---|---|---|---|
| V1 (legado) | ids 1–5 (2026-06-05 / 2026-06-10) | JSON de 6 campos canónicos **sin ordenar** | fila completa, **sin ordenar** |
| V2 (actual) | ids 6–490 | JSON de 6 campos canónicos **ordenado** | fila completa, **ordenado** |

## 4. Corrección aplicada

`src/cli/intelligence/integrity_chain.ts` — **solo el verificador**; sin tocar cadena ni manifest.

- Verificador **versionado**: cada link se verifica con el esquema que lo creó.
  - Frontera determinista: legado (V1) si `id <= 5` **y** `created_at < '2026-06-10 12:00:00'`;
    en caso contrario V2. El guard de fecha evita que una cadena nueva (cuyos ids también
    empiezan en 1) se clasifique como legado.
- `recordBoot()` verifica el último link con `verifyLink()` (esquema propio, **sin doble hash**)
  y el chequeo de `code_hash`.
- `getStatus()` recorre la cadena: `link_hash` por esquema propio + enlace `previous_link_hash`
  sobre la fila completa del previo con el esquema del link que lo creó.
- **Nuevos links siempre en V2** (una sola versión vigente para escritura; V1 es solo
  compatibilidad histórica de lectura/verificación).
- Constructor acepta `dbPath?` opcional (inyección para tests; el default no cambia).

## 5. Verificación

| Verificación | Resultado |
|---|---|
| Simulación sobre la cadena real | 490/490 `link_hash` + 489/489 enlaces → `INTACT` |
| `npx vitest run` (suite completa) | 67 files / **1305 tests passed** |
| Tests nuevos de integridad | **17/17** (legado válido, actual válido, cadena mixta INTACT, V1-only, V2-only, alteraciones de `session_id`/`code_hash`/`previous_link_hash`/`accumulated_seconds`/`link_hash` → roto; `created_at`/`id` → hash propio intacto pero binding de cadena roto; `recordBoot` repetido consistente; `recordBoot` detecta link final manipulado y hash de reglas distinto) |
| `npm run build` (tsc) | PASS |
| E2E `sentinel integrity --uptime` | `✓ Local environment verified and trusted.` + `🔗 INTEGRITY CHAIN: INTACT (491 links)` |
| Integridad de la evidencia histórica | Los **490 links originales permanecieron byte a byte idénticos** (snapshot previo/post). Solo se agregó el link 491, comportamiento normal de `recordBoot()` |

## 6. Notas de trazabilidad

- No se regeneró ningún manifest. No existe `integrity.json` en el repo (modo dev), por lo que
  el paso de verificación de manifest no participó.
- El manifest desactualizado es un **expediente separado**, no parte de este incidente.
- Cambiar la interpretación, no la evidencia: la corrección demuestra que la anomalía era un
  defecto determinista del verificador y no una modificación del host.

## 7. Hardening futuro (no bloqueante)

La frontera `id <= 5 && created_at < cutoff` es un discriminador heurístico funcional, respaldado
por la evidencia actual, pero no es versionado criptográfico ideal. Si se migran o importan
registros, o se cambian relojes, puede volverse frágil.

**Propuesta a futuro:** agregar una columna explícita `schema_version (1|2)` a los registros
nuevos y que forme parte del contrato. **No se aplicó ahora** para no alterar los 491 links
existentes (sería cirugía innecesaria sobre una auditoría cerrada).
