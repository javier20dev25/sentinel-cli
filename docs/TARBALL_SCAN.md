# Tarball Scan y Attestation (`verify-pkg`)

Ataque de referencia: **ChainDrop / Shai-Hulud** (4 ago 2026) — un worm npm
auto-propagante desde la cuenta comprometida de `jaredwray` publicaba versiones
maliciosas (`keyv@6.0.0`) con `preinstall: node setup.mjs` y un dropper
`Math_Symbol.js`, y luego las despublishaba.

## Qué aporta esta versión

`sentinel verify-pkg` ya descargaba el tarball real (vía `npm pack --ignore-scripts`)
y lo escaneaba con LiteScanner. Ahora además:

### 1. Hooks de ciclo de vida estructurales

Se extrae `scripts` de `package.json` del tarball y se listan en la salida humana:

```
  Lifecycle scripts:
    preinstall    → node setup.mjs    ⚠ DANGEROUS
      (runs a bundled script during install)
```

El flag `dangerous` cubre la firma de ChainDrop: script de ciclo de vida
(`preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `prepublish`, …) que
baje o ejecute código (`curl|wget|bash|powershell|node <archivo>.mjs/js/cjs/ts`).

### 2. Attestation firmada del reporte

Cada resultado de escaneo se firma con HMAC-SHA256 y una clave por máquina
(`~/.sentinel/scan-signing.key`). El reporte es **tamper-evident**: cualquier
edición de hallazgos/verdict/counts invalida la firma.

```
  Report signed (HMAC-SHA256): 01cedecd255a3b89… (3 findings, 2 critical)
```

- `src/cli/intelligence/scan_attestation.ts` — `canonicalize`, `signScanAttestation`,
  `verifyScanAttestation`, `getOrCreateSigningKey`, `findingSha`.
- La firma cubre `pkg`, `verdict`, `fileCount`, `findingCount`, `criticalCount`,
  `highCount`, los digests de cada finding y `sizeBytes`. No prueba que el paquete
  sea seguro — solo que el reporte proviene de esta instalación y no fue alterado.

### 3. `verify-pkg --json`

Emite el resultado estructurado completo (incluida la attestation y los hooks), útil
para pipelines:

```json
{
  "pkg": "keyv@6.0.0",
  "verdict": "MALICIOUS",
  "lifecycleHooks": [{ "script": "preinstall", "command": "node setup.mjs", "dangerous": true, "reason": "..." }],
  "attestation": { "version": 1, "type": "tarball_scan", "input": { ... }, "signature": "..." },
  "findings": [ ... ]
}
```

### 4. Integración con `scan --audit-node-modules`

Cuando el audit de `node_modules` encuentra hooks de ciclo de vida peligrosos
(`LIFECYCLE_CURL_BASH`), la salida humana sugiere el deep-audit del tarball real:

```
  Deep audit: sentinel verify-pkg keyv — signed tarball scan of the actual published package.
```

## Por qué no un escáner dedicado

Evaluado y rechazado como **no-ROI**:

- Es una capa delgada (~150 líneas de descarga + extracción + heurísticas) sobre el
  registro, no un producto.
- Un producto aparte exigiría CLI, storage, auth, signing y CI propios — más
  superficie y mantenimiento para una ganancia de detección nula.
- El valor solo aparece cuando los findings **se fusionan en un gate** (verdict +
  attestation). Una herramienta standalone es solo asesoría, no enforcement.
- Los tres productos ya poseen las piezas: Oracle (gate de PR), CLI (`verify-pkg`,
  `--audit-node-modules`) y Cloud (registry manifest intelligence).

Por eso el tarball scan se incrustó en Oracle y CLI en lugar de un cuarto producto.

## Tests

`src/cli/scan_attestation.test.ts` — determinismo, tamper detection (verdict, counts,
findings, clave distinta), canonicalización, `findingSha`.
`src/cli/scan_node_modules.test.ts` — regresión del audit con fixture ChainDrop.
