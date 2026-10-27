# Pull request scan progress map

The interactive `sntnl pr` flow renders a compact progress map on stderr. It
uses a spinner while a step is active and retains readable text in non-TTY
output. The displayed steps are driven by the selected engine's real actions.

## Sentinel Lite

Lite fetches the pull request diff through GitHub CLI and analyzes that diff on
the local machine. The map shows PR head resolution, diff retrieval, local
analysis, and the resulting findings. Its scope is changed lines and context
provided by the diff; it is not a full repository scan.

## Sentinel Cloud

Cloud mode pins the PR head SHA, retrieves `package.json` from that exact commit,
checks the stored API key's `remote_scan` capability, and submits the manifest
to `/api/scan/remote`. A successful request consumes one pulse. The output
reports the returned engine version, verdict, risk score, findings, and pulse
balance when the usage endpoint is available.

This API currently accepts an npm manifest, not the pull request diff or a
repository archive. It returns an aggregate result and no per-analyzer execution
events. Therefore the progress map reports the remote request and aggregate
response only; it does not imply that individual Cloud tools were observed.
Cloud and Lite findings and verdicts are shown using their selected engine's
result, not silently substituted for one another.

## Terminal behavior and credentials

Example Cloud view:

```text
Sentinel CLI | PR #42 | Sentinel Cloud | mapa de análisis
  [OK] Metadatos del pull request: COMPLETE — head 3f8a21c4d019
  [OK] Manifiesto del commit propuesto: COMPLETE — 812 bytes; SHA 3f8a21c4d019
  [OK] Acceso a Sentinel Cloud: COMPLETE — plan Team
  [OK] Motor de análisis: COMPLETE — motor Cloud 4.3; 2 hallazgos
  [OK] Veredicto y evidencia: COMPLETE — respuesta agregada SUSPICIOUS
  i El endpoint devuelve un resultado agregado; no publica eventos internos de sus analizadores.
```

Progress is written to stderr. Colors and redraw animation are enabled only for
interactive terminals and are disabled by `NO_COLOR` or `TERM=dumb`. The API key
is sent only as a bearer token over the configured Sentinel Cloud URL; the map
prints its label or plan, never the token. GitHub commands use argument arrays,
and the manifest is read from the pinned commit SHA.
