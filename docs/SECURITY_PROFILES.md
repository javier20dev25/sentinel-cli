# Sentinel CLI Security Profiles and Dependency Hardening

`sentinel hardening [audit|status|preset|toggle|menu]` reviews a JavaScript project and stores local hardening preferences in `~/.sentinel/security_profile.json`.

## Examples

```sh
sntnl hardening --path .
sntnl hardening --path . --json
sntnl hardening status
sntnl hardening preset agile
sntnl hardening preset strict
sntnl hardening toggle lockfile off
sntnl hardening menu
```

Available presets are `agile`, `strict`, and `ci`. They are starting configurations; individual protections are independent and can be switched on or off. Applying a preset only stores the profile. In the interactive menu, applying `strict` offers to install Guard wrappers and the existing SAST pre-commit hook; neither is silently installed. The menu toggle for Guard or pre-commit applies/removes that existing integration. The classified-data hook runs as part of Sentinel's SAST pre-commit integration.

## Audit behavior and trust boundary

The project audit reads `package.json`, `.npmrc`, and the first recognized lockfile (`pnpm-lock.yaml`, `package-lock.json`, or `yarn.lock`). It identifies startup/lifecycle scripts, passes script text through Sentinel Lite's local static rules, and reports selected lockfile URL/integrity signals. It does not execute project code, install dependencies, resolve packages, or make network requests. The JSON report includes `executedProjectCode: false` and `networkRequests: 0`.

The result is advisory. A script such as `node scripts/health-check.js` is a startup script, not automatically malicious. A suspicious static pattern is a signal for human review, not proof of exploitation. This command currently does not run the Sentinel Cloud full engine; Cloud full-engine scans consume subscription pulses and must be invoked through the separate, existing `sntnl pulse-scan` flow after explicitly enabling pulse mode.

## Current coverage and limitations

- `ignore-scripts` and `shamefully-hoist` are reported when present in the project `.npmrc`. Sentinel does not edit `.npmrc` automatically. Disabling lifecycle scripts can break native dependencies and does not stop scripts invoked at runtime.
- Lockfile review identifies URLs outside the public npm registry and missing `integrity` metadata in npm `package-lock.json` entries. It does not prove a custom registry is malicious, compare a downloaded tarball, or fully parse all pnpm lockfile semantics.
- Package age quarantine and SLSA/npm provenance are not enforced by this profile module yet. Their toggles record preferences only and the CLI labels them as not implemented here.
- `pnpm` content-addressable storage uses hardlinks to save space; ordinary writes through linked package files do not generally rewrite the store inode because package files are made read-only. This is not a security boundary against privileged processes or unsafe store permissions. Do not treat a shared-store poisoning scenario as established without a reproducible, platform-specific path.
- Guard wrappers affect shells where Sentinel's path/profile setup is active. They are not a kernel-level interceptor and can be bypassed by absolute paths, other shells, or direct runtime execution.
- A configured Cloud session never causes this audit to upload source or manifests automatically. The existing `pulse-scan` behavior is separate and explicitly consumes a pulse.

The module intentionally proposes inspection and operator-controlled integrations. It does not overwrite project policy or execute scripts while analyzing them.
