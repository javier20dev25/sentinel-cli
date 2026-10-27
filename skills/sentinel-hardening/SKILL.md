---
name: sentinel-hardening
description: Review npm, pnpm, and yarn project hardening posture with Sentinel CLI without executing project scripts or uploading source.
---

# Sentinel Dependency Hardening

Use this skill when a user asks to inspect package-manager configuration, startup or lifecycle scripts, `.npmrc`, or npm/pnpm/yarn lockfile signals.

## Workflow

1. Run `sntnl hardening --path <project> --json` for a local informational report.
2. Explain the difference between ordinary startup scripts and suspicious static findings. Do not call a script malicious solely because it invokes Node, a shell, or a network library.
3. Review `.npmrc` and lockfile signals in context. Custom registries may be legitimate; verify ownership and policy before recommending changes.
4. Offer profiles with `sntnl hardening preset agile|strict|ci`; explain they store preferences. In interactive mode, Strict asks before installing Guard wrappers and the SAST pre-commit hook.
5. Use `sntnl hardening toggle <toggle> on|off` for a specific preference. Explain that the age/provenance preferences are not enforcement integrations yet.
6. If a full Sentinel Cloud scan is requested, explain that `sntnl pulse-scan` sends the package manifest to Cloud and consumes one subscription pulse; never run it without explicit user choice.

## Safety constraints

- Never run `npm install`, `pnpm install`, project scripts, or build commands as part of this audit.
- Never change `.npmrc`, lockfiles, scripts, or hooks without explicit operator action. The interactive Strict preset and integration toggles ask before installing/removing existing hooks or Guard integrations.
- The hardening audit itself is local: it reads project metadata and runs static text rules only. It does not fetch packages or send source to Cloud.
- Treat scanner output as evidence to validate, not an automatic vulnerability verdict. Report what was observed, what remains unknown, and a practical next check.
- `ignore-scripts=true` can break legitimate packages and does not prevent runtime execution. Present it as a project-specific tradeoff, not a universal secure default.
- Do not describe Sentinel Guard shell wrappers as unbypassable or kernel-level protection.

See `docs/SECURITY_PROFILES.md` for command reference, stored-toggle semantics, coverage, and limitations.
