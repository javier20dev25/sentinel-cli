# Sentinel CLI

Sentinel Security Oracle — Unified Terminal Security Interface.

A supply chain enforcement layer, not a vulnerability scanner. Sentinel does not report what is wrong, it decides if something enters.

## Install

```bash
npm install -g @sentinel/cli
```

Or run directly:

```bash
npx @sentinel/cli scan .
```

## Quick Start

```bash
# Scan a directory for threats
sentinel scan ./src

# Audit an npm package without installing
sentinel verify-pkg dotenv --details

# Check system health
sentinel doctor --deep

# Verify CLI integrity
sentinel integrity

# Launch interactive hub
sentinel hub
```

## Documentation

Full documentation and CLI reference: https://sentinel-psi-nine.vercel.app/cli

## License

BUSSL-1.1 — Business Source License 1.1. See [LICENSE](LICENSE).

Free for non-production and personal use. Production use for security tools requires a license. Changes to GPL v2.0 after 2030-05-20.
