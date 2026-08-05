/**
 * Scan Attestation (v1) — signed tarball-scan report for the CLI.
 *
 * `sentinel verify-pkg` downloads a real tarball and scans it. This module
 * binds the scan result (package, verdict, per-finding digests, counts) to a
 * deterministic HMAC-SHA256 signature so the report is tamper-evident: any
 * edit to the reported findings invalidates the signature. The key is a
 * per-machine secret persisted at ~/.sentinel/scan-signing.key — it proves
 * the report came from this Sentinel install, not that the package is safe.
 */

import { createHmac, createHash, randomBytes } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface AttestationInput {
    pkg: string;
    name: string;
    version: string;
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    fileCount: number;
    findingCount: number;
    criticalCount: number;
    highCount: number;
    findingShas: string[];
    sizeBytes: number;
}

export interface ScanAttestation {
    version: 1;
    type: 'tarball_scan';
    input: AttestationInput;
    signedAt: number;
    signature: string;
}

/**
 * Deterministic stringification (sorted keys, stable for any JSON value).
 * Two structurally-equal objects always canonicalize to the same string.
 */
export function canonicalize(value: unknown): string {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

const KEY_PATH = path.join(os.homedir(), '.sentinel', 'scan-signing.key');

/**
 * Per-machine signing key, generated on first use and reused afterwards so
 * attestations stay verifiable across runs. Falls back to a constant only
 * when the home dir is not writable (read-only environment).
 */
export function getOrCreateSigningKey(): string {
    try {
        if (fs.existsSync(KEY_PATH)) {
            const existing = fs.readFileSync(KEY_PATH, 'utf8').trim();
            if (existing.length >= 32) return existing;
        }
        const key = randomBytes(32).toString('hex');
        fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true });
        fs.writeFileSync(KEY_PATH, key, { mode: 0o600 });
        return key;
    } catch (_) {
        return 'sentinel-local-readonly-fallback';
    }
}

/**
 * Sign a scan result. `key` is injectable for tests; production callers omit it.
 */
export function signScanAttestation(input: AttestationInput, key = getOrCreateSigningKey(), signedAt = Date.now()): ScanAttestation {
    const payload = { version: 1 as const, type: 'tarball_scan' as const, input, signedAt };
    const canonical = canonicalize(payload);
    const signature = createHmac('sha256', key).update(canonical).digest('hex');
    return { ...payload, signature };
}

/**
 * Verify a scan attestation against the machine key. Returns true only if the
 * signature is intact (i.e. the reported fields were not modified).
 */
export function verifyScanAttestation(att: ScanAttestation, key = getOrCreateSigningKey()): boolean {
    if (!att || typeof att.signature !== 'string') return false;
    const { signature, ...rest } = att;
    const expected = createHmac('sha256', key).update(canonicalize(rest)).digest('hex');
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(signature, 'hex');
    return a.length === b.length && a.equals(b);
}

/**
 * Digest a single finding into the shas array used by the attestation.
 */
export function findingSha(type: string, severity: string, file: string): string {
    return createHash('sha256').update(`${type}|${severity}|${file}`).digest('hex');
}
