import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import type { RemoteScanResult } from './cloud_client';

/**
 * Local persistence of full-engine (pulse) scan results. Each scan is stored
 * verbatim as the API returned it (the established RemoteScanResult contract),
 * one JSON file per scan under ~/.sentinel/pulses/<jobId>.json. The CLI never
 * re-runs the engine for these results; `sentinel results` reads them back.
 */

export const PULSE_RESULTS_DIR = path.join(os.homedir(), '.sentinel', 'pulses');

export interface PulseStoreOptions {
    dir?: string;
}

export function getPulseResultsDir(opts?: PulseStoreOptions): string {
    return opts?.dir ?? PULSE_RESULTS_DIR;
}

function sanitizeJobId(jobId: string): string {
    const cleaned = jobId.replace(/[^A-Za-z0-9._-]/g, '-');
    return cleaned.length > 0 ? cleaned : 'pulse';
}

function localIdOf(result: RemoteScanResult): string {
    if (typeof result.jobId === 'string' && result.jobId.length > 0) return result.jobId;
    if (typeof result.scannedAt === 'string' && result.scannedAt.length > 0) return result.scannedAt;
    return `pulse-${Date.now()}`;
}

export function savePulseResult(result: RemoteScanResult, opts?: PulseStoreOptions): string {
    const dir = getPulseResultsDir(opts);
    fs.mkdirSync(dir, { recursive: true });
    const stored: RemoteScanResult = { ...result, jobId: localIdOf(result) };
    const file = path.join(dir, `${sanitizeJobId(stored.jobId ?? 'pulse')}.json`);
    fs.writeFileSync(file, JSON.stringify(stored, null, 2) + '\n', { mode: 0o600 });
    return file;
}

export function isPulseResult(value: unknown): value is RemoteScanResult {
    if (typeof value !== 'object' || value === null) return false;
    const record = value as Record<string, unknown>;
    return (
        typeof record.jobId === 'string' &&
        typeof record.status === 'string' &&
        typeof record.verdict === 'string' &&
        Array.isArray(record.findings)
    );
}

export function listPulseResults(opts?: PulseStoreOptions): RemoteScanResult[] {
    const dir = getPulseResultsDir(opts);
    let files: string[] = [];
    try {
        files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
    } catch {
        return [];
    }
    const results: RemoteScanResult[] = [];
    for (const f of files) {
        try {
            const parsed = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) as unknown;
            if (isPulseResult(parsed)) results.push(parsed);
        } catch {
            // skip corrupt/foreign files
        }
    }
    results.sort(
        (a, b) =>
            new Date(b.scannedAt ?? 0).getTime() - new Date(a.scannedAt ?? 0).getTime(),
    );
    return results;
}

export function findPulseResult(jobId: string, opts?: PulseStoreOptions): RemoteScanResult | null {
    const results = listPulseResults(opts);
    return (
        results.find((r) => r.jobId === jobId) ??
        results.find((r) => (r.jobId ?? '').startsWith(jobId)) ??
        null
    );
}