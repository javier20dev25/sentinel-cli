import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    savePulseResult,
    listPulseResults,
    findPulseResult,
    isPulseResult,
} from './pulse_store';
import type { RemoteScanResult } from './cloud_client';

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pulse-store-test-'));

function result(jobId: string, scannedAt: string, verdict = 'MALICIOUS'): RemoteScanResult {
    return {
        jobId,
        status: 'complete',
        engineVersion: 'sentinel-engine-1.0.0',
        format: 'npm',
        scannedAt,
        risk: 'critical',
        riskScore: 80,
        verdict: verdict as RemoteScanResult['verdict'],
        confidence: 0.9,
        findings: [],
        summary: '1 critical lifecycle hook(s).',
        explanation: ['preinstall'],
    };
}

describe('pulse_store', () => {
    beforeEach(() => {
        if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
        fs.mkdirSync(TEST_DIR, { recursive: true });
    });

    afterEach(() => {
        if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
    });

    it('saves a result and lists it back newest-first', () => {
        const file = savePulseResult(result('job-older', '2026-09-01T00:00:00.000Z'), { dir: TEST_DIR });
        savePulseResult(result('job-newer', '2026-09-20T00:00:00.000Z'), { dir: TEST_DIR });
        expect(fs.existsSync(file)).toBe(true);

        const listed = listPulseResults({ dir: TEST_DIR });
        expect(listed.map((r) => r.jobId)).toEqual(['job-newer', 'job-older']);
    });

    it('looks up by exact id or by id prefix', () => {
        savePulseResult(result('pulse-abc-123', '2026-09-01T00:00:00.000Z'), { dir: TEST_DIR });
        expect(findPulseResult('pulse-abc-123', { dir: TEST_DIR })?.jobId).toBe('pulse-abc-123');
        expect(findPulseResult('pulse-abc', { dir: TEST_DIR })?.jobId).toBe('pulse-abc-123');
        expect(findPulseResult('nope', { dir: TEST_DIR })).toBeNull();
    });

    it('skips corrupt and foreign files', () => {
        savePulseResult(result('ok-1', '2026-09-01T00:00:00.000Z'), { dir: TEST_DIR });
        fs.writeFileSync(path.join(TEST_DIR, 'corrupt.json'), '{not json');
        fs.writeFileSync(path.join(TEST_DIR, 'notes.txt'), 'ignored');
        const listed = listPulseResults({ dir: TEST_DIR });
        expect(listed.map((r) => r.jobId)).toEqual(['ok-1']);
    });

    it('isPulseResult validates the established RemoteScanResult shape', () => {
        expect(isPulseResult(result('j', '2026-01-01T00:00:00.000Z'))).toBe(true);
        expect(isPulseResult({ foo: 'bar' })).toBe(false);
        expect(isPulseResult(null)).toBe(false);
    });

    it('returns an empty list when the directory does not exist', () => {
        expect(listPulseResults({ dir: path.join(TEST_DIR, 'missing') })).toEqual([]);
    });
});