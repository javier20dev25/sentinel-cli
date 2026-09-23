import { describe, it, expect } from 'vitest';
import {
    renderResultsSummary,
    renderResultTable,
    renderSeverityDonut,
    renderStoredPulseResult,
    isResultsFormat,
} from './pulse_render';
import type { RemoteScanResult } from './cloud_client';

function result(findings: RemoteScanResult['findings']): RemoteScanResult {
    return {
        jobId: 'job-1',
        status: 'complete',
        engineVersion: 'sentinel-engine-1.0.0',
        format: 'npm',
        scannedAt: '2026-09-20T12:00:00.000Z',
        risk: 'high',
        riskScore: 60,
        verdict: 'MALICIOUS',
        confidence: 0.75,
        findings,
        summary: '2 lifecycle hook(s).',
        explanation: ['preinstall triggers a remote fetch'],
    };
}

describe('pulse_render', () => {
    it('accepts table/donut/json and rejects anything else', () => {
        expect(isResultsFormat('table')).toBe(true);
        expect(isResultsFormat('donut')).toBe(true);
        expect(isResultsFormat('json')).toBe(true);
        expect(isResultsFormat('pie')).toBe(false);
    });

    it('renders a table with verdict, risk and findings', () => {
        const table = renderResultTable(
            result([
                { severity: 'critical', type: 'LIFECYCLE_CURL_BASH', title: 'preinstall', message: 'pipes curl to bash' },
                { severity: 'medium', type: 'NETWORK_ACTIVITY', title: 'postinstall', message: 'fetches payload' },
            ]),
        );
        expect(table).toContain('MALICIOUS');
        expect(table).toContain('score 60');
        expect(table).toContain('CRITICAL');
        expect(table).toContain('MEDIUM');
        expect(table).toContain('preinstall');
    });

    it('renders a severity donut with counts and percentages that sum to 100%', () => {
        const donut = renderSeverityDonut(
            result([
                { severity: 'critical', type: 'A', title: 'a' },
                { severity: 'critical', type: 'A', title: 'b' },
                { severity: 'high', type: 'B', title: 'c' },
            ]),
        );
        expect(donut).toContain('Findings distribution (3 total)');
        expect(donut).toContain('critical');
        expect(donut).toContain('2 (67%)');
        expect(donut).toContain('1 (33%)');
        expect(donut).toContain('█');
        expect(donut).toContain('░');
    });

    it('donut reports none when there are no findings', () => {
        const donut = renderSeverityDonut(result([]));
        expect(donut).toContain('Findings distribution (0 total)');
        expect(donut).toContain('(none)');
    });

    it('json format returns the raw result contract', () => {
        const r = result([{ severity: 'critical', type: 'A', title: 'a' }]);
        const out = renderStoredPulseResult(r, 'json');
        expect(JSON.parse(out)).toEqual(r);
    });

    it('lists clearly when no results are stored', () => {
        expect(renderResultsSummary([])).toContain('No pulse results stored yet');
    });
});