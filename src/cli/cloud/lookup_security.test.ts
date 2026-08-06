import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runLookup } from './lookup';
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
            remote_scan: false,
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
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-lookup-sec-'));
}

function outputText(result: { lines: { text: string }[] }): string {
    return result.lines.map((l) => l.text).join('\n');
}

const VALID_ID = `sha512:${'a'.repeat(128)}`;

function hitBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        found: true,
        usable: true,
        contentId: VALID_ID,
        verdict: 'KNOWN_SAFE',
        confidence: 0.98,
        signature: 'c'.repeat(64),
        firstSeen: 1700000000000,
        lastSeen: 1701000000000,
        seenInRepoCount: 12,
        historyLength: 34,
        ...overrides,
    };
}

describe('fetchLookup timeout (adversarial never-resolving server)', () => {
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
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com', timeoutMs: 20 },
                { sessionDir: dir }
            );
            const elapsed = Date.now() - started;

            expect(elapsed).toBeLessThan(2000);
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain('using local analysis');
            expect(fs.existsSync(sessionPath)).toBe(true);
            expect(capturedSignal?.aborted).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('cloud_client lookup contract (static source guards)', () => {
    it('maps 401 to auth and 403 to forbidden BEFORE the generic non-ok branch', () => {
        const src = fs.readFileSync(path.join(__dirname, 'cloud_client.ts'), 'utf8');
        const lookupStart = src.indexOf('export async function fetchLookup');
        const lookupBlock = src.slice(lookupStart);
        const authIdx = lookupBlock.indexOf('res.status === 401');
        const forbiddenIdx = lookupBlock.indexOf('res.status === 403');
        const genericIdx = lookupBlock.indexOf('if (!res.ok)');
        expect(authIdx).toBeGreaterThan(-1);
        expect(forbiddenIdx).toBeGreaterThan(authIdx);
        expect(genericIdx).toBeGreaterThan(forbiddenIdx);
    });

    it('requires a 64-hex signature and aborts after LOOKUP_TIMEOUT_MS', () => {
        const src = fs.readFileSync(path.join(__dirname, 'cloud_client.ts'), 'utf8');
        expect(src).toContain('const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;');
        expect(src).toContain('const LOOKUP_TIMEOUT_MS = 5000;');
        expect(src).toContain('new AbortController()');
        expect(src).toMatch(/setTimeout\(\(\) => controller\.abort\(\), timeoutMs\)/);
        expect(src).toContain('signal: controller.signal');
    });

    it('signature pattern is applied inside validateLookupResult (fail-closed on bad shape)', () => {
        const src = fs.readFileSync(path.join(__dirname, 'cloud_client.ts'), 'utf8');
        const validateStart = src.indexOf('function validateLookupResult');
        const validateBlock = src.slice(validateStart, src.indexOf('export async function fetchLookup'));
        expect(validateBlock).toContain('SIGNATURE_PATTERN.test');
    });
});

describe('lookup result passthrough pins (documenting current behavior)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('a hit that omits the signature passes structural validation and the verdict is shown', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const body = hitBody();
            delete body.signature;
            fetchMock.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(body) });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain('Cloud intelligence hit');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('--json emits every server field verbatim, including unexpected ones (no whitelisting)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockResolvedValue({
                ok: true,
                status: 200,
                json: () =>
                    Promise.resolve(
                        hitBody({ evidence: { alerts: ['secret-internal-data'] }, manifestHash: 'abc' })
                    ),
            });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com', json: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const parsed = JSON.parse(outputText(result));
            expect(parsed.evidence).toEqual({ alerts: ['secret-internal-data'] });
            expect(parsed.manifestHash).toBe('abc');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});
