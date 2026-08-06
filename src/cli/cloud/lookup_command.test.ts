import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runLookup } from './lookup';
import type { LookupRunResult } from './lookup';
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
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-lookup-'));
}

function outputText(result: LookupRunResult): string {
    return result.lines.map((l) => l.text).join('\n');
}

const VALID_ID = `sha512:${'a'.repeat(128)}`;
const VALID_SRI = `sha512-${'A'.repeat(44)}`;

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

describe('sentinel lookup command (runLookup)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('Given no session when I run lookup then it exits 1 and prints "Not logged in"', async () => {
        const dir = makeTempDir();
        try {
            const result = await runLookup({ contentId: VALID_ID }, { sessionDir: dir });
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Not logged in');
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a plan without content_intel_lookup when I run lookup then it exits 1 with the plan message and does NOT call the server', async () => {
        const dir = makeTempDir();
        try {
            const session = buildSession('tok-1');
            saveSession(
                buildSession('tok-1', {
                    capabilities: { ...session.capabilities, content_intel_lookup: false },
                }),
                { sessionDir: dir }
            );
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                'Your plan does not include content intelligence lookup.'
            );
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a valid login when I look up a known-safe content then the CLI muestra "Cloud intelligence hit" and exits 0 (login exitoso)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(hitBody()),
            });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain('Cloud intelligence hit');
            expect(outputText(result)).toContain('KNOWN_SAFE');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a cached hit with a valid signature when I look up then the cache-hit line is shown (hit de caché)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(hitBody({ signature: 'd'.repeat(64) })),
            });
            const result = await runLookup(
                { contentId: VALID_SRI, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Cloud intelligence hit');
            expect(text).toContain('KNOWN_SAFE');
            expect(text).toContain('98%');
            expect(text).toContain('seen in 12 repos');
            expect(text).toContain('history 34 snapshots');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given an expired/invalid token when I look up then the session file is removed and it exits 1 (token inválido)', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            expect(fs.existsSync(sessionPath)).toBe(true);
            fetchMock.mockResolvedValue({
                ok: false,
                status: 401,
                json: () => Promise.resolve({ error: 'Invalid or expired API token.' }),
            });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Session expired or invalid token');
            expect(fs.existsSync(sessionPath)).toBe(false);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud is offline when I look up then it falls back to local analysis and exits 0 (Cloud offline)', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockRejectedValue(new Error('fetch failed: ECONNREFUSED'));
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain('using local analysis');
            expect(fs.existsSync(sessionPath)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a structurally broken signature when I look up then it does not trust the response (exit 0, no verdict shown)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(hitBody({ signature: 'zz', verdict: 'MALICIOUS' })),
            });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('integrity check failed');
            expect(text).not.toContain('MALICIOUS');
            expect(text).not.toContain('Cloud intelligence hit');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a malformed contentId when I look up then it exits 1 without calling the server', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const result = await runLookup(
                { contentId: 'not-a-real-id', api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Malformed contentId');
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a revoked record when I revalidate it then it reports found-but-not-usable (revalidación por revocación)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockResolvedValue({
                ok: true,
                status: 200,
                json: () =>
                    Promise.resolve({
                        found: true,
                        usable: false,
                        reason: 'revoked',
                        contentId: VALID_ID,
                    }),
            });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Cloud knowledge found but not usable (revoked) — using local analysis.'
            );
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given no Cloud knowledge when I look up then it prints the miss line and exits 0', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockResolvedValue({
                ok: true,
                status: 200,
                json: () =>
                    Promise.resolve({ found: false, usable: false, contentId: VALID_ID }),
            });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain('No Cloud knowledge');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a plan-gate 403 when I look up then it prints the server error, exits 1, and preserves the session', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockResolvedValue({
                ok: false,
                status: 403,
                json: () =>
                    Promise.resolve({
                        error: 'Your plan does not include content intelligence lookup.',
                    }),
            });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                'Your plan does not include content intelligence lookup.'
            );
            expect(fs.existsSync(sessionPath)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given no SENTINEL_CLOUD_URL and no --api when I look up then it exits 1 with the base URL message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const result = await runLookup({ contentId: VALID_ID }, { sessionDir: dir, env: {} });
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Set SENTINEL_CLOUD_URL or pass --api <url>.');
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given --json on a usable hit when I look up then it emits the validated result as JSON', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(hitBody()),
            });
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com', json: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const parsed = JSON.parse(outputText(result));
            expect(parsed.found).toBe(true);
            expect(parsed.usable).toBe(true);
            expect(parsed.verdict).toBe('KNOWN_SAFE');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given --json on a network error when I look up then it emits {"error": ...} and exits 0', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fetchMock.mockRejectedValue(new Error('fetch failed'));
            const result = await runLookup(
                { contentId: VALID_ID, api: 'https://cloud.example.com', json: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const parsed = JSON.parse(outputText(result));
            expect(parsed.error).toContain('Cloud intelligence unavailable');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});
