import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    fetchCapabilities,
    loginWithToken,
    loadSession,
    clearSession,
    getResolvedBaseUrl,
    resolveToken,
    fetchLookup,
} from './cloud_client';
import type { CapabilitiesEnvelope, Session } from './cloud_client';

function buildEnvelope(overrides: Partial<CapabilitiesEnvelope> = {}): CapabilitiesEnvelope {
    return {
        user: 'octocat',
        subjectId: 'sub_123',
        plan: 'pro',
        planLabel: 'Pro',
        expiresAt: '2027-08-05T00:00:00.000Z',
        issuedAt: '2026-08-05T00:00:00.000Z',
        capabilities: {
            content_intel_lookup: true,
            remote_scan: false,
            oracle_integration: true,
            offline_sync: false,
            sbom: true,
            ai_review: false,
        },
        limits: {
            apiRequestsPerMonth: 10000,
            maxRepos: 25,
            retentionDays: 365,
        },
        ...overrides,
    };
}

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
        limits: {
            apiRequestsPerMonth: 10000,
            maxRepos: 25,
            retentionDays: 365,
        },
        fetchedAt: '2026-08-05T00:00:00.000Z',
        ...overrides,
    };
}

function makeTempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-cloud-'));
}

describe('cloud_client fetchCapabilities', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.unstubAllEnvs();
    });

    it('parses a valid capabilities envelope and returns ok:true', async () => {
        const envelope = buildEnvelope();
        fetchMock.mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve(envelope),
        });

        const result = await fetchCapabilities('tok-123', 'https://cloud.example.com');

        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.data.subjectId).toBe('sub_123');
            expect(result.data.user).toBe('octocat');
            expect(result.data.capabilities.sbom).toBe(true);
            expect(result.data.capabilities.ai_review).toBe(false);
            expect(result.data.limits.maxRepos).toBe(25);
        }

        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toBe('https://cloud.example.com/api/auth/capabilities');
        expect((init as { headers: Record<string, string> }).headers.Authorization).toBe(
            'Bearer tok-123'
        );
    });

    it('strips trailing slashes from the base URL', async () => {
        fetchMock.mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve(buildEnvelope()),
        });

        await fetchCapabilities('tok-123', 'https://cloud.example.com///');

        const [url] = fetchMock.mock.calls[0];
        expect(url).toBe('https://cloud.example.com/api/auth/capabilities');
    });

    it('returns ok:false with status 401 for invalid tokens', async () => {
        fetchMock.mockResolvedValue({
            ok: false,
            status: 401,
            json: () => Promise.resolve({ error: 'Invalid or expired API token.' }),
        });

        const result = await fetchCapabilities('bad-token', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.status).toBe(401);
            expect(result.error).toBe('Invalid or expired API token.');
        }
    });

    it('returns ok:false without throwing on network failure', async () => {
        fetchMock.mockRejectedValue(new Error('fetch failed: ECONNREFUSED'));

        const result = await fetchCapabilities('tok-123', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.status).toBeUndefined();
            expect(result.error).toContain('ECONNREFUSED');
        }
    });

    it('returns ok:false without throwing on non-200 status', async () => {
        fetchMock.mockResolvedValue({
            ok: false,
            status: 500,
            json: () => Promise.resolve({ error: 'boom' }),
        });

        const result = await fetchCapabilities('tok-123', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.status).toBe(500);
            expect(result.error).toBeTruthy();
        }
    });

    it('rejects a 200 body with an invalid capabilities shape', async () => {
        const bad = buildEnvelope() as unknown as Record<string, unknown>;
        delete (bad.capabilities as Record<string, unknown>).sbom;
        fetchMock.mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve(bad),
        });

        const result = await fetchCapabilities('tok-123', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.status).toBe(200);
        }
    });
});

describe('cloud_client loginWithToken', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('writes an auth.json session file on success', async () => {
        const dir = makeTempDir();
        try {
            fetchMock.mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(buildEnvelope()),
            });

            const result = await loginWithToken('tok-123', 'https://cloud.example.com', {
                sessionDir: dir,
            });

            expect(result.ok).toBe(true);
            if (result.ok) {
                expect(result.session.token).toBe('tok-123');
            }

            const sessionPath = path.join(dir, 'auth.json');
            expect(fs.existsSync(sessionPath)).toBe(true);
            const saved = JSON.parse(fs.readFileSync(sessionPath, 'utf8')) as Session;
            expect(saved.token).toBe('tok-123');
            expect(saved.subjectId).toBe('sub_123');
            expect(saved.user).toBe('octocat');
            expect(saved.capabilities.sbom).toBe(true);
            expect(saved.limits.maxRepos).toBe(25);
            expect(saved.fetchedAt).toBeTruthy();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('deletes an existing session file on 401', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            fs.writeFileSync(sessionPath, JSON.stringify(buildSession('old-token')), 'utf8');

            fetchMock.mockResolvedValue({
                ok: false,
                status: 401,
                json: () => Promise.resolve({ error: 'Invalid or expired API token.' }),
            });

            const result = await loginWithToken('new-token', 'https://cloud.example.com', {
                sessionDir: dir,
            });

            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error).toContain('Re-run "sentinel login"');
            }
            expect(fs.existsSync(sessionPath)).toBe(false);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('preserves an existing session file on network error', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            fs.writeFileSync(sessionPath, JSON.stringify(buildSession('old-token')), 'utf8');

            fetchMock.mockRejectedValue(new Error('fetch failed'));

            const result = await loginWithToken('new-token', 'https://cloud.example.com', {
                sessionDir: dir,
            });

            expect(result.ok).toBe(false);
            expect(fs.existsSync(sessionPath)).toBe(true);
            const saved = JSON.parse(fs.readFileSync(sessionPath, 'utf8')) as Session;
            expect(saved.token).toBe('old-token');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('cloud_client session persistence', () => {
    it('returns null for a missing session file', () => {
        const dir = makeTempDir();
        try {
            expect(loadSession({ sessionDir: dir })).toBeNull();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('returns null for corrupt or malformed session files', () => {
        const dir = makeTempDir();
        try {
            fs.writeFileSync(path.join(dir, 'auth.json'), '{not json', 'utf8');
            expect(loadSession({ sessionDir: dir })).toBeNull();

            fs.writeFileSync(path.join(dir, 'auth.json'), JSON.stringify({ token: 123 }), 'utf8');
            expect(loadSession({ sessionDir: dir })).toBeNull();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('loads a valid session file', () => {
        const dir = makeTempDir();
        try {
            fs.writeFileSync(path.join(dir, 'auth.json'), JSON.stringify(buildSession('tok-1')), 'utf8');
            const session = loadSession({ sessionDir: dir });
            expect(session?.token).toBe('tok-1');
            expect(session?.plan).toBe('pro');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('clearSession removes an existing file and does not throw when absent', () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            clearSession({ sessionDir: dir });
            expect(fs.existsSync(sessionPath)).toBe(false);

            fs.writeFileSync(sessionPath, 'x', 'utf8');
            clearSession({ sessionDir: dir });
            expect(fs.existsSync(sessionPath)).toBe(false);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('cloud_client config resolution', () => {
    it('getResolvedBaseUrl prefers flag over env and throws when both are missing', () => {
        expect(() => getResolvedBaseUrl(undefined, {})).toThrow(/SENTINEL_CLOUD_URL|--api/);

        const env = { SENTINEL_CLOUD_URL: 'https://env.example.com' };
        expect(getResolvedBaseUrl(undefined, env)).toBe('https://env.example.com');
        expect(getResolvedBaseUrl('https://flag.example.com', env)).toBe('https://flag.example.com');
    });

    it('resolveToken prefers flag over env and returns null when both are missing', () => {
        expect(resolveToken(undefined, {})).toBeNull();

        const env = { SENTINEL_CLOUD_API_TOKEN: 'env-token' };
        expect(resolveToken(undefined, env)).toBe('env-token');
        expect(resolveToken('flag-token', env)).toBe('flag-token');
    });

    it('reads from process.env by default', () => {
        vi.stubEnv('SENTINEL_CLOUD_URL', 'https://proc.example.com');
        vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', 'proc-token');
        expect(getResolvedBaseUrl(undefined)).toBe('https://proc.example.com');
        expect(resolveToken(undefined)).toBe('proc-token');
    });
});

describe('cloud_client fetchLookup', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    const VALID_ID = `sha512:${'a'.repeat(128)}`;

    function lookupBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
        return {
            found: true,
            usable: true,
            contentId: VALID_ID,
            verdict: 'KNOWN_SAFE',
            confidence: 0.98,
            ...overrides,
        };
    }

    function mockResponse(status: number, body: unknown): void {
        fetchMock.mockResolvedValue({
            ok: status >= 200 && status < 300,
            status,
            json: () => Promise.resolve(body),
        });
    }

    it('parses a usable hit and POSTs to /api/intelligence/query', async () => {
        mockResponse(200, lookupBody({ signature: 'a'.repeat(64) }));

        const result = await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com', {
            maxAgeMs: 3600000,
            scannerVersion: '4.0.0',
        });

        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.data.found).toBe(true);
            expect(result.data.usable).toBe(true);
            expect(result.data.contentId).toBe(VALID_ID);
            expect(result.data.verdict).toBe('KNOWN_SAFE');
        }

        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toBe('https://cloud.example.com/api/intelligence/query');
        const headers = (init as { headers: Record<string, string> }).headers;
        expect(headers.Authorization).toBe('Bearer tok-1');
        expect(headers['Content-Type']).toBe('application/json');
        const sentBody = JSON.parse((init as { body: string }).body);
        expect(sentBody.contentId).toBe(VALID_ID);
        expect(sentBody.maxAgeMs).toBe(3600000);
        expect(sentBody.scannerVersion).toBe('4.0.0');
    });

    it('omits maxAgeMs and scannerVersion from the body when not provided', async () => {
        mockResponse(200, lookupBody());

        await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com');

        const init = fetchMock.mock.calls[0][1] as { body: string };
        const sentBody = JSON.parse(init.body);
        expect(sentBody.contentId).toBe(VALID_ID);
        expect('maxAgeMs' in sentBody).toBe(false);
        expect('scannerVersion' in sentBody).toBe(false);
    });

    it('maps 401 to kind auth', async () => {
        mockResponse(401, { error: 'Invalid or expired API token.' });

        const result = await fetchLookup(VALID_ID, 'bad-token', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('auth');
            expect(result.status).toBe(401);
        }
    });

    it('maps 403 to kind forbidden with the server error', async () => {
        mockResponse(403, { error: 'Your plan does not include content intelligence lookup.' });

        const result = await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('forbidden');
            expect(result.status).toBe(403);
            expect(result.error).toContain('content intelligence');
        }
    });

    it('rejects a 200 body with a malformed signature as bad_response', async () => {
        mockResponse(200, lookupBody({ signature: 'zz' }));

        const result = await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('bad_response');
    });

    it('accepts a 200 body with a valid 64-hex signature', async () => {
        mockResponse(200, lookupBody({ signature: 'b'.repeat(64) }));

        const result = await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com');

        expect(result.ok).toBe(true);
        if (result.ok) expect(result.data.signature).toBe('b'.repeat(64));
    });

    it('accepts a 200 body without a signature (older records omit it)', async () => {
        mockResponse(200, lookupBody());

        const result = await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com');

        expect(result.ok).toBe(true);
    });

    it('rejects a 200 body missing required fields as bad_response', async () => {
        mockResponse(200, { found: true });

        const result = await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('bad_response');
    });

    it('maps network failure to kind network without throwing', async () => {
        fetchMock.mockRejectedValue(new Error('fetch failed: ECONNREFUSED'));

        const result = await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('maps 503 to kind network', async () => {
        mockResponse(503, { error: 'Content-intel is disabled on this server.' });

        const result = await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com');

        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.kind).toBe('network');
    });

    it('strips trailing slashes from the base URL', async () => {
        mockResponse(200, lookupBody());

        await fetchLookup(VALID_ID, 'tok-1', 'https://cloud.example.com///');

        const [url] = fetchMock.mock.calls[0];
        expect(url).toBe('https://cloud.example.com/api/intelligence/query');
    });
});
