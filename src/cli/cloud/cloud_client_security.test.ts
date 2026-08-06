import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    fetchCapabilities,
    loginWithToken,
    loadSession,
    saveSession,
    clearSession,
} from './cloud_client';
import type { CapabilitiesEnvelope, Session } from './cloud_client';

function buildEnvelope(overrides: Partial<CapabilitiesEnvelope> = {}): CapabilitiesEnvelope {
    return {
        user: 'octocat',
        subjectId: 'sub_123',
        plan: 'FREE',
        planLabel: 'FREE',
        expiresAt: '2027-08-05T00:00:00.000Z',
        issuedAt: '2026-08-05T00:00:00.000Z',
        capabilities: {
            content_intel_lookup: false,
            remote_scan: false,
            oracle_integration: false,
            offline_sync: false,
            sbom: false,
            ai_review: false,
        },
        limits: { apiRequestsPerMonth: 0, maxRepos: 0, retentionDays: 0 },
        ...overrides,
    };
}

function buildSession(token: string, overrides: Partial<Session> = {}): Session {
    return {
        token,
        user: 'octocat',
        subjectId: 'sub_123',
        plan: 'FREE',
        planLabel: 'FREE',
        expiresAt: '2027-08-05T00:00:00.000Z',
        capabilities: {
            content_intel_lookup: false,
            remote_scan: false,
            oracle_integration: false,
            offline_sync: false,
            sbom: false,
            ai_review: false,
        },
        limits: { apiRequestsPerMonth: 0, maxRepos: 0, retentionDays: 0 },
        fetchedAt: '2026-08-05T00:00:00.000Z',
        ...overrides,
    };
}

function makeTempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-cloud-sec-'));
}

function allCapsTrue(): Session['capabilities'] {
    return {
        content_intel_lookup: true,
        remote_scan: true,
        oracle_integration: true,
        offline_sync: true,
        sbom: true,
        ai_review: true,
    };
}

describe('cloud_client session file security', () => {
    it('saveSession creates the parent dir and writes 0600 perms on POSIX (no-op on Windows, no crash)', () => {
        const dir = makeTempDir();
        const nested = path.join(dir, 'nested', 'deeper');
        try {
            saveSession(buildSession('tok-1'), { sessionDir: nested });
            const p = path.join(nested, 'auth.json');
            expect(fs.existsSync(p)).toBe(true);
            const stat = fs.statSync(p);
            if (process.platform !== 'win32') {
                expect(stat.mode & 0o777).toBe(0o600);
            }
            const saved = JSON.parse(fs.readFileSync(p, 'utf8')) as Session;
            expect(saved.token).toBe('tok-1');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('tampered all-true capabilities session is surfaced as-is (display-only, never used to gate)', () => {
        const dir = makeTempDir();
        try {
            const tampered = buildSession('tok-1', {
                plan: 'FREE',
                capabilities: allCapsTrue(),
            });
            fs.writeFileSync(path.join(dir, 'auth.json'), JSON.stringify(tampered), 'utf8');
            const loaded = loadSession({ sessionDir: dir });
            expect(loaded).not.toBeNull();
            expect(loaded!.capabilities).toEqual(allCapsTrue());
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('cloud_client source has no console/log statements and no capability-based gating', () => {
        const src = fs.readFileSync(path.join(__dirname, 'cloud_client.ts'), 'utf8');
        expect(src).not.toMatch(/console\.(log|error|warn|info|debug)\s*\(/);
        // loadSession/validate must not branch on capability values.
        expect(src).not.toMatch(/if\s*\(\s*[^)]*\.capabilities/);
    });
});

describe('cloud_client network-failure behavior (security)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('login with unreachable host creates NO session file when none existed', async () => {
        const dir = makeTempDir();
        try {
            fetchMock.mockRejectedValue(new Error('fetch failed: ECONNREFUSED'));
            const result = await loginWithToken('tok-1', 'https://cloud.example.com', { sessionDir: dir });
            expect(result.ok).toBe(false);
            if (!result.ok) expect(result.status).toBeUndefined();
            expect(fs.existsSync(path.join(dir, 'auth.json'))).toBe(false);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('login with 500 response creates NO session file', async () => {
        const dir = makeTempDir();
        try {
            fetchMock.mockResolvedValue({ ok: false, status: 500, json: () => Promise.resolve({ error: 'boom' }) });
            const result = await loginWithToken('tok-1', 'https://cloud.example.com', { sessionDir: dir });
            expect(result.ok).toBe(false);
            expect(fs.existsSync(path.join(dir, 'auth.json'))).toBe(false);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('login with unreachable host preserves an existing session untouched', async () => {
        const dir = makeTempDir();
        try {
            const p = path.join(dir, 'auth.json');
            fs.writeFileSync(p, JSON.stringify(buildSession('old-token')), 'utf8');
            fetchMock.mockRejectedValue(new Error('fetch failed'));
            const result = await loginWithToken('new-token', 'https://cloud.example.com', { sessionDir: dir });
            expect(result.ok).toBe(false);
            const saved = JSON.parse(fs.readFileSync(p, 'utf8')) as Session;
            expect(saved.token).toBe('old-token');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('garbage token -> 401: fetch reports it and login clears the stale session', async () => {
        const dir = makeTempDir();
        try {
            const p = path.join(dir, 'auth.json');
            fs.writeFileSync(p, JSON.stringify(buildSession('stale-token')), 'utf8');
            fetchMock.mockResolvedValue({ ok: false, status: 401, json: () => Promise.resolve({ error: 'Invalid or expired API token.' }) });

            const fetched = await fetchCapabilities('garbage-not-a-sntl-token', 'https://cloud.example.com');
            expect(fetched.ok).toBe(false);
            if (!fetched.ok) expect(fetched.status).toBe(401);

            const login = await loginWithToken('garbage-not-a-sntl-token', 'https://cloud.example.com', { sessionDir: dir });
            expect(login.ok).toBe(false);
            expect(fs.existsSync(p)).toBe(false);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('token leakage guards (static source scan)', () => {
    const raw = fs.readFileSync(path.join(__dirname, '..', 'main.ts'), 'utf8');
    const mainSrc = raw.replace(/\r\n/g, '\n');

    const cloudStart = mainSrc.indexOf('Sentinel Cloud: Login & Capabilities');
    const cloudEnd = mainSrc.indexOf('AI Workflows Help Section');
    expect(cloudStart).toBeGreaterThan(0);
    expect(cloudEnd).toBeGreaterThan(cloudStart);

    const printStart = mainSrc.indexOf('function printSession');
    const loginStart = mainSrc.indexOf("program\n    .command('login')");
    expect(printStart).toBeGreaterThan(0);
    expect(loginStart).toBeGreaterThan(printStart);

    it('printSession JSON output never includes the raw token', () => {
        const jsonBlock = mainSrc.slice(printStart, loginStart);
        expect(jsonBlock).not.toMatch(/token/);
    });

    it('no console call in the login/whoami/logout region prints the session token', () => {
        const region = mainSrc.slice(cloudStart, cloudEnd);
        const consoleLines = region.split('\n').filter((l) => /console\.(log|error|warn|info)\s*\(/.test(l));
        expect(consoleLines.length).toBeGreaterThan(0);
        for (const line of consoleLines) {
            expect(line).not.toMatch(/session\.token/);
            expect(line).not.toMatch(/\$\{token\}/);
            expect(line).not.toMatch(/\btoken\b\s*[,)]/);
        }
    });
});
