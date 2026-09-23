import * as fs from 'fs';
import {
    loadSession,
    clearSession,
    getResolvedBaseUrl,
    fetchMatch,
    fetchContribute,
} from './cloud_client';
import type {
    MatchPayload,
    MatchResult,
    Session,
    ContributeEvidence,
    ContributePayload,
} from './cloud_client';
import { findingsToSignals } from './contribute_signals';
import { resolveManifestPath } from './remote-scan';
import {
    analyzeManifest,
    extractIdentity,
    computeContentId,
    toAlert,
    capAlerts,
    deriveState,
    deriveRisk,
    computeManifestHash,
} from './contribute';
import type { LiteFinding } from '../../core/lite/lite_scanner';

export interface MatchCommandOptions {
    targetPath: string;
    json?: boolean;
    format?: string;
    api?: string;
    timeoutMs?: number;
    maxAgeMs?: number;
    contribute?: boolean;
}

export interface MatchRunContext {
    sessionDir?: string;
    env?: NodeJS.ProcessEnv;
}

export interface MatchOutputLine {
    stream: 'stdout' | 'stderr';
    text: string;
}

export interface MatchRunResult {
    exitCode: number;
    lines: MatchOutputLine[];
}

const MAX_MANIFEST_BYTES = 262144;
const SUPPORTED_FORMATS: ReadonlyArray<string> = ['npm'];
const DEFAULT_FORMAT = 'npm';
const SCANNER_VERSION = 'sentinel-cli-4.0.0';

/**
 * Builds the N3.3 match request payload from a manifest and the CURRENT scan's
 * findings. `signals` are the current-scan signals (closed taxonomy); the Cloud
 * decides novelty via `newBehaviorSignals`, never the CLI.
 */
export function buildMatchPayload(
    manifest: string,
    findings: LiteFinding[],
    opts?: { scannerVersion?: string; maxAgeMs?: number }
): MatchPayload {
    const payload: MatchPayload = {
        contentId: computeContentId(Buffer.from(manifest, 'utf8')),
        scannerVersion: opts?.scannerVersion ?? SCANNER_VERSION,
    };
    if (opts?.maxAgeMs !== undefined && Number.isFinite(opts.maxAgeMs) && opts.maxAgeMs > 0) {
        payload.maxAgeMs = opts.maxAgeMs;
    }
    const signals = findingsToSignals(findings);
    if (signals.length > 0) payload.signals = signals;
    const identity = extractIdentity(manifest);
    if (identity) payload.identity = identity;
    return payload;
}

function localEvidenceLines(findings: LiteFinding[]): string[] {
    const lines: string[] = ['Local evidence:'];
    for (const f of findings) {
        lines.push(`  ${f.file}:${f.line ?? 1} — [${f.severity}] ${f.type}`);
    }
    return lines;
}

/**
 * Renders the match result as contextual intelligence per the N3.3C rules:
 *  - MALICIOUS is ADDITIONAL evidence (with local evidence location), never magic.
 *  - CORROBORATED is context, never an automatic block; new behavior is surfaced.
 *  - OBSERVED is soft ("previously observed", corroboration insufficient).
 *  - NO_MATCH prints NOTHING — it never implies SAFE.
 *  - REVOKED canonical content is flagged as untrusted.
 */
export function renderMatchContext(data: MatchResult, localFindings: LiteFinding[] = []): string[] {
    const lines: string[] = [];
    if (data.revoked) {
        lines.push('Content revoked (depublished) — treat as untrusted.');
        lines.push('');
    }

    if (data.state === 'NO_MATCH' && !data.revoked) {
        return [];
    }

    const signals = data.match.knownSignals.length > 0 ? data.match.knownSignals.join(', ') : 'none';
    const contributors =
        data.match.sharedEvidence?.distinctContributors ??
        data.identityLevel?.distinctContributors ??
        0;

    if (data.state === 'MALICIOUS') {
        lines.push('Known malicious dependency');
        lines.push('');
        const pkg = data.identityLevel?.packageIdentity ?? `${data.contentId.slice(0, 24)}…`;
        lines.push(`Package: ${pkg}`);
        if (data.identityLevel && !data.identityLevel.hasCurrentArtifact) {
            lines.push(
                'Local artifact: NOT SEEN — shared intelligence covers other artifacts of this identity.'
            );
            lines.push('Verify the current artifact locally before acting.');
        } else {
            lines.push('Local artifact: MATCHED');
        }
        lines.push('Shared intelligence:');
        lines.push('  State: MALICIOUS');
        lines.push(`  Corroborated: ${contributors} contributors`);
        lines.push(`  Signals: ${signals}`);
    } else if (data.state === 'CORROBORATED') {
        lines.push('Known dependency — corroborated behavior');
        lines.push('');
        const pkg = data.identityLevel?.packageIdentity ?? `${data.contentId.slice(0, 24)}…`;
        lines.push(`Package: ${pkg}`);
        lines.push('Shared intelligence:');
        lines.push(`  State: CORROBORATED (decisive: ${data.decisiveState ?? 'unknown'})`);
        lines.push(`  Corroborated: ${contributors} contributors`);
        lines.push(`  Signals: ${signals}`);
        if (data.match.newBehaviorSignals.length > 0) {
            lines.push('');
            lines.push('Known dependency — new behavior observed');
            lines.push(`New signals: ${data.match.newBehaviorSignals.join(', ')}`);
        }
    } else {
        lines.push('Previously observed by Sentinel');
        if (data.decisiveState) {
            lines.push(`Verdict: ${data.decisiveState}`);
        }
        lines.push('');
        lines.push('Signals:');
        if (data.match.knownSignals.length === 0) {
            lines.push('  none');
        } else {
            for (const s of data.match.knownSignals) lines.push(`  - ${s}`);
        }
        lines.push('');
        lines.push('Corroboration: insufficient');
    }

    if (localFindings.length > 0) {
        lines.push('');
        lines.push(...localEvidenceLines(localFindings));
    }
    return lines;
}

export function renderLocalFindings(findings: LiteFinding[]): string[] {
    if (findings.length === 0) {
        return ['Local analysis: no findings.'];
    }
    const lines: string[] = ['Local analysis (primary source):'];
    for (const f of findings) {
        lines.push(`  [${f.severity}] ${f.type} in ${f.file}:${f.line ?? 1}`);
        if (f.evidence) lines.push(`    Evidence: ${f.evidence}`);
    }
    return lines;
}

/**
 * N3.3C contribution gate: the CLI only submits evidence that is NEW relative to
 * Cloud knowledge. When the Cloud has already matched THIS artifact as
 * MALICIOUS (`hasCurrentArtifact: true`) and the verdict is NOT revoked,
 * contributing the same artifact adds nothing — skip it. Every other case
 * (NO_MATCH, OBSERVED, CORROBORATED, MALICIOUS on a different artifact, and any
 * REVOKED state) may contribute local evidence; a revoked verdict means the
 * Cloud decision was overturned, so re-submitting is exactly the intended
 * mechanism to surface fresh local evidence.
 */
export function shouldAttemptContribution(data: MatchResult): boolean {
    return !(data.state === 'MALICIOUS' && data.identityLevel?.hasCurrentArtifact === true && !data.revoked);
}

/**
 * Best-effort contribution attempt AFTER a match. The CLI NEVER decides novelty
 * itself: it submits the local evidence and reports whatever `applyContribution`
 * decided (accepted / duplicate / downgrade-rejected / pending-corroboration /
 * rejected / error). Best-effort: never throws, never changes the exit code.
 */
export async function attemptBestEffortContribute(
    manifest: string,
    findings: LiteFinding[],
    session: Session,
    baseUrl: string,
    opts?: { timeoutMs?: number; match?: MatchResult }
): Promise<{ lines: string[] }> {
    if (opts?.match && !shouldAttemptContribution(opts.match)) {
        return {
            lines: [
                'Contribution skipped: artifact already known to Sentinel (MALICIOUS, same artifact).',
            ],
        };
    }
    const alerts = capAlerts(findings.map(toAlert));
    if (alerts.length === 0) {
        return { lines: ['Contribution skipped: no local evidence produced.'] };
    }
    const evidence: ContributeEvidence = {
        risk: deriveRisk(alerts),
        manifestHash: computeManifestHash(alerts),
        alerts,
        deltas: [],
    };
    const signals = findingsToSignals(findings);
    if (signals.length > 0) evidence.signals = signals;
    const identity = extractIdentity(manifest);
    const payload: ContributePayload = {
        manifest,
        contentId: computeContentId(Buffer.from(manifest, 'utf8')),
        state: deriveState(alerts),
        scannerVersion: SCANNER_VERSION,
        evidence,
    };
    if (identity) payload.identity = identity;

    const result = await fetchContribute(payload, session.token, baseUrl, {
        timeoutMs: opts?.timeoutMs,
    });
    if (result.ok) {
        if (result.data.applied) {
            return {
                lines: [
                    `Contribution accepted by Cloud (${result.data.contentId.slice(0, 24)}…, state ${result.data.state}).`,
                ],
            };
        }
        return {
            lines: [
                `Contribution not applied by Cloud (reason: ${result.data.reason ?? 'none'}). Current Cloud state: ${result.data.state}.`,
            ],
        };
    }
    const retry = result.retryAfterSeconds ? ` Retry in ${result.retryAfterSeconds}s.` : '';
    return { lines: [`Contribution skipped by Cloud (${result.kind}).${retry}`] };
}

export async function runMatch(
    options: MatchCommandOptions,
    ctx: MatchRunContext = {}
): Promise<MatchRunResult> {
    const lines: MatchOutputLine[] = [];
    const out = (text: string): void => {
        lines.push({ stream: 'stdout', text });
    };
    const errOut = (text: string): void => {
        lines.push({ stream: 'stderr', text });
    };
    const fail = (message: string, exitCode: number): MatchRunResult => {
        if (options.json) {
            out(JSON.stringify({ error: message }));
        } else if (exitCode !== 0) {
            errOut(message);
        } else {
            out(message);
        }
        return { exitCode, lines };
    };
    const env = ctx.env ?? process.env;

    const manifestPath = resolveManifestPath(options.targetPath);
    if (!manifestPath) {
        return fail(`No package.json found at '${options.targetPath}'.`, 1);
    }

    const manifest = fs.readFileSync(manifestPath, 'utf8');
    if (Buffer.byteLength(manifest, 'utf8') > MAX_MANIFEST_BYTES) {
        return fail('Manifest too large (max 256KB).', 1);
    }

    const format = options.format ?? DEFAULT_FORMAT;
    if (!SUPPORTED_FORMATS.includes(format)) {
        return fail(`Unsupported format '${format}'. Supported: ['npm'].`, 1);
    }

    const session = loadSession({ sessionDir: ctx.sessionDir });
    if (!session) {
        return fail("No active session. Run 'sentinel login' first.", 1);
    }

    if (session.capabilities.content_intel_lookup === false) {
        return fail('Your plan does not include content intelligence lookup.', 1);
    }

    let baseUrl: string;
    try {
        baseUrl = getResolvedBaseUrl(options.api, env);
    } catch {
        return fail('Set SENTINEL_CLOUD_URL or pass --api <url>.', 1);
    }

    const findings = analyzeManifest(manifest);
    const payload = buildMatchPayload(manifest, findings, {
        maxAgeMs: options.maxAgeMs,
    });

    const result = await fetchMatch(payload, session.token, baseUrl, {
        timeoutMs: options.timeoutMs,
    });

    if (result.ok) {
        if (options.json) {
            out(JSON.stringify(result.data, null, 2));
            return { exitCode: 0, lines };
        }
        for (const line of renderLocalFindings(findings)) out(line);
        const context = renderMatchContext(result.data, findings);
        if (context.length > 0) {
            out('');
            for (const line of context) out(line);
        }
        if (options.contribute && session.capabilities.contribute === true) {
            const attempt = await attemptBestEffortContribute(manifest, findings, session, baseUrl, {
                timeoutMs: options.timeoutMs,
                match: result.data,
            });
            out('');
            for (const line of attempt.lines) out(line);
        }
        return { exitCode: 0, lines };
    }

    switch (result.kind) {
        case 'auth': {
            clearSession({ sessionDir: ctx.sessionDir });
            return fail("Session expired. Run 'sentinel login'.", 1);
        }
        case 'forbidden':
            return fail(result.error || 'Your plan does not include content intelligence lookup.', 1);
        case 'quota': {
            const suffix = result.error ? ` (${result.error})` : '';
            const retry = result.retryAfterSeconds ? ` Retry in ${result.retryAfterSeconds}s.` : '';
            return fail(`Cloud limit reached (quota or rate).${suffix}${retry}`, 1);
        }
        case 'disabled':
            return fail('Content intelligence is disabled on the Cloud.', 1);
        case 'bad_request':
            return fail(`Match rejected: ${result.error || 'Invalid match request.'}`, 1);
        case 'network':
            for (const line of renderLocalFindings(findings)) out(line);
            return fail('Cloud intelligence unavailable — continuing with local analysis.', 0);
    }
}

/**
 * Conservative `scan` integration hook: after the local scan, annotate the
 * output with Cloud shared intelligence for the scanned package.json (if any).
 * Purely additive — never mutates findings, scoring, verdicts or exit codes.
 * Fail-open: any error (no manifest, no session, missing capability, network)
 * returns an empty annotation and the scan result is unchanged.
 */
export async function runScanMatchAnnotation(
    targetPath: string,
    localFindings: LiteFinding[],
    ctx: MatchRunContext = {}
): Promise<string[]> {
    try {
        const manifestPath = resolveManifestPath(targetPath);
        if (!manifestPath) return [];
        const session = loadSession({ sessionDir: ctx.sessionDir });
        if (!session || session.capabilities.content_intel_lookup !== true) return [];
        let baseUrl: string;
        try {
            baseUrl = getResolvedBaseUrl(undefined, ctx.env ?? process.env);
        } catch {
            return [];
        }
        const manifest = fs.readFileSync(manifestPath, 'utf8');
        if (Buffer.byteLength(manifest, 'utf8') > MAX_MANIFEST_BYTES) return [];
        const payload = buildMatchPayload(manifest, localFindings);
        const result = await fetchMatch(payload, session.token, baseUrl);
        if (!result.ok) return [];
        return renderMatchContext(result.data, localFindings);
    } catch {
        return [];
    }
}
