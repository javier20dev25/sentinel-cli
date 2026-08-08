import * as fs from 'fs';
import * as crypto from 'crypto';
import {
    loadSession,
    clearSession,
    getResolvedBaseUrl,
    fetchContribute,
} from './cloud_client';
import type {
    ContributeAlert,
    ContributeAlertSeverity,
    ContributePayload,
    ContributeResult,
    ContributeRisk,
    ContributeState,
} from './cloud_client';
import { resolveManifestPath } from './remote-scan';
import { LiteScanner } from '../../core/lite/lite_scanner';
import type { LiteFinding } from '../../core/lite/lite_scanner';

export interface ContributeCommandOptions {
    targetPath: string;
    json?: boolean;
    format?: string;
    api?: string;
    timeoutMs?: number;
}

export interface ContributeRunContext {
    sessionDir?: string;
    env?: NodeJS.ProcessEnv;
}

export interface ContributeOutputLine {
    stream: 'stdout' | 'stderr';
    text: string;
}

export interface ContributeRunResult {
    exitCode: number;
    lines: ContributeOutputLine[];
}

const MAX_MANIFEST_BYTES = 262144;
const MAX_ALERTS = 100;
const SUPPORTED_FORMATS: ReadonlyArray<string> = ['npm'];
const DEFAULT_FORMAT = 'npm';
const SCANNER_VERSION = 'sentinel-cli-4.0.0';
const MANIFEST_FILENAME = 'package.json';

const scanner = new LiteScanner();

function toAlertSeverity(severity: string): ContributeAlertSeverity {
    const upper = severity.toUpperCase();
    if (upper.includes('CRITICAL')) return 'CRITICAL';
    if (upper.includes('MALICIOUS') || upper.includes('HIGH')) return 'HIGH';
    if (upper.includes('SUSPICIOUS') || upper.includes('MEDIUM')) return 'MEDIUM';
    if (upper.includes('WARNING') || upper.includes('LOW')) return 'WARNING';
    if (upper.includes('INFO')) return 'INFO';
    return 'WARNING';
}

function toRiskLevel(finding: LiteFinding): number {
    if (typeof finding.riskScore === 'number' && Number.isFinite(finding.riskScore)) {
        return Math.min(10, Math.max(0, Math.round(finding.riskScore / 10)));
    }
    switch (toAlertSeverity(finding.severity)) {
        case 'CRITICAL':
            return 10;
        case 'HIGH':
            return 8;
        case 'MEDIUM':
            return 6;
        case 'WARNING':
            return 3;
        case 'INFO':
            return 1;
    }
}

export function analyzeManifest(manifest: string): LiteFinding[] {
    return scanner.scanFileContent(MANIFEST_FILENAME, manifest).findings;
}

export function toAlert(finding: LiteFinding): ContributeAlert {
    const alert: ContributeAlert = {
        type: finding.type,
        severity: toAlertSeverity(finding.severity),
        riskLevel: toRiskLevel(finding),
        message: finding.title ?? finding.description,
    };
    if (finding.evidence !== undefined && finding.evidence !== '') {
        alert.evidence = finding.evidence;
    }
    if (finding.snippet !== undefined && finding.snippet !== '') {
        alert.script = finding.snippet;
    }
    if (finding.category !== undefined) {
        alert.category = finding.category;
    }
    return alert;
}

export function deriveState(alerts: ContributeAlert[]): ContributeState {
    if (alerts.some((a) => a.severity === 'CRITICAL' || a.severity === 'HIGH')) {
        return 'MALICIOUS';
    }
    if (alerts.some((a) => a.severity === 'MEDIUM' || a.severity === 'WARNING')) {
        return 'SUSPICIOUS';
    }
    return 'KNOWN_SAFE';
}

export function deriveRisk(alerts: ContributeAlert[]): ContributeRisk {
    if (alerts.some((a) => a.severity === 'CRITICAL')) return 'critical';
    if (alerts.some((a) => a.severity === 'HIGH')) return 'high';
    if (alerts.some((a) => a.severity === 'MEDIUM' || a.severity === 'WARNING')) return 'medium';
    return 'low';
}

export function computeContentId(manifestBytes: Buffer): string {
    return 'sha512:' + crypto.createHash('sha512').update(manifestBytes).digest('hex');
}

export function computeManifestHash(alerts: ContributeAlert[]): string {
    return crypto
        .createHash('sha256')
        .update(JSON.stringify({ alerts, deltas: [] }))
        .digest('hex')
        .slice(0, 24);
}

const SEVERITY_RANK: Record<ContributeAlertSeverity, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    WARNING: 2,
    INFO: 1,
};

/**
 * Enforces the contract cap of ≤100 alerts per contribution. The most severe
 * alerts (stable, severity-ranked) are kept so the derived state/risk remain
 * consistent with the evidence actually sent.
 */
export function capAlerts(alerts: ContributeAlert[]): ContributeAlert[] {
    if (alerts.length <= MAX_ALERTS) return alerts;
    return [...alerts]
        .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
        .slice(0, MAX_ALERTS);
}

export function renderContribute(data: ContributeResult): string {
    if (data.applied === false) {
        return `Contribution not applied (reason: ${data.reason ?? 'none'}). Current Cloud state: ${data.state}.`;
    }
    const lines: string[] = [];
    lines.push('Contribution recorded');
    lines.push(`Content: ${data.contentId.slice(0, 24)}…`);
    lines.push(`State: ${data.state} (was ${data.previousState ?? 'UNKNOWN'})`);
    lines.push(
        'Verified: false (seeds shared knowledge; not served as a usable hit until Sentinel verifies)'
    );
    return lines.join('\n');
}

export async function runContribute(
    options: ContributeCommandOptions,
    ctx: ContributeRunContext = {}
): Promise<ContributeRunResult> {
    const lines: ContributeOutputLine[] = [];
    const out = (text: string): void => {
        lines.push({ stream: 'stdout', text });
    };
    const errOut = (text: string): void => {
        lines.push({ stream: 'stderr', text });
    };
    const fail = (message: string, exitCode: number): ContributeRunResult => {
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

    if (session.capabilities?.contribute !== true) {
        return fail('Your plan does not include intelligence contribution.', 1);
    }

    let baseUrl: string;
    try {
        baseUrl = getResolvedBaseUrl(options.api, env);
    } catch {
        return fail('Set SENTINEL_CLOUD_URL or pass --api <url>.', 1);
    }

    const alerts = capAlerts(analyzeManifest(manifest).map(toAlert));
    const payload: ContributePayload = {
        manifest,
        contentId: computeContentId(Buffer.from(manifest, 'utf8')),
        state: deriveState(alerts),
        scannerVersion: SCANNER_VERSION,
        evidence: {
            risk: deriveRisk(alerts),
            manifestHash: computeManifestHash(alerts),
            alerts,
            deltas: [],
        },
    };

    const result = await fetchContribute(payload, session.token, baseUrl, {
        timeoutMs: options.timeoutMs,
    });

    if (result.ok) {
        if (options.json) {
            out(JSON.stringify(result.data, null, 2));
            return { exitCode: 0, lines };
        }
        out(renderContribute(result.data));
        return { exitCode: 0, lines };
    }

    switch (result.kind) {
        case 'auth': {
            clearSession({ sessionDir: ctx.sessionDir });
            return fail("Session expired. Run 'sentinel login'.", 1);
        }
        case 'forbidden':
            return fail(result.error || 'Your plan does not include intelligence contribution.', 1);
        case 'quota': {
            const suffix = result.error ? ` (${result.error})` : '';
            const retry = result.retryAfterSeconds
                ? ` Retry in ${result.retryAfterSeconds}s.`
                : '';
            return fail(`Cloud limit reached (quota or rate).${suffix}${retry}`, 1);
        }
        case 'disabled':
            return fail('Content intelligence is disabled on the Cloud.', 1);
        case 'bad_request':
            return fail(
                `Contribution rejected: ${result.error || 'Invalid contribution payload.'}`,
                1
            );
        case 'network':
            return fail('Cloud unavailable — continuing with local analysis.', 0);
    }
}
