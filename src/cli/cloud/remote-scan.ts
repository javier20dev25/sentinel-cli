import * as fs from 'fs';
import * as path from 'path';
import {
    loadSession,
    clearSession,
    getResolvedBaseUrl,
    fetchRemoteScan,
} from './cloud_client';
import type { RemoteScanResult } from './cloud_client';

export interface RemoteScanCommandOptions {
    targetPath: string;
    json?: boolean;
    format?: string;
    api?: string;
    timeoutMs?: number;
}

export interface RemoteScanRunContext {
    sessionDir?: string;
    env?: NodeJS.ProcessEnv;
}

export interface RemoteScanOutputLine {
    stream: 'stdout' | 'stderr';
    text: string;
}

export interface RemoteScanRunResult {
    exitCode: number;
    lines: RemoteScanOutputLine[];
}

const MAX_MANIFEST_BYTES = 262144;
const SUPPORTED_FORMATS: ReadonlyArray<string> = ['npm'];
const DEFAULT_FORMAT = 'npm';
const EVIDENCE_MAX_LENGTH = 120;

export function resolveManifestPath(targetPath: string): string | null {
    const abs = path.resolve(targetPath);
    if (!fs.existsSync(abs)) return null;
    const stat = fs.statSync(abs);
    if (stat.isFile()) {
        return path.basename(abs).toLowerCase() === 'package.json' ? abs : null;
    }
    if (stat.isDirectory()) {
        const candidate = path.join(abs, 'package.json');
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
    }
    return null;
}

function truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.slice(0, maxLength - 1) + '…';
}

export function summaryLine(data: RemoteScanResult): string {
    if (typeof data.summary === 'string' && data.summary.length > 0) {
        return `Summary: ${data.summary}`;
    }
    const parts: string[] = [];
    const severityOrder: ReadonlyArray<'critical' | 'high' | 'medium' | 'warning'> = [
        'critical',
        'high',
        'medium',
        'warning',
    ];
    for (const sev of severityOrder) {
        const count = data.findings.filter((f) => String(f.severity).toLowerCase() === sev).length;
        if (count > 0) parts.push(`${count} ${sev}`);
    }
    if (parts.length === 0) return 'Summary: no findings.';
    return `Summary: ${parts.join(', ')}.`;
}

export function renderRemoteScan(data: RemoteScanResult): string {
    const lines: string[] = [];
    lines.push(`Remote scan (${data.engineVersion ?? 'unknown'})`);
    lines.push(`Verdict: ${data.verdict}`);
    lines.push(`Risk: ${data.risk} (score ${data.riskScore})`);
    lines.push(`Confidence: ${data.confidence}`);
    if (data.findings.length > 0) {
        lines.push('Findings:');
        for (const finding of data.findings) {
            const suffix = finding.message ?? finding.description ? ` — ${finding.message ?? finding.description}` : '';
            lines.push(`  [${finding.severity}] ${finding.title}${suffix}`);
            if (finding.evidence) {
                const firstLine = finding.evidence.split(/\r?\n/)[0];
                lines.push(`      Evidence: ${truncate(firstLine, EVIDENCE_MAX_LENGTH)}`);
            }
        }
    }
    lines.push(summaryLine(data));
    return lines.join('\n');
}

export async function runRemoteScan(
    options: RemoteScanCommandOptions,
    ctx: RemoteScanRunContext = {}
): Promise<RemoteScanRunResult> {
    const lines: RemoteScanOutputLine[] = [];
    const out = (text: string): void => {
        lines.push({ stream: 'stdout', text });
    };
    const errOut = (text: string): void => {
        lines.push({ stream: 'stderr', text });
    };
    const fail = (message: string, exitCode: number): RemoteScanRunResult => {
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

    if (session.capabilities?.remote_scan !== true) {
        return fail('Your plan does not include remote scanning.', 1);
    }

    let baseUrl: string;
    try {
        baseUrl = getResolvedBaseUrl(options.api, env);
    } catch {
        return fail('Set SENTINEL_CLOUD_URL or pass --api <url>.', 1);
    }

    const result = await fetchRemoteScan(manifest, format, session.token, baseUrl, {
        timeoutMs: options.timeoutMs,
    });

    if (result.ok) {
        if (options.json) {
            out(JSON.stringify(result.data, null, 2));
            return { exitCode: 0, lines };
        }
        out(renderRemoteScan(result.data));
        return { exitCode: 0, lines };
    }

    switch (result.kind) {
        case 'auth': {
            clearSession({ sessionDir: ctx.sessionDir });
            return fail("Session expired. Run 'sentinel login'.", 1);
        }
        case 'forbidden':
            return fail(result.error || 'Your plan does not include remote scanning.', 1);
        case 'quota': {
            const suffix = result.error ? ` (${result.error})` : '';
            return fail(`Cloud limit reached (quota or rate). Retry later.${suffix}`, 1);
        }
        case 'busy':
            return fail('Scan engine is busy. Retry shortly.', 1);
        case 'bad_request':
            return fail(result.error || 'Scan service rejected the manifest.', 1);
        case 'network':
            return fail('Cloud scan unavailable — continuing with local analysis.', 0);
    }
}
