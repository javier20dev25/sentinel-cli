import {
    loadSession,
    clearSession,
    getResolvedBaseUrl,
    fetchLookup,
} from './cloud_client';
import type { LookupResult } from './cloud_client';

export interface LookupCommandOptions {
    contentId: string;
    json?: boolean;
    api?: string;
    timeoutMs?: number;
    maxAgeMs?: number;
    scannerVersion?: string;
}

export interface LookupRunContext {
    sessionDir?: string;
    env?: NodeJS.ProcessEnv;
}

export interface LookupOutputLine {
    stream: 'stdout' | 'stderr';
    text: string;
}

export interface LookupRunResult {
    exitCode: number;
    lines: LookupOutputLine[];
}

const SHA512_IDENTITY = /^sha512:[0-9a-f]{128}$/;
const SRI_PATTERN = /^sha(?:512|256)-[^\s]+$/;

export function isValidContentId(contentId: string): boolean {
    if (typeof contentId !== 'string' || contentId.length === 0) return false;
    if (SHA512_IDENTITY.test(contentId)) return true;
    return SRI_PATTERN.test(contentId);
}

function hitLine(data: LookupResult): string {
    let line = `Cloud intelligence hit: ${data.verdict ?? 'UNKNOWN'}`;
    if (typeof data.confidence === 'number') {
        line += ` (confidence ${Math.round(data.confidence * 100)}%)`;
    }
    const details: string[] = [];
    if (typeof data.firstSeen === 'number') {
        details.push(`first seen ${new Date(data.firstSeen).toLocaleString()}`);
    }
    if (typeof data.lastSeen === 'number') {
        details.push(`last seen ${new Date(data.lastSeen).toLocaleString()}`);
    }
    if (typeof data.seenInRepoCount === 'number') {
        details.push(`seen in ${data.seenInRepoCount} repos`);
    }
    if (typeof data.historyLength === 'number') {
        details.push(`history ${data.historyLength} snapshots`);
    }
    line += details.length > 0 ? ` — ${details.join(', ')}` : '';
    return line + '.';
}

export async function runLookup(
    options: LookupCommandOptions,
    ctx: LookupRunContext = {}
): Promise<LookupRunResult> {
    const lines: LookupOutputLine[] = [];
    const out = (text: string): void => {
        lines.push({ stream: 'stdout', text });
    };
    const errOut = (text: string): void => {
        lines.push({ stream: 'stderr', text });
    };
    const fail = (message: string, exitCode: number): LookupRunResult => {
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

    const session = loadSession({ sessionDir: ctx.sessionDir });
    if (!session) {
        return fail('Not logged in. Run "sentinel login".', 1);
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

    if (!isValidContentId(options.contentId)) {
        return fail('Malformed contentId. Use a sha512:<hex> identity or a registry SRI.', 1);
    }

    const result = await fetchLookup(options.contentId, session.token, baseUrl, {
        timeoutMs: options.timeoutMs,
        maxAgeMs: options.maxAgeMs,
        scannerVersion: options.scannerVersion,
        env,
    });

    if (result.ok) {
        if (options.json) {
            out(JSON.stringify(result.data, null, 2));
            return { exitCode: 0, lines };
        }
        if (result.data.usable === true) {
            out(hitLine(result.data));
            return { exitCode: 0, lines };
        }
        if (result.data.found === true) {
            const reason = result.data.reason ? ` (${result.data.reason})` : '';
            out(`Cloud knowledge found but not usable${reason} — using local analysis.`);
            return { exitCode: 0, lines };
        }
        out(`No Cloud knowledge for ${options.contentId}.`);
        return { exitCode: 0, lines };
    }

    switch (result.kind) {
        case 'auth': {
            clearSession({ sessionDir: ctx.sessionDir });
            return fail('Session expired or invalid token. Run "sentinel login".', 1);
        }
        case 'forbidden': {
            return fail(
                result.error || 'Your plan does not include content intelligence lookup.',
                1
            );
        }
        case 'bad_response':
            return fail('Invalid Cloud response (integrity check failed) — using local analysis.', 0);
        case 'network':
            return fail('Cloud intelligence unavailable — using local analysis.', 0);
    }
}
