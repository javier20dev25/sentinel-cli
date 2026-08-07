import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

export const SESSION_PATH = path.join(os.homedir(), '.sentinel', 'auth.json');

export interface CapabilityMap {
    content_intel_lookup: boolean;
    remote_scan: boolean;
    oracle_integration: boolean;
    offline_sync: boolean;
    sbom: boolean;
    ai_review: boolean;
}

export interface CapabilityLimits {
    apiRequestsPerMonth: number;
    maxRepos: number;
    retentionDays: number;
}

export interface CapabilitiesEnvelope {
    user: string | null;
    subjectId: string;
    plan: string;
    planLabel: string;
    expiresAt: string;
    issuedAt: string;
    capabilities: CapabilityMap;
    limits: CapabilityLimits;
}

export interface Session {
    token: string;
    user: string | null;
    subjectId: string;
    plan: string;
    planLabel: string;
    expiresAt: string;
    capabilities: CapabilityMap;
    limits: CapabilityLimits;
    fetchedAt: string;
}

export interface CloudClientOptions {
    sessionDir?: string;
    env?: NodeJS.ProcessEnv;
}

const CAPABILITY_KEYS: ReadonlyArray<keyof CapabilityMap> = [
    'content_intel_lookup',
    'remote_scan',
    'oracle_integration',
    'offline_sync',
    'sbom',
    'ai_review',
];

const LIMIT_KEYS: ReadonlyArray<keyof CapabilityLimits> = [
    'apiRequestsPerMonth',
    'maxRepos',
    'retentionDays',
];

const DEFAULT_TIMEOUT_MS = 10000;

const LOOKUP_TIMEOUT_MS = 5000;

const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
}

function isString(value: unknown): value is string {
    return typeof value === 'string';
}

function parseCapabilitiesAndLimits(
    value: Record<string, unknown>
): { capabilities: CapabilityMap; limits: CapabilityLimits } | null {
    const capabilities = value.capabilities;
    if (!isRecord(capabilities)) return null;
    for (const key of CAPABILITY_KEYS) {
        if (typeof capabilities[key] !== 'boolean') return null;
    }
    const limits = value.limits;
    if (!isRecord(limits)) return null;
    for (const key of LIMIT_KEYS) {
        if (typeof limits[key] !== 'number') return null;
    }
    return {
        capabilities: capabilities as unknown as CapabilityMap,
        limits: limits as unknown as CapabilityLimits,
    };
}

function validateEnvelope(body: unknown): CapabilitiesEnvelope | null {
    if (!isRecord(body)) return null;
    const parsed = parseCapabilitiesAndLimits(body);
    if (!parsed) return null;
    if (
        !isString(body.subjectId) ||
        !isString(body.plan) ||
        !isString(body.planLabel) ||
        !isString(body.expiresAt) ||
        !isString(body.issuedAt)
    ) {
        return null;
    }
    if (body.user !== null && !isString(body.user)) return null;
    return {
        user: body.user as string | null,
        subjectId: body.subjectId as string,
        plan: body.plan as string,
        planLabel: body.planLabel as string,
        expiresAt: body.expiresAt as string,
        issuedAt: body.issuedAt as string,
        ...parsed,
    };
}

function validateSession(value: unknown): Session | null {
    if (!isRecord(value)) return null;
    if (!isString(value.token) || value.token.length === 0) return null;
    if (!isString(value.fetchedAt)) return null;
    const parsed = parseCapabilitiesAndLimits(value);
    if (!parsed) return null;
    if (
        !isString(value.subjectId) ||
        !isString(value.plan) ||
        !isString(value.planLabel) ||
        !isString(value.expiresAt)
    ) {
        return null;
    }
    if (value.user !== null && !isString(value.user)) return null;
    return {
        token: value.token,
        user: value.user as string | null,
        subjectId: value.subjectId as string,
        plan: value.plan as string,
        planLabel: value.planLabel as string,
        expiresAt: value.expiresAt as string,
        fetchedAt: value.fetchedAt,
        ...parsed,
    };
}

function resolveSessionPath(opts?: { sessionDir?: string }): string {
    if (opts?.sessionDir) return path.join(opts.sessionDir, 'auth.json');
    return SESSION_PATH;
}

export async function fetchCapabilities(
    token: string,
    baseUrl: string,
    opts?: { timeoutMs?: number }
): Promise<{ ok: true; data: CapabilitiesEnvelope } | { ok: false; status?: number; error: string }> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/auth/capabilities';
    const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json',
            },
            signal: controller.signal,
        });
        if (res.status === 401) {
            return { ok: false, status: 401, error: 'Invalid or expired API token.' };
        }
        if (!res.ok) {
            return { ok: false, status: res.status, error: `Request failed with status ${res.status}.` };
        }
        const body: unknown = await res.json();
        const data = validateEnvelope(body);
        if (!data) {
            return { ok: false, status: res.status, error: 'Invalid capabilities response from server.' };
        }
        return { ok: true, data };
    } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
    } finally {
        clearTimeout(timer);
    }
}

export interface LookupResult {
    found: boolean;
    usable: boolean;
    reason?: 'invalid' | 'revoked' | 'not_decisive' | 'scanner_mismatch' | 'ttl_expired';
    contentId: string;
    state?: string;
    verdict?: 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    confidence?: number;
    signature?: string;
    historyLength?: number;
    scannerVersion?: string;
    firstSeen?: number;
    lastSeen?: number;
    stateSince?: number;
    seenInRepoCount?: number;
    risk?: string;
    alertCount?: number;
    deltaCount?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    takeover?: boolean;
    verified?: boolean;
}

export type LookupFetchResult =
    | { ok: true; data: LookupResult }
    | {
          ok: false;
          kind: 'auth' | 'forbidden' | 'bad_response' | 'network';
          status?: number;
          error?: string;
      };

function validateLookupResult(value: unknown): LookupResult | null {
    if (!isRecord(value)) return null;
    if (typeof value.found !== 'boolean') return null;
    if (typeof value.usable !== 'boolean') return null;
    if (!isString(value.contentId)) return null;
    if (value.signature !== undefined && value.signature !== null) {
        if (!isString(value.signature) || !SIGNATURE_PATTERN.test(value.signature)) {
            return null;
        }
    }
    return value as unknown as LookupResult;
}

export async function fetchLookup(
    contentId: string,
    token: string,
    baseUrl: string,
    opts?: {
        timeoutMs?: number;
        maxAgeMs?: number;
        scannerVersion?: string;
        env?: NodeJS.ProcessEnv;
    }
): Promise<LookupFetchResult> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/intelligence/query';
    const timeoutMs = opts?.timeoutMs ?? LOOKUP_TIMEOUT_MS;
    const body: Record<string, unknown> = { contentId };
    if (opts?.maxAgeMs !== undefined) body.maxAgeMs = opts.maxAgeMs;
    if (opts?.scannerVersion !== undefined) body.scannerVersion = opts.scannerVersion;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify(body),
            signal: controller.signal,
        });
        if (res.status === 401) {
            return { ok: false, kind: 'auth', status: 401 };
        }
        if (res.status === 403) {
            const errBody: unknown = await res.json().catch(() => null);
            const error = isRecord(errBody) && isString(errBody.error) ? errBody.error : undefined;
            return { ok: false, kind: 'forbidden', status: 403, error };
        }
        if (!res.ok) {
            return { ok: false, kind: 'network', status: res.status };
        }
        const responseBody: unknown = await res.json();
        const data = validateLookupResult(responseBody);
        if (!data) {
            return { ok: false, kind: 'bad_response', status: res.status };
        }
        return { ok: true, data };
    } catch {
        return { ok: false, kind: 'network' };
    } finally {
        clearTimeout(timer);
    }
}

export type RemoteScanVerdict = 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
export type RemoteScanRisk = 'low' | 'medium' | 'high' | 'critical';

export interface RemoteScanFinding {
    severity: string;
    title: string;
    description?: string;
    message?: string;
    evidence?: string;
}

export interface RemoteScanResult {
    status: string;
    verdict: RemoteScanVerdict;
    risk: RemoteScanRisk;
    riskScore: number;
    confidence: number;
    findings: RemoteScanFinding[];
    engineVersion?: string;
    summary?: string;
}

export type RemoteScanFetchResult =
    | { ok: true; data: RemoteScanResult }
    | {
          ok: false;
          kind: 'auth' | 'forbidden' | 'quota' | 'busy' | 'bad_request' | 'network';
          status?: number;
          error?: string;
          retryAfterSeconds?: number;
      };

const REMOTE_SCAN_TIMEOUT_MS = 20000;

const REMOTE_SCAN_VERDICTS: ReadonlyArray<string> = [
    'KNOWN_SAFE',
    'SUSPICIOUS',
    'MALICIOUS',
    'UNKNOWN',
];

const REMOTE_SCAN_RISKS: ReadonlyArray<string> = ['low', 'medium', 'high', 'critical'];

function isFiniteNumber(value: unknown): value is number {
    return typeof value === 'number' && Number.isFinite(value);
}

async function readErrorBody(res: Response): Promise<string | undefined> {
    try {
        const body: unknown = await res.json();
        if (isRecord(body) && isString(body.error)) return body.error;
    } catch {
        // never throw
    }
    return undefined;
}

export function validateRemoteScanResult(value: unknown): RemoteScanResult | null {
    if (!isRecord(value)) return null;
    if (value.status !== 'complete') return null;
    if (!isString(value.verdict) || !REMOTE_SCAN_VERDICTS.includes(value.verdict)) return null;
    if (!isString(value.risk) || !REMOTE_SCAN_RISKS.includes(value.risk)) return null;
    if (!isFiniteNumber(value.riskScore) || value.riskScore < 0 || value.riskScore > 100) {
        return null;
    }
    if (!isFiniteNumber(value.confidence) || value.confidence < 0 || value.confidence > 1) {
        return null;
    }
    if (!Array.isArray(value.findings)) return null;
    for (const finding of value.findings) {
        if (!isRecord(finding)) return null;
        if (!isString(finding.severity) || !isString(finding.title)) return null;
    }
    return value as unknown as RemoteScanResult;
}

export async function fetchRemoteScan(
    manifest: string,
    format: string,
    token: string,
    baseUrl: string,
    opts?: { timeoutMs?: number }
): Promise<RemoteScanFetchResult> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/scan/remote';
    const timeoutMs = opts?.timeoutMs ?? REMOTE_SCAN_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify({ manifest, format }),
            signal: controller.signal,
        });
        if (res.status === 401) {
            return { ok: false, kind: 'auth', status: 401 };
        }
        if (res.status === 403) {
            return { ok: false, kind: 'forbidden', status: 403, error: await readErrorBody(res) };
        }
        if (res.status === 429) {
            const retryHeader = res.headers?.get?.('retry-after');
            const retryAfterSeconds = retryHeader ? parseInt(retryHeader, 10) : undefined;
            return {
                ok: false,
                kind: 'quota',
                status: 429,
                error: await readErrorBody(res),
                retryAfterSeconds: Number.isFinite(retryAfterSeconds)
                    ? retryAfterSeconds
                    : undefined,
            };
        }
        if (res.status === 503) {
            return { ok: false, kind: 'busy', status: 503, error: await readErrorBody(res) };
        }
        if (res.status === 400 || res.status === 413) {
            return {
                ok: false,
                kind: 'bad_request',
                status: res.status,
                error: await readErrorBody(res),
            };
        }
        if (!res.ok) {
            return { ok: false, kind: 'network', status: res.status };
        }
        const responseBody: unknown = await res.json();
        const data = validateRemoteScanResult(responseBody);
        if (!data) {
            return { ok: false, kind: 'network', status: res.status };
        }
        return { ok: true, data };
    } catch {
        return { ok: false, kind: 'network' };
    } finally {
        clearTimeout(timer);
    }
}

export function saveSession(session: Session, opts?: { sessionDir?: string }): void {
    const sessionPath = resolveSessionPath(opts);
    const dir = path.dirname(sessionPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(sessionPath, JSON.stringify(session, null, 2) + '\n', { mode: 0o600 });
}

export async function loginWithToken(
    token: string,
    baseUrl: string,
    opts?: { sessionDir?: string }
): Promise<{ ok: true; session: Session } | { ok: false; error: string }> {
    const result = await fetchCapabilities(token, baseUrl);
    if (!result.ok) {
        if (result.status === 401) {
            clearSession(opts);
            return { ok: false, error: 'Invalid or expired token. Re-run "sentinel login" with a valid token.' };
        }
        return { ok: false, error: result.error };
    }
    const session: Session = {
        token,
        user: result.data.user,
        subjectId: result.data.subjectId,
        plan: result.data.plan,
        planLabel: result.data.planLabel,
        expiresAt: result.data.expiresAt,
        capabilities: result.data.capabilities,
        limits: result.data.limits,
        fetchedAt: new Date().toISOString(),
    };
    saveSession(session, opts);
    return { ok: true, session };
}

export function loadSession(opts?: { sessionDir?: string }): Session | null {
    const sessionPath = resolveSessionPath(opts);
    let raw: string;
    try {
        raw = fs.readFileSync(sessionPath, 'utf8');
    } catch {
        return null;
    }
    try {
        return validateSession(JSON.parse(raw));
    } catch {
        return null;
    }
}

export function clearSession(opts?: { sessionDir?: string }): void {
    try {
        const sessionPath = resolveSessionPath(opts);
        if (fs.existsSync(sessionPath)) fs.unlinkSync(sessionPath);
    } catch {
        // never throw
    }
}

export function getResolvedBaseUrl(
    flagValue: string | undefined,
    env: NodeJS.ProcessEnv = process.env
): string {
    if (flagValue) return flagValue;
    const fromEnv = env.SENTINEL_CLOUD_URL;
    if (fromEnv) return fromEnv;
    throw new Error(
        'No Sentinel Cloud base URL configured. Set SENTINEL_CLOUD_URL or pass --api <url>.'
    );
}

export function resolveToken(
    flagValue: string | undefined,
    env: NodeJS.ProcessEnv = process.env
): string | null {
    if (flagValue) return flagValue;
    const fromEnv = env.SENTINEL_CLOUD_API_TOKEN;
    if (fromEnv) return fromEnv;
    return null;
}
