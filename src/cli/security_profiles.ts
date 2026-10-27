import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { randomBytes } from 'crypto';
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner';

export type SecurityProfileName = 'agile' | 'strict' | 'ci';
export type SecurityToggle = 'guard' | 'precommit' | 'lockfile' | 'newPackages' | 'ignoreScripts' | 'provenance' | 'classified';
export interface SecurityProfile {
    version: 1;
    preset: SecurityProfileName | 'custom';
    toggles: Record<SecurityToggle, boolean>;
    updatedAt: string;
}

export const TOGGLE_LABELS: Record<SecurityToggle, string> = {
    guard: 'Sentinel Guard package-manager wrappers',
    precommit: 'SAST pre-commit hook',
    lockfile: 'Lockfile presence and registry URL review',
    newPackages: 'Warn about packages under 7 days old (registry age lookup not implemented)',
    ignoreScripts: 'Recommend project-local ignore-scripts (never applied automatically)',
    provenance: 'Request package provenance review (verification not implemented in this profile)',
    classified: 'Classified-data pre-commit hook',
};

const DEFAULT_TOGGLES: Record<SecurityToggle, boolean> = {
    guard: false, precommit: false, lockfile: true, newPackages: false,
    ignoreScripts: false, provenance: false, classified: false,
};

export function profilePath(home = os.homedir()): string {
    return path.join(home, '.sentinel', 'security_profile.json');
}

export function createProfile(preset: SecurityProfileName, now = new Date()): SecurityProfile {
    const toggles = { ...DEFAULT_TOGGLES };
    if (preset === 'agile') {
        toggles.precommit = true;
    } else if (preset === 'strict') {
        toggles.guard = true; toggles.precommit = true; toggles.provenance = true;
    } else {
        toggles.lockfile = true; toggles.newPackages = true; toggles.provenance = true;
    }
    return { version: 1, preset, toggles, updatedAt: now.toISOString() };
}

export function loadProfile(filePath = profilePath()): SecurityProfile {
    try {
        const value: unknown = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (!value || typeof value !== 'object') return createProfile('agile');
        const obj = value as Partial<SecurityProfile>;
        if (obj.version !== 1 || !obj.toggles || typeof obj.toggles !== 'object') return createProfile('agile');
        const toggles = { ...DEFAULT_TOGGLES };
        for (const key of Object.keys(toggles) as SecurityToggle[]) {
            if (typeof obj.toggles[key] === 'boolean') toggles[key] = obj.toggles[key];
        }
        return { version: 1, preset: obj.preset || 'custom', toggles, updatedAt: obj.updatedAt || new Date(0).toISOString() };
    } catch {
        return createProfile('agile');
    }
}

export function saveProfile(profile: SecurityProfile, filePath = profilePath()): void {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    const temporary = `${filePath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    const fd = fs.openSync(temporary, 'wx', 0o600);
    try {
        fs.writeFileSync(fd, `${JSON.stringify({ ...profile, updatedAt: new Date().toISOString() }, null, 2)}\n`);
        fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    try { fs.renameSync(temporary, filePath); }
    catch (error) { try { fs.unlinkSync(temporary); } catch { /* cleanup best effort */ } throw error; }
}

export interface StartupScript { name: string; command: string; findings: LiteFinding[]; }
export interface HardeningAudit {
    root: string; manifestFound: boolean; packageManager: string; scripts: StartupScript[];
    findings: LiteFinding[]; config: { npmrcFound: boolean; ignoreScripts: string | null; shamefullyHoist: string | null };
    lockfile: { file: string | null; format: 'pnpm' | 'npm' | 'yarn' | 'none'; customTarballs: string[]; integrityMissing: number };
    executedProjectCode: false; networkRequests: 0;
}

const STARTUP_SCRIPT_NAMES = new Set(['prestart','start','poststart','prebuild','build','postbuild','pretest','test','posttest','predev','dev','postdev','prewatch','watch','postwatch','preprepare','prepare','postprepare']);
const LIFECYCLE_NAMES = new Set(['preinstall','install','postinstall','prepare']);

function finding(scanner: LiteScanner, file: string, content: string): LiteFinding[] {
    return scanner.scanFileContent(file, content).findings.map(item => ({
        ...item,
        evidence: item.evidence ? redactSensitive(item.evidence) : undefined,
        snippet: redactSensitive(item.snippet),
        description: redactSensitive(item.description),
    }));
}

function redactSensitive(value: string): string {
    return value
        .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
        .replace(/(https?:\/\/)[^/@\s:]+:[^/@\s]+@/gi, '$1[REDACTED]@')
        .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b/g, '[REDACTED_TOKEN]')
        .replace(/\b(sk_live_|rk_live_|xox[baprs]-|SG\.)[A-Za-z0-9_./+-]{12,}/g, '$1[REDACTED]')
        .replace(/((?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*['"]?)[^\s,'";]{6,}/gi, '$1[REDACTED]');
}

function readBoundedRegularFile(filePath: string, maxBytes: number): string | null {
    try {
        const stat = fs.lstatSync(filePath);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) return null;
        return fs.readFileSync(filePath, 'utf8');
    } catch { return null; }
}

export function auditProject(rootPath = process.cwd(), scanner = new LiteScanner()): HardeningAudit {
    const root = path.resolve(rootPath);
    const manifestPath = path.join(root, 'package.json');
    let manifest: Record<string, unknown> = {};
    let manifestFound = false;
    try {
        const text = readBoundedRegularFile(manifestPath, 1024 * 1024);
        if (text === null) throw new Error('manifest unavailable, linked, or exceeds 1 MiB');
        manifest = JSON.parse(text) as Record<string, unknown>;
        manifestFound = true;
    } catch { /* absent/invalid manifest is reported below */ }

    const scriptsObj = manifest.scripts && typeof manifest.scripts === 'object' ? manifest.scripts as Record<string, unknown> : {};
    const scripts: StartupScript[] = [];
    const allFindings: LiteFinding[] = [];
    for (const [name, command] of Object.entries(scriptsObj)) {
        if (typeof command !== 'string') continue;
        const content = JSON.stringify({ scripts: { [name]: command } }, null, 2);
        const matches = finding(scanner, 'package.json', content);
        const startup = STARTUP_SCRIPT_NAMES.has(name) || LIFECYCLE_NAMES.has(name);
        if (startup || matches.length > 0) scripts.push({ name, command: redactSensitive(command), findings: matches });
        allFindings.push(...matches);
    }
    if (!manifestFound) allFindings.push(...finding(scanner, 'package.json', ''));

    const npmrcPath = path.join(root, '.npmrc');
    let npmrc = '';
    npmrc = readBoundedRegularFile(npmrcPath, 256 * 1024) || '';
    const configValue = (key: string): string | null => {
        const match = npmrc.match(new RegExp(`^\\s*${key}\\s*=\\s*([^#\\r\\n]+)`, 'im'));
        return match ? match[1].trim() : null;
    };

    let lockfile: HardeningAudit['lockfile'] = { file: null, format: 'none', customTarballs: [], integrityMissing: 0 };
    for (const candidate of ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock']) {
        const filePath = path.join(root, candidate);
        try {
            const content = readBoundedRegularFile(filePath, 20 * 1024 * 1024);
            if (content === null) continue;
            const customTarballs = [...content.matchAll(/(?:tarball|resolved):\s*['"]?(https?:\/\/[^\s'"#]+)/gi)]
                .map(match => redactSensitive(match[1])).filter(url => !/^https:\/\/(?:registry\.npmjs\.org|registry\.npmjs\.com)\//i.test(url));
            const integrityMissing = candidate === 'package-lock.json'
                ? (() => { try { const parsed = JSON.parse(content) as { packages?: Record<string, { resolved?: string; integrity?: string }> }; return Object.values(parsed.packages || {}).filter(pkg => pkg.resolved && !pkg.integrity).length; } catch { return 0; } })()
                : 0;
            lockfile = { file: candidate, format: candidate === 'pnpm-lock.yaml' ? 'pnpm' : candidate === 'yarn.lock' ? 'yarn' : 'npm', customTarballs, integrityMissing };
            break;
        } catch { /* try next supported lockfile */ }
    }

    return {
        root, manifestFound,
        packageManager: typeof manifest.packageManager === 'string' ? redactSensitive(manifest.packageManager).slice(0, 256) : 'not declared',
        scripts, findings: allFindings,
        config: { npmrcFound: fs.existsSync(npmrcPath), ignoreScripts: configValue('ignore-scripts'), shamefullyHoist: configValue('shamefully-hoist') },
        lockfile, executedProjectCode: false, networkRequests: 0,
    };
}

export function renderAudit(audit: HardeningAudit): string {
    const lines = [
        'Sentinel dependency hardening review (informational)',
        `Project: ${audit.root}`,
        `Package manager: ${audit.packageManager}`,
        `Manifest: ${audit.manifestFound ? 'valid package.json' : 'missing or invalid package.json'}`,
        `Lockfile: ${audit.lockfile.file || 'not found'}`,
        `Project code executed: no | Network requests: 0`,
        '', 'Startup and lifecycle scripts:',
    ];
    if (audit.scripts.length === 0) lines.push('  none found');
    for (const script of audit.scripts) {
        lines.push(`  ${script.name}: ${redactSensitive(script.command).slice(0, 1000)}`);
        for (const item of script.findings) lines.push(`    [${item.severity}/${item.confidence}] ${item.title || item.type}: ${item.description}`);
    }
    lines.push('', 'Configuration observations:');
    lines.push(`  .npmrc: ${audit.config.npmrcFound ? 'present' : 'not found'}`);
    lines.push(`  ignore-scripts: ${audit.config.ignoreScripts ?? 'not set (package manager default applies)'}`);
    lines.push(`  shamefully-hoist: ${audit.config.shamefullyHoist ?? 'not set'}`);
    if (audit.config.ignoreScripts !== 'true') lines.push('  Note: disabling lifecycle scripts can break native builds and does not prevent runtime scripts.');
    lines.push('  pnpm store: package hardlinks alone do not let an ordinary write mutate the shared store; verify store integrity and avoid unsafe privileged scripts.');
    lines.push(`  Lockfile URLs outside npmjs: ${audit.lockfile.customTarballs.length}`);
    for (const url of audit.lockfile.customTarballs.slice(0, 20)) lines.push(`    ${url}`);
    if (audit.lockfile.integrityMissing) lines.push(`  Resolved npm packages without integrity: ${audit.lockfile.integrityMissing}`);
    lines.push('', 'This report identifies signals for human review; it does not prove malicious behavior or modify policy.');
    return lines.join('\n');
}
