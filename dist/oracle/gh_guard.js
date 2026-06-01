"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runGuard = runGuard;
exports.formatGuardReport = formatGuardReport;
const child_process_1 = require("child_process");
function run(cmd) {
    var _a, _b;
    try {
        const out = (0, child_process_1.execSync)(cmd, { timeout: 10000, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
        return { ok: true, out: out.trim(), err: '' };
    }
    catch (e) {
        return { ok: false, out: ((_a = e.stdout) === null || _a === void 0 ? void 0 : _a.trim()) || '', err: ((_b = e.stderr) === null || _b === void 0 ? void 0 : _b.trim()) || e.message };
    }
}
function runGuard() {
    const report = {
        passed: false,
        machine: { status: '❌', detail: '' },
        gh: { status: '❌', detail: '' },
        auth: { status: '❌', detail: '' },
        remote: { status: '❌', detail: '' },
        repo: { status: '❌', detail: '' },
    };
    // 1. Machine check — OS + Node
    const osCheck = run('node -e "console.log(process.version)"');
    if (osCheck.ok) {
        report.machine = { status: '✅', detail: `Node.js ${osCheck.out} | ${process.platform} ${process.arch}` };
    }
    else {
        report.machine = { status: '❌', detail: 'Node.js not found' };
        return report;
    }
    // 2. gh CLI installed
    const ghCheck = run('gh --version');
    if (ghCheck.ok) {
        const ver = ghCheck.out.split('\n')[0] || ghCheck.out;
        report.gh = { status: '✅', detail: ver };
    }
    else {
        report.gh = { status: '❌', detail: 'gh CLI not installed. Install from https://cli.github.com/' };
        return report;
    }
    // 3. gh authenticated
    const authCheck = run('gh auth status 2>&1');
    if (authCheck.ok) {
        const userLine = authCheck.out.split('\n').find(l => l.includes('Logged in'));
        report.auth = { status: '✅', detail: userLine || 'Authenticated' };
    }
    else {
        report.auth = { status: '❌', detail: 'Not authenticated. Run: gh auth login' };
        return report;
    }
    // 4. Remote URL check (from cwd git repo)
    const remoteCheck = run('git remote get-url origin 2>&1');
    if (remoteCheck.ok) {
        const url = remoteCheck.out;
        if (url.startsWith('https://')) {
            report.remote = { status: '✅', detail: `HTTPS remote: ${url}` };
        }
        else if (url.startsWith('git@')) {
            report.remote = { status: '⚠️', detail: `SSH remote — no HTTPS verification: ${url}` };
        }
        else {
            report.remote = { status: '⚠️', detail: `Unknown protocol: ${url}` };
        }
    }
    else {
        report.remote = { status: '⚠️', detail: 'No git remote "origin" found (not in a repo?)' };
    }
    // 5. Repo access check
    const repoCheck = run('gh repo view --json name,owner 2>&1');
    if (repoCheck.ok) {
        report.repo = { status: '✅', detail: 'Repo accessible via gh' };
    }
    else {
        report.repo = { status: '⚠️', detail: 'Not in a valid GitHub repo: ' + repoCheck.err.slice(0, 100) };
    }
    report.passed = report.machine.status === '✅' && report.gh.status === '✅' && report.auth.status === '✅';
    return report;
}
function formatGuardReport(report) {
    const lines = [
        '🔐 Guarda de Conexión — Máquina ⇄ gh ⇄ GitHub',
        '',
        `  ${report.machine.status} Máquina:  ${report.machine.detail}`,
        `  ${report.gh.status}     gh CLI:  ${report.gh.detail}`,
        `  ${report.auth.status}     Auth:     ${report.auth.detail}`,
        `  ${report.remote.status}     Remote:   ${report.remote.detail}`,
        `  ${report.repo.status}     Repo:     ${report.repo.detail}`,
        '',
        report.passed
            ? '  ✅ Conexión segura — todo en orden.'
            : '  ❌ Guarda bloqueada — revisá los errores arriba.',
    ];
    return lines.join('\n');
}
