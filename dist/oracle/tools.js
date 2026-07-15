"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.tools = void 0;
exports.getToolDefs = getToolDefs;
exports.runTool = runTool;
const lite_scanner_1 = require("../core/lite/lite_scanner");
const supply_chain_shield_1 = require("../cli/intelligence/supply_chain_shield");
const system_auditor_1 = require("../cli/intelligence/system_auditor");
const integrity_manager_1 = require("../cli/intelligence/integrity_manager");
const memory_manager_1 = require("../cli/intelligence/memory_manager");
const classify_1 = require("../cli/classify");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const child_process_1 = require("child_process");
let _ghUser = null;
function getGhUser() {
    if (_ghUser !== null)
        return _ghUser;
    try {
        _ghUser = (0, child_process_1.execFileSync)('gh', ['api', 'user', '--jq', '.login'], {
            timeout: 10000, encoding: 'utf-8', windowsHide: true,
        }).trim();
    }
    catch (_a) {
        _ghUser = '';
    }
    return _ghUser;
}
function resolveRepo(repo) {
    if (!repo)
        return '';
    if (repo.includes('/'))
        return repo;
    const owner = getGhUser();
    if (!owner)
        return repo;
    return `${owner}/${repo}`;
}
function sanitizePath(input) {
    return input.replace(/[^a-zA-Z0-9_\-./\\:]/g, '').replace(/\.\./g, '').trim();
}
function sanitizePkg(input) {
    const match = input.match(/^@?[a-zA-Z0-9._\-\/]+(@\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?)?$/);
    return match ? match[0] : input.replace(/[^a-zA-Z0-9._\-@\/]/g, '');
}
function runGh(ghArgs) {
    var _a, _b;
    try {
        return (0, child_process_1.execFileSync)('gh', ghArgs, {
            timeout: 30000, encoding: 'utf-8',
            maxBuffer: 10 * 1024 * 1024, windowsHide: true,
        }).trim();
    }
    catch (e) {
        return ((_a = e.stdout) === null || _a === void 0 ? void 0 : _a.trim()) || ((_b = e.stderr) === null || _b === void 0 ? void 0 : _b.trim()) || e.message;
    }
}
function captureConsoleAsync(fn) {
    return __awaiter(this, void 0, void 0, function* () {
        const chunks = [];
        const origLog = console.log;
        const origErr = console.error;
        console.log = (...args) => chunks.push(args.map(a => typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)).join(' '));
        console.error = (...args) => chunks.push(args.map(a => typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)).join(' '));
        try {
            yield fn();
        }
        finally {
            console.log = origLog;
            console.error = origErr;
        }
        return chunks.join('\n');
    });
}
function walkDir(dir, results, depth = 0) {
    if (!fs.existsSync(dir) || depth > 8)
        return;
    const list = fs.readdirSync(dir);
    for (const file of list) {
        if (file.startsWith('.') || file === 'node_modules' || file === '.git')
            continue;
        const full = path.resolve(dir, file);
        if (!full.startsWith(path.resolve(dir)))
            continue;
        try {
            if (fs.lstatSync(full).isSymbolicLink())
                continue;
            const stat = fs.statSync(full);
            if (stat.isDirectory()) {
                walkDir(full, results, depth + 1);
            }
            else if (file.endsWith('.js') || file.endsWith('.ts') || file.endsWith('.mjs') || file.endsWith('.cjs') || file.endsWith('.json')) {
                results.push(full);
            }
        }
        catch (_) { }
    }
}
function scanPath(target) {
    const absTarget = path.resolve(target);
    if (!fs.existsSync(absTarget))
        return `Error: path not found: ${target}`;
    const scanner = new lite_scanner_1.LiteScanner();
    const allFindings = [];
    if (fs.statSync(absTarget).isDirectory()) {
        const files = [];
        walkDir(absTarget, files);
        for (const file of files) {
            try {
                const content = fs.readFileSync(file, 'utf8');
                const relPath = path.relative(absTarget, file);
                const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                const findings = scanner.scanPatch(relPath, patch);
                allFindings.push(...findings);
            }
            catch (_) { }
        }
    }
    else {
        try {
            const content = fs.readFileSync(absTarget, 'utf8');
            const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
            const findings = scanner.scanPatch(path.basename(absTarget), patch);
            allFindings.push(...findings);
        }
        catch (e) {
            return `Error reading file: ${e.message}`;
        }
    }
    if (allFindings.length === 0)
        return 'No threats found.';
    const groups = new Map();
    for (const f of allFindings) {
        const key = `${f.severity}`;
        if (!groups.has(key))
            groups.set(key, []);
        groups.get(key).push(f);
    }
    const lines = [];
    for (const [severity, fnds] of groups) {
        lines.push(`\n${severity} (${fnds.length}):`);
        for (const f of fnds.slice(0, 10)) {
            lines.push(`  ${f.file}:${f.line}  ${f.type}  ${f.description.substring(0, 80)}`);
        }
        if (fnds.length > 10)
            lines.push(`  ... and ${fnds.length - 10} more`);
    }
    return lines.join('\n');
}
exports.tools = [
    {
        name: 'scan',
        description: 'Scan a directory or file for security threats using LiteScanner (30 SAST rules including secrets, eval, network, env access)',
        parameters: {
            type: 'object',
            properties: {
                path: { type: 'string', description: 'File or directory path to scan (default: current dir)' },
            },
            required: [],
        },
        run: ({ path: p }) => scanPath(p || '.'),
    },
    {
        name: 'verify-pkg',
        description: 'Audit an npm package via npm pack (zero-install) — detects typosquatting, secret leaks, hardcoded credentials, and supply chain threats in the tarball',
        parameters: {
            type: 'object',
            properties: {
                package: { type: 'string', description: 'npm package name to audit (e.g. axios, lodash)' },
            },
            required: ['package'],
        },
        run: (_a) => __awaiter(void 0, [_a], void 0, function* ({ package: pkg }) {
            const safePkg = sanitizePkg(pkg || '');
            if (!safePkg)
                return 'Error: invalid package name';
            try {
                const shield = new supply_chain_shield_1.SupplyChainShield();
                const result = yield shield.analyzePackage(safePkg);
                const lines = [
                    `Package: ${result.pkg}`,
                    `Size: ${(result.sizeBytes / 1024).toFixed(1)} KB`,
                    `Files analyzed: ${result.fileCount}`,
                    `Scan time: ${result.scanTimeMs}ms`,
                    `Verdict: ${result.verdict}`,
                ];
                if (result.findings.length > 0) {
                    lines.push(`\nFindings (${result.findings.length}):`);
                    for (const f of result.findings) {
                        lines.push(`  [${f.severity}] ${f.type} in ${f.file}:${f.line}`);
                        lines.push(`    ${f.description}`);
                    }
                }
                return lines.join('\n');
            }
            catch (e) {
                return `Error: ${e.message}`;
            }
        }),
    },
    {
        name: 'doctor',
        description: 'System health check for npm dependencies in a project — scans for known vulnerabilities, capability risks, and outdated packages',
        parameters: {
            type: 'object',
            properties: {
                path: { type: 'string', description: 'Project path to scan (default: current dir)' },
                deep: { type: 'string', enum: ['--deep'], description: 'Pass --deep for full dependency tree scan' },
            },
            required: [],
        },
        run: (_a) => __awaiter(void 0, [_a], void 0, function* ({ path: p, deep }) {
            const originalCwd = process.cwd();
            if (p) {
                const safePath = path.resolve(sanitizePath(p));
                if (fs.existsSync(safePath))
                    process.chdir(safePath);
            }
            try {
                const auditor = new system_auditor_1.SystemAuditor();
                return yield captureConsoleAsync(() => auditor.runDoctor(deep === '--deep'));
            }
            finally {
                if (p)
                    process.chdir(originalCwd);
            }
        }),
    },
    {
        name: 'check-classified',
        description: 'Check staged files in a git repo against the classified documents database. Blocks commits when classified files are staged.',
        parameters: {
            type: 'object',
            properties: {
                path: { type: 'string', description: 'Git repository path (default: current dir)' },
            },
            required: [],
        },
        run: ({ path: p }) => {
            const checkPath = p ? path.resolve(sanitizePath(p)) : process.cwd();
            try {
                const exitCode = (0, classify_1.checkClassifiedHook)(checkPath);
                if (exitCode === 0)
                    return 'All staged files cleared. No classified files detected.';
                return 'Classification violations detected — commit blocked.';
            }
            catch (e) {
                return `Error: ${e.message}`;
            }
        },
    },
    {
        name: 'integrity',
        description: 'Verify Sentinel host integrity — checks code hash, PATH poisoning, vault integrity, clock anomalies, signed manifest, and persistent integrity chain',
        parameters: {
            type: 'object',
            properties: {},
            required: [],
        },
        run: () => __awaiter(void 0, void 0, void 0, function* () {
            try {
                const manager = new integrity_manager_1.IntegrityManager();
                const { level, reasons } = yield manager.checkIntegrity();
                const lines = [`Integrity Level: ${level}`];
                if (reasons.length > 0) {
                    lines.push('Issues found:');
                    for (const r of reasons)
                        lines.push(`  - ${r}`);
                }
                return lines.join('\n');
            }
            catch (e) {
                return `Integrity check error: ${e.message}`;
            }
        }),
    },
    {
        name: 'memory',
        description: 'Query the Signal Vault (local SQLite) for past scan results, findings, threat correlations, and session history',
        parameters: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'Action like --findings, --sessions, --threats' },
                query: { type: 'string', description: 'Optional search term' },
            },
            required: [],
        },
        run: ({ action }) => {
            const mem = new memory_manager_1.MemoryManager();
            const status = mem.getStatus();
            const lines = [
                `Signal Vault Status:`,
                `  Signals: ${status.signals}`,
                `  Scans: ${status.scans}`,
                `  Findings: ${status.findings}`,
                `  Repos: ${status.repos}`,
                `  Authors: ${status.authors}`,
            ];
            if (action === '--threats' || action === '--findings') {
                const analysis = mem.getThresholdAnalysis(3);
                if (analysis.length > 0) {
                    lines.push(`\nThreshold Analysis (repos with >= 3 signals):`);
                    for (const entry of analysis) {
                        lines.push(`  ${entry.repo}: ${entry.signalCount} signals, trend: ${entry.riskTrend}`);
                    }
                }
            }
            return lines.join('\n');
        },
    },
    {
        name: 'gh-audit-all',
        description: 'List ALL open pull requests across ALL your GitHub repositories. Runs gh repo list then gh pr list on each repo. Use when user asks to review/audit all PRs or all repos.',
        parameters: {
            type: 'object',
            properties: {
                limit: { type: 'string', description: 'Max repos to scan (default: 50)' },
            },
            required: [],
        },
        run: ({ limit }) => {
            var _a, _b, _c;
            const repoLimit = String(Math.min(Math.max(parseInt(limit) || 50, 1), 100));
            try {
                const reposJson = (0, child_process_1.execFileSync)('gh', ['repo', 'list', '--limit', repoLimit, '--json', 'name,owner'], {
                    timeout: 30000, encoding: 'utf-8', windowsHide: true,
                }).trim();
                const repos = JSON.parse(reposJson);
                if (!Array.isArray(repos) || repos.length === 0)
                    return 'No repositories found.';
                const results = [];
                for (const repo of repos) {
                    const fullName = `${repo.owner.login}/${repo.name}`;
                    try {
                        const prsJson = (0, child_process_1.execFileSync)('gh', ['pr', 'list', '--repo', fullName, '--state', 'open', '--json', 'number,title,headRefName,createdAt,state,author'], {
                            timeout: 15000, encoding: 'utf-8', windowsHide: true,
                        }).trim();
                        const prs = JSON.parse(prsJson);
                        if (Array.isArray(prs) && prs.length > 0) {
                            results.push(`\n## ${fullName} (${prs.length} PRs)`);
                            for (const pr of prs) {
                                const author = ((_a = pr.author) === null || _a === void 0 ? void 0 : _a.login) || 'unknown';
                                results.push(`  #${pr.number} — ${pr.title} (${pr.headRefName}) by @${author}`);
                            }
                        }
                    }
                    catch (_d) { }
                }
                if (results.length === 0)
                    return 'No open PRs found across any repository.';
                return `Found open PRs across ${repos.length} repos:\n${results.join('\n')}`;
            }
            catch (e) {
                return ((_b = e.stdout) === null || _b === void 0 ? void 0 : _b.trim()) || ((_c = e.stderr) === null || _c === void 0 ? void 0 : _c.trim()) || e.message;
            }
        },
    },
    {
        name: 'gh-pr-list',
        description: 'List open pull requests in the current GitHub repository. Returns PR number, title, author, and status.',
        parameters: {
            type: 'object',
            properties: {
                repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
                limit: { type: 'string', description: 'Max PRs to return (default: 10)' },
                state: { type: 'string', enum: ['open', 'closed', 'all'], description: 'PR state filter' },
            },
            required: [],
        },
        run: ({ repo, limit, state }) => {
            const args = ['pr', 'list'];
            const fullRepo = resolveRepo(repo || '');
            if (fullRepo)
                args.push('--repo', fullRepo);
            args.push('--limit', String(Math.min(Math.max(parseInt(limit) || 10, 1), 100)));
            args.push('--state', state === 'closed' ? 'closed' : state === 'all' ? 'all' : 'open');
            args.push('--json', 'number,title,author,headRefName,baseRefName,createdAt,state');
            return runGh(args);
        },
    },
    {
        name: 'gh-pr-view',
        description: 'View detailed information about a specific pull request: diff stats, changed files, labels, reviewers, and CI status.',
        parameters: {
            type: 'object',
            properties: {
                number: { type: 'string', description: 'PR number to view' },
                repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
            },
            required: ['number'],
        },
        run: ({ number, repo }) => {
            const prNum = parseInt(number);
            if (isNaN(prNum) || prNum < 1)
                return 'Error: invalid PR number';
            const args = ['pr', 'view', String(prNum)];
            const fullRepo = resolveRepo(repo || '');
            if (fullRepo)
                args.push('--repo', fullRepo);
            args.push('--json', 'title,body,author,state,mergeable,reviews,additions,deletions,files,labels,createdAt,closedAt,headRepository,baseRepository');
            return runGh(args);
        },
    },
    {
        name: 'gh-pr-diff',
        description: 'Get the full diff of a pull request. Returns the raw diff output which can be parsed by gh-full-audit for SAST analysis.',
        parameters: {
            type: 'object',
            properties: {
                number: { type: 'string', description: 'PR number to get diff from' },
                repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
            },
            required: ['number'],
        },
        run: ({ number, repo }) => {
            var _a, _b;
            const prNum = parseInt(number);
            if (isNaN(prNum) || prNum < 1)
                return 'Error: invalid PR number';
            const args = ['pr', 'diff', String(prNum)];
            const fullRepo = resolveRepo(repo || '');
            if (fullRepo)
                args.push('--repo', fullRepo);
            try {
                return (0, child_process_1.execFileSync)('gh', args, {
                    timeout: 30000, encoding: 'utf-8',
                    maxBuffer: 50 * 1024 * 1024, windowsHide: true,
                }).trim();
            }
            catch (e) {
                return ((_a = e.stdout) === null || _a === void 0 ? void 0 : _a.trim()) || ((_b = e.stderr) === null || _b === void 0 ? void 0 : _b.trim()) || e.message;
            }
        },
    },
    {
        name: 'gh-pr-comment',
        description: 'Post a comment on a pull request. Use to deliver security audit results directly on the PR.',
        parameters: {
            type: 'object',
            properties: {
                number: { type: 'string', description: 'PR number to comment on' },
                body: { type: 'string', description: 'Comment body text' },
                repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
            },
            required: ['number', 'body'],
        },
        run: ({ number, body, repo }) => {
            var _a, _b;
            const prNum = parseInt(number);
            if (isNaN(prNum) || prNum < 1)
                return 'Error: invalid PR number';
            if (!body)
                return 'Error: comment body is required';
            const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-gh-'));
            const tempFile = path.join(tmpDir, `comment_${prNum}.md`);
            try {
                fs.writeFileSync(tempFile, body, 'utf-8');
                const args = ['pr', 'comment', String(prNum)];
                const fullRepo = resolveRepo(repo || '');
                if (fullRepo)
                    args.push('--repo', fullRepo);
                args.push('--body-file', tempFile);
                return (0, child_process_1.execFileSync)('gh', args, {
                    timeout: 15000, encoding: 'utf-8', windowsHide: true,
                }).trim();
            }
            catch (e) {
                return ((_a = e.stdout) === null || _a === void 0 ? void 0 : _a.trim()) || ((_b = e.stderr) === null || _b === void 0 ? void 0 : _b.trim()) || e.message;
            }
            finally {
                try {
                    fs.unlinkSync(tempFile);
                }
                catch (_c) { }
                try {
                    fs.rmdirSync(tmpDir);
                }
                catch (_d) { }
            }
        },
    },
    {
        name: 'gh-repo-list',
        description: 'List GitHub repositories for the authenticated user or organization. Shows name, visibility, and description.',
        parameters: {
            type: 'object',
            properties: {
                owner: { type: 'string', description: 'User or organization name (default: authenticated user)' },
                limit: { type: 'string', description: 'Max repos to return (default: 20)' },
            },
            required: [],
        },
        run: ({ owner, limit }) => {
            const args = ['repo', 'list'];
            const safeOwner = owner ? owner.replace(/[^a-zA-Z0-9_.-]/g, '') : '';
            if (safeOwner)
                args.push('--owner', safeOwner);
            args.push('--limit', String(Math.min(Math.max(parseInt(limit) || 20, 1), 100)));
            args.push('--json', 'name,owner,visibility,description,url,isFork');
            return runGh(args);
        },
    },
    {
        name: 'machine-classify',
        description: 'Classify a file against the classified documents database. Detects if a file contains classified/sensitive content.',
        parameters: {
            type: 'object',
            properties: {
                file: { type: 'string', description: 'File path to classify' },
            },
            required: ['file'],
        },
        run: ({ file }) => {
            const safeFile = sanitizePath(file || '');
            if (!safeFile)
                return 'Error: invalid file path';
            const absFile = path.resolve(safeFile);
            if (!fs.existsSync(absFile))
                return 'Error: file not found';
            const db = (0, classify_1.readClassifiedDb)();
            for (const [repoPath, files] of Object.entries(db)) {
                const normalizedFile = path.resolve(absFile).replace(/\\/g, '/');
                const normalizedRepo = path.resolve(repoPath).replace(/\\/g, '/');
                if (normalizedFile.startsWith(normalizedRepo)) {
                    const relPath = path.relative(repoPath, absFile).replace(/\\/g, '/');
                    if (files.includes(relPath)) {
                        return `CLASSIFIED: ${relPath} is in the classified documents database.`;
                    }
                }
            }
            return 'Not classified.';
        },
    },
    {
        name: 'machine-integrity',
        description: 'Run Sentinel integrity check on the host system — verifies code hash, PATH, vault, clock, and manifest integrity.',
        parameters: {
            type: 'object',
            properties: {},
            required: [],
        },
        run: () => __awaiter(void 0, void 0, void 0, function* () {
            const manager = new integrity_manager_1.IntegrityManager();
            const { level, reasons } = yield manager.checkIntegrity();
            manager.report(level, reasons);
            const lines = [`Integrity Level: ${level}`];
            if (reasons.length > 0) {
                lines.push('Issues found:');
                for (const r of reasons)
                    lines.push(`  - ${r}`);
            }
            return lines.join('\n');
        }),
    },
    {
        name: 'machine-memory',
        description: 'Query the Signal Vault (local SQLite) for past scan results, findings, threat correlations, and session history.',
        parameters: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'Action: --findings, --sessions, --threats, or custom query' },
                query: { type: 'string', description: 'Optional search term' },
            },
            required: [],
        },
        run: ({ action }) => {
            const mem = new memory_manager_1.MemoryManager();
            const status = mem.getStatus();
            const lines = [
                `Signals: ${status.signals}`,
                `Scans: ${status.scans}`,
                `Findings: ${status.findings}`,
                `Repos: ${status.repos}`,
                `Authors: ${status.authors}`,
            ];
            if (action === '--threats') {
                const analysis = mem.getThresholdAnalysis(3);
                if (analysis.length > 0) {
                    lines.push(`\nThreshold Analysis:`);
                    for (const entry of analysis) {
                        lines.push(`  ${entry.repo}: ${entry.signalCount} signals, ${entry.riskTrend}`);
                    }
                }
            }
            return lines.join('\n');
        },
    },
    {
        name: 'gh-full-audit',
        description: 'Complete pipeline: list all repos → get open PRs → fetch diffs → scan with LiteScanner → compile findings with severity. One-shot security audit of all open PRs.',
        parameters: {
            type: 'object',
            properties: {
                limit: { type: 'string', description: 'Max repos to audit (default: 10)' },
            },
            required: [],
        },
        run: ({ limit }) => {
            var _a;
            const startTime = Date.now();
            const repoLimit = String(Math.min(Math.max(parseInt(limit) || 10, 1), 50));
            let reposJson;
            try {
                reposJson = (0, child_process_1.execFileSync)('gh', ['repo', 'list', '--limit', repoLimit, '--json', 'name,owner'], {
                    timeout: 30000, encoding: 'utf-8', windowsHide: true,
                }).trim();
            }
            catch (e) {
                return `GitHub CLI error: ${((_a = e.stderr) === null || _a === void 0 ? void 0 : _a.trim()) || e.message}`;
            }
            const repos = JSON.parse(reposJson);
            if (!Array.isArray(repos) || repos.length === 0)
                return 'No repositories found.';
            const scanner = new lite_scanner_1.LiteScanner();
            const report = [`# Full Security Audit (${repos.length} repos)`];
            let totalFindings = 0;
            let totalPRs = 0;
            for (const repo of repos) {
                const fullName = `${repo.owner.login}/${repo.name}`;
                let prsJson;
                try {
                    prsJson = (0, child_process_1.execFileSync)('gh', ['pr', 'list', '--repo', fullName, '--state', 'open', '--json', 'number,title,headRefName'], {
                        timeout: 15000, encoding: 'utf-8', windowsHide: true,
                    }).trim();
                }
                catch (_b) {
                    continue;
                }
                const prs = JSON.parse(prsJson);
                if (!Array.isArray(prs) || prs.length === 0)
                    continue;
                for (const pr of prs) {
                    totalPRs++;
                    let diff;
                    try {
                        diff = (0, child_process_1.execFileSync)('gh', ['pr', 'diff', String(pr.number), '--repo', fullName], {
                            timeout: 30000, encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024, windowsHide: true,
                        }).trim();
                    }
                    catch (_c) {
                        continue;
                    }
                    const parts = diff.split(/(?=^diff --git )/m);
                    const files = [];
                    for (const part of parts) {
                        const trimmed = part.trim();
                        if (!trimmed)
                            continue;
                        const m = trimmed.match(/^diff --git a\/\S+ b\/(.+)$/m);
                        if (m)
                            files.push({ filename: m[1].trim(), patch: trimmed });
                    }
                    if (files.length === 0) {
                        const m = diff.match(/^\+\+\+ b\/(.+)$/m);
                        if (m)
                            files.push({ filename: m[1].trim(), patch: diff });
                    }
                    const allFindings = [];
                    for (const file of files) {
                        const fnds = scanner.scanPatch(file.filename, file.patch);
                        allFindings.push(...fnds);
                    }
                    if (allFindings.length > 0) {
                        totalFindings += allFindings.length;
                        report.push(`\n## ${fullName} PR #${pr.number}: ${pr.title}`);
                        for (const f of allFindings) {
                            const snippet = (f.snippet || '').substring(0, 200);
                            report.push(`=== SENTINEL FINDING ===`);
                            report.push(`[${f.severity}] ${f.type} in ${f.file}:${f.line}`);
                            report.push(`Snippet: ${snippet.replace(/\n/g, '\\n')}`);
                            report.push(`Description: ${f.description}`);
                            report.push(`---`);
                        }
                    }
                }
            }
            const elapsed = Date.now() - startTime;
            report.push(`\n---`);
            report.push(`**Summary**: ${totalPRs} PRs audited, ${totalFindings} findings.`);
            report.push(`**Scan Time**: ${elapsed}ms`);
            return report.join('\n');
        },
    },
    {
        name: 'download-verify-pkg',
        description: 'Download an npm package to a temp directory and scan it with Sentinel. Does NOT install. Reports typosquatting, secrets, malicious patterns before any installation.',
        parameters: {
            type: 'object',
            properties: {
                package: { type: 'string', description: 'npm package name to download and analyze' },
            },
            required: ['package'],
        },
        run: (_a) => __awaiter(void 0, [_a], void 0, function* ({ package: pkg }) {
            const safePkg = sanitizePkg(pkg || '');
            if (!safePkg)
                return 'Error: invalid package name';
            try {
                const shield = new supply_chain_shield_1.SupplyChainShield();
                const result = yield shield.analyzePackage(safePkg);
                const lines = [
                    `Package: ${result.pkg}`,
                    `Tarball Size: ${(result.sizeBytes / 1024).toFixed(1)} KB`,
                    `Files Analyzed: ${result.fileCount}`,
                    `Scan Time: ${result.scanTimeMs}ms`,
                    `Memory: ${result.memoryMB} MB`,
                    `Verdict: ${result.verdict}`,
                ];
                if (result.findings.length > 0) {
                    lines.push(`\nFindings (${result.findings.length}):`);
                    for (const f of result.findings) {
                        lines.push(`  [${f.severity}] ${f.type} in ${f.file}:${f.line}`);
                        lines.push(`    ${f.description}`);
                    }
                }
                else {
                    lines.push('\nNo threats detected.');
                }
                return lines.join('\n');
            }
            catch (e) {
                return `Error: ${e.message}`;
            }
        }),
    },
    {
        name: 'install-pkg',
        description: 'Install an npm package. ONLY use after verifying with download-verify-pkg AND after the user explicitly asks to install.',
        parameters: {
            type: 'object',
            properties: {
                package: { type: 'string', description: 'npm package name to install' },
                global: { type: 'string', enum: ['--global'], description: '--global for global install' },
            },
            required: ['package'],
        },
        run: ({ package: pkg, global }) => {
            var _a, _b;
            const safePkg = sanitizePkg(pkg || '');
            if (!safePkg)
                return 'Error: invalid package name';
            try {
                const args = global === '--global' ? ['install', '--global', safePkg] : ['install', safePkg];
                return (0, child_process_1.execFileSync)('npm', args, {
                    timeout: 60000, encoding: 'utf-8',
                    maxBuffer: 10 * 1024 * 1024, windowsHide: true,
                }).trim();
            }
            catch (e) {
                return ((_a = e.stdout) === null || _a === void 0 ? void 0 : _a.trim()) || ((_b = e.stderr) === null || _b === void 0 ? void 0 : _b.trim()) || e.message;
            }
        },
    },
    {
        name: 'remove-pkg',
        description: 'Remove an installed npm package. Use when a package is found to be malicious or unwanted.',
        parameters: {
            type: 'object',
            properties: {
                package: { type: 'string', description: 'npm package name to remove' },
                global: { type: 'string', enum: ['--global'], description: '--global if globally installed' },
            },
            required: ['package'],
        },
        run: ({ package: pkg, global }) => {
            var _a, _b;
            const safePkg = sanitizePkg(pkg || '');
            if (!safePkg)
                return 'Error: invalid package name';
            try {
                const args = global === '--global' ? ['uninstall', '--global', safePkg] : ['uninstall', safePkg];
                return (0, child_process_1.execFileSync)('npm', args, {
                    timeout: 30000, encoding: 'utf-8',
                    maxBuffer: 10 * 1024 * 1024, windowsHide: true,
                }).trim();
            }
            catch (e) {
                return ((_a = e.stdout) === null || _a === void 0 ? void 0 : _a.trim()) || ((_b = e.stderr) === null || _b === void 0 ? void 0 : _b.trim()) || e.message;
            }
        },
    },
];
function getToolDefs() {
    return exports.tools.map(t => ({
        name: t.name,
        description: t.description,
        parameters: t.parameters,
    }));
}
function runTool(name, args) {
    return __awaiter(this, void 0, void 0, function* () {
        const tool = exports.tools.find(t => t.name === name);
        if (!tool)
            return `Unknown tool: ${name}`;
        return yield tool.run(args);
    });
}
