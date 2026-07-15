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
exports.runMcpTool = runMcpTool;
const child_process_1 = require("child_process");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const lite_scanner_1 = require("../core/lite/lite_scanner");
const supply_chain_shield_1 = require("../cli/intelligence/supply_chain_shield");
const system_auditor_1 = require("../cli/intelligence/system_auditor");
const integrity_manager_1 = require("../cli/intelligence/integrity_manager");
const memory_manager_1 = require("../cli/intelligence/memory_manager");
const classify_1 = require("../cli/classify");
const threat_db_1 = require("./threat_db");
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
            const findings = scanner.scanPatch(absTarget, patch);
            allFindings.push(...findings);
        }
        catch (e) {
            return `Error reading file: ${e.message}`;
        }
    }
    if (allFindings.length === 0)
        return 'No threats detected.';
    const lines = [];
    for (const f of allFindings) {
        lines.push(`[${f.severity}] ${f.type} in ${f.file}:${f.line}`);
        lines.push(`  ${f.description}`);
    }
    return lines.join('\n');
}
function runMcpTool(name, args) {
    return __awaiter(this, void 0, void 0, function* () {
        const toolArgs = args || {};
        switch (name) {
            case 'scan': {
                const target = sanitizePath(toolArgs.path || '.');
                return scanPath(target);
            }
            case 'verify-pkg': {
                const pkg = sanitizePkg(toolArgs.package || '');
                if (!pkg)
                    return 'Error: invalid package name';
                try {
                    const shield = new supply_chain_shield_1.SupplyChainShield();
                    const result = yield shield.analyzePackage(pkg);
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
            }
            case 'doctor': {
                const originalCwd = process.cwd();
                const p = sanitizePath(toolArgs.path || '');
                if (p && fs.existsSync(path.resolve(p)))
                    process.chdir(path.resolve(p));
                try {
                    const auditor = new system_auditor_1.SystemAuditor();
                    return yield captureConsoleAsync(() => auditor.runDoctor(toolArgs.deep === '--deep'));
                }
                catch (e) {
                    return `Error: ${e.message}`;
                }
                finally {
                    if (p)
                        process.chdir(originalCwd);
                }
            }
            case 'check-classified': {
                try {
                    const db = (0, classify_1.readClassifiedDb)();
                    return JSON.stringify(db, null, 2);
                }
                catch (e) {
                    return `Error: ${e.message}`;
                }
            }
            case 'integrity': {
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
            }
            case 'memory': {
                try {
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
                    const action = toolArgs.action || '';
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
                }
                catch (e) {
                    return `Error: ${e.message}`;
                }
            }
            case 'threat-query': {
                const author = toolArgs.author || '';
                const threats = (0, threat_db_1.getThreatsByAuthor)(author);
                return JSON.stringify(threats.length > 0 ? threats : { message: 'No threats found for this author', author }, null, 2);
            }
            case 'threat-correlate': {
                const corr = (0, threat_db_1.correlateFindings)(toolArgs.author || undefined, toolArgs.findings || undefined, toolArgs.diffHash || undefined);
                return JSON.stringify(corr, null, 2);
            }
            case 'gh-pr-list': {
                const repo = toolArgs.repo || '';
                const limit = toolArgs.limit || '10';
                const state = toolArgs.state || 'open';
                const args = ['pr', 'list', '--limit', limit, '--state', state];
                if (repo)
                    args.push('--repo', repo);
                return runGh(args);
            }
            case 'gh-pr-view': {
                const number = toolArgs.number || '';
                const repo = toolArgs.repo || '';
                const args = ['pr', 'view', number, '--json', 'number,title,state,body,author,headRefName,baseRefName,createdAt,mergedAt,mergeable'];
                if (repo)
                    args.push('--repo', repo);
                return runGh(args);
            }
            case 'gh-pr-diff': {
                const number = toolArgs.number || '';
                const repo = toolArgs.repo || '';
                const args = ['pr', 'diff', number];
                if (repo)
                    args.push('--repo', repo);
                return runGh(args);
            }
            case 'gh-repo-list': {
                const owner = toolArgs.owner || '';
                const limit = toolArgs.limit || '20';
                const args = ['repo', 'list', '--limit', limit, '--json', 'nameWithOwner,description,isPrivate'];
                if (owner)
                    args.push(owner);
                return runGh(args);
            }
            default:
                return `Unknown tool: ${name}`;
        }
    });
}
