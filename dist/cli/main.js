#!/usr/bin/env node
"use strict";
/**
 * Sentinel CLI (v4.0)
 *
 * Security Intelligence for AI Coding Agents.
 */
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
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const crypto = __importStar(require("crypto"));
const lite_scanner_1 = require("../core/lite/lite_scanner");
const agency_score_1 = require("../core/agency_score");
const evidence_card_1 = require("../core/evidence_card");
const render_evidence_1 = require("./render_evidence");
const json_1 = require("./export/json");
const sarif_1 = require("./export/sarif");
const markdown_1 = require("./export/markdown");
const policy_1 = require("./export/policy");
const ci_comment_1 = require("./ci_comment");
const agency_graph_1 = require("../core/agency_graph");
const render_graph_1 = require("./render_graph");
const attack_scenario_1 = require("../core/attack_scenario");
const render_scenario_1 = require("./render_scenario");
const evidence_pack_1 = require("../core/evidence_pack");
const render_evidence_pack_1 = require("./render_evidence_pack");
const risk_history_1 = require("../core/risk_history");
const render_history_1 = require("./render_history");
const pr_delta_1 = require("../core/pr_delta");
const render_delta_1 = require("./render_delta");
const ownership_graph_1 = require("../core/ownership_graph");
const render_ownership_1 = require("./render_ownership");
const render_teams_1 = require("./render_teams");
const graph_persistence_1 = require("../core/graph_persistence");
const render_graph_history_1 = require("./render_graph_history");
const pdf_1 = require("./export/pdf");
const child_process_1 = require("child_process");
const guard_1 = require("./guard");
const classify_1 = require("./classify");
const memory_manager_1 = require("./intelligence/memory_manager");
const supply_chain_shield_1 = require("./intelligence/supply_chain_shield");
const system_auditor_1 = require("./intelligence/system_auditor");
const baseline_manager_1 = require("./intelligence/baseline_manager");
const capability_analyzer_1 = require("./intelligence/capability_analyzer");
const behavioral_drift_1 = require("./intelligence/behavioral_drift");
const render_drift_1 = require("./render_drift");
const integrity_manager_1 = require("./intelligence/integrity_manager");
const osv_integrator_1 = require("./intelligence/osv_integrator");
const pc = __importStar(require("picocolors"));
const hub_1 = require("./hub");
const live_1 = require("./live");
const program = new commander_1.Command();
const scanner = new lite_scanner_1.LiteScanner();
const memory = new memory_manager_1.MemoryManager();
const shield = new supply_chain_shield_1.SupplyChainShield();
const auditor = new system_auditor_1.SystemAuditor();
const baseline = new baseline_manager_1.BaselineManager();
const integrity = new integrity_manager_1.IntegrityManager();
function preFlightCheck() {
    return __awaiter(this, void 0, void 0, function* () {
        const status = yield integrity.checkIntegrity();
        if (status.level !== 'TRUSTED') {
            integrity.report(status.level, status.reasons);
        }
        return status;
    });
}
program
    .name('sentinel')
    .version('4.0.0')
    .description('Sentinel Security Intelligence — SAST, supply chain, threat intel + Skills/MCP for AI agents');
// --- Subcommands ---
program
    .command('integrity')
    .description('Check the integrity of the Sentinel CLI and its local environment.')
    .option('--uptime', 'Show integrity chain with verified uptime counter')
    .option('--watch', 'Watch uptime in real-time (updates every second)')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const status = yield integrity.checkIntegrity();
    integrity.report(status.level, status.reasons, options.uptime || options.watch);
    if (options.watch && status.level === 'TRUSTED') {
        const chain = integrity.getChain();
        console.log(pc.dim('   Watching integrity chain (Ctrl+C to stop)...\n'));
        const interval = setInterval(() => {
            const s = chain.getStatus();
            const elapsed = chain.formatDuration(s.accumulatedSeconds);
            process.stdout.write(`\r${pc.green('   🔗')} ${pc.white(elapsed)} ${pc.dim('verified uptime')}   `);
        }, 1000);
        process.on('SIGINT', () => {
            clearInterval(interval);
            process.stdout.write('\n');
            process.exit(0);
        });
    }
}));
program
    .command('benchmark')
    .description('Run corpus-based benchmark to measure FP/FN')
    .option('--corpus <path>', 'Path to corpus directory', './scripts/corpus')
    .option('--json', 'JSON output')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    yield preFlightCheck();
    const { runBenchmark, aggregateBenchmark } = yield Promise.resolve().then(() => __importStar(require('./benchmark')));
    const { renderBenchmark } = yield Promise.resolve().then(() => __importStar(require('./render_benchmark')));
    const results = runBenchmark(options.corpus);
    const aggregated = aggregateBenchmark(results);
    if (options.json) {
        console.log(JSON.stringify({ results, aggregated }, null, 2));
    }
    else {
        console.log(renderBenchmark(results, aggregated));
    }
}));
program
    .command('explain')
    .description('Explain security findings for files or directories — driver breakdown, correlations, recommendation')
    .argument('[paths...]', 'Files or directories to analyze')
    .action((paths) => __awaiter(void 0, void 0, void 0, function* () {
    yield preFlightCheck();
    const { explainFiles, renderExplain } = yield Promise.resolve().then(() => __importStar(require('./explain')));
    const targets = paths.length > 0 ? paths : ['.'];
    const { result, files } = explainFiles(targets);
    console.log(renderExplain(result, files));
}));
program
    .command('doctor')
    .description('Perform a system health check for vulnerabilities and suspicious behavior.')
    .option('--deep', 'Perform deep behavioral analysis')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    yield preFlightCheck();
    const live = new live_1.LiveIndicator();
    live.start(options.deep ? 'Deep behavioral analysis...' : 'System health check...', 'wave');
    yield auditor.runDoctor(options.deep);
    live.stop();
}));
program
    .command('drift')
    .description('Track behavioral drift of package capabilities across versions.')
    .argument('<package>', 'Package name')
    .argument('<version>', 'Package version')
    .argument('<path>', 'Path to package directory')
    .action((pkg, version, pkgPath) => {
    const resolvedPath = path.resolve(pkgPath);
    if (!fs.existsSync(resolvedPath)) {
        console.error(pc.red(`Error: Path ${pkgPath} does not exist.`));
        return;
    }
    const live = new live_1.LiveIndicator();
    live.start(`Analyzing ${pkg}@${version}...`, 'dots');
    const snapshot = (0, behavioral_drift_1.analyzeCapabilities)(pkg, version, resolvedPath);
    (0, behavioral_drift_1.saveSnapshot)(snapshot);
    const previous = (0, behavioral_drift_1.loadPreviousSnapshot)(pkg, version);
    if (previous) {
        const result = (0, behavioral_drift_1.computeDrift)(previous, snapshot);
        live.stop();
        console.log((0, render_drift_1.renderDrift)(result));
    }
    else {
        live.stop();
        console.log(pc.green(`\n✔ Baseline snapshot saved for ${pkg}@${version} (no previous version to compare).\n`));
    }
});
program
    .command('permissions')
    .description('List and audit package capabilities (Capability Governance).')
    .argument('[package]', 'Package name to audit')
    .action((pkgName) => __awaiter(void 0, void 0, void 0, function* () {
    yield preFlightCheck();
    console.log(pc.magenta('\n📋 SENTINEL CAPABILITY AUDIT'));
    if (pkgName) {
        console.log(pc.cyan(`   Analyzing real capabilities for: ${pkgName}...\n`));
        const pkgPath = path.join(process.cwd(), 'node_modules', pkgName);
        if (!fs.existsSync(pkgPath)) {
            console.error(pc.red(`Error: Package ${pkgName} not found in node_modules.`));
            return;
        }
        // Real scan of the package directory
        const allFindings = [];
        const files = walkDir(pkgPath).filter(f => f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs'));
        files.forEach(f => {
            const content = fs.readFileSync(f, 'utf8');
            const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
            const findings = scanner.scanPatch(path.relative(pkgPath, f), patch);
            allFindings.push(...findings);
        });
        if (allFindings.length === 0) {
            console.log(pc.green('   ✓ No high-risk capabilities detected.'));
        }
        else {
            const caps = capability_analyzer_1.CapabilityAnalyzer.analyze(allFindings);
            caps.forEach(c => {
                const color = c.risk === 'CRITICAL' ? pc.red : (c.risk === 'HIGH' ? pc.yellow : pc.cyan);
                console.log(`${color(`  ${c.capability.padEnd(15)}`)} [${c.risk}]`);
                console.log(pc.dim(`    Evidence: ${c.evidence.substring(0, 80)}...`));
            });
        }
    }
    else {
        console.log(pc.cyan('   Scanning local workspace node_modules for capability matrix...\n'));
        const nodeModulesPath = path.join(process.cwd(), 'node_modules');
        let depNames = [];
        let source = '';
        const pkgJsonPath = path.join(process.cwd(), 'package.json');
        if (fs.existsSync(pkgJsonPath)) {
            // Primary: enumerate from package.json
            let pkgJson;
            try {
                pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
            }
            catch (_e2) {
                console.error(pc.red('Error: Failed to parse package.json.'));
                return;
            }
            const deps = Object.assign(Object.assign({}, pkgJson.dependencies), pkgJson.devDependencies);
            depNames = Object.keys(deps).sort((a, b) => a.localeCompare(b));
            source = 'package.json';
        }
        else if (fs.existsSync(nodeModulesPath)) {
            // Fallback: scan node_modules directory directly (including scoped @org packages)
            console.log(pc.yellow('   No package.json found. Falling back to direct node_modules scan...\n'));
            const entries = fs.readdirSync(nodeModulesPath);
            entries.forEach(entry => {
                if (entry.startsWith('.'))
                    return; // skip hidden dirs (.cache, .bin, etc.)
                const entryPath = path.join(nodeModulesPath, entry);
                if (!fs.statSync(entryPath).isDirectory())
                    return;
                if (entry.startsWith('@')) {
                    // Scoped package: enumerate sub-dirs
                    const scoped = fs.readdirSync(entryPath);
                    scoped.forEach(sub => {
                        const subPath = path.join(entryPath, sub);
                        if (fs.statSync(subPath).isDirectory()) {
                            depNames.push(`${entry}/${sub}`);
                        }
                    });
                }
                else {
                    depNames.push(entry);
                }
            });
            depNames.sort((a, b) => a.localeCompare(b));
            source = 'node_modules';
        }
        else {
            console.error(pc.red('Error: No package.json or node_modules found.'));
            console.log(pc.dim('Tip: sentinel permissions <package-name> still works from anywhere.'));
            return;
        }
        if (depNames.length === 0) {
            console.log(pc.yellow('   No dependencies found.'));
            return;
        }
        console.log(pc.cyan(`   Found ${depNames.length} dependencies (via ${source}). Starting recursive audit...\n`));
        let auditedCount = 0;
        let totalCapabilitiesFound = 0;
        depNames.forEach(depName => {
            const pkgPath = path.join(process.cwd(), 'node_modules', depName);
            if (!fs.existsSync(pkgPath)) {
                return; // Skip if not installed locally
            }
            auditedCount++;
            const allFindings = [];
            const files = walkDir(pkgPath).filter(f => f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs'));
            files.forEach(f => {
                try {
                    const content = fs.readFileSync(f, 'utf8');
                    const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                    const findings = scanner.scanPatch(path.relative(pkgPath, f), patch);
                    allFindings.push(...findings);
                }
                catch (_e1) { }
            });
            if (allFindings.length > 0) {
                const caps = capability_analyzer_1.CapabilityAnalyzer.analyze(allFindings);
                if (caps.length > 0) {
                    totalCapabilitiesFound += caps.length;
                    console.log(pc.white(pc.bold(`  📦 ${depName}`)));
                    caps.forEach(c => {
                        const color = c.risk === 'CRITICAL' ? pc.red : (c.risk === 'HIGH' ? pc.yellow : pc.cyan);
                        console.log(`     ↳ ${color(c.capability.padEnd(15))} [${c.risk}]`);
                        console.log(pc.dim(`       Evidence: ${c.evidence.substring(0, 100)}`));
                    });
                    console.log('');
                }
            }
        });
        if (totalCapabilitiesFound === 0) {
            console.log(pc.green(`   ✓ All ${auditedCount} installed packages audited. No high-risk capabilities detected.`));
        }
        else {
            console.log(pc.green(`   ✓ Audited ${auditedCount} installed dependencies. Found capabilities mapped above.`));
        }
    }
    console.log(pc.dim('\nRun "sentinel policy" to apply governance rules.'));
}));
function walkDir(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    list.forEach(file => {
        const lowerFile = file.toLowerCase();
        // Ignore noise folders
        if (lowerFile === 'test' || lowerFile === 'tests' || lowerFile === 'example' ||
            lowerFile === 'examples' || lowerFile === 'benchmark' || lowerFile === 'docs' ||
            lowerFile === 'node_modules' || (file.startsWith('.') && file !== '.github' &&
            file !== '.cursorrules' && file !== '.windsurfrules' && !lowerFile.endsWith('.mdc'))) {
            return;
        }
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat && stat.isDirectory()) {
            results = results.concat(walkDir(fullPath));
        }
        else {
            results.push(fullPath);
        }
    });
    return results;
}
program
    .command('policy')
    .description('Configure Sentinel security policies (ci-mode, fail-closed, quarantine).')
    .argument('<action>', 'set | get | list')
    .argument('[key]', 'Policy key (ci-mode, fail-closed, quarantine)')
    .argument('[value]', 'Policy value (strict, lenient, on, off)')
    .action((action, key, value) => {
    const policyDir = path.join(os.homedir(), '.sentinel');
    const policyFile = path.join(policyDir, 'policy.json');
    if (!fs.existsSync(policyDir))
        fs.mkdirSync(policyDir, { recursive: true });
    let policies = {};
    try {
        policies = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
    }
    catch (_a) { }
    if (action === 'list') {
        console.log(pc.cyan('\n📋 Sentinel Policy'));
        if (Object.keys(policies).length === 0) {
            console.log(pc.dim('   No custom policies set. All defaults active.'));
        }
        else {
            for (const [k, v] of Object.entries(policies)) {
                console.log(`  ${pc.white(k.padEnd(20))} = ${pc.cyan(v)}`);
            }
        }
        console.log(pc.dim('\nAvailable: ci-mode (strict|lenient), fail-closed (on|off), quarantine (on|off)'));
    }
    else if (action === 'get') {
        const val = policies[key];
        if (val)
            console.log(`${pc.white(key)} = ${pc.cyan(val)}`);
        else
            console.log(pc.yellow(`  ${key} not set.`));
    }
    else if (action === 'set') {
        if (!key || !value) {
            console.error(pc.red('Usage: sentinel policy set <key> <value>'));
            return;
        }
        const validKeys = ['ci-mode', 'fail-closed', 'quarantine'];
        if (!validKeys.includes(key)) {
            console.error(pc.red(`Invalid policy key. Valid: ${validKeys.join(', ')}`));
            return;
        }
        const validValues = {
            'ci-mode': ['strict', 'lenient'],
            'fail-closed': ['on', 'off'],
            'quarantine': ['on', 'off']
        };
        if (validValues[key] && !validValues[key].includes(value)) {
            console.error(pc.red(`Invalid value for ${key}. Valid: ${validValues[key].join(' | ')}`));
            return;
        }
        policies[key] = value;
        fs.writeFileSync(policyFile, JSON.stringify(policies, null, 2));
        console.log(pc.green(`✔ Policy ${key} set to ${value}`));
    }
    else {
        console.error(pc.red(`Unknown action: ${action}. Use set, get, or list.`));
    }
});
program
    .command('baseline')
    .description('Manage system snapshots and detect behavior drift.')
    .argument('<action>', 'create | diff')
    .argument('[name]', 'Snapshot name', 'default')
    .action((action, name) => __awaiter(void 0, void 0, void 0, function* () {
    yield preFlightCheck();
    if (action === 'create')
        baseline.createBaseline(name);
    else if (action === 'diff')
        baseline.diffBaseline(name);
}));
program
    .command('scan')
    .description('Scan local directory, file, or staged git changes for threats.')
    .argument('[path]', 'Path to scan', '.')
    .option('--json', 'Output findings in JSON format')
    .option('--staged', 'Scan only files staged in git (git diff --cached)')
    .option('--cards', 'Show evidence cards with agency score report')
    .option('--sarif', 'Output results in SARIF 2.1.0 format')
    .option('--md', 'Output results as Markdown report')
    .option('--fail-on-score <n>', 'Exit code 1 if agency score >= threshold', parseFloat)
    .option('--fail-on-critical', 'Exit code 1 if any CRITICAL finding exists')
    .option('--fail-on-high', 'Exit code 1 if any HIGH finding exists')
    .option('--fail-on-verdict <verdict>', 'Exit code 1 if verdict >= threshold (REVIEW|BLOCK)')
    .option('--graph', 'Show attack chain graph connecting findings')
    .option('--scenarios', 'Show attack scenario narratives')
    .option('--exec-report', 'Show executive evidence report with narratives and remediation')
    .option('--save-history', 'Save scan snapshot to risk history')
    .option('--save-graph', 'Save graph snapshot after scan')
    .option('--pdf <output-path>', 'Export executive report as HTML (use browser Save as PDF)')
    .option('--diff-main', 'Compare results against latest main branch scan')
    .option('--ownership', 'Show ownership graph (findings grouped by git author)')
    .option('--teams', 'Group findings by CODEOWNERS team')
    .option('--ci-comment', 'Post results as PR comment (auto-detects CI env)')
    .action((targetPath, options) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
    const host = yield preFlightCheck();
    const live = new live_1.LiveIndicator();
    live.start(options.staged ? 'Scanning staged files...' : `Scanning ${targetPath}...`, 'bars');
    let findings = [];
    if (options.staged) {
        const { getStagedFiles } = require('./classify');
        const staged = getStagedFiles();
        if (staged.length === 0) {
            live.stop();
            console.log(pc.dim('No files staged for commit.'));
            return;
        }
        for (const file of staged) {
            try {
                const absPath = path.resolve(file);
                if (!fs.existsSync(absPath))
                    continue;
                const content = fs.readFileSync(absPath, 'utf8');
                const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                const fnds = scanner.scanPatch(file, patch);
                findings.push(...fnds);
            }
            catch (_) { }
        }
    }
    else {
        const fullPath = path.resolve(targetPath);
        if (!fs.existsSync(fullPath)) {
            console.error(pc.red(`Error: Path ${targetPath} does not exist.`));
            process.exit(1);
        }
        if (fs.lstatSync(fullPath).isFile()) {
            const content = fs.readFileSync(fullPath, 'utf8');
            const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
            findings = scanner.scanPatch(targetPath, patch);
        }
        else {
            live.update(`Scanning directory ${targetPath}...`);
            const files = walkDir(fullPath);
            for (const file of files) {
                try {
                    const content = fs.readFileSync(file, 'utf8');
                    const relPath = path.relative(fullPath, file);
                    const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                    const fnds = scanner.scanPatch(relPath, patch);
                    findings.push(...fnds);
                }
                catch (_) { }
            }
        }
    }
    live.stop();
    // Compute agency + cards once if any flag needs them
    const needsAgency = options.cards || options.sarif || options.md || options.graph || options.scenarios || options.execReport || options.saveHistory || options.diffMain || options.failOnScore !== undefined || options.failOnVerdict || options.ciComment;
    const agency = needsAgency ? (0, agency_score_1.calculateAgencyScore)(findings) : null;
    const cards = (needsAgency && agency) ? (0, evidence_card_1.buildEvidenceCards)(findings, agency) : [];
    if (options.json) {
        if (options.cards && agency) {
            console.log((0, json_1.renderEnrichedJson)(findings, agency, cards, { host: String(host.level || 'unknown'), scanTimeMs: 0, memoryMB: 0 }));
        }
        else {
            console.log(JSON.stringify({ host, findings }, null, 2));
        }
    }
    else if (options.sarif && agency) {
        console.log((0, sarif_1.renderSarif)(findings, agency, cards));
    }
    else if (options.md && agency) {
        console.log((0, markdown_1.renderMarkdown)(findings.length, agency, cards));
    }
    else {
        if (findings.length === 0) {
            console.log(pc.green('✔ No threats detected locally.'));
        }
        else if (options.cards && agency) {
            console.log((0, render_evidence_1.renderEvidenceCards)(cards, agency));
        }
        else {
            findings.forEach(f => {
                console.log(pc.yellow(`  ■ [${f.severity}] ${f.type} in ${f.file}:${f.line}`));
                console.log(pc.dim(`    Evidence: ${f.snippet}`));
            });
            console.log(pc.cyan(`\n(Heuristic pass complete. ${findings.length} threats found locally.)`));
        }
    }
    // Agency Graph (always after main output, before policy)
    if (options.graph && findings.length > 0 && agency) {
        const graph = (0, agency_graph_1.buildAgencyGraph)(findings, agency);
        console.log((0, render_graph_1.renderGraph)(graph));
    }
    // Attack Scenarios
    if (options.scenarios && findings.length > 0 && agency) {
        const graph = (0, agency_graph_1.buildAgencyGraph)(findings, agency);
        const scenarios = (0, attack_scenario_1.buildScenarios)(graph.chains, agency);
        console.log((0, render_scenario_1.renderScenarios)(scenarios));
    }
    // Executive Evidence Report
    if (options.execReport && findings.length > 0 && agency) {
        const graph = (0, agency_graph_1.buildAgencyGraph)(findings, agency);
        const scenarios = (0, attack_scenario_1.buildScenarios)(graph.chains, agency);
        const packs = (0, evidence_pack_1.buildEvidencePacks)(scenarios, graph, findings, cards, agency);
        console.log((0, render_evidence_pack_1.renderEvidencePacks)(packs));
    }
    // PDF Export (HTML for Save as PDF)
    if (options.pdf && findings.length > 0 && agency) {
        const graph = (0, agency_graph_1.buildAgencyGraph)(findings, agency);
        const scenarios = (0, attack_scenario_1.buildScenarios)(graph.chains, agency);
        const packs = (0, evidence_pack_1.buildEvidencePacks)(scenarios, graph, findings, cards, agency);
        const html = (0, pdf_1.renderPdfHtml)(packs, agency);
        const pdfPath = String(options.pdf);
        if (pdfPath) {
            fs.writeFileSync(path.resolve(pdfPath), html, 'utf8');
            console.log(pc.green(`\n✔ PDF report written to ${path.resolve(pdfPath)}`));
            console.log(pc.dim('   Open in browser and use Save as PDF / Print to generate PDF.\n'));
        }
        else {
            console.log(html);
        }
    }
    // PR Delta Analysis
    if (options.diffMain && agency) {
        const { delta, baseline } = (0, pr_delta_1.computeDeltaVsBaseline)(findings, agency, targetPath);
        if (delta && baseline) {
            console.log((0, render_delta_1.renderDelta)(delta));
        }
        else {
            console.log(pc.dim('\n  No baseline scan found. Run scan --save-history first.\n'));
        }
    }
    // Ownership Graph
    if (options.ownership && findings.length > 0) {
        const result = yield (0, ownership_graph_1.buildOwnershipGraph)(findings);
        console.log((0, render_ownership_1.renderOwnership)(result));
    }
    // Team grouping via CODEOWNERS
    if (options.teams && findings.length > 0) {
        const result = yield (0, ownership_graph_1.buildOwnershipGraph)(findings);
        const teams = (0, ownership_graph_1.groupByTeam)(result, targetPath);
        console.log((0, render_teams_1.renderTeams)(teams));
    }
    // Save history after all output
    if (options.saveHistory && agency) {
        const graph = (0, agency_graph_1.buildAgencyGraph)(findings, agency);
        const scenarios = (0, attack_scenario_1.buildScenarios)(graph.chains, agency);
        (0, risk_history_1.saveSnapshot)(targetPath, agency, scenarios);
    }
    // Save graph snapshot
    if (options.saveGraph && findings.length > 0 && agency) {
        const graph = (0, agency_graph_1.buildAgencyGraph)(findings, agency);
        const graphPath = (0, graph_persistence_1.saveGraphSnapshot)(targetPath, graph);
        if (options.pdf || options.json || options.sarif || options.md) {
            // silent
        }
        else {
            console.log(pc.dim(`\n  Graph snapshot saved.\n`));
        }
    }
    // CI Comment: post Markdown report as PR comment (before policy engine)
    if (options.ciComment && agency) {
        const ciEnv = (0, ci_comment_1.detectCiEnv)();
        if (ciEnv.isCi && ciEnv.repo && ciEnv.prNumber && ciEnv.token) {
            const md = (0, markdown_1.renderMarkdown)(findings.length, agency, cards);
            const ciResult = yield (0, ci_comment_1.postPrComment)({
                repo: ciEnv.repo,
                prNumber: ciEnv.prNumber,
                token: ciEnv.token,
                findingsCount: findings.length,
                agencyScore: agency.agencyScore,
                verdict: agency.verdict,
                markdownReport: md,
            });
            if (ciResult.posted) {
                console.log(pc.green(`\n✔ PR comment posted: ${ciResult.url}`));
            }
            else {
                console.error(pc.red(`\n✖ Failed to post PR comment: ${ciResult.error}`));
            }
        }
        else {
            console.log(pc.yellow('\n⚠  --ci-comment specified but CI environment not detected.'));
        }
    }
    // Policy engine: evaluate all fail conditions (always last)
    const failVerdict = typeof options.failOnVerdict === 'string'
        ? options.failOnVerdict.toUpperCase()
        : undefined;
    const policyResult = (0, policy_1.evaluatePolicy)(findings, {
        agencyScore: (_a = agency === null || agency === void 0 ? void 0 : agency.agencyScore) !== null && _a !== void 0 ? _a : 0,
        blastRadius: (_b = agency === null || agency === void 0 ? void 0 : agency.blastRadius) !== null && _b !== void 0 ? _b : 'LOW',
        verdict: (_c = agency === null || agency === void 0 ? void 0 : agency.verdict) !== null && _c !== void 0 ? _c : 'PASS',
        drivers: (_d = agency === null || agency === void 0 ? void 0 : agency.drivers) !== null && _d !== void 0 ? _d : [],
        totalFindings: (_e = agency === null || agency === void 0 ? void 0 : agency.totalFindings) !== null && _e !== void 0 ? _e : findings.length,
        criticalCount: (_f = agency === null || agency === void 0 ? void 0 : agency.criticalCount) !== null && _f !== void 0 ? _f : findings.filter(f => f.severity === 'CRITICAL').length,
        highCount: (_g = agency === null || agency === void 0 ? void 0 : agency.highCount) !== null && _g !== void 0 ? _g : findings.filter(f => f.severity === 'HIGH').length,
        correlations: (_h = agency === null || agency === void 0 ? void 0 : agency.correlations) !== null && _h !== void 0 ? _h : [],
        recommendation: (_j = agency === null || agency === void 0 ? void 0 : agency.recommendation) !== null && _j !== void 0 ? _j : '',
    }, {
        failOnScore: options.failOnScore,
        failOnCritical: (_k = options.failOnCritical) !== null && _k !== void 0 ? _k : false,
        failOnHigh: (_l = options.failOnHigh) !== null && _l !== void 0 ? _l : false,
        failOnVerdict: failVerdict,
    });
    if (policyResult.shouldFail) {
        console.error(pc.red(`\n✖ ${policyResult.reason}`));
        process.exit(1);
    }
    const hasCritical = findings.some(f => f.severity === 'CRITICAL');
    if (hasCritical) {
        process.exit(1);
    }
}));
program
    .command('history')
    .description('Show risk history and trend for a repository')
    .argument('[path]', 'Repository path', '.')
    .option('--days <n>', 'Show only last N days', (v) => parseInt(v, 10))
    .option('--branch <name>', 'Filter to specific branch')
    .action((repoPath, options) => __awaiter(void 0, void 0, void 0, function* () {
    const fullPath = path.resolve(repoPath);
    let snapshots;
    if (options.days) {
        snapshots = (0, risk_history_1.loadHistoryInWindow)(fullPath, options.days);
    }
    else {
        snapshots = (0, risk_history_1.loadHistory)(fullPath);
    }
    if (options.branch) {
        snapshots = snapshots.filter(s => s.branch === options.branch);
    }
    if (snapshots.length === 0) {
        const allRepos = (0, risk_history_1.loadAllHistory)();
        if (allRepos.size > 0) {
            console.log((0, render_history_1.renderSnapshotList)(allRepos));
        }
        else {
            console.log(pc.dim('\n  No history found. Run scan --save-history to start tracking.\n'));
        }
        return;
    }
    const trend = (0, risk_history_1.computeTrend)(snapshots);
    const baseline = snapshots.find(s => s.branch === 'main' || s.branch === 'master') || null;
    console.log((0, render_history_1.renderTrend)(trend, {
        windowDays: options.days || undefined,
        branch: options.branch,
        baselineScore: baseline === null || baseline === void 0 ? void 0 : baseline.agencyScore,
        baselineCritical: baseline === null || baseline === void 0 ? void 0 : baseline.criticalCount,
    }));
}));
const graphCmd = program.command('graph')
    .description('Manage agency graph snapshots for trend analysis');
graphCmd
    .command('history')
    .description('Show graph snapshot history with chain count trend')
    .argument('[path]', 'Repository path', '.')
    .action((repoPath) => __awaiter(void 0, void 0, void 0, function* () {
    const fullPath = path.resolve(repoPath);
    const snapshots = (0, graph_persistence_1.loadGraphHistory)(fullPath);
    console.log((0, render_graph_history_1.renderGraphHistory)(snapshots));
}));
graphCmd
    .command('diff')
    .description('Show diff between latest two graph snapshots')
    .argument('[path]', 'Repository path', '.')
    .action((repoPath) => __awaiter(void 0, void 0, void 0, function* () {
    const fullPath = path.resolve(repoPath);
    const snapshots = (0, graph_persistence_1.loadGraphHistory)(fullPath);
    if (snapshots.length === 0) {
        console.log(pc.dim('\n  No graph snapshots found. Run scan --save-graph to start tracking.\n'));
        return;
    }
    const sorted = [...snapshots].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const current = sorted[sorted.length - 1];
    const previous = sorted.length >= 2 ? sorted[sorted.length - 2] : null;
    console.log((0, render_graph_history_1.renderGraphDiff)(previous, current));
}));
program
    .command('verify-pkg')
    .description('Manually audit a package for supply chain threats.')
    .argument('<package>', 'Package name or name@version')
    .option('--details', 'Show detailed evidence for each finding')
    .option('--summary', 'Condensed output — counts only, no evidence')
    .action((pkg, options) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d, _e, _f;
    const live = new live_1.LiveIndicator();
    live.start(`Downloading and analyzing ${pkg}...`, 'dots');
    const result = yield shield.analyzePackage(pkg);
    live.stop();
    // Package metadata
    console.log(pc.cyan('\n📦 Package Metadata'));
    console.log(pc.white(`  Name:      ${pc.bold(result.pkg)}`));
    console.log(pc.white(`  Files:     ${pc.cyan(String(result.fileCount))}`));
    console.log(pc.white(`  Size:      ${pc.cyan((result.sizeBytes / 1024).toFixed(1) + ' KB')}`));
    console.log(pc.white(`  Scan:      ${pc.cyan(result.scanTimeMs + 'ms')}  ${pc.dim('Mem: ' + result.memoryMB + ' MB')}`));
    // Try npm metadata
    try {
        const safePkg = pkg.replace(/[^a-zA-Z0-9._\-@\/]/g, '');
        const info = JSON.parse((0, child_process_1.execFileSync)('npm', ['view', safePkg, 'description', 'author', 'homepage', '--json'], { encoding: 'utf8', timeout: 10000, windowsHide: true }));
        if (info.description)
            console.log(pc.white(`  Desc:      ${pc.dim(String(info.description).substring(0, 100))}`));
        if (((_a = info.author) === null || _a === void 0 ? void 0 : _a.name) || ((_c = (_b = info.maintainers) === null || _b === void 0 ? void 0 : _b[0]) === null || _c === void 0 ? void 0 : _c.name)) {
            const author = ((_d = info.author) === null || _d === void 0 ? void 0 : _d.name) || ((_f = (_e = info.maintainers) === null || _e === void 0 ? void 0 : _e[0]) === null || _f === void 0 ? void 0 : _f.name);
            console.log(pc.white(`  Author:    ${pc.dim(author)}`));
        }
    }
    catch (_unused) { }
    // OSV Vulnerabilities
    if (result.osvResult && result.osvResult.vulnerabilities.length > 0) {
        console.log(pc.red(`\n  ⚠️  Known Vulnerabilities (${result.osvResult.vulnerabilities.length}):`));
        for (const v of result.osvResult.vulnerabilities.slice(0, 5)) {
            const maxS = osv_integrator_1.OSVIntegrator.getMaxSeverity(v);
            const scoreStr = maxS ? ` (${maxS.type}: ${maxS.score})` : '';
            console.log(pc.dim(`     [${v.id}] ${v.summary.substring(0, 80)}${scoreStr}`));
        }
        if (result.osvResult.vulnerabilities.length > 5) {
            console.log(pc.dim(`     ... and ${result.osvResult.vulnerabilities.length - 5} more`));
        }
    }
    else {
        console.log(pc.green(`  CVEs:      None known`));
    }
    // Typosquatting
    if (result.typosquat && result.typosquat.isSuspicious) {
        console.log(pc.red(`  ⚠️  Typosquatting: Possible typo of:`));
        for (const m of result.typosquat.matches) {
            const homoglyphStr = m.homoglyphs.length > 0 ? ` (homoglyphs: ${m.homoglyphs.join(', ')})` : '';
            console.log(pc.dim(`     ${m.target} (distance: ${m.distance})${homoglyphStr}`));
        }
    }
    else {
        console.log(pc.green(`  Typosquat:  Clean`));
    }
    // Verdict
    const verdictColor = result.verdict === 'MALICIOUS' ? pc.bgRed(pc.white(' MALICIOUS ')) :
        result.verdict === 'SUSPICIOUS' ? pc.bgYellow(pc.black(' SUSPICIOUS ')) :
            pc.bgGreen(pc.black(' SAFE '));
    console.log(`\n  Verdict:   ${verdictColor}\n`);
    // Findings
    if (result.findings.length === 0) {
        console.log(pc.green('✔ No threats detected. Package appears clean.\n'));
        return;
    }
    // Group by capability type for summary
    const byType = new Map();
    const bySeverity = new Map();
    for (const f of result.findings) {
        byType.set(f.type, (byType.get(f.type) || 0) + 1);
        bySeverity.set(f.severity, (bySeverity.get(f.severity) || 0) + 1);
    }
    if (options.summary) {
        console.log(pc.bold(`🔍 ${result.findings.length} FINDING(S) — Summary:`));
        console.log('');
        const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        for (const sev of severityOrder) {
            const count = bySeverity.get(sev);
            if (!count)
                continue;
            const color = sev === 'CRITICAL' || sev === 'HIGH' ? pc.red :
                sev === 'MEDIUM' ? pc.yellow : pc.dim;
            console.log(color(`  ${sev.padEnd(10)} ${'■'.repeat(Math.min(count, 20))} ${count}`));
        }
        console.log('');
        for (const [type, count] of byType) {
            console.log(pc.dim(`  ${type.padEnd(25)} ${count} occurrence(s)`));
        }
        console.log(pc.dim(`\n  Run with --details for full evidence.`));
        return;
    }
    // Default: show HIGH+ with evidence, capability overview for LOW/MEDIUM
    const highFindings = result.findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL');
    const lowFindings = result.findings.filter(f => f.severity === 'LOW' || f.severity === 'MEDIUM');
    console.log(pc.magenta('═'.repeat(60)));
    console.log(pc.bold(`🔍 ${result.findings.length} FINDING(S)`));
    console.log(pc.magenta('═'.repeat(60) + '\n'));
    // Capability bar chart
    console.log(pc.dim('  Capability distribution:'));
    for (const [type, count] of byType) {
        const bar = '█'.repeat(Math.min(count, 20));
        const color = type.startsWith('SECRET_') || type === 'POTENTIAL_SECRET' ? pc.red :
            type === 'NETWORK_ACTIVITY' ? pc.yellow : pc.cyan;
        console.log(`   ${color(bar)} ${pc.dim(type + ' ' + count)}`);
    }
    console.log('');
    // HIGH+ findings with evidence
    if (highFindings.length > 0) {
        console.log(pc.red(`  ■ HIGH/CRITICAL findings (${highFindings.length}):\n`));
        const grouped = new Map();
        for (const f of highFindings) {
            if (!grouped.has(f.file))
                grouped.set(f.file, []);
            grouped.get(f.file).push(f);
        }
        for (const [file, findings] of grouped) {
            console.log(`   ${pc.dim('📄')} ${pc.bold(file)}`);
            const shown = new Set();
            for (const f of findings) {
                const key = f.type + f.line;
                if (shown.has(key))
                    continue;
                shown.add(key);
                console.log(`     ${pc.red(f.type.padEnd(22))} ${pc.dim('Line ' + f.line)}`);
                if (options.details) {
                    console.log(`     ${pc.dim('  Code: ' + f.snippet.substring(0, 150))}`);
                }
            }
            console.log('');
        }
    }
    // Low/medium: just list counts
    if (lowFindings.length > 0 && !options.details) {
        const byTypeLow = new Map();
        for (const f of lowFindings) {
            byTypeLow.set(f.type, (byTypeLow.get(f.type) || 0) + 1);
        }
        console.log(pc.dim(`  ■ LOW/MEDIUM (${lowFindings.length}):`));
        for (const [type, count] of byTypeLow) {
            console.log(pc.dim(`     ${type.padEnd(22)} ${count} occurrence(s)`));
        }
        console.log(pc.dim('   Run with --details for full evidence.\n'));
    }
    // Full details mode
    if (options.details) {
        const grouped = new Map();
        for (const f of result.findings) {
            if (!grouped.has(f.file))
                grouped.set(f.file, []);
            grouped.get(f.file).push(f);
        }
        for (const [file, fileFindings] of grouped) {
            console.log(` ${pc.cyan('📄')} ${pc.bold(file)}`);
            for (const f of fileFindings) {
                const sevColor = f.severity === 'CRITICAL' ? pc.bgRed :
                    f.severity === 'HIGH' ? pc.bgRed :
                        f.severity === 'MEDIUM' ? pc.bgYellow : pc.bgCyan;
                console.log(`   ${sevColor(pc.black(` ${f.severity.padEnd(8)} `))} ${pc.bold(f.type)}`);
                console.log(`   ${pc.dim('  Line ' + f.line + ': ' + f.description)}`);
                console.log(`   ${pc.dim('  Code: ' + f.snippet.substring(0, 200))}`);
                console.log();
            }
        }
    }
    // User decision prompt
    if (result.verdict !== 'SAFE') {
        console.log(pc.yellow('⚠️  This package has suspicious findings.'));
        console.log(pc.dim('   Review the evidence above. If you consider them false positives,'));
        console.log(pc.dim('   install manually with: npm install ' + pkg + '\n'));
    }
}));
program
    .command('deps-tree')
    .description('Scan transitive dependencies (up to depth 3) for supply chain threats.')
    .argument('[path]', 'Path to node_modules', 'node_modules')
    .option('--depth <n>', 'Max tree depth', '3')
    .option('--json', 'JSON output')
    .action((targetPath, options) => __awaiter(void 0, void 0, void 0, function* () {
    const { DepsScanner } = require('./intelligence/deps_scanner');
    const absPath = path.resolve(targetPath);
    if (!fs.existsSync(absPath)) {
        console.error(pc.red(`Error: ${targetPath} not found.`));
        return;
    }
    const scanner = new DepsScanner();
    console.log(pc.cyan(`\n🔍 Walking dependency tree from ${absPath} (depth ${options.depth})...`));
    const nodes = scanner.walkTree(absPath, parseInt(options.depth));
    console.log(pc.white(`   Found ${nodes.length} unique packages. Scanning...\n`));
    const result = scanner.scanTree(nodes);
    if (options.json) {
        console.log(JSON.stringify(result, null, 2));
    }
    else {
        if (result.totalFindings === 0) {
            console.log(pc.green('✔ No threats found in dependency tree.'));
        }
        else {
            console.log(pc.red(`🚨 ${result.totalFindings} finding(s) across ${result.findings.length} package(s)`));
            for (const { node, findings } of result.findings) {
                console.log(pc.yellow(`\n  📦 ${node.name}@${node.version}`));
                for (const f of findings) {
                    const color = f.severity === 'CRITICAL' ? pc.red : f.severity === 'HIGH' ? pc.yellow : pc.dim;
                    console.log(`     ${color(`[${f.severity}] ${f.type}`)} ${pc.dim(f.file)}`);
                }
            }
            if (result.criticalCount > 0)
                process.exit(1);
        }
    }
}));
program
    .command('trust-cache')
    .description('Manage the trust cache for package analysis results.')
    .argument('<action>', 'status | clear | prune')
    .action((action) => {
    const { TrustCache } = require('./intelligence/trust_cache');
    const cache = new TrustCache();
    if (action === 'status') {
        const s = cache.stats();
        console.log(pc.cyan('\n⭐ Trust Cache Status'));
        console.log(pc.white(`  Entries: ${pc.cyan(String(s.entries))}`));
        if (s.entries > 0) {
            const oldest = new Date(s.oldest).toISOString();
            const newest = new Date(s.newest).toISOString();
            console.log(pc.white(`  Oldest:  ${pc.dim(oldest)}`));
            console.log(pc.white(`  Newest:  ${pc.dim(newest)}`));
        }
    }
    else if (action === 'clear') {
        cache.clear();
        console.log(pc.yellow('✔ Trust cache cleared.'));
    }
    else if (action === 'prune') {
        const removed = cache.prune();
        console.log(pc.green(`✔ Pruned ${removed} expired entries.`));
    }
});
program
    .command('audit-deps')
    .description('Comprehensive dependency audit: lockfile parse, OSV CVE lookup, registry reputation, provenance, npm audit.')
    .option('--lockfile <path>', 'Path to lockfile (auto-detect: package-lock.json, yarn.lock)', '')
    .option('--provenance', 'Check npm attestation/provenance for top-level deps')
    .option('--quarantine', 'Auto-quarantine packages with CRITICAL findings')
    .option('--npm-audit', 'Also run npm audit --json and show results')
    .option('--ci', 'CI mode: fail (exit 1) if ANY finding exists, not just CRITICAL')
    .option('--json', 'JSON output')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const { LockfileParser } = yield Promise.resolve().then(() => __importStar(require('./intelligence/lockfile_parser')));
    const { RegistryReputation } = yield Promise.resolve().then(() => __importStar(require('./intelligence/registry_reputation')));
    const { ProvenanceVerifier } = yield Promise.resolve().then(() => __importStar(require('./intelligence/provenance_verifier')));
    const { QuarantineManager } = yield Promise.resolve().then(() => __importStar(require('./intelligence/quarantine')));
    const { NpmAuditParser } = yield Promise.resolve().then(() => __importStar(require('./intelligence/npm_audit_parser')));
    const cwd = process.cwd();
    // 1. Detect and parse lockfile
    let lockfilePath = options.lockfile;
    if (!lockfilePath) {
        const candidates = ['package-lock.json', 'yarn.lock'];
        for (const c of candidates) {
            const testPath = path.join(cwd, c);
            if (fs.existsSync(testPath)) {
                lockfilePath = testPath;
                break;
            }
        }
    }
    if (!lockfilePath || !fs.existsSync(lockfilePath)) {
        console.error(pc.red('No lockfile found. Run npm install first, or specify --lockfile.'));
        return;
    }
    const parser = new LockfileParser();
    const parsed = parser.parse(lockfilePath);
    if (parsed.entries.length === 0) {
        console.log(pc.yellow('No dependencies found in lockfile.'));
        return;
    }
    console.log(pc.cyan(`\n📋 Audit: ${parsed.entries.length} dependencies (${parsed.format})`));
    console.log(pc.dim(`   Lockfile: ${lockfilePath}`));
    const startTime = Date.now();
    const live = new live_1.LiveIndicator();
    let anyFindings = false;
    live.start('Querying OSV.dev for known vulnerabilities...', 'dots');
    // 2. Batch OSV query
    const osv = new osv_integrator_1.OSVIntegrator();
    const osvPackages = parsed.entries.map(e => ({ name: e.name, version: e.version }));
    const osvResults = yield osv.queryBatch(osvPackages);
    live.update('Checking registry reputation...');
    // 3. Registry reputation
    const rep = new RegistryReputation();
    const repResults = [];
    for (const entry of parsed.entries.slice(0, 50)) {
        try {
            const s = yield rep.score(entry.name);
            repResults.push(s);
        }
        catch (_b) { }
    }
    // 4. Provenance (if --provenance)
    let provResults = [];
    if (options.provenance) {
        live.update('Verifying npm attestations...');
        const prov = new ProvenanceVerifier();
        if (prov.checkCommandAvailable()) {
            const topLevel = parsed.entries.filter(e => !e.name.startsWith('@types/')).slice(0, 20);
            for (const entry of topLevel) {
                try {
                    const r = yield prov.verify(entry.name, entry.version);
                    provResults.push(r);
                }
                catch (_c) { }
            }
        }
    }
    // 5. npm audit (if --npm-audit)
    let npmAuditResult = null;
    if (options.npmAudit) {
        live.update('Running npm audit...');
        try {
            const nap = new NpmAuditParser();
            npmAuditResult = yield nap.runAudit();
        }
        catch (_d) { }
    }
    live.stop();
    // Compile report
    const vulnsBySeverity = new Map();
    let totalVulns = 0;
    for (const r of osvResults) {
        for (const v of r.vulnerabilities) {
            totalVulns++;
            const maxS = osv_integrator_1.OSVIntegrator.getMaxSeverity(v);
            const sev = maxS ? osv_integrator_1.OSVIntegrator.toSentinelSeverity(maxS.score) : 'MEDIUM';
            vulnsBySeverity.set(sev, (vulnsBySeverity.get(sev) || 0) + 1);
        }
    }
    const suspiciousRep = repResults.filter((r) => r.label === 'SUSPICIOUS' || r.label === 'MALICIOUS');
    const verifiedProv = provResults.filter(r => r.verified);
    if (totalVulns > 0 || suspiciousRep.length > 0)
        anyFindings = true;
    // Display results
    console.log(pc.magenta('\n═'.repeat(60)));
    console.log(pc.bold('📊 DEPENDENCY AUDIT REPORT'));
    console.log(pc.magenta('═'.repeat(60)));
    console.log(pc.white(`\n  Packages scanned: ${pc.cyan(String(parsed.entries.length))}`));
    console.log(pc.white(`  Lockfile format:  ${pc.cyan(parsed.format)}`));
    // OSV
    if (totalVulns > 0) {
        console.log(pc.red(`\n  ⚠️  Known Vulnerabilities: ${pc.bold(String(totalVulns))}`));
        const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        for (const s of order) {
            const c = vulnsBySeverity.get(s);
            if (c) {
                if (s === 'CRITICAL') {
                    console.log(`     ${pc.bgRed(pc.white(` ${s.padEnd(8)} `))} ${'■'.repeat(Math.min(c, 20))} ${c}`);
                }
                else {
                    const color = s === 'HIGH' ? pc.red : s === 'MEDIUM' ? pc.yellow : pc.dim;
                    console.log(`     ${color(` ${s.padEnd(8)} `)} ${'■'.repeat(Math.min(c, 20))} ${c}`);
                }
            }
        }
        const sorted = osvResults
            .filter(r => r.vulnerabilities.length > 0)
            .sort((a, b) => b.vulnerabilities.length - a.vulnerabilities.length)
            .slice(0, 5);
        for (const r of sorted) {
            const worst = r.vulnerabilities.slice(0, 3);
            for (const v of worst) {
                const maxS = osv_integrator_1.OSVIntegrator.getMaxSeverity(v);
                const sStr = maxS ? ` (${maxS.score})` : '';
                console.log(pc.dim(`     ${r.packageName}@${r.version}: [${v.id}] ${v.summary.substring(0, 70)}${sStr}`));
            }
        }
    }
    else {
        console.log(pc.green(`\n  CVEs: None known`));
    }
    // npm audit results
    if (npmAuditResult) {
        const m = npmAuditResult.metadata;
        const hasAuditIssues = m.critical + m.high + m.medium + m.low > 0;
        if (hasAuditIssues) {
            anyFindings = true;
            console.log(pc.red(`\n  📦 npm audit: ${m.totalVulnerabilities} vulnerability(ies)`));
            if (m.critical > 0)
                console.log(`     ${pc.bgRed(pc.white(' CRITICAL '))} ${m.critical}`);
            if (m.high > 0)
                console.log(`     ${pc.red(' HIGH     ')} ${m.high}`);
            if (m.medium > 0)
                console.log(`     ${pc.yellow(' MEDIUM   ')} ${m.medium}`);
            if (m.low > 0)
                console.log(`     ${pc.dim(' LOW      ')} ${m.low}`);
        }
        else {
            console.log(pc.green(`\n  📦 npm audit: clean (${m.totalDependencies} deps)`));
        }
    }
    // Reputation
    if (suspiciousRep.length > 0) {
        console.log(pc.yellow(`\n  ⚠️  Suspicious Registry Signals: ${suspiciousRep.length} package(s)`));
        for (const r of suspiciousRep.slice(0, 10)) {
            const worst = r.factors.filter((f) => f.impact < 0).slice(0, 2);
            console.log(`     ${pc.yellow(r.packageName)} ${pc.dim(`score: ${r.score}, ${worst.map((f) => f.name).join(', ')}`)}`);
        }
    }
    else {
        console.log(pc.green(`\n  Registry: ${repResults.length} packages checked, all normal`));
    }
    // Provenance
    if (options.provenance) {
        if (verifiedProv.length > 0) {
            console.log(pc.green(`\n  ✅ Provenance: ${verifiedProv.length} package(s) have verified attestations`));
        }
        else if (provResults.length > 0) {
            console.log(pc.yellow(`\n  ⚠️  Provenance: No verified attestations found`));
        }
        else {
            console.log(pc.dim(`\n  Provenance: npm attestation not available`));
        }
    }
    const elapsed = Date.now() - startTime;
    console.log(pc.dim(`\n  Audit completed in ${(elapsed / 1000).toFixed(1)}s`));
    // Auto-quarantine (if --quarantine)
    if (options.quarantine) {
        const qm = new QuarantineManager();
        if (qm.isEnabled()) {
            const criticalPkgs = osvResults.filter(r => r.vulnerabilities.some(v => {
                const ms = osv_integrator_1.OSVIntegrator.getMaxSeverity(v);
                return ms && ms.score >= 9.0;
            }));
            for (const pkg of criticalPkgs) {
                try {
                    const pkgPath = path.join(cwd, 'node_modules', pkg.packageName);
                    if (fs.existsSync(pkgPath)) {
                        qm.quarantinePackage(pkg.packageName, pkg.version, `Critical CVE: ${((_a = pkg.vulnerabilities[0]) === null || _a === void 0 ? void 0 : _a.id) || 'unknown'}`, 'CRITICAL');
                        console.log(pc.red(`  🔒 Quarantined: ${pkg.packageName}@${pkg.version}`));
                    }
                }
                catch (_e) { }
            }
        }
        else {
            console.log(pc.yellow('  Quarantine is disabled. Enable with: sentinel policy set quarantine on'));
        }
    }
    if (options.json) {
        console.log(JSON.stringify({
            packages: parsed.entries.length,
            format: parsed.format,
            vulnerabilities: totalVulns,
            bySeverity: Object.fromEntries(vulnsBySeverity),
            suspiciousPackages: suspiciousRep.length,
            provenance: verifiedProv.length,
            npmAudit: (npmAuditResult === null || npmAuditResult === void 0 ? void 0 : npmAuditResult.metadata) || null,
            durationMs: elapsed
        }, null, 2));
    }
    // Exit code: --ci fails on any finding, default fails only on CRITICAL
    const shouldFail = options.ci ? anyFindings : totalVulns > 0;
    if (shouldFail)
        process.exit(1);
}));
program
    .command('sbom')
    .description('Generate CycloneDX SBOM from lockfile.')
    .option('--lockfile <path>', 'Path to lockfile (auto-detect: package-lock.json, yarn.lock)', '')
    .option('--output <path>', 'Output file path (default: stdout)', '')
    .option('--enrich', 'Enrich SBOM with CVE data from OSV')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const { SbomGenerator, enrichSbomWithCves } = yield Promise.resolve().then(() => __importStar(require('./intelligence/sbom_generator')));
    const cwd = process.cwd();
    let lockfilePath = options.lockfile;
    if (!lockfilePath) {
        const candidates = ['package-lock.json', 'yarn.lock'];
        for (const c of candidates) {
            const testPath = path.join(cwd, c);
            if (fs.existsSync(testPath)) {
                lockfilePath = testPath;
                break;
            }
        }
    }
    if (!lockfilePath || !fs.existsSync(lockfilePath)) {
        console.error(pc.red('No lockfile found. Run npm install first, or specify --lockfile.'));
        return;
    }
    const gen = new SbomGenerator();
    const sbom = gen.generate(lockfilePath);
    let outputSbom = sbom;
    if (options.enrich) {
        const osv = new osv_integrator_1.OSVIntegrator();
        const osvPackages = sbom.components.map((c) => ({ name: c.name, version: c.version }));
        const osvResults = yield osv.queryBatch(osvPackages);
        outputSbom = enrichSbomWithCves(sbom, osvResults);
    }
    const output = JSON.stringify(outputSbom, null, 2);
    if (options.output) {
        fs.writeFileSync(path.resolve(options.output), output, 'utf8');
        console.log(pc.green(`✔ SBOM written to ${options.output}`));
    }
    else {
        console.log(output);
    }
}));
program
    .command('install')
    .description('Security-gated package installation. Scans then installs.')
    .argument('<manager>', 'npm | pip | yarn | etc.')
    .argument('[args...]', 'Manager arguments')
    .action((manager, args) => __awaiter(void 0, void 0, void 0, function* () {
    const res = yield shield.scanInstallation(manager, args);
    if (!res.success) {
        process.exit(1);
    }
    console.log(pc.cyan(`\nProceeding with native installation via ${manager}...`));
    try {
        const mgrMap = {
            'npm': 'npm.cmd', 'yarn': 'yarn.cmd', 'pnpm': 'pnpm.cmd',
            'pip': 'pip.exe', 'pip3': 'pip3.exe',
            'cargo': 'cargo.exe', 'docker': 'docker.exe'
        };
        const exe = mgrMap[manager] || manager;
        const installArgs = manager === 'npm' ? ['install', ...args] :
            manager === 'yarn' ? ['add', ...args] :
                manager === 'pnpm' ? ['add', ...args] :
                    manager === 'pip' || manager === 'pip3' ? ['install', ...args] :
                        manager === 'cargo' ? ['install', ...args] : args;
        const cmdStr = `${exe} ${installArgs.join(' ')}`;
        const result = (0, child_process_1.execSync)(cmdStr, {
            encoding: 'utf8', stdio: 'inherit', windowsHide: true,
            timeout: 300000, shell: true
        });
    }
    catch (e) {
        const err = e;
        console.error(pc.red(`\n✖ Installation failed (exit ${err.status || 1}).`));
        process.exit(err.status || 1);
    }
}));
program
    .command('check-classified')
    .description('Verify if staged files contain classified data (Pre-commit Hook).')
    .argument('<repoPath>', 'Path to the repository')
    .action((repoPath) => {
    const result = (0, classify_1.checkClassifiedHook)(repoPath);
    process.exit(result);
});
program
    .command('guard')
    .description('Manage OS-level package manager interception.')
    .argument('<action>', 'enable | disable | status | trust-cache')
    .action((action) => {
    if (action === 'status') {
        const active = (0, guard_1.isGuardEnabled)();
        console.log(`\n🛡️  Sentinel Guard: ${active ? pc.green('ACTIVE') : pc.red('INACTIVE')}`);
    }
    else if (action === 'enable') {
        const res = (0, guard_1.enableGuard)();
        if (res.success)
            console.log(pc.green(`\n✔ Sentinel Guard enabled on ${res.profilePath}`));
        else
            console.log(pc.yellow(`\n⚠️  ${res.reason}`));
    }
    else if (action === 'disable') {
        const res = (0, guard_1.disableGuard)();
        if (res.success)
            console.log(pc.yellow('\n🛡️  Sentinel Guard disabled.'));
    }
    else if (action === 'trust-cache') {
        console.log(pc.cyan('\n⭐ Trust Cache (Whitelisted Packages)'));
        const cachePath = path.join(os.homedir(), '.sentinel', 'trust_cache.json');
        if (fs.existsSync(cachePath)) {
            const cache = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
            const entries = cache.packages || [];
            if (entries.length === 0) {
                console.log(pc.dim('   No whitelisted packages.'));
            }
            else {
                entries.forEach((e, i) => {
                    const obj = e;
                    const name = obj.name || String(e);
                    const reason = obj.reason ? '— ' + obj.reason : '';
                    console.log(`  ${pc.cyan(String(i + 1))}. ${pc.white(name)} ${pc.dim(reason)}`);
                });
            }
        }
        else {
            console.log(pc.dim('   No trust cache found. Packages are analyzed fresh every time.'));
        }
        console.log('');
    }
});
// --- Pre-commit Hook Command ---
program
    .command('precommit')
    .description('Manage Sentinel SAST pre-commit hook (install/uninstall/status)')
    .argument('<action>', 'install | uninstall | status')
    .argument('[repoPath]', 'Path to git repository (default: current directory)')
    .action((action, repoPath) => {
    const targetPath = repoPath ? path.resolve(repoPath) : process.cwd();
    const gitDir = path.join(targetPath, '.git');
    if (!fs.existsSync(gitDir)) {
        console.error(pc.red(`Error: ${targetPath} is not a git repository (no .git found).`));
        process.exit(1);
    }
    if (action === 'install') {
        const installed = (0, classify_1.installSastPreCommitHook)(targetPath);
        if (installed) {
            console.log(pc.green(`\n✔ Sentinel SAST pre-commit hook installed in ${targetPath}`));
            console.log(pc.dim('   Hook runs: sentinel scan --staged + sentinel check-classified'));
        }
        else {
            console.error(pc.red('✖ Failed to install pre-commit hook.'));
            process.exit(1);
        }
    }
    else if (action === 'uninstall') {
        const removed = (0, classify_1.uninstallPreCommitHook)(targetPath);
        if (removed) {
            console.log(pc.yellow(`\n🛡️  Sentinel pre-commit hook removed from ${targetPath}`));
        }
        else {
            console.log(pc.dim('No Sentinel pre-commit hook found.'));
        }
    }
    else if (action === 'status') {
        const installed = (0, classify_1.isPreCommitHookInstalled)(targetPath);
        if (installed) {
            console.log(pc.green(`\n✔ Sentinel pre-commit hook is ACTIVE in ${targetPath}`));
        }
        else {
            console.log(pc.yellow(`\n⚠  No Sentinel pre-commit hook in ${targetPath}`));
            console.log(pc.dim('   Run: sentinel precommit install'));
        }
    }
});
// --- Pre-push Hook Command ---
program
    .command('prepush')
    .description('Manage Sentinel pre-push hook (install/uninstall/status)')
    .argument('<action>', 'install | uninstall | status')
    .argument('[repoPath]', 'Path to git repository (default: current directory)')
    .action((action, repoPath) => {
    const targetPath = repoPath ? path.resolve(repoPath) : process.cwd();
    const gitDir = path.join(targetPath, '.git');
    if (!fs.existsSync(gitDir)) {
        console.error(pc.red(`Error: ${targetPath} is not a git repository (no .git found).`));
        process.exit(1);
    }
    const hooksDir = path.join(gitDir, 'hooks');
    const hookPath = path.join(hooksDir, 'pre-push');
    if (action === 'install') {
        if (!fs.existsSync(hooksDir)) {
            fs.mkdirSync(hooksDir, { recursive: true });
        }
        let existing = '';
        if (fs.existsSync(hookPath)) {
            existing = fs.readFileSync(hookPath, 'utf8');
            if (existing.includes('SENTINEL PRE-PUSH')) {
                console.log(pc.yellow('⚠  Sentinel pre-push hook already installed.'));
                return;
            }
        }
        const hookScript = `#!/bin/sh
# SENTINEL PRE-PUSH HOOK
echo "[Sentinel] Running SAST scan on all files before push..."
sentinel scan . --json > /dev/null 2>&1
SENTINEL_EXIT=$?
if [ $SENTINEL_EXIT -ne 0 ]; then
  echo "[Sentinel] ❌ SAST scan found threats. Push blocked."
  echo "[Sentinel] Run 'sentinel scan .' locally to review findings."
  exit 1
fi
echo "[Sentinel] ✅ All checks passed. Push allowed."
${existing.startsWith('#!') ? existing.split('\n').slice(1).join('\n') : existing}
`;
        fs.writeFileSync(hookPath, hookScript, { mode: 0o755 });
        console.log(pc.green(`\n✔ Sentinel pre-push hook installed in ${targetPath}`));
    }
    else if (action === 'uninstall') {
        if (!fs.existsSync(hookPath)) {
            console.log(pc.dim('No Sentinel pre-push hook found.'));
            return;
        }
        const content = fs.readFileSync(hookPath, 'utf8');
        if (!content.includes('SENTINEL PRE-PUSH')) {
            console.log(pc.dim('No Sentinel pre-push hook found.'));
            return;
        }
        const remaining = content.split('\n').filter(line => !line.includes('SENTINEL PRE-PUSH')).join('\n');
        const cleaned = remaining.replace(/echo "\[Sentinel\].*"/g, '').replace(/sentinel scan.*/g, '').replace(/SENTINEL_EXIT.*/g, '').replace(/if.*SENTINEL.*/g, '').replace(/fi/g, '').replace(/\n{3,}/g, '\n\n').trim();
        if (cleaned) {
            fs.writeFileSync(hookPath, cleaned + '\n', { mode: 0o755 });
        }
        else {
            fs.unlinkSync(hookPath);
        }
        console.log(pc.yellow(`\n🛡️  Sentinel pre-push hook removed from ${targetPath}`));
    }
    else if (action === 'status') {
        if (fs.existsSync(hookPath)) {
            const content = fs.readFileSync(hookPath, 'utf8');
            if (content.includes('SENTINEL PRE-PUSH')) {
                console.log(pc.green(`\n✔ Sentinel pre-push hook is ACTIVE in ${targetPath}`));
            }
            else {
                console.log(pc.yellow(`\n⚠  No Sentinel pre-push hook in ${targetPath}`));
            }
        }
        else {
            console.log(pc.yellow(`\n⚠  No Sentinel pre-push hook in ${targetPath}`));
        }
    }
});
program
    .command('env-encrypt')
    .description('Encrypt a .env file with AES-256-CBC for secure storage.')
    .argument('<file>', 'Path to .env file')
    .action((file) => {
    const resolved = path.resolve(file);
    if (!fs.existsSync(resolved)) {
        console.error(pc.red(`Error: File ${file} not found.`));
        process.exit(1);
    }
    const envKey = process.env.SENTINEL_ENV_KEY;
    if (!envKey) {
        console.error(pc.red('\nError: SENTINEL_ENV_KEY environment variable is required for encryption.\n'));
        process.exit(1);
    }
    const key = crypto.createHash('sha256').update(envKey).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const input = fs.readFileSync(resolved, 'utf8');
    const encrypted = Buffer.concat([cipher.update(input, 'utf8'), cipher.final()]);
    const output = iv.toString('hex') + ':' + encrypted.toString('hex');
    const outPath = resolved + '.enc';
    fs.writeFileSync(outPath, output, 'utf8');
    console.log(pc.green(`\n✔ Encrypted ${file} → ${outPath}`));
    console.log(pc.yellow('⚠ Keep your SENTINEL_ENV_KEY safe. Without it, decryption is impossible.\n'));
});
program
    .command('env-decrypt')
    .description('Decrypt a .env.enc file back to plaintext.')
    .argument('<file>', 'Path to .env.enc file')
    .action((file) => {
    const resolved = path.resolve(file);
    if (!fs.existsSync(resolved)) {
        console.error(pc.red(`Error: File ${file} not found.`));
        process.exit(1);
    }
    const envKey = process.env.SENTINEL_ENV_KEY;
    if (!envKey) {
        console.error(pc.red('\nError: SENTINEL_ENV_KEY environment variable is required for decryption.\n'));
        process.exit(1);
    }
    const key = crypto.createHash('sha256').update(envKey).digest();
    const content = fs.readFileSync(resolved, 'utf8').trim();
    const parts = content.split(':');
    if (parts.length < 2) {
        console.error(pc.red('Error: Invalid encrypted file format.'));
        process.exit(1);
    }
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = Buffer.from(parts.slice(1).join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    try {
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
        const outPath = resolved.replace(/\.enc$/, '') + '.decrypted';
        fs.writeFileSync(outPath, decrypted, 'utf8');
        console.log(pc.green(`\n✔ Decrypted ${file} → ${outPath}\n`));
    }
    catch (_e3) {
        console.error(pc.red('Error: Decryption failed. Wrong key or corrupted file.'));
        process.exit(1);
    }
});
program
    .command('memory')
    .description('Manage local Signal Vault (Historical Persistence).')
    .option('--ingest <file>', 'Ingest a cloud JSON report')
    .option('--ingest-dir <dir>', 'Batch ingest all JSON reports from a directory')
    .option('--stdin', 'Read JSON report from stdin (pipe mode)')
    .option('--paste', 'Paste raw JSON content interactively')
    .option('--wipe', 'Permanently erase local history')
    .option('--status', 'Show signal vault metrics')
    .option('--threshold <n>', 'Show repos crossing signal threshold (default 5)', '5')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, e_1, _b, _c, _d, e_2, _e, _f;
    if (options.ingestDir) {
        const dir = path.resolve(options.ingestDir);
        if (!fs.existsSync(dir) || !fs.lstatSync(dir).isDirectory()) {
            console.error(pc.red(`Error: Directory ${options.ingestDir} not found.`));
            return;
        }
        const files = fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort();
        if (files.length === 0) {
            console.log(pc.yellow('No JSON files found in directory.'));
            return;
        }
        console.log(pc.cyan(`\n📂 Batch ingesting ${files.length} reports from ${options.ingestDir}...\n`));
        for (const f of files) {
            const fullPath = path.join(dir, f);
            try {
                const scanId = memory.ingestReport(fullPath);
                console.log(pc.green(`  ✔ ${f} → scan: ${scanId}`));
            }
            catch (err) {
                console.log(pc.red(`  ✖ ${f} → ${err.message}`));
            }
        }
        console.log(pc.green(`\n✔ Batch ingestion complete.\n`));
    }
    else if (options.stdin) {
        const chunks = [];
        try {
            for (var _g = true, _h = __asyncValues(process.stdin), _j; _j = yield _h.next(), _a = _j.done, !_a; _g = true) {
                _c = _j.value;
                _g = false;
                const chunk = _c;
                chunks.push(chunk);
            }
        }
        catch (e_1_1) { e_1 = { error: e_1_1 }; }
        finally {
            try {
                if (!_g && !_a && (_b = _h.return)) yield _b.call(_h);
            }
            finally { if (e_1) throw e_1.error; }
        }
        const raw = Buffer.concat(chunks).toString('utf8');
        if (raw.length > 10000000) {
            console.error(pc.red('Error: Input exceeds maximum size (10 MB).'));
            return;
        }
        let json;
        try {
            json = JSON.parse(raw);
        }
        catch (_k) {
            console.error(pc.red('Error: Invalid JSON input.'));
            return;
        }
        if (typeof json !== 'object' || json === null) {
            console.error(pc.red('Error: Expected a JSON object.'));
            return;
        }
        const scanId = json.id
            ? memory.getVault().ingestCloudReport(json)
            : memory.ingestReportFromJson(json);
        console.log(pc.green(`\n✔ Signals from piped JSON persisted to local Vault (scan: ${scanId}).`));
    }
    else if (options.paste) {
        console.log(pc.cyan('\n📋 Paste the JSON report below. Press Ctrl+Z then Enter when done (Windows), or Ctrl+D (Unix):\n'));
        const chunks = [];
        if (process.stdin.isTTY) {
            try {
                // Interactive terminal — wait for EOF
                for (var _l = true, _m = __asyncValues(process.stdin), _o; _o = yield _m.next(), _d = _o.done, !_d; _l = true) {
                    _f = _o.value;
                    _l = false;
                    const chunk = _f;
                    chunks.push(chunk);
                }
            }
            catch (e_2_1) { e_2 = { error: e_2_1 }; }
            finally {
                try {
                    if (!_l && !_d && (_e = _m.return)) yield _e.call(_m);
                }
                finally { if (e_2) throw e_2.error; }
            }
        }
        const raw = Buffer.concat(chunks).toString('utf8').trim();
        if (!raw) {
            console.log(pc.yellow('No input received.'));
            return;
        }
        if (raw.length > 10000000) {
            console.error(pc.red('Error: Input exceeds maximum size (10 MB).'));
            return;
        }
        let json;
        try {
            json = JSON.parse(raw);
        }
        catch (_p) {
            console.error(pc.red('Error: Invalid JSON input.'));
            return;
        }
        if (typeof json !== 'object' || json === null) {
            console.error(pc.red('Error: Expected a JSON object.'));
            return;
        }
        const scanId = json.id
            ? memory.getVault().ingestCloudReport(json)
            : memory.ingestReportFromJson(json);
        console.log(pc.green(`\n✔ Pasted JSON persisted to local Vault (scan: ${scanId}).`));
    }
    else if (options.ingest) {
        const scanId = memory.ingestReport(options.ingest);
        console.log(pc.green(`\n✔ Signals from ${options.ingest} persisted to local Vault (scan: ${scanId}).`));
    }
    else if (options.wipe) {
        memory.wipe();
        console.log(pc.red('\n🔥 Local Signal Vault wiped. History erased.'));
    }
    else if (options.status) {
        const status = memory.getStatus();
        console.log(pc.cyan('\n🧠 Sentinel Signal Vault Status'));
        console.log(pc.white(`  📊 Scans recorded:   ${pc.cyan(String(status.scans))}`));
        console.log(pc.white(`  ⚠️  Findings stored: ${pc.cyan(String(status.findings))}`));
        console.log(pc.white(`  📡 Signals tracked:  ${pc.cyan(String(status.signals))}`));
        console.log(pc.white(`  📁 Repos monitored:  ${pc.cyan(String(status.repos))}`));
        console.log(pc.white(`  👤 Authors tracked: ${pc.cyan(String(status.authors))}`));
        console.log(pc.dim(`  💾 Retention:       ${status.retention}`));
        // Show threshold analysis with multi-author correlation
        memory.printThresholdReport(parseInt(options.threshold) || 5);
        memory.printMultiAuthorCorrelation();
    }
}));
program
    .command('hub')
    .description('Launch interactive Sentinel operations menu.')
    .action(() => __awaiter(void 0, void 0, void 0, function* () {
    // Opening animation
    const frames = ['◴', '◷', '◶', '◵'];
    const msg = ' INITIALIZING SENTINEL INTELLIGENCE ENGINE v4.0 ';
    for (let i = 0; i < 12; i++) {
        const f = frames[i % frames.length];
        const bar = '█'.repeat(Math.min(i, 10)) + '░'.repeat(Math.max(10 - i, 0));
        process.stdout.write(`\r${pc.cyan(f)} ${pc.dim(msg)} ${pc.cyan(bar)}`);
        yield new Promise(r => setTimeout(r, 60));
    }
    const checks = ['✓ Boot sequence', '✓ Cipher modules', '✓ Signal Vault', '✓ Threat Grid'];
    for (const c of checks) {
        process.stdout.write(`\r${pc.green('✔')} ${pc.dim(c.padEnd(60))}`);
        yield new Promise(r => setTimeout(r, 200));
    }
    process.stdout.write(`\r${' '.repeat(70)}\r`);
    console.log(pc.green(pc.bold('\n⬡  SENTINEL HUB v4.0 — INTERACTIVE MENU\n')));
    yield (0, hub_1.startInteractiveHub)();
}));
program
    .command('policies')
    .description('Show Sentinel security policy, responsible disclosure, and contribution guidelines.')
    .action(() => {
    const b = pc.bold;
    const d = pc.dim;
    const w = pc.white;
    const c = pc.cyan;
    const policy = `
${c(b('╔══════════════════════════════════════════════════════════════════════╗'))}
${c(b('║               SENTINEL — POLICIES & RESPONSIBILITIES               ║'))}
${c(b('╚══════════════════════════════════════════════════════════════════════╝'))}

${b('1. SECURITY & RESPONSIBLE DISCLOSURE')}
${d('   Sentinel is a security tool — its own security is paramount.')}
${d('   If you discover a vulnerability in Sentinel itself:')}
${d('')}
${d('   • DO NOT open a public GitHub issue.')}
${d('   • Report via email: javier20dev25@sentinel.security')}
${d('   • Provide a clear description, steps to reproduce, and impact.')}
${d('   • We commit to acknowledging receipt within 48 hours.')}
${d('   • We aim to release a fix within 7 days for critical issues.')}
${d('')}
${w('   Scope: CLI binary, SAST rules, Signal Vault, Supply Chain Shield.')}
${w('   Out of scope: third-party dependencies (report them to their maintainers).')}

${b('2. REPORTING VULNERABILITIES IN YOUR CODE')}
${d('   Sentinel helps you find threats in your own code and dependencies.')}
${d('   If Sentinel reports a finding:')}
${d('')}
${d('   • Review the evidence shown (file, line, snippet).')}
${d('   • Use sentinel verify-pkg --details for supply chain deep dives.')}
${d('   • Use sentinel hub → PR Bot for automated batch analysis.')}
${d('   • If you believe it is a false positive, skip with:')}
${d('     npm install <package> (bypasses shield).')}
${d('')}
${w('   To whitelist a package permanently: sentinel guard trust-cache')}

${b('3. CONTRIBUTING — PROPOSING CHANGES (PRs)')}
${d('   We welcome contributions that improve Sentinel. Guidelines:')}
${d('')}
${d('   • Open an issue first to discuss the change you want to make.')}
${d('   • Fork the repository and create a feature branch.')}
${d('   • Follow the existing code style (no semicolons, 2-space indent).')}
${d('   • Add or update SAST rules in src/core/lite/lite_scanner.ts.')}
${d('   • Run the linter: npm run lint')}
${d('   • Ensure TypeScript compiles: npm run build:cli')}
${d('   • Update the guide if adding new commands: sentinel guide')}
${d('   • Submit a PR with a clear title and description.')}
${d('')}
${w('   All PRs are scanned by Sentinel PR Bot before review.')}
${w('   Malicious PRs will be blocked and reported.')}

${b('4. CODE OF CONDUCT')}
${d('   • Be respectful and constructive.')}
${d('   • No harassment, trolling, or personal attacks.')}
${d('   • Focus on what is best for the community and the tool.')}
${d('   • Help others learn — this is a security education tool.')}

${b('5. VERSIONING & SUPPORT')}
${d('   • Sentinel follows Semantic Versioning (MAJOR.MINOR.PATCH).')}
   ${d('   • v4.x = current stable line (Skills/MCP).')}
${d('   • Breaking changes increment the MAJOR version.')}
${d('   • Security patches are backported to the latest minor.')}
${d('   • No guaranteed support for versions older than 6 months.')}

${b('6. DATA & PRIVACY')}
${d('   • Sentinel runs locally. No telemetry is sent externally.')}
${d('   • The Signal Vault lives in ~/.sentinel/vault.db (local SQLite).')}
${d('   • GitHub API calls are made only when you explicitly request them.')}
${d('   • npm pack downloads are cached temporarily and deleted after scan.')}

${c(b('══════════════════════════════════════════════════════════════════════'))}
${d('   For urgent security issues, email: javier20dev25@sentinel.security')}
${d('   Repository: https://github.com/javier20dev25/sentinel-cli')}
${d('   Report issues: https://github.com/anomalyco/opencode/issues')}
`;
    console.log(policy);
});
program
    .command('guide')
    .description('Show interactive user guide with all commands, sub-options, examples and test results.')
    .action(() => {
    const g = pc.green;
    const c = pc.cyan;
    const y = pc.yellow;
    const d = pc.dim;
    const b = pc.bold;
    const w = pc.white;
    const guide = `
${c(b('╔══════════════════════════════════════════════════════════════════════╗'))}
${c(b('║              SENTINEL — SECURITY INTELLIGENCE v4.0 GUIDE             ║'))}
${c(b('╚══════════════════════════════════════════════════════════════════════╝'))}
${d('   SAST scan, supply chain audit, threat intel, skills/MCP for AI agents.')}

${b('A. SKILLS SYSTEM — AI Agent Integration')}
   ${w('$ sentinel install-skills')}
   ${d('   Install skill files for detected AI coding agents (Claude, Cursor, etc.)')}
   ${w('$ sentinel install-skills --list')}
   ${d('   Show detected agents on this system')}
   ${w('$ sentinel install-skills --all')}
   ${d('   Install for all supported agents regardless of detection')}
   ${w('$ sentinel install-skills --agent claude --agent cursor')}
   ${d('   Install for specific agents only')}
   ${d('')}
   ${d('   Supported: claude, cursor, cline, windsurf, opencode, roo, gemini, codex')}
   ${d('   Skills location: skills/ directory — CONSTITUTION.md + per-agent adapters')}

${b('B. MCP SERVER — Model Context Protocol')}
   ${w('$ sentinel mcp')}
   ${d('   Start MCP server in stdio mode (connect Claude Desktop, Cursor, Cline)')}
   ${w('$ sentinel mcp --http --port 3003')}
   ${d('   Start MCP server in HTTP/SSE mode')}
   ${d('')}
   ${d('   12 tools: scan, verify-pkg, doctor, check-classified, integrity,')}
   ${d('   memory, threat-query, threat-correlate, gh-pr-list, gh-pr-view,')}
   ${d('   gh-pr-diff, gh-repo-list')}

${b('1. SCAN — LiteScanner SAST')}
   ${w('$ sentinel scan [path] [--json]')}
   ${d('   path: file or directory (default .)')}
   ${d('   --json: JSON output for pipelines')}
   ${d('   Scans JS/TS with 30 SAST rules (injection, XSS, eval, secrets, etc).')}
   ${g('   ex: sentinel scan ./src/myfile.js')}

${b('2. VERIFY-PKG — Supply chain audit')}
   ${w('$ sentinel verify-pkg <package> [--details]')}
   ${d('   package: name or name@version (ex: lodash, dotenv@16.4.7)')}
   ${d('   --details: full evidence per finding')}
   ${d('   Downloads tarball via npm pack (no install), extracts and scans.')}
   ${g('   ✓ sentinel verify-pkg utilz --details')}
   ${d('     → SAFE | 2 findings (ENV_ACCESS, OS_CAPABILITY)')}
   ${y('   ⚠ sentinel verify-pkg dotenv --details')}
   ${d('     → SUSPICIOUS | 20 findings (ENV_ACCESS, POTENTIAL_SECRET)')}

${b('3. DOCTOR — System health')}
   ${w('$ sentinel doctor [--deep]')}
   ${d('   --deep: full node_modules scan (25+ dependencies)')}
   ${d('   Without flag: package.json + host integrity')}
   ${g('   ex: sentinel doctor --deep')}

${b('4. MEMORY — Signal Vault (local SQLite)')}
   ${w('$ sentinel memory --status [--threshold <n>]')}
   ${d('   --status: metrics (scans, findings, signals, repos, authors)')}
   ${d('   --threshold <n>: repos crossing threshold (default 5)')}
   ${w('$ sentinel memory --ingest <file.json>')}
   ${d('   --ingest: ingest a cloud report from file')}
   ${w('$ sentinel memory --stdin < pipe.json')}
   ${d('   --stdin: pipe mode — cat report.json | sentinel memory --stdin')}
   ${w('$ sentinel memory --paste')}
   ${d('   --paste: paste JSON manually (Ctrl+Z / Ctrl+D)')}
   ${w('$ sentinel memory --wipe')}
   ${d('   --wipe: erase all local history')}

${b('5. HUB — Interactive menu')}
   ${w('$ sentinel hub')}
   ${d('   TUI menu with: Workspace Discovery, System Doctor,')}
   ${d('   Integrity Check, Permissions Audit, Scan, Guard,')}
    ${d('   Classified Documents, Signal Vault, GitHub PR Bot.')}

${b('6. PERMISSIONS — Capability governance')}
   ${w('$ sentinel permissions [package]')}
   ${d('   Without arg: auto-scan all installed dependencies')}
   ${d('   With package: analyze one specific package')}
   ${d('   Maps: NETWORK, FILESYSTEM, PROCESS_EXEC, ENV_ACCESS,')}
   ${d('   DYNAMIC_EXEC, DOM_MANIPULATION, CREDENTIAL_LEAK')}

${b('7. GUARD — OS-level interception')}
   ${w('$ sentinel guard <status|enable|disable>')}
   ${d('   status:  show if Guard is active')}
   ${d('   enable:  install aliases in PowerShell/profile to intercept')}
   ${d('            npm, yarn, pnpm, pip, pip3, cargo, docker')}
   ${d('   disable: remove aliases from profile')}

${b('8. CLASSIFIED DOCS — Leak prevention')}
   ${w('$ sentinel check-classified <repoPath>')}
   ${d('   Check staged files against classified DB')}
   ${d('   Pre-commit hook installs from HUB, chains with existing hooks.')}

${b('9. INTEGRITY — Verification')}
   ${w('$ sentinel integrity')}
   ${d('   Checks: SAST rule hash, PATH poisoning, vault state, clock anomaly, signed manifest')}

${b('10. BASELINE — Drift detection')}
   ${w('$ sentinel baseline <create|diff> [name]')}
   ${d('   create: save current system snapshot')}
   ${d('   diff:   compare against a previous snapshot')}

${b('11. INSTALL — Gated installation')}
   ${w('$ sentinel install <manager> [args...]')}
   ${d('   manager: npm | pip | yarn | etc')}
   ${d('   args: manager arguments (packages to install)')}
   ${d('   Scans via SupplyChainShield before allowing installation')}

${b('12. ENVIRONMENT ENCRYPT')}
   ${w('$ sentinel env-encrypt <file>')}
   ${w('$ sentinel env-decrypt <file>')}

${b('13. AUDIT-DEPS — Full dependency audit')}
   ${w('$ sentinel audit-deps [--lockfile <path>] [--provenance] [--quarantine] [--npm-audit] [--ci]')}
   ${d('   Parses package-lock.json/yarn.lock, batch OSV CVE lookup,')}
   ${d('   registry reputation, npm provenance, npm audit integration.')}
   ${d('   --ci: exit 1 on ANY finding (default: only CRITICAL)')}
   ${g('   ex: sentinel audit-deps --ci --provenance')}

${b('14. DEPS-TREE — Transitive dependency scan')}
   ${w('$ sentinel deps-tree [path] --depth 3')}
   ${d('   Walks node_modules up to depth 3, scans each package')}
   ${d('   with LiteScanner SAST rules.')}
   ${g('   ex: sentinel deps-tree ./node_modules --depth 2')}

${b('15. SBOM — CycloneDX generation')}
   ${w('$ sentinel sbom [--lockfile <path>] [--output <file>]')}
   ${d('   Generates CycloneDX v1.5 SBOM from lockfile.')}
   ${d('   Outputs JSON to stdout or file with --output.')}
   ${g('   ex: sentinel sbom --output bom.json')}

${b('16. TRUST-CACHE — Package verdict cache')}
   ${w('$ sentinel trust-cache <status|clear|prune>')}
   ${d('   status: show cached package analysis results')}
   ${d('   clear:  reset the cache')}
   ${d('   prune:  remove entries older than 7 days')}

${c(b('══════════════════════════════════════════════════════════════════════'))}
${b('TEST RESULTS  —  Verificados Mayo 2026:')}
${g('  ✔')} ${d('verify-pkg utilz --details       → SAFE       | 2 findings con evidencia')}
${g('  ✔')} ${d('verify-pkg dotenv --details      → SUSPICIOUS | 20 findings (1 HIGH)')}
${g('  ✔')} ${d('verify-pkg browserify-fs         → SAFE       | 0 findings, paquete limpio')}
${g('  ✔')} ${d('doctor --deep                    → OK         | 25 dependencias escaneadas')}
${g('  ✔')} ${d('memory --stdin (pipe)            → OK         | JSON ingerido al vault')}
${g('  ✔')} ${d('memory --status                  → OK         | 3 scans, 76 findings, 2 autores')}
${g('  ✔')} ${d('hub config menu                  → OK         | Trust Cache option 4 agregada')}
${g('  ✔')} ${d('hub animation                    → OK         | Barra de carga + checks')}
${g('  ✔')} ${d('pre-commit hook                  → OK         | Append a hooks existentes')}
${g('  ✔')} ${d('PowerShell guard                 → OK         | Resolución .exe/.cmd por manejador')}
${g('  ✔')} ${d('TypeScript compile               → OK         | 0 errores')}

${d('   Report issues: https://github.com/anomalyco/opencode/issues')}
${d('')}
${b('Need more?')} ${d('Run')} ${w('sentinel policies')} ${d('for security policy, responsible disclosure,')}
${d('and contribution guidelines.')}
`;
    console.log(guide);
});
// --- Skills Install Command ---
program
    .command('install-skills')
    .description('Install Sentinel skill files for AI coding agents (Claude, Cursor, Cline, etc.)')
    .argument('[agents...]', 'Specific agents to target (default: auto-detect)')
    .option('--list', 'List detected agents and exit')
    .option('--all', 'Install for all supported agents')
    .action((agents, options) => {
    const args = [];
    if (options.list)
        args.push('--list');
    if (options.all)
        args.push('--all');
    if (agents && agents.length > 0) {
        for (const a of agents) {
            args.push('--agent', a);
        }
    }
    const { installSkillsCommand } = require('./install-skills');
    installSkillsCommand(args);
});
// --- MCP Server Command ---
program
    .command('mcp')
    .description('Start the MCP (Model Context Protocol) server for AI agent tool integration')
    .option('--port <number>', 'HTTP server port', '3003')
    .option('--http', 'Use HTTP/SSE transport instead of stdio')
    .option('--stdio', 'Use stdio transport (default)')
    .action((options) => {
    const { startMcpServer } = require('../mcp/server');
    startMcpServer({
        port: parseInt(options.port, 10),
        http: options.http || false,
    });
});
// --- PR Audit Command ---
program
    .command('pr-audit')
    .description('Audit a single GitHub pull request')
    .option('--repo <owner/repo>', 'Repository name (or set SENTINEL_REPO)')
    .option('--pr <number>', 'PR number (or set SENTINEL_PR)')
    .option('--author <login>', 'PR author (or set SENTINEL_AUTHOR)')
    .option('--diff-file <path>', 'Read diff from file instead of fetching from GitHub')
    .option('--comment', 'Post findings as a PR comment')
    .option('--check-run', 'Create a GitHub Check Run with pass/fail')
    .option('--output <path>', 'Write JSON output to file')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const { runPrAudit } = require('./pr-audit');
    const repo = options.repo || process.env.SENTINEL_REPO;
    const prNumber = parseInt(options.pr || process.env.SENTINEL_PR || '0', 10);
    if (!repo || !prNumber) {
        console.error('Error: --repo and --pr are required (or SENTINEL_REPO and SENTINEL_PR env vars)');
        process.exit(1);
    }
    const result = yield runPrAudit({
        repo,
        prNumber,
        author: options.author || process.env.SENTINEL_AUTHOR || '',
        diffFile: options.diffFile,
        comment: options.comment || !!process.env.SENTINEL_COMMENT,
        checkRun: options.checkRun || !!process.env.SENTINEL_CHECK_RUN,
        outputFile: options.output || process.env.SENTINEL_OUTPUT || undefined,
    });
    if (result.error) {
        console.error(result.error);
        process.exit(1);
    }
    if (!options.output) {
        console.log(JSON.stringify(result, null, 2));
    }
    if (result.verdict.decision === 'BLOCK') {
        process.exit(1);
    }
}));
// --- Workflow Commands ---
const workflow = program.command('workflow')
    .description('Multi-step security workflows (audit, scan, comment)');
workflow
    .command('pr-review')
    .description('Audit a single PR and post results')
    .option('--repo <owner/repo>', 'Repository name')
    .option('--pr <number>', 'PR number')
    .option('--comment', 'Post findings as PR comment')
    .option('--check-run', 'Create GitHub Check Run')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const { prReview } = require('./workflow');
    yield prReview({
        repo: options.repo,
        prNumber: parseInt(options.pr, 10),
        comment: options.comment,
        checkRun: options.checkRun,
    });
}));
workflow
    .command('full-audit')
    .description('Audit all open PRs (all repos or --repo R)')
    .option('--repo <owner/repo>', 'Single repository to audit (overrides --owner)')
    .option('--owner <login>', 'GitHub owner (default: authenticated user)')
    .option('--comment', 'Post findings as PR comments')
    .option('--check-run', 'Create GitHub Check Runs')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const { fullAudit } = require('./workflow');
    yield fullAudit({
        repo: options.repo,
        owner: options.owner,
        comment: options.comment,
        checkRun: options.checkRun,
    });
}));
// --- Network Auditor CLI ---
const networkCmd = program.command('network')
    .description('Audit AI agent network activity and detect repository exfiltration');
networkCmd
    .command('start')
    .description('Start a network audit session')
    .option('--http-proxy', 'Enable HTTP proxy interception (port 8089)')
    .option('--tls', 'Enable TLS interception (requires CA cert, port 9090)')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const { requestConsent } = yield Promise.resolve().then(() => __importStar(require('./network/legal-consent')));
    const auditor = new NetworkAuditor();
    if (!requestConsent(auditor['db'])) {
        console.log('Cannot start audit without consent.');
        process.exit(1);
    }
    if (options.httpProxy) {
        auditor['config'].enableHttpInterceptor = true;
    }
    if (options.tls) {
        auditor['config'].enableTlsInterceptor = true;
    }
    yield auditor.start();
    process.on('SIGINT', () => {
        auditor.stop();
        process.exit(0);
    });
}));
networkCmd
    .command('stop')
    .description('Stop the running network audit session')
    .action(() => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.stop();
    const verdict = auditor.getVerdict();
    if (verdict) {
        const { renderVerdict, renderDnaSummary } = yield Promise.resolve().then(() => __importStar(require('./network/render-network')));
        console.log(renderVerdict(verdict));
        console.log(renderDnaSummary(verdict.sessionDna));
    }
}));
networkCmd
    .command('status')
    .description('Show audit status and current session info')
    .action(() => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c;
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    const status = auditor.getStatus();
    if (status.running) {
        console.log(`Status: running (session: ${(_a = status.session) === null || _a === void 0 ? void 0 : _a.id})`);
        console.log(`Flows captured: ${(_b = status.session) === null || _b === void 0 ? void 0 : _b.flows.length}`);
        console.log(`Behaviors: ${(_c = status.session) === null || _c === void 0 ? void 0 : _c.behaviors.length}`);
    }
    else {
        console.log('Status: stopped');
    }
}));
networkCmd
    .command('history')
    .description('Show past audit sessions')
    .option('-l, --limit <number>', 'Number of sessions to show', '10')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.showHistory();
}));
networkCmd
    .command('session <id>')
    .description('Show details for a specific session')
    .action((id) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.showSessionDetail(id);
}));
networkCmd
    .command('export <id>')
    .description('Export session data')
    .option('--format <format>', 'Output format (json|markdown)', 'json')
    .action((id, options) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    const output = auditor.exportSession(id, options.format);
    console.log(output);
}));
networkCmd
    .command('trusted')
    .description('Manage trusted agents')
    .argument('<action>', 'list|add|remove')
    .argument('[name]', 'Agent name')
    .action((action, name) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    switch (action) {
        case 'list':
            auditor.listTrustedAgents();
            break;
        case 'add':
            if (name)
                auditor.addTrustedAgent(name);
            break;
        case 'remove':
            if (name)
                auditor.removeTrustedAgent(name);
            break;
        default:
            console.log('Usage: sentinel network trusted <list|add|remove> [name]');
    }
}));
networkCmd
    .command('doctor')
    .description('Check network auditor health, coverage, and sensor drift')
    .option('--metrics', 'Show runtime metrics')
    .option('--coverage', 'Show detailed coverage report')
    .option('--drift', 'Run sensor confidence drift test')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.doctor(options.metrics, options.coverage, options.drift);
}));
networkCmd
    .command('blindspots')
    .description('Manage the blind spot log (record detection failures)')
    .argument('<action>', 'list|add|show|update|delete|stats')
    .argument('[args...]', 'Additional arguments')
    .action((action, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.blindspots(action, ...(args || []));
}));
networkCmd
    .command('campaign')
    .description('Run validation campaigns against the detection pipeline')
    .argument('<action>', 'list|run|show|delete')
    .argument('[args...]', 'Additional arguments (tag filter, campaign id)')
    .action((action, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.campaign(action, ...(args || []));
}));
networkCmd
    .command('benchmark')
    .description('View benchmark history across engine versions')
    .argument('<action>', 'history')
    .action((action) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.benchmark(action);
}));
networkCmd
    .command('replay')
    .description('Replay recorded sessions through the detection pipeline')
    .argument('<action>', 'run|campaign|diff')
    .argument('[args...]', 'Session file, directory, or baseline/current dirs')
    .action((action, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.replay(action, ...(args || []));
}));
networkCmd
    .command('record')
    .description('Record a real OS session and replay through the pipeline')
    .argument('[duration_sec]', 'Recording duration in seconds (default: 30)')
    .argument('[output_dir]', 'Output directory (default: replay-corpus/recorded)')
    .argument('[tags...]', 'Optional tags')
    .option('--profile <id>', 'Canonical profile ID (e.g. git-clone)')
    .action((duration_sec, output_dir, tags, options) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    const args = [duration_sec || '30'];
    if (output_dir)
        args.push(output_dir);
    if (tags)
        args.push(...tags);
    if (options.profile)
        args.push('--profile', options.profile);
    yield auditor.record('start', ...args);
}));
networkCmd
    .command('corpus')
    .description('Inspect corpus coverage against canonical profiles')
    .argument('<action>', 'coverage')
    .argument('[corpus_dir]', 'Corpus directory (default: replay-corpus)')
    .action((action, corpus_dir) => __awaiter(void 0, void 0, void 0, function* () {
    const { NetworkAuditor } = yield Promise.resolve().then(() => __importStar(require('./network/auditor')));
    const auditor = new NetworkAuditor();
    auditor.corpus(action, corpus_dir);
}));
// --- Token Inspector CLI (Fase 1C) ---
program
    .command('token-inspect')
    .description('Inspect and classify a token string (GitHub PAT, AWS, Stripe, Slack, etc.)')
    .argument('<token>', 'Token string to inspect')
    .option('--check', 'Verify GitHub token scopes and expiration via API (no data stored)')
    .action((token, options) => __awaiter(void 0, void 0, void 0, function* () {
    const { inspectToken, formatInspectResult } = yield Promise.resolve().then(() => __importStar(require('./token_inspect')));
    try {
        const result = yield inspectToken(token, { check: options.check });
        console.log(formatInspectResult(result));
        if (result.riskLevel === 'critical' || result.riskLevel === 'high') {
            process.exitCode = 1;
        }
    }
    catch (err) {
        console.error(pc.red(`Token inspection failed: ${err instanceof Error ? err.message : err}`));
        process.exit(1);
    }
}));
// --- AI Workflows Help Section ---
// Appended to --help so AI agents see recommended workflows immediately
program.on('--help', () => {
    const w = (s) => `  ${s}`;
    const cmd = (c) => pc.cyan(c);
    const desc = (d) => pc.dim(d);
    console.log('');
    console.log(pc.magenta(pc.bold('  🤖 AI Workflows — recommended for AI agents')));
    console.log(pc.magenta('  ───────────────────────────────────────────'));
    console.log(w(`${cmd('sentinel workflow full-audit --repo R')}    — ${desc('Audit ALL PRs in one repo')}`));
    console.log(w(`${cmd('sentinel pr-audit --repo R --pr N')}        — ${desc('Audit a single PR')}`));
    console.log(w(`${cmd('sentinel scan <path>')}                      — ${desc('SAST scan (30 rules)')}`));
    console.log(w(`${cmd('sentinel verify-pkg <pkg> --details')}       — ${desc('Audit npm package')}`));
    console.log(w(`${cmd('sentinel doctor --deep')}                    — ${desc('Full system health + deps')}`));
    console.log(w(`${cmd('sentinel integrity')}                        — ${desc('Host integrity check')}`));
    console.log(w(`${cmd('sentinel guard status')}                     — ${desc('OS package interception')}`));
    console.log(w(`${cmd('sentinel permissions <pkg>')}                — ${desc('Capability audit')}`));
    console.log(w(`${cmd('sentinel baseline diff')}                    — ${desc('Drift detection')}`));
    console.log(w(`${cmd('sentinel memory --status')}                  — ${desc('Threat history vault')}`));
    console.log(w(`${cmd('sentinel memory --findings')}                — ${desc('Query past findings')}`));
    console.log(w(`${cmd('sentinel memory --threats')}                 — ${desc('Threat correlations')}`));
    console.log(w(`${cmd('sentinel install npm <pkg>')}                 — ${desc('Install pkg (scan then install)')}`));
    console.log(w(`${cmd('sentinel guard enable')}                     — ${desc('Intercept npm installs OS-wide')}`));
    console.log(w(`${cmd('sentinel precommit install')}                — ${desc('Block commits with threats')}`));
    console.log(w(`${cmd('sentinel prepush install')}                  — ${desc('Block pushes with threats')}`));
    console.log(w(`${cmd('sentinel audit-deps')}                       — ${desc('Full dep audit: OSV + reputation + provenance')}`));
    console.log(w(`${cmd('sentinel deps-tree <path>')}                 — ${desc('Walk transitive deps, depth 3')}`));
    console.log(w(`${cmd('sentinel verify-pkg <pkg>')}                 — ${desc('Audit single npm pkg (SAST + OSV + typosquat)')}`));
    console.log(w(`${cmd('sentinel trust-cache status')}               — ${desc('Show cached package verdicts')}`));
    console.log(w(`${cmd('sentinel check-classified <path>')}          — ${desc('Classified data check')}`));
    console.log(w(`${cmd('sentinel token-inspect <token>')}            — ${desc('Classify and risk-assess a token')}`));
    console.log(w(`${cmd('sentinel token-inspect <token> --check')}    — ${desc('Verify GitHub token scopes via API')}`));
    console.log(w(`${cmd('sentinel network start')}                    — ${desc('Start AI agent network audit')}`));
    console.log(w(`${cmd('sentinel network stop')}                     — ${desc('Stop audit and get verdict')}`));
    console.log(w(`${cmd('sentinel network status')}                   — ${desc('Show audit status')}`));
    console.log(w(`${cmd('sentinel network history')}                  — ${desc('Past audit sessions')}`));
    console.log(w(`${cmd('sentinel network session <id>')}             — ${desc('Session details')}`));
    console.log(w(`${cmd('sentinel network export <id>')}              — ${desc('Export session report')}`));
    console.log(w(`${cmd('sentinel network doctor')}                   — ${desc('Health, coverage & sensor diagnostics')}`));
    console.log(w(`${cmd('sentinel network doctor --metrics')}         — ${desc('Runtime metrics')}`));
    console.log(w(`${cmd('sentinel network doctor --coverage')}        — ${desc('Detailed coverage per sensor')}`));
    console.log(w(`${cmd('sentinel network doctor --drift')}           — ${desc('Sensor confidence drift test')}`));
    console.log(w(`${cmd('sentinel network blindspots list')}          — ${desc('List blind spot entries')}`));
    console.log(w(`${cmd('sentinel network blindspots add')}           — ${desc('Log a new blind spot')}`));
    console.log(w(`${cmd('sentinel network blindspots stats')}         — ${desc('Blind spot statistics')}`));
    console.log(w(`${cmd('sentinel network blindspots show <id>')}     — ${desc('Show blind spot detail')}`));
    console.log(w(`${cmd('sentinel network blindspots update <id>')}   — ${desc('Update blind spot status')}`));
    console.log(w(`${cmd('sentinel network campaign run')}             — ${desc('Run all validation scenarios')}`));
    console.log(w(`${cmd('sentinel network campaign run <tag>')}       — ${desc('Run scenarios with a specific tag')}`));
    console.log(w(`${cmd('sentinel network campaign list')}            — ${desc('List past campaign runs')}`));
    console.log(w(`${cmd('sentinel network campaign show <id>')}       — ${desc('Show campaign report')}`));
    console.log(w(`${cmd('sentinel network record [sec] [dir] [--profile <id>]')} — ${desc('Record session (use --profile for canonical tag)')}`));
    console.log(w(`${cmd('sentinel network corpus coverage')}           — ${desc('Show corpus coverage vs canonical profiles')}`));
    console.log(w(`${cmd('sentinel network replay run <file>')}        — ${desc('Replay a single session JSON through pipeline')}`));
    console.log(w(`${cmd('sentinel network replay campaign <dir>')}    — ${desc('Replay all sessions in directory as campaign')}`));
    console.log(w(`${cmd('sentinel network replay diff <a> <b>')}      — ${desc('Compare two replay campaign results')}`));
    console.log(w(`${cmd('sentinel network benchmark history')}        — ${desc('Show benchmark history across versions')}`));
    console.log(w(`${cmd('sentinel mcp')}                              — ${desc('MCP server for AI tools')}`));
    console.log(w(`${cmd('sentinel hub')}                              — ${desc('Interactive operations menu')}`));
    console.log('');
    console.log(pc.magenta(pc.bold('  🛡️  Verdicts: BLOCK=DO NOT MERGE | REVIEW=Human review | PASS=Safe')));
    console.log(pc.dim('  Report issues: https://github.com/anomalyco/opencode/issues'));
});
// Default: show help when no subcommand given
if (!process.argv.slice(2).length) {
    program.help();
}
else {
    program.parse(process.argv);
}
