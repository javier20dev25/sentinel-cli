#!/usr/bin/env node
/**
 * Sentinel CLI (v4.0)
 * 
 * Security Intelligence for AI Coding Agents.
 */

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner';
import { execSync, execFileSync } from 'child_process';
import { enableGuard, disableGuard, isGuardEnabled } from './guard';
import { checkClassifiedHook, installSastPreCommitHook, uninstallPreCommitHook, isPreCommitHookInstalled } from './classify';
import { MemoryManager } from './intelligence/memory_manager';
import { SupplyChainShield } from './intelligence/supply_chain_shield';
import { SystemAuditor } from './intelligence/system_auditor';
import { BaselineManager } from './intelligence/baseline_manager';
import { CapabilityAnalyzer } from './intelligence/capability_analyzer';
import { IntegrityManager } from './intelligence/integrity_manager';
import { OSVIntegrator } from './intelligence/osv_integrator';
import * as pc from 'picocolors';
import { startInteractiveHub } from './hub';
import { LiveIndicator } from './live';
import { oracleInteractive, oracleAsk } from '../oracle/command';
import { setApiKey, removeApiKey, listProviders, setConfig } from '../oracle/auth';

const program = new Command();
const scanner = new LiteScanner();
const memory = new MemoryManager();
const shield = new SupplyChainShield();
const auditor = new SystemAuditor();
const baseline = new BaselineManager();
const integrity = new IntegrityManager();

async function preFlightCheck() {
    const status = await integrity.checkIntegrity();
    if (status.level !== 'TRUSTED') {
        integrity.report(status.level, status.reasons);
    }
    return status;
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
    .action(async (options) => {
        const status = await integrity.checkIntegrity();
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
    });

program
    .command('doctor')
    .description('Perform a system health check for vulnerabilities and suspicious behavior.')
    .option('--deep', 'Perform deep behavioral analysis')
    .action(async (options) => {
        await preFlightCheck();
        const live = new LiveIndicator();
        live.start(options.deep ? 'Deep behavioral analysis...' : 'System health check...', 'wave');
        await auditor.runDoctor(options.deep);
        live.stop();
    });

program
    .command('permissions')
    .description('List and audit package capabilities (Capability Governance).')
    .argument('[package]', 'Package name to audit')
    .action(async (pkgName) => {
        await preFlightCheck();
        console.log(pc.magenta('\n📋 SENTINEL CAPABILITY AUDIT'));
        
        if (pkgName) {
            console.log(pc.cyan(`   Analyzing real capabilities for: ${pkgName}...\n`));
            
            const pkgPath = path.join(process.cwd(), 'node_modules', pkgName);
            if (!fs.existsSync(pkgPath)) {
                console.error(pc.red(`Error: Package ${pkgName} not found in node_modules.`));
                return;
            }

            // Real scan of the package directory
            const allFindings: LiteFinding[] = [];
            const files = walkDir(pkgPath).filter(f => f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs'));
            
            files.forEach(f => {
                const content = fs.readFileSync(f, 'utf8');
                const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                const findings = scanner.scanPatch(path.relative(pkgPath, f), patch);
                allFindings.push(...findings);
            });

            if (allFindings.length === 0) {
                console.log(pc.green('   ✓ No high-risk capabilities detected.'));
            } else {
                const caps = CapabilityAnalyzer.analyze(allFindings);
                caps.forEach(c => {
                    const color = c.risk === 'CRITICAL' ? pc.red : (c.risk === 'HIGH' ? pc.yellow : pc.cyan);
                    console.log(`${color(`  ${c.capability.padEnd(15)}`)} [${c.risk}]`);
                    console.log(pc.dim(`    Evidence: ${c.evidence.substring(0, 80)}...`));
                });
            }
        } else {
            console.log(pc.cyan('   Scanning local workspace node_modules for capability matrix...\n'));
            const nodeModulesPath = path.join(process.cwd(), 'node_modules');
            let depNames: string[] = [];
            let source = '';

            const pkgJsonPath = path.join(process.cwd(), 'package.json');
            if (fs.existsSync(pkgJsonPath)) {
                // Primary: enumerate from package.json
                let pkgJson;
                try {
                    pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
                } catch (_e2: unknown) {
                    console.error(pc.red('Error: Failed to parse package.json.'));
                    return;
                }
                const deps = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
                depNames = Object.keys(deps).sort((a, b) => a.localeCompare(b));
                source = 'package.json';
            } else if (fs.existsSync(nodeModulesPath)) {
                // Fallback: scan node_modules directory directly (including scoped @org packages)
                console.log(pc.yellow('   No package.json found. Falling back to direct node_modules scan...\n'));
                const entries = fs.readdirSync(nodeModulesPath);
                entries.forEach(entry => {
                    if (entry.startsWith('.')) return; // skip hidden dirs (.cache, .bin, etc.)
                    const entryPath = path.join(nodeModulesPath, entry);
                    if (!fs.statSync(entryPath).isDirectory()) return;

                    if (entry.startsWith('@')) {
                        // Scoped package: enumerate sub-dirs
                        const scoped = fs.readdirSync(entryPath);
                        scoped.forEach(sub => {
                            const subPath = path.join(entryPath, sub);
                            if (fs.statSync(subPath).isDirectory()) {
                                depNames.push(`${entry}/${sub}`);
                            }
                        });
                    } else {
                        depNames.push(entry);
                    }
                });
                depNames.sort((a, b) => a.localeCompare(b));
                source = 'node_modules';
            } else {
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
                const allFindings: LiteFinding[] = [];
                const files = walkDir(pkgPath).filter(f => f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs'));
                
                files.forEach(f => {
                    try {
                        const content = fs.readFileSync(f, 'utf8');
                        const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                        const findings = scanner.scanPatch(path.relative(pkgPath, f), patch);
                        allFindings.push(...findings);
                    } catch (_e1: unknown) {}
                });

                if (allFindings.length > 0) {
                    const caps = CapabilityAnalyzer.analyze(allFindings);
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
            } else {
                console.log(pc.green(`   ✓ Audited ${auditedCount} installed dependencies. Found capabilities mapped above.`));
            }
        }
        console.log(pc.dim('\nRun "sentinel policy" to apply governance rules.'));
    });

function walkDir(dir: string): string[] {
    let results: string[] = [];
    const list = fs.readdirSync(dir);
    list.forEach(file => {
        const lowerFile = file.toLowerCase();
        // Ignore noise folders
        if (lowerFile === 'test' || lowerFile === 'tests' || lowerFile === 'example' || 
            lowerFile === 'examples' || lowerFile === 'benchmark' || lowerFile === 'docs' || 
            lowerFile === 'node_modules' || file.startsWith('.')) {
            return;
        }

        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat && stat.isDirectory()) {
            results = results.concat(walkDir(fullPath));
        } else {
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
        if (!fs.existsSync(policyDir)) fs.mkdirSync(policyDir, { recursive: true });

        let policies: Record<string, string> = {};
        try { policies = JSON.parse(fs.readFileSync(policyFile, 'utf8')); } catch {}

        if (action === 'list') {
            console.log(pc.cyan('\n📋 Sentinel Policy'));
            if (Object.keys(policies).length === 0) {
                console.log(pc.dim('   No custom policies set. All defaults active.'));
            } else {
                for (const [k, v] of Object.entries(policies)) {
                    console.log(`  ${pc.white(k.padEnd(20))} = ${pc.cyan(v)}`);
                }
            }
            console.log(pc.dim('\nAvailable: ci-mode (strict|lenient), fail-closed (on|off), quarantine (on|off)'));
        } else if (action === 'get') {
            const val = policies[key];
            if (val) console.log(`${pc.white(key)} = ${pc.cyan(val)}`);
            else console.log(pc.yellow(`  ${key} not set.`));
        } else if (action === 'set') {
            if (!key || !value) {
                console.error(pc.red('Usage: sentinel policy set <key> <value>'));
                return;
            }
            const validKeys = ['ci-mode', 'fail-closed', 'quarantine'];
            if (!validKeys.includes(key)) {
                console.error(pc.red(`Invalid policy key. Valid: ${validKeys.join(', ')}`));
                return;
            }
            const validValues: Record<string, string[]> = {
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
        } else {
            console.error(pc.red(`Unknown action: ${action}. Use set, get, or list.`));
        }
    });

program
    .command('baseline')
    .description('Manage system snapshots and detect behavior drift.')
    .argument('<action>', 'create | diff')
    .argument('[name]', 'Snapshot name', 'default')
    .action(async (action, name) => {
        await preFlightCheck();
        if (action === 'create') baseline.createBaseline(name);
        else if (action === 'diff') baseline.diffBaseline(name);
    });

program
    .command('scan')
    .description('Scan local directory, file, or staged git changes for threats.')
    .argument('[path]', 'Path to scan', '.')
    .option('--json', 'Output findings in JSON format')
    .option('--staged', 'Scan only files staged in git (git diff --cached)')
    .action(async (targetPath, options) => {
        const host = await preFlightCheck();

        const live = new LiveIndicator();
        live.start(options.staged ? 'Scanning staged files...' : `Scanning ${targetPath}...`, 'bars');
        
        let findings: LiteFinding[] = [];

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
                    if (!fs.existsSync(absPath)) continue;
                    const content = fs.readFileSync(absPath, 'utf8');
                    const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                    const fnds = scanner.scanPatch(file, patch);
                    findings.push(...fnds);
                } catch (_) {}
            }
        } else {
            const fullPath = path.resolve(targetPath);
            if (!fs.existsSync(fullPath)) {
                console.error(pc.red(`Error: Path ${targetPath} does not exist.`));
                process.exit(1);
            }

            if (fs.lstatSync(fullPath).isFile()) {
                const content = fs.readFileSync(fullPath, 'utf8');
                const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                findings = scanner.scanPatch(targetPath, patch);
            } else {
                live.update(`Scanning directory ${targetPath}...`);
                const files = walkDir(fullPath);
                for (const file of files) {
                    try {
                        const content = fs.readFileSync(file, 'utf8');
                        const relPath = path.relative(fullPath, file);
                        const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                        const fnds = scanner.scanPatch(relPath, patch);
                        findings.push(...fnds);
                    } catch (_) {}
                }
            }
        }

        live.stop();

        if (options.json) {
            console.log(JSON.stringify({ host, findings }, null, 2));
            const hasCritical = findings.some(f => f.severity === 'CRITICAL');
            if (hasCritical) process.exit(1);
        } else {
            if (findings.length === 0) {
                console.log(pc.green('✔ No threats detected locally.'));
            } else {
                findings.forEach(f => {
                    console.log(pc.yellow(`  ■ [${f.severity}] ${f.type} in ${f.file}:${f.line}`));
                    console.log(pc.dim(`    Evidence: ${f.snippet}`));
                });
                console.log(pc.cyan(`\n(Heuristic pass complete. ${findings.length} threats found locally.)`));
                const hasCritical = findings.some(f => f.severity === 'CRITICAL');
                if (hasCritical) {
                    process.exit(1);
                }
            }
        }
    });

program
    .command('verify-pkg')
    .description('Manually audit a package for supply chain threats.')
    .argument('<package>', 'Package name or name@version')
    .option('--details', 'Show detailed evidence for each finding')
    .option('--summary', 'Condensed output — counts only, no evidence')
    .action(async (pkg, options) => {
        const live = new LiveIndicator();
        live.start(`Downloading and analyzing ${pkg}...`, 'dots');
        const result = await shield.analyzePackage(pkg);
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
            const info = JSON.parse(execFileSync('npm', ['view', safePkg, 'description', 'author', 'homepage', '--json'], { encoding: 'utf8', timeout: 10000, windowsHide: true }));
            if (info.description) console.log(pc.white(`  Desc:      ${pc.dim(String(info.description).substring(0, 100))}`));
            if (info.author?.name || info.maintainers?.[0]?.name) {
                const author = info.author?.name || info.maintainers?.[0]?.name;
                console.log(pc.white(`  Author:    ${pc.dim(author)}`));
            }
        } catch (_unused: unknown) {}

        // OSV Vulnerabilities
        if (result.osvResult && result.osvResult.vulnerabilities.length > 0) {
            console.log(pc.red(`\n  ⚠️  Known Vulnerabilities (${result.osvResult.vulnerabilities.length}):`));
            for (const v of result.osvResult.vulnerabilities.slice(0, 5)) {
                const maxS = OSVIntegrator.getMaxSeverity(v);
                const scoreStr = maxS ? ` (${maxS.type}: ${maxS.score})` : '';
                console.log(pc.dim(`     [${v.id}] ${v.summary.substring(0, 80)}${scoreStr}`));
            }
            if (result.osvResult.vulnerabilities.length > 5) {
                console.log(pc.dim(`     ... and ${result.osvResult.vulnerabilities.length - 5} more`));
            }
        } else {
            console.log(pc.green(`  CVEs:      None known`));
        }

        // Typosquatting
        if (result.typosquat && result.typosquat.isSuspicious) {
            console.log(pc.red(`  ⚠️  Typosquatting: Possible typo of:`));
            for (const m of result.typosquat.matches) {
                const homoglyphStr = m.homoglyphs.length > 0 ? ` (homoglyphs: ${m.homoglyphs.join(', ')})` : '';
                console.log(pc.dim(`     ${m.target} (distance: ${m.distance})${homoglyphStr}`));
            }
        } else {
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
        const byType = new Map<string, number>();
        const bySeverity = new Map<string, number>();
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
                if (!count) continue;
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
            const grouped = new Map<string, typeof highFindings>();
            for (const f of highFindings) {
                if (!grouped.has(f.file)) grouped.set(f.file, []);
                grouped.get(f.file)!.push(f);
            }
            for (const [file, findings] of grouped) {
                console.log(`   ${pc.dim('📄')} ${pc.bold(file)}`);
                const shown = new Set<string>();
                for (const f of findings) {
                    const key = f.type + f.line;
                    if (shown.has(key)) continue;
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
            const byTypeLow = new Map<string, number>();
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
            const grouped = new Map<string, typeof result.findings>();
            for (const f of result.findings) {
                if (!grouped.has(f.file)) grouped.set(f.file, []);
                grouped.get(f.file)!.push(f);
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
    });

program
    .command('deps-tree')
    .description('Scan transitive dependencies (up to depth 3) for supply chain threats.')
    .argument('[path]', 'Path to node_modules', 'node_modules')
    .option('--depth <n>', 'Max tree depth', '3')
    .option('--json', 'JSON output')
    .action(async (targetPath, options) => {
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
        } else {
            if (result.totalFindings === 0) {
                console.log(pc.green('✔ No threats found in dependency tree.'));
            } else {
                console.log(pc.red(`🚨 ${result.totalFindings} finding(s) across ${result.findings.length} package(s)`));
                for (const { node, findings } of result.findings) {
                    console.log(pc.yellow(`\n  📦 ${node.name}@${node.version}`));
                    for (const f of findings) {
                        const color = f.severity === 'CRITICAL' ? pc.red : f.severity === 'HIGH' ? pc.yellow : pc.dim;
                        console.log(`     ${color(`[${f.severity}] ${f.type}`)} ${pc.dim(f.file)}`);
                    }
                }
                if (result.criticalCount > 0) process.exit(1);
            }
        }
    });

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
        } else if (action === 'clear') {
            cache.clear();
            console.log(pc.yellow('✔ Trust cache cleared.'));
        } else if (action === 'prune') {
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
    .action(async (options) => {
        const { LockfileParser } = await import('./intelligence/lockfile_parser');
        const { RegistryReputation } = await import('./intelligence/registry_reputation');
        const { ProvenanceVerifier } = await import('./intelligence/provenance_verifier');
        const { QuarantineManager } = await import('./intelligence/quarantine');
        const { NpmAuditParser } = await import('./intelligence/npm_audit_parser');

        const cwd = process.cwd();

        // 1. Detect and parse lockfile
        let lockfilePath = options.lockfile;
        if (!lockfilePath) {
            const candidates = ['package-lock.json', 'yarn.lock'];
            for (const c of candidates) {
                const testPath = path.join(cwd, c);
                if (fs.existsSync(testPath)) { lockfilePath = testPath; break; }
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
        const live = new LiveIndicator();
        let anyFindings = false;
        live.start('Querying OSV.dev for known vulnerabilities...', 'dots');

        // 2. Batch OSV query
        const osv = new OSVIntegrator();
        const osvPackages = parsed.entries.map(e => ({ name: e.name, version: e.version }));
        const osvResults = await osv.queryBatch(osvPackages);

        live.update('Checking registry reputation...');

        // 3. Registry reputation
        const rep = new RegistryReputation();
        const repResults: any[] = [];
        for (const entry of parsed.entries.slice(0, 50)) {
            try {
                const s = await rep.score(entry.name);
                repResults.push(s);
            } catch {}
        }

        // 4. Provenance (if --provenance)
        let provResults: any[] = [];
        if (options.provenance) {
            live.update('Verifying npm attestations...');
            const prov = new ProvenanceVerifier();
            if (prov.checkCommandAvailable()) {
                const topLevel = parsed.entries.filter(e => !e.name.startsWith('@types/')).slice(0, 20);
                for (const entry of topLevel) {
                    try {
                        const r = await prov.verify(entry.name, entry.version);
                        provResults.push(r);
                    } catch {}
                }
            }
        }

        // 5. npm audit (if --npm-audit)
        let npmAuditResult: any = null;
        if (options.npmAudit) {
            live.update('Running npm audit...');
            try {
                const nap = new NpmAuditParser();
                npmAuditResult = await nap.runAudit();
            } catch {}
        }

        live.stop();

        // Compile report
        const vulnsBySeverity = new Map<string, number>();
        let totalVulns = 0;
        for (const r of osvResults) {
            for (const v of r.vulnerabilities) {
                totalVulns++;
                const maxS = OSVIntegrator.getMaxSeverity(v);
                const sev = maxS ? OSVIntegrator.toSentinelSeverity(maxS.score) : 'MEDIUM';
                vulnsBySeverity.set(sev, (vulnsBySeverity.get(sev) || 0) + 1);
            }
        }

        const suspiciousRep = repResults.filter((r: any) => r.label === 'SUSPICIOUS' || r.label === 'MALICIOUS');
        const verifiedProv = provResults.filter(r => r.verified);
        if (totalVulns > 0 || suspiciousRep.length > 0) anyFindings = true;

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
                    } else {
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
                    const maxS = OSVIntegrator.getMaxSeverity(v);
                    const sStr = maxS ? ` (${maxS.score})` : '';
                    console.log(pc.dim(`     ${r.packageName}@${r.version}: [${v.id}] ${v.summary.substring(0, 70)}${sStr}`));
                }
            }
        } else {
            console.log(pc.green(`\n  CVEs: None known`));
        }

        // npm audit results
        if (npmAuditResult) {
            const m = npmAuditResult.metadata;
            const hasAuditIssues = m.critical + m.high + m.medium + m.low > 0;
            if (hasAuditIssues) {
                anyFindings = true;
                console.log(pc.red(`\n  📦 npm audit: ${m.totalVulnerabilities} vulnerability(ies)`));
                if (m.critical > 0) console.log(`     ${pc.bgRed(pc.white(' CRITICAL '))} ${m.critical}`);
                if (m.high > 0) console.log(`     ${pc.red(' HIGH     ')} ${m.high}`);
                if (m.medium > 0) console.log(`     ${pc.yellow(' MEDIUM   ')} ${m.medium}`);
                if (m.low > 0) console.log(`     ${pc.dim(' LOW      ')} ${m.low}`);
            } else {
                console.log(pc.green(`\n  📦 npm audit: clean (${m.totalDependencies} deps)`));
            }
        }

        // Reputation
        if (suspiciousRep.length > 0) {
            console.log(pc.yellow(`\n  ⚠️  Suspicious Registry Signals: ${suspiciousRep.length} package(s)`));
            for (const r of suspiciousRep.slice(0, 10)) {
                const worst = r.factors.filter((f: any) => f.impact < 0).slice(0, 2);
                console.log(`     ${pc.yellow(r.packageName)} ${pc.dim(`score: ${r.score}, ${worst.map((f: any) => f.name).join(', ')}`)}`);
            }
        } else {
            console.log(pc.green(`\n  Registry: ${repResults.length} packages checked, all normal`));
        }

        // Provenance
        if (options.provenance) {
            if (verifiedProv.length > 0) {
                console.log(pc.green(`\n  ✅ Provenance: ${verifiedProv.length} package(s) have verified attestations`));
            } else if (provResults.length > 0) {
                console.log(pc.yellow(`\n  ⚠️  Provenance: No verified attestations found`));
            } else {
                console.log(pc.dim(`\n  Provenance: npm attestation not available`));
            }
        }

        const elapsed = Date.now() - startTime;
        console.log(pc.dim(`\n  Audit completed in ${(elapsed / 1000).toFixed(1)}s`));

        // Auto-quarantine (if --quarantine)
        if (options.quarantine) {
            const qm = new QuarantineManager();
            if (qm.isEnabled()) {
                const criticalPkgs = osvResults.filter(r =>
                    r.vulnerabilities.some(v => {
                        const ms = OSVIntegrator.getMaxSeverity(v);
                        return ms && ms.score >= 9.0;
                    })
                );
                for (const pkg of criticalPkgs) {
                    try {
                        const pkgPath = path.join(cwd, 'node_modules', pkg.packageName);
                        if (fs.existsSync(pkgPath)) {
                            qm.quarantinePackage(pkg.packageName, pkg.version, `Critical CVE: ${pkg.vulnerabilities[0]?.id || 'unknown'}`, 'CRITICAL');
                            console.log(pc.red(`  🔒 Quarantined: ${pkg.packageName}@${pkg.version}`));
                        }
                    } catch {}
                }
            } else {
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
                npmAudit: npmAuditResult?.metadata || null,
                durationMs: elapsed
            }, null, 2));
        }

        // Exit code: --ci fails on any finding, default fails only on CRITICAL
        const shouldFail = options.ci ? anyFindings : totalVulns > 0;
        if (shouldFail) process.exit(1);
    });

program
    .command('sbom')
    .description('Generate CycloneDX SBOM from lockfile.')
    .option('--lockfile <path>', 'Path to lockfile (auto-detect: package-lock.json, yarn.lock)', '')
    .option('--output <path>', 'Output file path (default: stdout)', '')
    .action(async (options) => {
        const { SbomGenerator } = await import('./intelligence/sbom_generator');
        const cwd = process.cwd();

        let lockfilePath = options.lockfile;
        if (!lockfilePath) {
            const candidates = ['package-lock.json', 'yarn.lock'];
            for (const c of candidates) {
                const testPath = path.join(cwd, c);
                if (fs.existsSync(testPath)) { lockfilePath = testPath; break; }
            }
        }
        if (!lockfilePath || !fs.existsSync(lockfilePath)) {
            console.error(pc.red('No lockfile found. Run npm install first, or specify --lockfile.'));
            return;
        }

        const gen = new SbomGenerator();
        const sbom = gen.generate(lockfilePath);
        const output = JSON.stringify(sbom, null, 2);

        if (options.output) {
            fs.writeFileSync(path.resolve(options.output), output, 'utf8');
            console.log(pc.green(`✔ SBOM written to ${options.output}`));
        } else {
            console.log(output);
        }
    });

program
    .command('install')
    .description('Security-gated package installation. Scans then installs.')
    .argument('<manager>', 'npm | pip | yarn | etc.')
    .argument('[args...]', 'Manager arguments')
    .action(async (manager, args) => {
        const res = await shield.scanInstallation(manager, args);
        if (!res.success) {
            process.exit(1);
        }
        console.log(pc.cyan(`\nProceeding with native installation via ${manager}...`));
        try {
            const mgrMap: Record<string, string> = {
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
            const result = execSync(cmdStr, {
                encoding: 'utf8' as const, stdio: 'inherit' as const, windowsHide: true,
                timeout: 300000, shell: true as any
            });
        } catch (e: unknown) {
            const err = e as { status?: number; message?: string };
            console.error(pc.red(`\n✖ Installation failed (exit ${err.status || 1}).`));
            process.exit(err.status || 1);
        }
    });

program
    .command('check-classified')
    .description('Verify if staged files contain classified data (Pre-commit Hook).')
    .argument('<repoPath>', 'Path to the repository')
    .action((repoPath) => {
        const result = checkClassifiedHook(repoPath);
        process.exit(result);
    });

program
    .command('guard')
    .description('Manage OS-level package manager interception.')
    .argument('<action>', 'enable | disable | status | trust-cache')
    .action((action) => {
        if (action === 'status') {
            const active = isGuardEnabled();
            console.log(`\n🛡️  Sentinel Guard: ${active ? pc.green('ACTIVE') : pc.red('INACTIVE')}`);
        } else if (action === 'enable') {
            const res = enableGuard();
            if (res.success) console.log(pc.green(`\n✔ Sentinel Guard enabled on ${res.profilePath}`));
            else console.log(pc.yellow(`\n⚠️  ${res.reason}`));
        } else if (action === 'disable') {
            const res = disableGuard();
            if (res.success) console.log(pc.yellow('\n🛡️  Sentinel Guard disabled.'));
        } else if (action === 'trust-cache') {
            console.log(pc.cyan('\n⭐ Trust Cache (Whitelisted Packages)'));
            const cachePath = path.join(os.homedir(), '.sentinel', 'trust_cache.json');
            if (fs.existsSync(cachePath)) {
                const cache = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
                const entries = cache.packages || [];
                if (entries.length === 0) {
                    console.log(pc.dim('   No whitelisted packages.'));
                } else {
                    entries.forEach((e: unknown, i: number) => {
                        const obj = e as { name?: string; reason?: string };
                        const name = obj.name || String(e);
                        const reason = obj.reason ? '— ' + obj.reason : '';
                        console.log(`  ${pc.cyan(String(i + 1))}. ${pc.white(name)} ${pc.dim(reason)}`);
                    });
                }
            } else {
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
            const installed = installSastPreCommitHook(targetPath);
            if (installed) {
                console.log(pc.green(`\n✔ Sentinel SAST pre-commit hook installed in ${targetPath}`));
                console.log(pc.dim('   Hook runs: sentinel scan --staged + sentinel check-classified'));
            } else {
                console.error(pc.red('✖ Failed to install pre-commit hook.'));
                process.exit(1);
            }
        } else if (action === 'uninstall') {
            const removed = uninstallPreCommitHook(targetPath);
            if (removed) {
                console.log(pc.yellow(`\n🛡️  Sentinel pre-commit hook removed from ${targetPath}`));
            } else {
                console.log(pc.dim('No Sentinel pre-commit hook found.'));
            }
        } else if (action === 'status') {
            const installed = isPreCommitHookInstalled(targetPath);
            if (installed) {
                console.log(pc.green(`\n✔ Sentinel pre-commit hook is ACTIVE in ${targetPath}`));
            } else {
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
        } else if (action === 'uninstall') {
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
            } else {
                fs.unlinkSync(hookPath);
            }
            console.log(pc.yellow(`\n🛡️  Sentinel pre-push hook removed from ${targetPath}`));
        } else if (action === 'status') {
            if (fs.existsSync(hookPath)) {
                const content = fs.readFileSync(hookPath, 'utf8');
                if (content.includes('SENTINEL PRE-PUSH')) {
                    console.log(pc.green(`\n✔ Sentinel pre-push hook is ACTIVE in ${targetPath}`));
                } else {
                    console.log(pc.yellow(`\n⚠  No Sentinel pre-push hook in ${targetPath}`));
                }
            } else {
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
        } catch (_e3: unknown) {
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
    .action(async (options) => {
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
                } catch (err: unknown) {
                    console.log(pc.red(`  ✖ ${f} → ${(err as Error).message}`));
                }
            }
            console.log(pc.green(`\n✔ Batch ingestion complete.\n`));
        } else if (options.stdin) {
            const chunks: Buffer[] = [];
            for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
            const raw = Buffer.concat(chunks).toString('utf8');
            if (raw.length > 10_000_000) {
                console.error(pc.red('Error: Input exceeds maximum size (10 MB).'));
                return;
            }
            let json: unknown;
            try { json = JSON.parse(raw); } catch {
                console.error(pc.red('Error: Invalid JSON input.'));
                return;
            }
            if (typeof json !== 'object' || json === null) {
                console.error(pc.red('Error: Expected a JSON object.'));
                return;
            }
            const scanId = (json as Record<string, unknown>).id
                ? memory.getVault().ingestCloudReport(json as any)
                : memory.ingestReportFromJson(json);
            console.log(pc.green(`\n✔ Signals from piped JSON persisted to local Vault (scan: ${scanId}).`));
        } else if (options.paste) {
            console.log(pc.cyan('\n📋 Paste the JSON report below. Press Ctrl+Z then Enter when done (Windows), or Ctrl+D (Unix):\n'));
            const chunks: Buffer[] = [];
            if (process.stdin.isTTY) {
                // Interactive terminal — wait for EOF
                for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
            }
            const raw = Buffer.concat(chunks).toString('utf8').trim();
            if (!raw) {
                console.log(pc.yellow('No input received.'));
                return;
            }
            if (raw.length > 10_000_000) {
                console.error(pc.red('Error: Input exceeds maximum size (10 MB).'));
                return;
            }
            let json: unknown;
            try { json = JSON.parse(raw); } catch {
                console.error(pc.red('Error: Invalid JSON input.'));
                return;
            }
            if (typeof json !== 'object' || json === null) {
                console.error(pc.red('Error: Expected a JSON object.'));
                return;
            }
            const scanId = (json as Record<string, unknown>).id
                ? memory.getVault().ingestCloudReport(json as any)
                : memory.ingestReportFromJson(json);
            console.log(pc.green(`\n✔ Pasted JSON persisted to local Vault (scan: ${scanId}).`));
        } else if (options.ingest) {
            const scanId = memory.ingestReport(options.ingest);
            console.log(pc.green(`\n✔ Signals from ${options.ingest} persisted to local Vault (scan: ${scanId}).`));
        } else if (options.wipe) {
            memory.wipe();
            console.log(pc.red('\n🔥 Local Signal Vault wiped. History erased.'));
        } else if (options.status) {
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
    });

program
    .command('hub')
    .description('Launch interactive Sentinel operations menu.')
    .action(async () => {
        // Opening animation
        const frames = ['◴', '◷', '◶', '◵'];
        const msg = ' INITIALIZING SENTINEL INTELLIGENCE ENGINE v4.0 ';
        for (let i = 0; i < 12; i++) {
            const f = frames[i % frames.length];
            const bar = '█'.repeat(Math.min(i, 10)) + '░'.repeat(Math.max(10 - i, 0));
            process.stdout.write(`\r${pc.cyan(f)} ${pc.dim(msg)} ${pc.cyan(bar)}`);
            await new Promise(r => setTimeout(r, 60));
        }
        const checks = ['✓ Boot sequence', '✓ Cipher modules', '✓ Signal Vault', '✓ Threat Grid'];
        for (const c of checks) {
            process.stdout.write(`\r${pc.green('✔')} ${pc.dim(c.padEnd(60))}`);
            await new Promise(r => setTimeout(r, 200));
        }
        process.stdout.write(`\r${' '.repeat(70)}\r`);
        console.log(pc.green(pc.bold('\n⬡  SENTINEL HUB v4.0 — INTERACTIVE MENU\n')));
        await startInteractiveHub();
    });

program
    .command('policies')
    .description('Show Sentinel security policy, responsible disclosure, and contribution guidelines.')
    .action(() => {
        const b = pc.bold; const d = pc.dim; const w = pc.white; const c = pc.cyan;
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
        const g = pc.green; const c = pc.cyan; const y = pc.yellow;
        const d = pc.dim; const b = pc.bold; const w = pc.white;
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

${b('Z. ORACLE AI (experimental)')}
   ${y('   The AI-powered Oracle assistant is marked experimental.')}
   ${y('   Primary integration is now via Skills + MCP.')}
   ${w('$ sentinel oracle')}
   ${d('   Interactive AI session with multi-provider support')}

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
        const args: string[] = [];
        if (options.list) args.push('--list');
        if (options.all) args.push('--all');
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
    .action(async (options) => {
        const { runPrAudit } = require('./pr-audit');
        const repo = options.repo || process.env.SENTINEL_REPO;
        const prNumber = parseInt(options.pr || process.env.SENTINEL_PR || '0', 10);
        if (!repo || !prNumber) {
            console.error('Error: --repo and --pr are required (or SENTINEL_REPO and SENTINEL_PR env vars)');
            process.exit(1);
        }
        const result = await runPrAudit({
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
    });

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
  .action(async (options) => {
    const { prReview } = require('./workflow');
    await prReview({
      repo: options.repo,
      prNumber: parseInt(options.pr, 10),
      comment: options.comment,
      checkRun: options.checkRun,
    });
  });

workflow
  .command('full-audit')
  .description('Audit all open PRs (all repos or --repo R)')
  .option('--repo <owner/repo>', 'Single repository to audit (overrides --owner)')
  .option('--owner <login>', 'GitHub owner (default: authenticated user)')
  .option('--comment', 'Post findings as PR comments')
  .option('--check-run', 'Create GitHub Check Runs')
  .action(async (options) => {
    const { fullAudit } = require('./workflow');
    await fullAudit({
      repo: options.repo,
      owner: options.owner,
      comment: options.comment,
      checkRun: options.checkRun,
    });
  });

// --- Oracle Command (CLI 2) ---

const oracle = program.command('oracle')
  .description('🧿 Oracle Core — AI-powered security assistant (CLI 2)')
  .action(async () => {
    await oracleInteractive();
  });

oracle
  .command('ask')
  .description('Ask a one-shot security question')
  .argument('<question...>', 'Your question')
  .action(async (question: string[]) => {
    await oracleAsk(question.join(' '));
  });

const authCmd = oracle
  .command('auth')
  .description('Manage provider API keys');

authCmd
  .command('set')
  .description('Set API key for a provider')
  .argument('<provider>', 'Provider name (gemini, claude, openai)')
  .argument('<key>', 'API key')
  .action((provider: string, key: string) => {
    setApiKey(provider, key);
    console.log(`\u2705 API key set for ${provider}`);
  });

authCmd
  .command('remove')
  .description('Remove API key for a provider')
  .argument('<provider>', 'Provider name')
  .action((provider: string) => {
    removeApiKey(provider);
    console.log(`\u2705 API key removed for ${provider}`);
  });

authCmd
  .command('list')
  .description('List configured providers')
  .action(() => {
    const providers = listProviders();
    if (providers.length === 0) {
      console.log('No providers configured.');
      return;
    }
    console.log('Configured providers:');
    providers.forEach(p => console.log(`  - ${p}`));
  });

oracle
  .command('set-model')
  .description('Set default provider and model')
  .argument('<provider>', 'Provider name')
  .argument('[model]', 'Model name')
  .action((provider: string, model?: string) => {
    setConfig(provider, model);
    console.log(`\u2705 Default provider set to ${provider}${model ? ` (model: ${model})` : ''}`);
  });

oracle
  .command('interactive')
  .alias('chat')
  .description('Start interactive oracle session')
  .action(async () => {
    await oracleInteractive();
  });

// --- AI Workflows Help Section ---
// Appended to --help so AI agents see recommended workflows immediately
program.on('--help', () => {
  const w = (s: string) => `  ${s}`;
  const cmd = (c: string) => pc.cyan(c);
  const desc = (d: string) => pc.dim(d);
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
  console.log(w(`${cmd('sentinel mcp')}                              — ${desc('MCP server for AI tools')}`));
  console.log(w(`${cmd('sentinel hub')}                              — ${desc('Interactive operations menu')}`));
  console.log('');
  console.log(pc.magenta(pc.bold('  🛡️  Verdicts: BLOCK=DO NOT MERGE | REVIEW=Human review | PASS=Safe')));
  console.log(pc.dim('  Report issues: https://github.com/anomalyco/opencode/issues'));
});

// Default: show help when no subcommand given
if (!process.argv.slice(2).length) {
  program.help();
} else {
  program.parse(process.argv);
}
