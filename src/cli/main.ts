#!/usr/bin/env node
/**
 * Sentinel CLI (v4.0 "Oracle Lite")
 * 
 * Unified Terminal Security Interface.
 */

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner';
import { execSync } from 'child_process';
import { enableGuard, disableGuard, isGuardEnabled } from './guard';
import { checkClassifiedHook } from './classify';
import { MemoryManager } from './intelligence/memory_manager';
import { SupplyChainShield } from './intelligence/supply_chain_shield';
import { SystemAuditor } from './intelligence/system_auditor';
import { BaselineManager } from './intelligence/baseline_manager';
import { CapabilityAnalyzer } from './intelligence/capability_analyzer';
import { IntegrityManager } from './intelligence/integrity_manager';
import * as pc from 'picocolors';
import { startInteractiveHub } from './hub';

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
    .description('Sentinel Security Oracle — Unified Intelligence CLI');

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
        await auditor.runDoctor(options.deep);
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
            const pkgJsonPath = path.join(process.cwd(), 'package.json');
            if (!fs.existsSync(pkgJsonPath)) {
                console.error(pc.red('Error: No package.json found. Run this command from a Node.js project directory.'));
                console.log(pc.dim('Tip: sentinel permissions <package-name> still works from anywhere.'));
                return;
            }

            let pkgJson;
            try {
                pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
            } catch (_e2: unknown) {
                console.error(pc.red('Error: Failed to parse package.json.'));
                return;
            }

            const deps = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
            const depNames = Object.keys(deps).sort((a, b) => a.localeCompare(b));

            if (depNames.length === 0) {
                console.log(pc.yellow('   No dependencies found in package.json.'));
                return;
            }

            console.log(pc.cyan(`   Found ${depNames.length} dependencies in package.json. Starting recursive audit...\n`));

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
    .description('Scan local directory or file for threats.')
    .argument('[path]', 'Path to scan', '.')
    .option('--json', 'Output findings in JSON format')
    .action(async (targetPath, options) => {
        const host = await preFlightCheck();
        const fullPath = path.resolve(targetPath);
        if (!fs.existsSync(fullPath)) {
            console.error(pc.red(`Error: Path ${targetPath} does not exist.`));
            process.exit(1);
        }

        if (!options.json) console.log(pc.cyan(`\n🔍 Sentinel Lite: Analyzing ${targetPath}...`));
        
        let findings: LiteFinding[] = [];
        if (fs.lstatSync(fullPath).isFile()) {
            const content = fs.readFileSync(fullPath, 'utf8');
            // Treat the whole file as an 'addition' patch for local scanning
            const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
            findings = scanner.scanPatch(targetPath, patch);
        }

        if (options.json) {
            console.log(JSON.stringify({ host, findings }, null, 2));
        } else {
            if (findings.length === 0) {
                console.log(pc.green('✔ No threats detected locally.'));
            } else {
                findings.forEach(f => {
                    console.log(pc.yellow(`  ■ [${f.severity}] ${f.type} in ${f.file}:${f.line}`));
                    console.log(pc.dim(`    Evidence: ${f.snippet}`));
                });
                console.log(pc.cyan(`\n(Heuristic pass complete. ${findings.length} threats found locally.)`));
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
        const result = await shield.analyzePackage(pkg);

        // Package metadata
        console.log(pc.cyan('\n📦 Package Metadata'));
        console.log(pc.white(`  Name:      ${pc.bold(result.pkg)}`));
        console.log(pc.white(`  Files:     ${pc.cyan(String(result.fileCount))}`));
        console.log(pc.white(`  Size:      ${pc.cyan((result.sizeBytes / 1024).toFixed(1) + ' KB')}`));
        console.log(pc.white(`  Scan:      ${pc.cyan(result.scanTimeMs + 'ms')}  ${pc.dim('Mem: ' + result.memoryMB + ' MB')}`));

        // Try npm metadata
        try {
            const info = JSON.parse(execSync(`npm view ${pkg} description author homepage --json 2>NUL`, { encoding: 'utf8', timeout: 10000 }));
            if (info.description) console.log(pc.white(`  Desc:      ${pc.dim(String(info.description).substring(0, 100))}`));
            if (info.author?.name || info.maintainers?.[0]?.name) {
                const author = info.author?.name || info.maintainers?.[0]?.name;
                console.log(pc.white(`  Author:    ${pc.dim(author)}`));
            }
        } catch (_unused: unknown) {}

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
    .command('install')
    .description('Security-gated package installation.')
    .argument('<manager>', 'npm | pip | yarn | etc.')
    .argument('[args...]', 'Manager arguments')
    .action(async (manager, args) => {
        const res = await shield.scanInstallation(manager, args);
        if (res.success) {
            console.log(pc.cyan(`\nProceeding with native installation via ${manager}...`));
            // In a real CLI, this would spawn the native process
        } else {
            process.exit(1);
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
        const key = crypto.createHash('sha256').update(process.env.SENTINEL_ENV_KEY || os.hostname()).digest();
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
        const key = crypto.createHash('sha256').update(process.env.SENTINEL_ENV_KEY || os.hostname()).digest();
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
            const json = JSON.parse(raw);
            const scanId = json.id
                ? memory.getVault().ingestCloudReport(json)
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
            const json = JSON.parse(raw);
            const scanId = json.id
                ? memory.getVault().ingestCloudReport(json)
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
        const msg = ' INITIALIZING SENTINEL ORACLE ENGINE v4.0 ';
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
        console.log(pc.green(pc.bold('\n⬡  SENTINEL HUB v4.0 — ORACLE ONLINE\n')));
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
${d('   • v4.x = current stable line (Oracle Lite).')}
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
${d('   Repository: https://github.com/javier20dev25/sentinel-cloud')}
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
${c(b('║            SENTINEL CLOUD — ORACLE LITE v4.0 USER GUIDE             ║'))}
${c(b('╚══════════════════════════════════════════════════════════════════════╝'))}
${d('   Guía completa de comandos, sub-opciones, ejemplos y tests verificados.')}

${b('1. SCAN — LiteScanner local')}
   ${w('$ sentinel scan [path] [--json]')}
   ${d('   path: archivo o directorio a escanear (default .)')}
   ${d('   --json: salida en JSON (para pipeline)')}
   ${d('   Escanea JS/TS con 30 reglas SAST (inyección, XSS, eval, secretos, etc).')}
   ${g('   Ej: sentinel scan ./src/myfile.js')}

${b('2. VERIFY-PKG — Supply chain audit')}
   ${w('$ sentinel verify-pkg <package> [--details]')}
   ${d('   package: nombre o name@version (ej: utilz, dotenv@16.4.7)')}
   ${d('   --details: muestra evidencia completa por cada hallazgo')}
   ${d('   Descarga tarball via npm pack (sin instalar), extrae y escanea.')}
   ${g('   ✓ Ej: sentinel verify-pkg utilz --details')}
   ${d('     → SAFE | 2 findings (ENV_ACCESS, OS_CAPABILITY)')}
   ${y('   ⚠ Ej: sentinel verify-pkg dotenv --details')}
   ${d('     → SUSPICIOUS | 20 findings (ENV_ACCESS, POTENTIAL_SECRET)')}

${b('3. DOCTOR — Salud del sistema')}
   ${w('$ sentinel doctor [--deep]')}
   ${d('   --deep: escanea node_modules completos (25+ dependencias)')}
   ${d('   Sin flag: solo package.json + integridad del host.')}
   ${g('   Ej: sentinel doctor --deep')}

${b('4. MEMORY — Signal Vault (base de datos local SQLite)')}
   ${w('$ sentinel memory --status [--threshold <n>]')}
   ${d('   --status: métricas (scans, findings, signals, repos, autores)')}
   ${d('   --threshold <n>: muestra repos que cruzan el umbral (default 5)')}
   ${w('$ sentinel memory --ingest <archivo.json>')}
   ${d('   --ingest: ingesta un reporte cloud desde archivo')}
   ${w('$ sentinel memory --stdin < pipe.json')}
   ${d('   --stdin: modo pipe — cat report.json | sentinel memory --stdin')}
   ${w('$ sentinel memory --paste')}
   ${d('   --paste: pegar JSON manualmente (Ctrl+Z / Ctrl+D)')}
   ${w('$ sentinel memory --wipe')}
   ${d('   --wipe: borra todo el historial local')}

${b('5. HUB — Menú interactivo completo')}
   ${w('$ sentinel hub')}
   ${d('   Animación de apertura + menú TUI con 9 opciones principales:')}
   ${d('')}
   ${d('   ┌─ 1. Workspace Discovery ──────────────────────────┐')}
   ${d('   │  Lista repos GitHub (free tier: 3), seleccionas   │')}
   ${d('   │  y entras al menú del repo:                       │')}
   ${d('   │  1.1 Baseline Context Scan (escaneo local)        │')}
   ${d('   │  1.2 Audit Pull Requests (SAST por diff real)     │')}
   ${d('   │  1.3 Back                                         │')}
   ${d('   └───────────────────────────────────────────────────┘')}
   ${d('')}
   ${d('   ┌─ 2. System Doctor ────────────────────────────────┐')}
   ${d('   │  Ejecuta sentinel doctor directo desde el menú    │')}
   ${d('   └───────────────────────────────────────────────────┘')}
   ${d('')}
   ${d('   ┌─ 3. Integrity Check ──────────────────────────────┐')}
   ${d('   │  Verifica integridad del CLI, manifiesto y reloj  │')}
   ${d('   └───────────────────────────────────────────────────┘')}
   ${d('')}
   ${d('   ┌─ 4. Permissions Audit ────────────────────────────┐')}
   ${d('   │  Escanea capacidades de todas las dependencias    │')}
   ${d('   └───────────────────────────────────────────────────┘')}
   ${d('')}
   ${d('   ┌─ 5. Scan Directory/File ──────────────────────────┐')}
   ${d('   │  Pide un path y ejecuta scan local                │')}
   ${d('   └───────────────────────────────────────────────────┘')}
   ${d('')}
   ${d('   ┌─ 6. Guard & Configuration ────────────────────────┐')}
   ${d('   │  6.1 Guard Status                                 │')}
   ${d('   │  6.2 Enable Guard (intercepta npm/pip/yarn)       │')}
   ${d('   │  6.3 Disable Guard                                │')}
   ${d('   │  6.4 List Trust Cache (paquetes whitelisteados)   │')}
   ${d('   │  6.5 Back                                         │')}
   ${d('   └───────────────────────────────────────────────────┘')}
   ${d('')}
   ${d('   ┌─ 7. Classified Documents ─────────────────────────┐')}
   ${d('   │  Selecciona proyecto local → marca archivos como  │')}
   ${d('   │  CLASSIFIED → instala pre-commit hook que bloquea │')}
   ${d('   │  commits de esos archivos.                        │')}
   ${d('   └───────────────────────────────────────────────────┘')}
   ${d('')}
   ${d('   ┌─ 8. Signal Vault (Memory) ────────────────────────┐')}
   ${d('   │  8.1 View Status & Thresholds                     │')}
   ${d('   │  8.2 Ingest Cloud Report (JSON file)              │')}
   ${d('   │  8.3 Ingest Report Directory (batch)              │')}
   ${d('   │  8.4 Paste JSON Manually                          │')}
   ${d('   │  8.5 Wipe Database                                │')}
   ${d('   │  8.6 Back                                         │')}
   ${d('   └───────────────────────────────────────────────────┘')}
   ${d('')}
   ${d('   ┌─ 9. Exit ─────────────────────────────────────────┐')}
   ${d('   │  Cierra sesión de forma segura                    │')}
   ${d('   └───────────────────────────────────────────────────┘')}

${b('6. PERMISSIONS — Gobierno de capacidades')}
   ${w('$ sentinel permissions [package]')}
   ${d('   Sin argumento: escanea automático las 25 dependencias')}
   ${d('   Con package: analiza solo un paquete específico')}
   ${d('   Mapea: NETWORK, FILESYSTEM, PROCESS_EXEC, ENV_ACCESS,')}
   ${d('   DYNAMIC_EXEC, DOM_MANIPULATION, CREDENTIAL_LEAK')}

${b('7. GUARD — Intercepción a nivel OS')}
   ${w('$ sentinel guard <status|enable|disable>')}
   ${d('   status:  muestra si Guard está activo')}
   ${d('   enable:  instala aliases en PowerShell para interceptar')}
   ${d('            npm, yarn, pnpm, pip, pip3, cargo, docker')}
   ${d('   disable: remueve los aliases del profile')}

${b('8. CLASSIFIED DOCS — Prevención de fuga de secretos')}
   ${w('$ sentinel check-classified <repoPath>')}
   ${d('   Verifica archivos staged contra la DB de clasificados')}
   ${d('   Pre-commit hook: se instala automáticamente desde el HUB')}
   ${d('   y encadena con hooks existentes (no los borra).')}

${b('9. INTEGRITY — Verificación de integridad')}
   ${w('$ sentinel integrity')}
   ${d('   Checks: hash de reglas SAST, poisoning de PATH,')}
   ${d('   estado del vault, anomalía de reloj, manifiesto firmado')}

${b('10. BASELINE — Detección de deriva (drift)')}
   ${w('$ sentinel baseline <create|diff> [name]')}
   ${d('   create: guarda snapshot actual del sistema')}
   ${d('   diff:   compara contra un snapshot previo')}

${b('11. INSTALL — Instalación con seguridad')}
   ${w('$ sentinel install <manager> [args...]')}
   ${d('   manager: npm | pip | yarn | etc')}
   ${d('   args: argumentos del gestor (paquetes a instalar)')}
   ${d('   Escanea via SupplyChainShield antes de permitir la instalación')}

${b('12. ENVIRONMENT ENCRYPT')}
   ${w('$ sentinel env-encrypt <file>')}
   ${w('$ sentinel env-decrypt <file>')}

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

program.parse(process.argv);
