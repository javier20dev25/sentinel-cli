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
import { calculateAgencyScore } from '../core/agency_score';
import { buildEvidenceCards } from '../core/evidence_card';
import { renderEvidenceCards } from './render_evidence';
import { renderEnrichedJson } from './export/json';
import { renderSarif } from './export/sarif';
import { renderMarkdown } from './export/markdown';
import { evaluatePolicy } from './export/policy';
import { detectCiEnv, postPrComment } from './ci_comment';
import { buildAgencyGraph } from '../core/agency_graph';
import { renderGraph } from './render_graph';
import { buildScenarios } from '../core/attack_scenario';
import { renderScenarios } from './render_scenario';
import { buildEvidencePacks } from '../core/evidence_pack';
import { renderEvidencePacks } from './render_evidence_pack';
import { saveSnapshot, loadHistory, computeTrend, loadAllHistory, loadBaseline, loadHistoryInWindow, computeTrendInWindow, RiskSnapshot } from '../core/risk_history';
import { renderTrend, renderSnapshotList } from './render_history';
import { computeDeltaVsLatest, computeDeltaVsBaseline } from '../core/pr_delta';
import { renderDelta } from './render_delta';
import { buildOwnershipGraph, groupByTeam } from '../core/ownership_graph';
import { renderOwnership } from './render_ownership';
import { renderTeams } from './render_teams';
import { saveGraphSnapshot, loadGraphHistory, computeGraphTrend, GraphSnapshot } from '../core/graph_persistence';
import { renderGraphHistory, renderGraphDiff } from './render_graph_history';
import { renderPdfHtml } from './export/pdf';
import { execSync, execFileSync } from 'child_process';
import { enableGuard, disableGuard, isGuardEnabled } from './guard';
import { checkClassifiedHook, installSastPreCommitHook, uninstallPreCommitHook, isPreCommitHookInstalled } from './classify';
import { MemoryManager } from './intelligence/memory_manager';
import { SupplyChainShield } from './intelligence/supply_chain_shield';
import { SystemAuditor } from './intelligence/system_auditor';
import { BaselineManager } from './intelligence/baseline_manager';
import { CapabilityAnalyzer } from './intelligence/capability_analyzer';
import { analyzeCapabilities, saveSnapshot as saveDriftSnapshot, loadPreviousSnapshot, computeDrift } from './intelligence/behavioral_drift';
import { renderDrift } from './render_drift';
import { IntegrityManager } from './intelligence/integrity_manager';
import { OSVIntegrator } from './intelligence/osv_integrator';
import * as pc from 'picocolors';
import { startInteractiveHub } from './hub';
import { LiveIndicator } from './live';
import { fetchCapabilities, loginWithToken, loadSession, saveSession, clearSession, getResolvedBaseUrl, resolveToken } from './cloud/cloud_client';
import type { CapabilityMap, Session } from './cloud/cloud_client';
import { runLookup } from './cloud/lookup';

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

const buildCmd = program.command('build')
    .description('Record, analyze, and explain build processes')

buildCmd
    .command('observe <command>')
    .alias('run')
    .description('Observe a build process — trust score, highlights, recommendations')
    .option('--cwd <path>', 'Working directory (default: current)')
    .option('--timeout <ms>', 'Timeout in milliseconds', '300000')
    .option('--provenance', 'Print full Build Provenance Report')
    .option('--verbose', 'Print technical details: evidence graph, Bayesian, dominators')
    .option('--json', 'Output as JSON for pipelines')
    .option('--save', 'Save build record for later comparison')
    .action(async (cmd: string, options) => {
        await preFlightCheck();
        const { recordBuild } = await import('./build/build-recorder');
        const { renderBuildSummary, renderBuildSummaryVerbose, renderBuildSummaryJson } = await import('./build/build-summary');
        const { renderBuildProvenance } = await import('./build/build-provenance');

        const parts = cmd.match(/(?:[^\s"]+|"[^"]*")+/g) || [cmd];
        const command = parts[0];
        const args = parts.slice(1).map((s: string) => s.replace(/^"(.*)"$/, '$1'));

        const cwd = options.cwd ? path.resolve(options.cwd) : process.cwd();
        const timeout = parseInt(options.timeout, 10);

        const sentinelDir = path.join(os.homedir(), '.sentinel', 'builds');
        const buildKey = command.replace(/[^a-z0-9]/gi, '_') + '_' + cwd.replace(/[^a-z0-9]/gi, '_');

        let prevRecord: any = null;
        const prevPath = path.join(sentinelDir, `${buildKey}_prev.json`);
        if (options.provenance || options.save) {
          if (fs.existsSync(prevPath)) {
            try { prevRecord = JSON.parse(fs.readFileSync(prevPath, 'utf8')) } catch {}
          }
        }

        if (!options.json) {
          console.log(pc.dim(`  Recording: ${cmd}`));
          console.log(pc.dim(`  CWD:       ${cwd}`));
          console.log('');
        }

        const record = await recordBuild(command, args, cwd, { timeoutMs: timeout });

        if (options.json) {
          console.log(renderBuildSummaryJson(record));
        } else if (options.verbose) {
          console.log(renderBuildSummaryVerbose(record));
        } else if (options.provenance) {
          console.log(renderBuildProvenance(record, prevRecord || undefined));
        } else {
          console.log(renderBuildSummary(record));
        }

        if (options.save) {
          try {
            fs.mkdirSync(sentinelDir, { recursive: true });
            const ts = (record.startTime || new Date().toISOString()).replace(/[^0-9]/g, '').substring(0, 14) + '_' + command.replace(/[^a-z0-9]/gi, '_');
            const savePath = path.join(sentinelDir, `${ts}.json`);
            fs.writeFileSync(savePath, JSON.stringify(record, null, 2), 'utf8');
            if (!options.json) console.log(pc.dim(`  Saved to ${savePath}`));
          } catch (e: any) {
            if (!options.json) console.log(pc.red(`  Could not save build record: ${e.message}`));
          }
        }
    });

buildCmd
    .command('explain')
    .description('Explain why a build differs from previous or release baseline')
    .argument('[build-id]', 'Build ID to explain (defaults to latest)')
    .option('--current', 'Explain the most recent build')
    .option('--release', 'Compare against release baseline instead of previous build')
    .option('--json', 'Output as JSON')
    .action(async (buildId: string | undefined, options) => {
        await preFlightCheck();
        const { explainBuild } = await import('./build/explain');

        const { result, error, output } = await explainBuild(
          buildId || (options.current ? undefined : undefined),
          options.release || false,
          options.json ? 'json' : 'human',
        );

        if (error) {
          console.error(pc.red(error));
          process.exit(1);
        }

        console.log(output);
    });

buildCmd
    .command('mark-release')
    .description('Mark a build as the current release baseline')
    .argument('<build-id>', 'Build ID to mark as release')
    .option('--tag <tag>', 'Release tag (e.g. v1.0.0)', 'release')
    .option('--force', 'Overwrite existing release baseline')
    .action(async (buildId: string, options) => {
        await preFlightCheck();
        const { markRelease, renderReleaseStatus } = await import('./build/release');

        const result = markRelease(buildId, options.tag, options.force);
        if (!result.success) {
          console.error(pc.red(result.error));
          process.exit(1);
        }

        console.log(pc.green(`Release ${options.tag} set to build ${buildId}`));
    });

buildCmd
    .command('release')
    .description('Show current release baseline information')
    .action(async () => {
        await preFlightCheck();
        const { renderReleaseStatus } = await import('./build/release');
        console.log(renderReleaseStatus());
    });

// ── Top Findings ──────────────────────────────────────────────
program
    .command('top')
    .description('Top findings from recent builds ranked by severity')
    .option('--limit <n>', 'Number of findings to show', '10')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
        await preFlightCheck();
        const { computeTrustScore } = await import('./build/build-summary');
        const fsMod = await import('fs');
        const pathMod = await import('path');
        const osMod = await import('os');
        const sentinelDir = pathMod.join(osMod.homedir(), '.sentinel', 'builds');

        if (!fsMod.existsSync(sentinelDir)) {
            console.log(pc.yellow('  No builds found. Run `sentinel build observe` first.'));
            return;
        }

        const files = fsMod.readdirSync(sentinelDir)
            .filter(f => f.endsWith('.json') && f !== 'releases.json')
            .sort()
            .reverse()
            .slice(0, 5);

        interface Finding {
            severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
            source: string
            text: string
            confidence: number
            buildId: string
        }

        const findings: Finding[] = []

        for (const f of files) {
            try {
                const record = JSON.parse(fsMod.readFileSync(pathMod.join(sentinelDir, f), 'utf8'));
                const buildId = record.startTime?.replace(/[^0-9]/g, '').substring(0, 14) || f.replace('.json', '');

                // Anomalies
                for (const a of (record.summary?.anomalies || [])) {
                    const sev: Finding['severity'] = a.includes('exfiltrat') || a.includes('contract') ? 'CRITICAL'
                        : a.includes('secret') || a.includes('suspicious') || a.includes('unknown') ? 'HIGH'
                        : a.includes('orphan') || a.includes('response file') ? 'MEDIUM'
                        : 'LOW'
                    findings.push({ severity: sev, source: 'anomaly', text: a, confidence: 0.9, buildId })
                }

                // Contract violations
                for (const v of (record.buildContractViolations || [])) {
                    const sev: Finding['severity'] = v.severity === 'critical' ? 'CRITICAL' : v.severity === 'high' ? 'HIGH' : 'MEDIUM'
                    findings.push({ severity: sev, source: 'contract', text: `${v.type}: ${v.description || 'violation'}`, confidence: 0.85, buildId })
                }

                // Secret exfiltration risks
                if (record.secretFlow?.exfiltrationRisks) {
                    for (const r of record.secretFlow.exfiltrationRisks) {
                        findings.push({ severity: 'CRITICAL', source: 'secret', text: `Exfiltration risk: ${r.secret || 'unknown'} → ${r.target || 'unknown'}`, confidence: 0.92, buildId })
                    }
                }

                // Secret accesses (no exfil)
                if (record.secretFlow?.secretAccesses && (!record.secretFlow.exfiltrationRisks || record.secretFlow.exfiltrationRisks.length === 0)) {
                    for (const a of record.secretFlow.secretAccesses) {
                        findings.push({ severity: 'MEDIUM', source: 'secret', text: `Secret accessed: ${a.filePath || a.secret || 'unknown'}`, confidence: 0.8, buildId })
                    }
                }

                // Orphan processes
                for (const o of (record.orphanProcesses || [])) {
                    findings.push({ severity: 'MEDIUM', source: 'process', text: `Orphan process: ${o.name} (${o.reason})`, confidence: 0.75, buildId })
                }

                // Response file changes
                for (const r of (record.responseFileChanges || []).filter((r: any) => r.changed)) {
                    findings.push({ severity: 'HIGH', source: 'build', text: `Response file modified: ${r.responseFile}`, confidence: 0.88, buildId })
                }

                // Network connections
                if ((record.summary?.networkConnections || 0) > 3) {
                    findings.push({ severity: 'MEDIUM', source: 'network', text: `${record.summary.networkConnections} network connections during build`, confidence: 0.7, buildId })
                }

                // Unknown build tools
                const unknownTools = (record.summary?.buildToolsDetected || []).filter((t: string) => {
                    const known = ['gcc', 'g++', 'clang', 'make', 'cmake', 'cargo', 'rustc', 'go', 'javac', 'node', 'tsc', 'esbuild', 'webpack', 'rollup', 'vite', 'python', 'pip', 'npm', 'yarn', 'pnpm']
                    return !known.some(k => t.toLowerCase().includes(k))
                })
                for (const t of unknownTools) {
                    findings.push({ severity: 'MEDIUM', source: 'toolchain', text: `Unknown build tool: ${t}`, confidence: 0.7, buildId })
                }

                // Trust score
                const trust = computeTrustScore(record);
                if (trust.verdict === 'BLOCK') {
                    findings.push({ severity: 'CRITICAL', source: 'trust', text: `Build blocked — trust score ${trust.score}/100`, confidence: 0.95, buildId })
                } else if (trust.verdict === 'REVIEW') {
                    findings.push({ severity: 'HIGH', source: 'trust', text: `Build requires review — trust score ${trust.score}/100`, confidence: 0.85, buildId })
                }
            } catch {}
        }

        // Sort by severity then confidence
        const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
        findings.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity] || b.confidence - a.confidence)

        const limit = parseInt(options.limit, 10)
        const topFindings = findings.slice(0, limit)

        if (options.json) {
            console.log(JSON.stringify({ totalFindings: findings.length, shown: topFindings.length, findings: topFindings }, null, 2));
            return;
        }

        console.log('');
        console.log(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')));
        console.log(pc.cyan(pc.bold('   TOP FINDINGS')));
        console.log(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')));
        console.log('');
        console.log(pc.dim(`  From ${files.length} recent build(s), ${findings.length} finding(s) total`));
        console.log('');

        if (topFindings.length === 0) {
            console.log(pc.green(pc.bold('  No findings detected. Builds look clean.')));
            console.log('');
            return;
        }

        for (let i = 0; i < topFindings.length; i++) {
            const f = topFindings[i]
            const sevColor = f.severity === 'CRITICAL' ? pc.red : f.severity === 'HIGH' ? pc.yellow : pc.dim
            const sevBg = f.severity === 'CRITICAL' ? pc.bgRed : f.severity === 'HIGH' ? pc.bgYellow : pc.bgGreen

            console.log(`  ${pc.bold(String(i + 1).padStart(2))}. ${sevBg(pc.white(` ${f.severity} `))} ${sevColor(f.text)}`)
            console.log(`      ${pc.dim('Source:')} ${f.source}  ${pc.dim('Confidence:')} ${(f.confidence * 100).toFixed(0)}%  ${pc.dim('Build:')} ${f.buildId}`)
            if (i < topFindings.length - 1) console.log(pc.dim('  ────────────────────────────────────────────'))
        }
        console.log('');
    });

// ── Trust Calibration ──────────────────────────────────────────
program
    .command('trust')
    .description('Trust calibration: corpus stats, feature vectors, model state')
    .option('--status', 'Show corpus and calibration status (default)')
    .option('--features', 'Show last extracted feature vector')
    .option('--labels', 'Show label distribution in corpus')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
        await preFlightCheck();
        const { getDefaultStore } = await import('../core/network/trust-calibration');
        const store = getDefaultStore();
        const all = store.getAll();
        const labelCounts = store.countByLabel();

        if (options.json) {
            console.log(JSON.stringify({ count: all.length, labels: labelCounts }, null, 2));
            return;
        }

        console.log('');
        console.log(pc.cyan(pc.bold('  Trust Calibration')));
        console.log(pc.dim('  ─────────────────'));
        console.log(`  ${pc.dim('Corpus size:')}      ${pc.white(String(all.length))} vectors`);
        console.log(`  ${pc.dim('Labeled:')}          ${pc.white(String(all.filter((v: any) => v.label).length))}`);
        console.log(`  ${pc.dim('Unlabeled:')}        ${pc.white(String(all.filter((v: any) => !v.label).length))}`);
        console.log('');

        const activeLabels = Object.entries(labelCounts).filter(([, count]) => count > 0);
        if (activeLabels.length > 0) {
            console.log(pc.bold('  Label distribution:'));
            const maxCount = Math.max(...activeLabels.map(([, c]) => c));
            for (const [label, count] of activeLabels.sort((a, b) => b[1] - a[1])) {
                const bar = '█'.repeat(Math.min(Math.round(count / maxCount * 20), 20));
                console.log(`    ${label.padEnd(16)} ${bar} ${count}`);
            }
            console.log('');
        }

        if (options.features && all.length > 0) {
            const last = all[all.length - 1] as any;
            console.log(pc.bold('  Last feature vector:'));
            console.log(`    Build:    ${last.buildId}`);
            console.log(`    Label:    ${last.label || '(unlabeled)'}`);
            console.log(`    Source:   ${last.labelSource || 'none'}`);
            const featureEntries: [string, number][] = [];
            for (const [key, val] of Object.entries(last.graph || {})) {
                if (typeof val === 'number' && val !== 0) featureEntries.push([`graph.${key}`, val]);
            }
            for (const [key, val] of Object.entries(last.centrality || {})) {
                if (typeof val === 'number' && val !== 0) featureEntries.push([`centrality.${key}`, val]);
            }
            for (const [key, val] of Object.entries(last.temporal || {})) {
                if (typeof val === 'number' && val !== 0) featureEntries.push([`temporal.${key}`, val]);
            }
            for (const [key, val] of Object.entries(last.bayesian || {})) {
                if (typeof val === 'number' && val !== 0) featureEntries.push([`bayesian.${key}`, val]);
            }
            for (const [key, val] of Object.entries(last.dominator || {})) {
                if (typeof val === 'number' && val !== 0) featureEntries.push([`dominator.${key}`, val]);
            }
            const sorted = featureEntries.sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
            for (const [key, value] of sorted.slice(0, 15)) {
                const bar = '█'.repeat(Math.min(Math.round(Math.abs(value) * 20), 20));
                console.log(`    ${key.padEnd(24)} ${bar} ${value.toFixed(3)}`);
            }
            if (sorted.length > 15) console.log(`    ... and ${sorted.length - 15} more features`);
            console.log('');
        }

        if (options.labels) {
            console.log(pc.bold('  All labels in corpus:'));
            for (const [label, count] of activeLabels) {
                console.log(`    ${label}: ${count}`);
            }
            console.log('');
        }
    });

// ── Continuous Learning ────────────────────────────────────────
program
    .command('learning')
    .description('Continuous learning pipeline: feedback, model versions, retrain detection')
    .option('--status', 'Show pipeline status (default)')
    .option('--feedback', 'Show feedback history')
    .option('--models', 'Show model version history')
    .option('--check', 'Check if retraining is needed')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
        await preFlightCheck();
        const { ContinuousLearner, renderContinuousLearner } = await import('../core/network/graph-analytics');

        // Create learner and populate from corpus
        const learner = new ContinuousLearner();
        const { getDefaultStore } = await import('../core/network/trust-calibration');
        const store = getDefaultStore();
        const all = store.getAll();

        // Simulate feedback from labeled corpus entries
        for (const v of all) {
            if (v.label) {
                learner.recordFeedback(v.buildId, v.label, v.label, 0.8);
            }
        }

        const stats = learner.getFeedbackStats();
        const latest = learner.getLatestModel();
        const history = learner.getVersionHistory();
        const shouldRetrain = learner.shouldRetrain();

        if (options.json) {
            console.log(JSON.stringify({ stats, latest, history, shouldRetrain }, null, 2));
            return;
        }

        console.log('');
        console.log(pc.cyan(pc.bold('  Continuous Learning Pipeline')));
        console.log(pc.dim('  ───────────────────────────'));
        console.log(`  ${pc.dim('Model versions:')}     ${pc.white(String(history.length))}`);
        console.log(`  ${pc.dim('Current model:')}      ${pc.white(latest?.version || 'none')}`);
        console.log(`  ${pc.dim('Feedback entries:')}   ${pc.white(String(stats.total))}`);
        const accColor = stats.accuracy >= 0.8 ? pc.green : stats.accuracy >= 0.5 ? pc.yellow : pc.red;
        console.log(`  ${pc.dim('Accuracy:')}           ${accColor((stats.accuracy * 100).toFixed(1) + '%')}`);
        console.log('');

        if (Object.keys(stats.byPredictedLabel).length > 0) {
            console.log(pc.bold('  By predicted label:'));
            for (const [label, data] of Object.entries(stats.byPredictedLabel)) {
                const pct = (data.correct / data.total * 100).toFixed(1);
                console.log(`    ${label.padEnd(16)} ${data.correct}/${data.total} (${pct}%)`);
            }
            console.log('');
        }

        if (options.feedback && all.length > 0) {
            console.log(pc.bold('  Recent corpus entries:'));
            for (const v of all.slice(-10)) {
                const labelColor = v.label === 'normal' ? pc.green : v.label === 'malicious' ? pc.red : v.label ? pc.yellow : pc.dim;
                const featureCount = Object.keys(v.graph || {}).length + Object.keys(v.centrality || {}).length + Object.keys(v.temporal || {}).length + Object.keys(v.bayesian || {}).length + Object.keys(v.dominator || {}).length;
                console.log(`    ${v.buildId}  ${labelColor(v.label || 'unlabeled')}  features=${featureCount}`);
            }
            console.log('');
        }

        if (options.models && history.length > 0) {
            console.log(pc.bold('  Model version history:'));
            for (const v of history.slice(-5)) {
                console.log(`    ${v.version}: acc=${(v.accuracy * 100).toFixed(1)}% auc=${(v.auc * 100).toFixed(1)}% n=${v.trainedOnExamples}`);
            }
            console.log('');
        }

        if (shouldRetrain) {
            console.log(pc.yellow(pc.bold('  ⚠ RETRAIN RECOMMENDED: accuracy drop detected')));
            console.log('');
        }

        if (all.length < 10) {
            console.log(pc.dim(`  Corpus has ${all.length} entries. Need 10+ for meaningful learning.`));
            console.log(pc.dim('  Run more builds to populate the corpus.'));
            console.log('');
        }
    });

program
    .command('benchmark')
    .description('Run corpus-based benchmark to measure FP/FN')
    .option('--corpus <path>', 'Path to corpus directory', './scripts/corpus')
    .option('--json', 'JSON output')
    .action(async (options) => {
        await preFlightCheck();
        const { runBenchmark, aggregateBenchmark } = await import('./benchmark');
        const { renderBenchmark } = await import('./render_benchmark');
        const results = runBenchmark(options.corpus);
        const aggregated = aggregateBenchmark(results);
        if (options.json) {
            console.log(JSON.stringify({ results, aggregated }, null, 2));
        } else {
            console.log(renderBenchmark(results, aggregated));
        }
    });

program
    .command('explain')
    .description('Explain security findings for files or directories — driver breakdown, correlations, recommendation')
    .argument('[paths...]', 'Files or directories to analyze')
    .action(async (paths: string[]) => {
        await preFlightCheck();
        const { explainFiles, renderExplain } = await import('./explain');
        const targets = paths.length > 0 ? paths : ['.'];
        const { result, files } = explainFiles(targets);
        console.log(renderExplain(result, files));
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

        const live = new LiveIndicator();
        live.start(`Analyzing ${pkg}@${version}...`, 'dots');

        const snapshot = analyzeCapabilities(pkg, version, resolvedPath);
        saveDriftSnapshot(snapshot);

        const previous = loadPreviousSnapshot(pkg, version);
        if (previous) {
            const result = computeDrift(previous, snapshot);
            live.stop();
            console.log(renderDrift(result));
        } else {
            live.stop();
            console.log(pc.green(`\n✔ Baseline snapshot saved for ${pkg}@${version} (no previous version to compare).\n`));
        }
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
            lowerFile === 'node_modules' || (file.startsWith('.') && file !== '.github' && 
            file !== '.cursorrules' && file !== '.windsurfrules' && !lowerFile.endsWith('.mdc'))) {
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

const MAX_PACKAGES_AUDITED = 120;
const MAX_FILES_PER_PACKAGE = 300;

function countInstalledPackages(root: string): number {
    const nm = path.join(root, 'node_modules');
    if (!fs.existsSync(nm)) return 0;
    let count = 0;
    try {
        for (const entry of fs.readdirSync(nm)) {
            if (entry.startsWith('.') || entry === '.bin') continue;
            const pkgDir = path.join(nm, entry);
            if (!fs.statSync(pkgDir).isDirectory()) continue;
            if (entry.startsWith('@')) {
                try {
                    for (const sub of fs.readdirSync(pkgDir)) {
                        if (fs.statSync(path.join(pkgDir, sub)).isDirectory()) count++;
                    }
                } catch {}
            } else {
                count++;
            }
        }
    } catch {}
    return count;
}

/**
 * Permissions-grade audit of installed node_modules packages. Scans each
 * top-level package's code files through the LiteScanner with paths prefixed
 * node_modules/... so a payload that shipped inside a tarball (ChainDrop) is
 * caught the same way `sentinel permissions` catches it.
 */
function scanInstalledPackages(root: string): LiteFinding[] {
    const out: LiteFinding[] = [];
    const nm = path.join(root, 'node_modules');
    if (!fs.existsSync(nm)) return out;

    let scanned = 0;
    const visit = (pkgRoot: string): void => {
        if (scanned >= MAX_PACKAGES_AUDITED) return;
        scanned++;
        let files: string[] = [];
        try {
            files = walkDir(pkgRoot).filter(f => f.endsWith('package.json') || /\.(js|ts|mjs|cjs)$/.test(f));
        } catch {}
        const capped = files.slice(0, MAX_FILES_PER_PACKAGE);
        for (const file of capped) {
            try {
                const content = fs.readFileSync(file, 'utf8');
                const rel = path.relative(root, file).replace(/\\/g, '/');
                const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                out.push(...scanner.scanPatch(rel, patch));
            } catch (_) {}
        }
    };

    try {
        for (const entry of fs.readdirSync(nm)) {
            if (scanned >= MAX_PACKAGES_AUDITED) break;
            if (entry.startsWith('.') || entry === '.bin') continue;
            const pkgDir = path.join(nm, entry);
            if (!fs.statSync(pkgDir).isDirectory()) continue;
            if (entry.startsWith('@')) {
                try {
                    for (const sub of fs.readdirSync(pkgDir)) {
                        const subPath = path.join(pkgDir, sub);
                        if (fs.statSync(subPath).isDirectory()) visit(subPath);
                    }
                } catch {}
            } else {
                visit(pkgDir);
            }
        }
    } catch {}
    return out;
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
    .option('--audit-node-modules', 'Also scan installed node_modules packages (permissions-grade audit)')
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
    .action(async (targetPath, options) => {
        const host = await preFlightCheck();

        const live = new LiveIndicator();
        live.start(options.staged ? 'Scanning staged files...' : `Scanning ${targetPath}...`, 'bars');
        
        let findings: LiteFinding[] = [];

        // node_modules coverage disclosure: installed packages run lifecycle
        // scripts on install, so silently skipping them hid the ChainDrop-class
        // payload. Default scan is source-only with an explicit warning; the
        // --audit-node_modules flag promotes node_modules to a real scan.
        let coverageMeta: { mode: string; skipped?: string[]; nodeModulesScanned?: number } | null = null;

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

                const nodeModulesPath = path.join(fullPath, 'node_modules');
                const hasNodeModules = fs.existsSync(nodeModulesPath);
                if (options.auditNodeModules) {
                    live.update(`Auditing installed node_modules packages...`);
                    findings.push(...scanInstalledPackages(fullPath));
                    coverageMeta = { mode: 'node_modules', nodeModulesScanned: countInstalledPackages(fullPath) };
                } else if (hasNodeModules) {
                    coverageMeta = { mode: 'source_only', skipped: ['node_modules'] };
                }
            }
        }

        live.stop();

        // Semantic false-positive filter for staged scans: the regex scanner
        // flags attack patterns inside test fixtures, string literals, comments
        // and its own detector rule definitions. Drop those before the policy
        // gate so the pre-commit hook never blocks over data instead of
        // execution. Secrets and filename-based findings are never dropped.
        // Run `scan --staged --json` to see the skippedFalsePositives count.
        let skippedFalsePositives = 0;
        if (options.staged && findings.length > 0) {
            const { classifyFinding, loadFileLines } = require('./semantic_filter');
            const lineCache = new Map<string, string[] | null>();
            const kept: LiteFinding[] = [];
            for (const f of findings) {
                let srcLines: string[] | null = null;
                if (f.file && f.line) {
                    if (!lineCache.has(f.file)) lineCache.set(f.file, loadFileLines(path.resolve(f.file)));
                    srcLines = lineCache.get(f.file) ?? null;
                }
                const verdict = classifyFinding(f, srcLines);
                if (verdict.keep) kept.push(f);
                else skippedFalsePositives++;
            }
            findings = kept;
        }

        const skippedNodeModules = !!coverageMeta && coverageMeta.mode === 'source_only';
        const nmWarning = skippedNodeModules
            ? pc.yellow('\n  ⚠  WARNING: node_modules skipped — installed packages run lifecycle scripts on install.\n     Run: sentinel scan . --audit-node-modules  (or: sentinel permissions) to audit installed packages.\n')
            : '';

        // Compute agency + cards once if any flag needs them
        const needsAgency = options.cards || options.sarif || options.md || options.graph || options.scenarios || options.execReport || options.saveHistory || options.diffMain || options.failOnScore !== undefined || options.failOnVerdict || options.ciComment;
        const agency = needsAgency ? calculateAgencyScore(findings) : null;
        const cards = (needsAgency && agency) ? buildEvidenceCards(findings, agency) : [];

        if (options.json) {
            if (options.cards && agency) {
                console.log(renderEnrichedJson(findings, agency, cards, { host: String(host.level || 'unknown'), scanTimeMs: 0, memoryMB: 0 }));
            } else {
                const payload: Record<string, unknown> = { host, findings };
                if (coverageMeta) payload.coverage = coverageMeta;
                if (options.staged) payload.skippedFalsePositives = skippedFalsePositives;
                if (nmWarning) payload.warning = nmWarning.replace(/\x1b\[[0-9;]*m/g, '').replace(/\n\s*/g, ' ').trim();
                console.log(JSON.stringify(payload, null, 2));
            }
        } else if (options.sarif && agency) {
            console.log(renderSarif(findings, agency, cards));
        } else if (options.md && agency) {
            console.log(renderMarkdown(findings.length, agency, cards));
        } else {
            if (nmWarning) console.log(nmWarning);
            if (findings.length === 0) {
                console.log(pc.green('✔ No threats detected locally.'));
            } else if (options.cards && agency) {
                console.log(renderEvidenceCards(cards, agency));
            } else {
                findings.forEach(f => {
                    console.log(pc.yellow(`  ■ [${f.severity}] ${f.type} in ${f.file}:${f.line}`));
                    console.log(pc.dim(`    Evidence: ${f.snippet}`));
                });
                console.log(pc.cyan(`\n(Heuristic pass complete. ${findings.length} threats found locally.)`));

                if (skippedFalsePositives > 0) {
                    console.log(pc.dim(`\n  (${skippedFalsePositives} false positives dropped by semantic context — run \`sentinel scan --staged --json\` for the raw count.)`));
                }

                if (coverageMeta && coverageMeta.mode === 'node_modules') {
                    const lifecycle = findings.filter(f => f.type === 'LIFECYCLE_CURL_BASH');
                    if (lifecycle.length > 0) {
                        const names = [...new Set(lifecycle.map(f => {
                            const m = (f.file || '').split('node_modules/')[1];
                            return m ? m.split('/').slice(0, m.startsWith('@') ? 2 : 1).join('/') : '';
                        }).filter(Boolean))];
                        if (names.length > 0) {
                            console.log(pc.dim(`  Deep audit: sentinel verify-pkg ${names.join(' ')} — signed tarball scan of the actual published package.`));
                        }
                    }
                }
            }
        }

        // Agency Graph (always after main output, before policy)
        if (options.graph && findings.length > 0 && agency) {
            const graph = buildAgencyGraph(findings, agency);
            console.log(renderGraph(graph));
        }

        // Attack Scenarios
        if (options.scenarios && findings.length > 0 && agency) {
            const graph = buildAgencyGraph(findings, agency);
            const scenarios = buildScenarios(graph.chains, agency);
            console.log(renderScenarios(scenarios));
        }

        // Executive Evidence Report
        if (options.execReport && findings.length > 0 && agency) {
            const graph = buildAgencyGraph(findings, agency);
            const scenarios = buildScenarios(graph.chains, agency);
            const packs = buildEvidencePacks(scenarios, graph, findings, cards, agency);
            console.log(renderEvidencePacks(packs));
        }

        // PDF Export (HTML for Save as PDF)
        if (options.pdf && findings.length > 0 && agency) {
            const graph = buildAgencyGraph(findings, agency);
            const scenarios = buildScenarios(graph.chains, agency);
            const packs = buildEvidencePacks(scenarios, graph, findings, cards, agency);
            const html = renderPdfHtml(packs, agency);

            const pdfPath = String(options.pdf);
            if (pdfPath) {
                fs.writeFileSync(path.resolve(pdfPath), html, 'utf8');
                console.log(pc.green(`\n✔ PDF report written to ${path.resolve(pdfPath)}`));
                console.log(pc.dim('   Open in browser and use Save as PDF / Print to generate PDF.\n'));
            } else {
                console.log(html);
            }
        }

        // PR Delta Analysis
        if (options.diffMain && agency) {
            const { delta, baseline } = computeDeltaVsBaseline(findings, agency, targetPath);
            if (delta && baseline) {
                console.log(renderDelta(delta));
            } else {
                console.log(pc.dim('\n  No baseline scan found. Run scan --save-history first.\n'));
            }
        }

        // Ownership Graph
        if (options.ownership && findings.length > 0) {
            const result = await buildOwnershipGraph(findings);
            console.log(renderOwnership(result));
        }

        // Team grouping via CODEOWNERS
        if (options.teams && findings.length > 0) {
            const result = await buildOwnershipGraph(findings);
            const teams = groupByTeam(result, targetPath);
            console.log(renderTeams(teams));
        }

        // Save history after all output
        if (options.saveHistory && agency) {
            const graph = buildAgencyGraph(findings, agency);
            const scenarios = buildScenarios(graph.chains, agency);
            saveSnapshot(targetPath, agency, scenarios);
        }

        // Save graph snapshot
        if (options.saveGraph && findings.length > 0 && agency) {
            const graph = buildAgencyGraph(findings, agency);
            const graphPath = saveGraphSnapshot(targetPath, graph);
            if (options.pdf || options.json || options.sarif || options.md) {
                // silent
            } else {
                console.log(pc.dim(`\n  Graph snapshot saved.\n`));
            }
        }

        // CI Comment: post Markdown report as PR comment (before policy engine)
        if (options.ciComment && agency) {
            const ciEnv = detectCiEnv();
            if (ciEnv.isCi && ciEnv.repo && ciEnv.prNumber && ciEnv.token) {
                const md = renderMarkdown(findings.length, agency, cards);
                const ciResult = await postPrComment({
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
                } else {
                    console.error(pc.red(`\n✖ Failed to post PR comment: ${ciResult.error}`));
                }
            } else {
                console.log(pc.yellow('\n⚠  --ci-comment specified but CI environment not detected.'));
            }
        }

        // Policy engine: evaluate all fail conditions (always last)
        const failVerdict = typeof options.failOnVerdict === 'string'
          ? (options.failOnVerdict.toUpperCase() as 'BLOCK' | 'REVIEW')
          : undefined;
        const policyResult = evaluatePolicy(findings, {
          agencyScore: agency?.agencyScore ?? 0,
          blastRadius: agency?.blastRadius ?? 'LOW',
          verdict: agency?.verdict ?? 'PASS',
          drivers: agency?.drivers ?? [],
          totalFindings: agency?.totalFindings ?? findings.length,
          criticalCount: agency?.criticalCount ?? findings.filter(f => f.severity === 'CRITICAL').length,
          highCount: agency?.highCount ?? findings.filter(f => f.severity === 'HIGH').length,
          correlations: agency?.correlations ?? [],
          recommendation: agency?.recommendation ?? '',
        }, {
          failOnScore: options.failOnScore,
          failOnCritical: options.failOnCritical ?? false,
          failOnHigh: options.failOnHigh ?? false,
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
    });

program
    .command('history')
    .description('Show risk history and trend for a repository')
    .argument('[path]', 'Repository path', '.')
    .option('--days <n>', 'Show only last N days', (v) => parseInt(v, 10))
    .option('--branch <name>', 'Filter to specific branch')
    .action(async (repoPath, options) => {
        const fullPath = path.resolve(repoPath);

        let snapshots: RiskSnapshot[];
        if (options.days) {
            snapshots = loadHistoryInWindow(fullPath, options.days);
        } else {
            snapshots = loadHistory(fullPath);
        }

        if (options.branch) {
            snapshots = snapshots.filter(s => s.branch === options.branch);
        }

        if (snapshots.length === 0) {
            const allRepos = loadAllHistory();
            if (allRepos.size > 0) {
                console.log(renderSnapshotList(allRepos));
            } else {
                console.log(pc.dim('\n  No history found. Run scan --save-history to start tracking.\n'));
            }
            return;
        }

        const trend = computeTrend(snapshots);

        const baseline = snapshots.find(s => s.branch === 'main' || s.branch === 'master') || null;

        console.log(renderTrend(trend, {
            windowDays: options.days || undefined,
            branch: options.branch,
            baselineScore: baseline?.agencyScore,
            baselineCritical: baseline?.criticalCount,
        }));
    });

const graphCmd = program.command('graph')
  .description('Manage agency graph snapshots for trend analysis');

graphCmd
  .command('history')
  .description('Show graph snapshot history with chain count trend')
  .argument('[path]', 'Repository path', '.')
  .action(async (repoPath) => {
    const fullPath = path.resolve(repoPath);
    const snapshots = loadGraphHistory(fullPath);
    console.log(renderGraphHistory(snapshots));
  });

graphCmd
  .command('diff')
  .description('Show diff between latest two graph snapshots')
  .argument('[path]', 'Repository path', '.')
  .action(async (repoPath) => {
    const fullPath = path.resolve(repoPath);
    const snapshots = loadGraphHistory(fullPath);
    if (snapshots.length === 0) {
      console.log(pc.dim('\n  No graph snapshots found. Run scan --save-graph to start tracking.\n'));
      return;
    }
    const sorted = [...snapshots].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const current = sorted[sorted.length - 1];
    const previous = sorted.length >= 2 ? sorted[sorted.length - 2] : null;
    console.log(renderGraphDiff(previous, current));
  });

// ── Graph Analytics (evidence graph advanced) ──────────────────
graphCmd
    .command('analytics')
    .alias('inspect')
    .description('Advanced graph analytics: centrality, dominators, Bayesian shifts, critical path')
    .argument('[build-id]', 'Build ID to analyze (loads from saved builds)')
    .option('--compare <build-id>', 'Compare against another build')
    .option('--json', 'Output as JSON')
    .action(async (buildId: string | undefined, options) => {
        await preFlightCheck();
        const { getDefaultStore } = await import('../core/network/trust-calibration');
        const store = getDefaultStore();
        const all = store.getAll();

        let record: any = null;
        if (buildId) {
            record = all.find((v: any) => v.buildId === buildId);
        } else if (all.length > 0) {
            record = all[all.length - 1];
        }

        if (!record) {
            console.log(pc.yellow('  No build records found. Run `sentinel build observe` first.'));
            return;
        }

        const fsMod = await import('fs');
        const pathMod = await import('path');
        const osMod = await import('os');
        const sentinelDir = pathMod.join(osMod.homedir(), '.sentinel', 'builds');
        let fullRecord: any = null;

        if (fsMod.existsSync(sentinelDir)) {
            const files = fsMod.readdirSync(sentinelDir).filter(f => f.endsWith('.json')).sort();
            for (const f of files) {
                try {
                    const data = JSON.parse(fsMod.readFileSync(pathMod.join(sentinelDir, f), 'utf8'));
                    if (data.evidenceGraph) {
                        fullRecord = data;
                        break;
                    }
                } catch {}
            }
        }

        if (!fullRecord || !fullRecord.evidenceGraph) {
            console.log(pc.yellow('  No evidence graph found in saved builds.'));
            console.log(pc.dim('  Run `sentinel build observe --save` to save a build with evidence graph.'));
            return;
        }

        const { buildTemporalEvidenceGraph, buildBayesianNetwork, analyzeDominators, computeFullGraphMetrics } = await import('../core/network/temporal-graph');
        const { computeGraphStats } = await import('../core/network/evidence-graph');
        const { computeGraphDiff, renderGraphDiff: renderDiff } = await import('../core/network/graph-analytics');

        const evGraph = fullRecord.evidenceGraph;
        const teg = buildTemporalEvidenceGraph(evGraph);
        const bn = buildBayesianNetwork(evGraph);
        const da = analyzeDominators(evGraph);
        const metrics = computeFullGraphMetrics(evGraph, teg, bn, da);
        const graphStats = computeGraphStats(evGraph);

        if (options.compare) {
            let compareRecord: any = null;
            if (fsMod.existsSync(sentinelDir)) {
                const files = fsMod.readdirSync(sentinelDir).filter(f => f.endsWith('.json')).sort();
                for (const f of files) {
                    try {
                        const data = JSON.parse(fsMod.readFileSync(pathMod.join(sentinelDir, f), 'utf8'));
                        if (data.evidenceGraph && data.buildId === options.compare) {
                            compareRecord = data;
                            break;
                        }
                    } catch {}
                }
            }

            if (!compareRecord || !compareRecord.evidenceGraph) {
                console.log(pc.red(`  Build ${options.compare} not found or has no evidence graph.`));
                return;
            }

            const diff = computeGraphDiff(evGraph, compareRecord.evidenceGraph);
            const diffLines = renderDiff(diff);

            console.log('');
            for (const line of diffLines) {
                if (line.includes('Risk score')) {
                    const riskColor = diff.riskScore > 0.5 ? pc.red : diff.riskScore > 0.2 ? pc.yellow : pc.green;
                    console.log(`  ${riskColor(pc.bold(line))}`);
                } else if (line.startsWith('    ⚠')) {
                    console.log(pc.yellow(`  ${line}`));
                } else if (line.startsWith('    +')) {
                    console.log(pc.green(`  ${line}`));
                } else if (line.startsWith('    -')) {
                    console.log(pc.red(`  ${line}`));
                } else {
                    console.log(`  ${line}`);
                }
            }
            console.log('');
            return;
        }

        if (options.json) {
            console.log(JSON.stringify({ graphStats, metrics, temporal: { paths: teg.paths.length, avgLatency: teg.avgEdgeLatencyMs, criticalPathMs: teg.criticalPath.causalDelayMs }, bayesian: { globalPrior: bn.globalPrior, overallPosterior: bn.overallPosterior }, dominator: { dominant: da.dominantProcess, hijackRisk: da.hijackRiskScore, shift: da.toolchainShiftDetected } }, null, 2));
            return;
        }

        console.log('');
        console.log(pc.cyan(pc.bold('  Evidence Graph Analytics')));
        console.log(pc.dim('  ───────────────────────'));
        console.log(`  ${pc.dim('Build:')} ${fullRecord.buildId || 'unknown'}`);
        console.log(`  ${pc.dim('Nodes:')} ${graphStats.nodeCount}  |  ${pc.dim('Edges:')} ${graphStats.edgeCount}  |  ${pc.dim('Components:')} ${graphStats.componentCount}`);
        console.log(`  ${pc.dim('Confidence:')} avg=${graphStats.avgConfidence} min=${graphStats.minConfidence} max=${graphStats.maxConfidence}`);
        console.log('');

        console.log(pc.bold('  Graph Metrics:'));
        console.log(`    Density:      ${metrics.graphDensity}`);
        console.log(`    Entropy:      ${metrics.graphEntropy}`);
        console.log(`    Max depth:    ${metrics.maxDepth}`);
        console.log(`    Is DAG:       ${metrics.isDag}`);
        console.log(`    SCC count:    ${metrics.sccCount}`);
        console.log(`    IDom count:   ${metrics.idomCount}`);
        console.log('');

        console.log(pc.bold('  Temporal:'));
        console.log(`    Paths:            ${teg.paths.length}`);
        console.log(`    Avg edge latency: ${teg.avgEdgeLatencyMs}ms`);
        console.log(`    Max edge latency: ${teg.maxEdgeLatencyMs}ms`);
        console.log(`    Critical path:    ${teg.criticalPath.causalDelayMs}ms (${teg.criticalPath.nodes.length} nodes)`);
        console.log(`    Longest chain:    ${teg.longestCausalChain.nodes.length} nodes`);
        console.log('');

        console.log(pc.bold('  Bayesian:'));
        console.log(`    Global prior:     ${bn.globalPrior}`);
        console.log(`    Overall posterior: ${bn.overallPosterior}`);
        const sortedRels = [...bn.relations].sort((a, b) => b.posteriorGivenEvidence - a.posteriorGivenEvidence);
        for (const r of sortedRels.slice(0, 5)) {
            const delta = r.posteriorGivenEvidence - r.priorP;
            const deltaStr = delta >= 0 ? `+${delta.toFixed(3)}` : delta.toFixed(3);
            console.log(`    ${r.relation.padEnd(24)} prior=${r.priorP} posterior=${r.posteriorGivenEvidence} (Δ${deltaStr})`);
        }
        console.log('');

        console.log(pc.bold('  Dominator:'));
        const domNode = evGraph.nodes.find((n: any) => n.id === da.dominantProcess);
        console.log(`    Dominant:         ${domNode?.label || da.dominantProcess || 'none'}`);
        console.log(`    Hijack risk:      ${(da.hijackRiskScore * 100).toFixed(1)}%`);
        if (da.toolchainShiftDetected) {
            console.log(pc.red(pc.bold(`    ⚠ TOOLCHAIN SHIFT DETECTED`)));
        }
        if (da.anomalySignals.length > 0) {
            for (const s of da.anomalySignals) {
                console.log(pc.yellow(`    ⚠ ${s}`));
            }
        }
        if (da.dominantPath.length > 0) {
            console.log(`    Path: ${da.dominantPath.join(' → ')}`);
        }
        console.log('');
    });

// ── Inspect (top-level alias for graph analytics) ──────────────
program
    .command('inspect')
    .description('Investigate a build: evidence graph, centrality, dominators, Bayesian shifts')
    .argument('[build-id]', 'Build ID to analyze (loads from saved builds)')
    .option('--compare <build-id>', 'Compare against another build')
    .option('--json', 'Output as JSON')
    .action(async (buildId: string | undefined, options) => {
        // Delegate to graph analytics
        await preFlightCheck();
        const { getDefaultStore } = await import('../core/network/trust-calibration');
        const store = getDefaultStore();
        const all = store.getAll();

        let record: any = null;
        if (buildId) {
            record = all.find((v: any) => v.buildId === buildId);
        } else if (all.length > 0) {
            record = all[all.length - 1];
        }

        if (!record) {
            console.log(pc.yellow('  No build records found. Run `sentinel build observe` first.'));
            return;
        }

        const fsMod = await import('fs');
        const pathMod = await import('path');
        const osMod = await import('os');
        const sentinelDir = pathMod.join(osMod.homedir(), '.sentinel', 'builds');
        let fullRecord: any = null;

        if (fsMod.existsSync(sentinelDir)) {
            const files = fsMod.readdirSync(sentinelDir).filter(f => f.endsWith('.json')).sort();
            for (const f of files) {
                try {
                    const data = JSON.parse(fsMod.readFileSync(pathMod.join(sentinelDir, f), 'utf8'));
                    if (data.evidenceGraph) {
                        fullRecord = data;
                        break;
                    }
                } catch {}
            }
        }

        if (!fullRecord || !fullRecord.evidenceGraph) {
            console.log(pc.yellow('  No evidence graph found in saved builds.'));
            console.log(pc.dim('  Run `sentinel build observe --save` to save a build with evidence graph.'));
            return;
        }

        const { buildTemporalEvidenceGraph, buildBayesianNetwork, analyzeDominators, computeFullGraphMetrics } = await import('../core/network/temporal-graph');
        const { computeGraphStats } = await import('../core/network/evidence-graph');
        const { computeGraphDiff, renderGraphDiff: renderDiff } = await import('../core/network/graph-analytics');

        const evGraph = fullRecord.evidenceGraph;
        const teg = buildTemporalEvidenceGraph(evGraph);
        const bn = buildBayesianNetwork(evGraph);
        const da = analyzeDominators(evGraph);
        const metrics = computeFullGraphMetrics(evGraph, teg, bn, da);
        const graphStats = computeGraphStats(evGraph);

        if (options.compare) {
            let compareRecord: any = null;
            if (fsMod.existsSync(sentinelDir)) {
                const files = fsMod.readdirSync(sentinelDir).filter(f => f.endsWith('.json')).sort();
                for (const f of files) {
                    try {
                        const data = JSON.parse(fsMod.readFileSync(pathMod.join(sentinelDir, f), 'utf8'));
                        if (data.evidenceGraph && data.buildId === options.compare) {
                            compareRecord = data;
                            break;
                        }
                    } catch {}
                }
            }

            if (!compareRecord || !compareRecord.evidenceGraph) {
                console.log(pc.red(`  Build ${options.compare} not found or has no evidence graph.`));
                return;
            }

            const diff = computeGraphDiff(evGraph, compareRecord.evidenceGraph);
            const diffLines = renderDiff(diff);

            console.log('');
            for (const line of diffLines) {
                if (line.includes('Risk score')) {
                    const riskColor = diff.riskScore > 0.5 ? pc.red : diff.riskScore > 0.2 ? pc.yellow : pc.green;
                    console.log(`  ${riskColor(pc.bold(line))}`);
                } else if (line.startsWith('    ⚠')) {
                    console.log(pc.yellow(`  ${line}`));
                } else if (line.startsWith('    +')) {
                    console.log(pc.green(`  ${line}`));
                } else if (line.startsWith('    -')) {
                    console.log(pc.red(`  ${line}`));
                } else {
                    console.log(`  ${line}`);
                }
            }
            console.log('');
            return;
        }

        if (options.json) {
            console.log(JSON.stringify({ graphStats, metrics, temporal: { paths: teg.paths.length, avgLatency: teg.avgEdgeLatencyMs, criticalPathMs: teg.criticalPath.causalDelayMs }, bayesian: { globalPrior: bn.globalPrior, overallPosterior: bn.overallPosterior }, dominator: { dominant: da.dominantProcess, hijackRisk: da.hijackRiskScore, shift: da.toolchainShiftDetected } }, null, 2));
            return;
        }

        console.log('');
        console.log(pc.cyan(pc.bold('  Build Investigation')));
        console.log(pc.dim('  ───────────────────'));
        console.log(`  ${pc.dim('Build:')} ${fullRecord.buildId || 'unknown'}`);
        console.log(`  ${pc.dim('Nodes:')} ${graphStats.nodeCount}  |  ${pc.dim('Edges:')} ${graphStats.edgeCount}  |  ${pc.dim('Components:')} ${graphStats.componentCount}`);
        console.log(`  ${pc.dim('Confidence:')} avg=${graphStats.avgConfidence} min=${graphStats.minConfidence} max=${graphStats.maxConfidence}`);
        console.log('');

        console.log(pc.bold('  Graph Metrics:'));
        console.log(`    Density:      ${metrics.graphDensity}`);
        console.log(`    Entropy:      ${metrics.graphEntropy}`);
        console.log(`    Max depth:    ${metrics.maxDepth}`);
        console.log(`    Is DAG:       ${metrics.isDag}`);
        console.log(`    SCC count:    ${metrics.sccCount}`);
        console.log(`    IDom count:   ${metrics.idomCount}`);
        console.log('');

        console.log(pc.bold('  Temporal:'));
        console.log(`    Paths:            ${teg.paths.length}`);
        console.log(`    Avg edge latency: ${teg.avgEdgeLatencyMs}ms`);
        console.log(`    Max edge latency: ${teg.maxEdgeLatencyMs}ms`);
        console.log(`    Critical path:    ${teg.criticalPath.causalDelayMs}ms (${teg.criticalPath.nodes.length} nodes)`);
        console.log(`    Longest chain:    ${teg.longestCausalChain.nodes.length} nodes`);
        console.log('');

        console.log(pc.bold('  Bayesian:'));
        console.log(`    Global prior:     ${bn.globalPrior}`);
        console.log(`    Overall posterior: ${bn.overallPosterior}`);
        const sortedRels = [...bn.relations].sort((a, b) => b.posteriorGivenEvidence - a.posteriorGivenEvidence);
        for (const r of sortedRels.slice(0, 5)) {
            const delta = r.posteriorGivenEvidence - r.priorP;
            const deltaStr = delta >= 0 ? `+${delta.toFixed(3)}` : delta.toFixed(3);
            console.log(`    ${r.relation.padEnd(24)} prior=${r.priorP} posterior=${r.posteriorGivenEvidence} (Δ${deltaStr})`);
        }
        console.log('');

        console.log(pc.bold('  Dominator:'));
        const domNode = evGraph.nodes.find((n: any) => n.id === da.dominantProcess);
        console.log(`    Dominant:         ${domNode?.label || da.dominantProcess || 'none'}`);
        console.log(`    Hijack risk:      ${(da.hijackRiskScore * 100).toFixed(1)}%`);
        if (da.toolchainShiftDetected) {
            console.log(pc.red(pc.bold(`    ⚠ TOOLCHAIN SHIFT DETECTED`)));
        }
        if (da.anomalySignals.length > 0) {
            for (const s of da.anomalySignals) {
                console.log(pc.yellow(`    ⚠ ${s}`));
            }
        }
        if (da.dominantPath.length > 0) {
            console.log(`    Path: ${da.dominantPath.join(' → ')}`);
        }
        console.log('');
    });

// ── Red Team Campaign Runner ──────────────────────────────────
program
    .command('redteam')
    .description('Run Red Team attack scenarios and measure detection rates')
    .option('--campaign <id>', 'Run specific campaign (sensor-evasion, identity-evasion, etc.)')
    .option('--list', 'List all attack scenarios')
    .option('--coverage', 'Show coverage matrix')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
        await preFlightCheck();
        const { runAllCampaigns, runCampaign, computeCoverageMatrix, renderRedTeamReport, renderCoverageMatrix } = await import('../core/network/redteam-runner');
        const { ALL_ATTACKS } = await import('../core/network/redteam-attacks');

        if (options.list) {
            console.log('');
            console.log(pc.cyan(pc.bold('  Red Team Attack Scenarios')));
            console.log(pc.dim('  ─────────────────────────'));
            for (const attack of ALL_ATTACKS) {
                const sevColor = attack.severity === 'critical' ? pc.red : attack.severity === 'high' ? pc.yellow : pc.dim;
                console.log(`  ${sevColor(attack.severity.toUpperCase().padEnd(8))} ${attack.id}  ${attack.name}`);
                console.log(`  ${pc.dim(attack.description)}`);
                if (attack.mitreId) console.log(`  ${pc.dim('MITRE:')} ${attack.mitreId}`);
                console.log('');
            }
            return;
        }

        // Load build records
        const fsMod = await import('fs');
        const pathMod = await import('path');
        const osMod = await import('os');
        const sentinelDir = pathMod.join(osMod.homedir(), '.sentinel', 'builds');
        const records: any[] = [];

        if (fsMod.existsSync(sentinelDir)) {
            const files = fsMod.readdirSync(sentinelDir).filter(f => f.endsWith('.json')).sort();
            for (const f of files) {
                try {
                    records.push(JSON.parse(fsMod.readFileSync(pathMod.join(sentinelDir, f), 'utf8')));
                } catch {}
            }
        }

        if (records.length === 0) {
            console.log(pc.yellow('  No build records found. Run `sentinel build observe --save` first.'));
            return;
        }

        if (options.campaign) {
            const campaign = runCampaign(options.campaign, records);
            console.log(`\n  Campaign: ${campaign.name}`);
            console.log(pc.dim(`  ${campaign.description}`));
            console.log(`  Detection rate: ${(campaign.detectionRate! * 100).toFixed(1)}%\n`);
            for (const attack of campaign.attacks) {
                const icon = attack.actualOutcome === 'detected' ? pc.green('✓') : attack.actualOutcome === 'partial' ? pc.yellow('⚠') : pc.red('✗');
                console.log(`  ${icon} ${attack.name} (${attack.actualOutcome})`);
                if (attack.missedIndicators && attack.missedIndicators.length > 0) {
                    for (const mi of attack.missedIndicators) {
                        console.log(`    ${pc.red('missed:')} ${mi}`);
                    }
                }
            }
            console.log('');
            return;
        }

        if (options.coverage) {
            const matrix = computeCoverageMatrix(records);
            console.log(renderCoverageMatrix(matrix));
            return;
        }

        // Full report
        const report = runAllCampaigns(records);
        if (options.json) {
            console.log(JSON.stringify(report, null, 2));
        } else {
            console.log(renderRedTeamReport(report));
        }
    });

// ── Atomic Red Team Integration ────────────────────────────────
program
    .command('atomic')
    .description('Run Atomic Red Team tests and measure detection rates')
    .option('--dry-run', 'Show what would be executed without running')
    .option('--priority <n>', 'Max priority level to execute (1-4)', '4')
    .option('--timeout <ms>', 'Timeout per test in milliseconds', '30000')
    .option('--list', 'List all mapped Atomic RT tests')
    .option('--script', 'Generate integration bash script')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
        await preFlightCheck();
        const { ALL_ATOMIC_TESTS, EXECUTION_ORDER } = await import('../core/network/atomic-redteam-map');
        const { executeAllAtomicTests, renderAtomicCampaignResult, generateIntegrationScript } = await import('../core/network/atomic-redteam-runner');

        if (options.script) {
            console.log(generateIntegrationScript());
            return;
        }

        if (options.list) {
            console.log('');
            console.log(pc.cyan(pc.bold('  Atomic Red Team → Sentinel Mapping')));
            console.log(pc.dim('  ─────────────────────────────────'));
            for (const test of ALL_ATOMIC_TESTS) {
                const sevColor = test.gapSeverity === 'critical' ? pc.red : test.gapSeverity === 'high' ? pc.yellow : pc.dim;
                console.log(`  ${sevColor(test.gapSeverity.toUpperCase().padEnd(8))} P${test.priority}  ${test.sentinelAttackId}  ${test.techniqueName}`);
                console.log(`  ${pc.dim(test.atomicTestName)} (${test.techniqueId})`);
                console.log(`  ${pc.dim('Platform:')} ${test.platform.join(', ')}`);
                console.log('');
            }

            console.log(pc.bold('  Execution Order'));
            console.log(pc.dim('  ──────────────'));
            for (const group of EXECUTION_ORDER) {
                console.log(`  ${pc.bold('Priority ' + group.priority + ':')} ${group.description}`);
                console.log(`  ${pc.dim('Attacks:')} ${group.attacks.join(', ')}`);
                console.log('');
            }
            return;
        }

        const maxPriority = parseInt(options.priority, 10)
        const timeout = parseInt(options.timeout, 10)

        if (!options.json) {
            console.log(pc.dim('  Executing Atomic Red Team tests...'));
            console.log(pc.dim(`  Max priority: ${maxPriority}, Timeout: ${timeout}ms`));
            console.log('');
        }

        const result = executeAllAtomicTests({
            dryRun: options.dryRun,
            timeout,
            maxPriority,
        });

        if (options.json) {
            console.log(JSON.stringify(result, null, 2));
        } else {
            console.log(renderAtomicCampaignResult(result));
        }
    });

program
    .command('verify-pkg')
    .description('Manually audit a package for supply chain threats.')
    .argument('<package>', 'Package name or name@version')
    .option('--details', 'Show detailed evidence for each finding')
    .option('--summary', 'Condensed output — counts only, no evidence')
    .option('--json', 'Emit the full scan result incl. signed attestation as JSON')
    .action(async (pkg, options) => {
        const live = new LiveIndicator();
        live.start(`Downloading and analyzing ${pkg}...`, 'dots');
        const result = await shield.analyzePackage(pkg);
        live.stop();

        if (options.json) {
            console.log(JSON.stringify({
                pkg: result.pkg,
                verdict: result.verdict,
                fileCount: result.fileCount,
                sizeBytes: result.sizeBytes,
                scanTimeMs: result.scanTimeMs,
                lifecycleHooks: result.lifecycleHooks,
                attestation: result.attestation ?? null,
                findings: result.findings,
            }, null, 2));
            return;
        }

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

        // Lifecycle scripts (ChainDrop install vector)
        if (result.lifecycleHooks.length > 0) {
            console.log(pc.bold('  Lifecycle scripts:'));
            for (const h of result.lifecycleHooks) {
                const flag = h.dangerous ? pc.red('  ⚠ DANGEROUS') : pc.dim('');
                console.log(`    ${h.script.padEnd(14)} → ${pc.dim(h.command)}${flag}`);
                if (h.dangerous) console.log(pc.dim(`      (${h.reason})`));
            }
            console.log('');
        }

        // Signed attestation (tamper-evident report)
        if (result.attestation) {
            const sig = result.attestation.signature.substring(0, 16);
            console.log(pc.dim(`  Report signed (HMAC-SHA256): ${sig}… ` +
                `(${result.attestation.input.findingCount} findings, ${result.attestation.input.criticalCount} critical)`));
            console.log('');
        }

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
    .option('--enrich', 'Enrich SBOM with CVE data from OSV')
    .action(async (options) => {
        const { SbomGenerator, enrichSbomWithCves } = await import('./intelligence/sbom_generator');
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

        let outputSbom = sbom;
        if (options.enrich) {
            const osv = new OSVIntegrator();
            const osvPackages = sbom.components.map((c: any) => ({ name: c.name, version: c.version }));
            const osvResults = await osv.queryBatch(osvPackages);
            outputSbom = enrichSbomWithCves(sbom, osvResults);
        }

        const output = JSON.stringify(outputSbom, null, 2);

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
   ${w('$ sentinel scan [path] [--json] [--audit-node-modules]')}
   ${d('   path: file or directory (default .)')}
   ${d('   --json: JSON output for pipelines (includes coverage/skipped disclosure)')}
   ${d('   --audit-node-modules: also scan installed packages (permissions-grade)')}
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

${b('17. TRUST — Trust calibration & corpus')}
   ${w('$ sentinel trust [--status] [--features] [--labels] [--json]')}
   ${d('   --status:  show corpus and calibration status (default)')}
   ${d('   --features: show last extracted feature vector')}
   ${d('   --labels:  show label distribution in corpus')}
   ${d('   --json:    JSON output for pipelines')}
   ${g('   ex: sentinel trust')}
   ${g('   ex: sentinel trust --features')}

${b('18. INSPECT — Investigate a build')}
   ${w('$ sentinel inspect [build-id] [--compare <id>] [--json]')}
   ${d('   Investigate build: evidence graph, centrality, dominators, Bayesian shifts.')}
   ${d('   --compare: diff two builds')}
   ${d('   --json:    JSON output for pipelines')}
   ${g('   ex: sentinel inspect')}
   ${g('   ex: sentinel inspect --compare build-123')}

${b('19. LEARNING — Continuous learning pipeline')}
   ${w('$ sentinel learning [--status] [--feedback] [--models] [--check] [--json]')}
   ${d('   --status:   show pipeline status (default)')}
   ${d('   --feedback: show feedback history')}
   ${d('   --models:   show model version history')}
   ${d('   --check:    check if retraining is needed')}
   ${d('   --json:     JSON output for pipelines')}
   ${g('   ex: sentinel learning')}
   ${g('   ex: sentinel learning --feedback --models')}

${b('20. TOP — Top findings from recent builds')}
   ${w('$ sentinel top [--limit <n>] [--json]')}
   ${d('   --limit: max findings to show (default 10)')}
   ${d('   --json:  JSON output for pipelines')}
   ${g('   ex: sentinel top')}
   ${g('   ex: sentinel top --limit 5')}

${b('21. REDTEAM — Attack resilience testing')}
   ${w('$ sentinel redteam [options]')}
   ${d('   --list:           list all 15 attack scenarios')}
   ${d('   --campaign <id>:  run specific campaign')}
   ${d('   --coverage:       show coverage matrix')}
   ${d('   --json:           JSON output for pipelines')}
   ${d('   Campaigns: sensor-evasion, identity-evasion, secret-exfiltration,')}
   ${d('              toolchain-hijack, graph-poisoning, ml-poisoning, timeline-confusion')}
   ${g('   ex: sentinel redteam --list')}
   ${g('   ex: sentinel redteam --campaign sensor-evasion')}
   ${g('   ex: sentinel redteam --coverage')}
   ${g('   ex: sentinel redteam')}

${b('22. ATOMIC — Atomic Red Team integration')}
   ${w('$ sentinel atomic [options]')}
   ${d('   --list:           list all mapped Atomic RT tests')}
   ${d('   --dry-run:        show what would be executed')}
   ${d('   --priority <n>:   max priority (1-4, default 4)')}
   ${d('   --timeout <ms>:   timeout per test (default 30000)')}
   ${d('   --script:         generate integration bash script')}
   ${d('   --json:           JSON output for pipelines')}
   ${d('   Maps Atomic RT techniques to Sentinel attack scenarios:')}
   ${d('   P1: ETW bypass, LD_PRELOAD, DLL injection, corpus poisoning')}
   ${d('   P2: Identity evasion, named pipes, DoH, response file')}
   ${d('   P3: LOLBins, temp file destruction')}
   ${d('   P4: Adversarial features, fragmentation, sensor confusion')}
   ${g('   ex: sentinel atomic --list')}
   ${g('   ex: sentinel atomic --dry-run --priority 1')}
   ${g('   ex: sentinel atomic --script > run-attacks.sh')}

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

// --- Network Auditor CLI ---

const networkCmd = program.command('network')
  .description('Audit AI agent network activity and detect repository exfiltration');

networkCmd
  .command('start')
  .description('Start a network audit session')
  .option('--http-proxy', 'Enable HTTP proxy interception (port 8089)')
  .option('--tls', 'Enable TLS interception (requires CA cert, port 9090)')
  .action(async (options) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const { requestConsent } = await import('./network/legal-consent');
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
    await auditor.start();
    process.on('SIGINT', () => {
      auditor.stop();
      process.exit(0);
    });
  });

networkCmd
  .command('stop')
  .description('Stop the running network audit session')
  .action(async () => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.stop();
    const verdict = auditor.getVerdict();
    if (verdict) {
      const { renderVerdict, renderDnaSummary } = await import('./network/render-network');
      console.log(renderVerdict(verdict));
      console.log(renderDnaSummary(verdict.sessionDna));
    }
  });

networkCmd
  .command('status')
  .description('Show audit status and current session info')
  .action(async () => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    const status = auditor.getStatus();
    if (status.running) {
      console.log(`Status: running (session: ${status.session?.id})`);
      console.log(`Flows captured: ${status.session?.flows.length}`);
      console.log(`Behaviors: ${status.session?.behaviors.length}`);
    } else {
      console.log('Status: stopped');
    }
  });

networkCmd
  .command('history')
  .description('Show past audit sessions')
  .option('-l, --limit <number>', 'Number of sessions to show', '10')
  .action(async (options) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.showHistory();
  });

networkCmd
  .command('session <id>')
  .description('Show details for a specific session')
  .action(async (id) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.showSessionDetail(id);
  });

networkCmd
  .command('export <id>')
  .description('Export session data')
  .option('--format <format>', 'Output format (json|markdown)', 'json')
  .action(async (id, options) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    const output = auditor.exportSession(id, options.format as 'json' | 'markdown');
    console.log(output);
  });

networkCmd
  .command('trusted')
  .description('Manage trusted agents')
  .argument('<action>', 'list|add|remove')
  .argument('[name]', 'Agent name')
  .action(async (action, name) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    switch (action) {
      case 'list':
        auditor.listTrustedAgents();
        break;
      case 'add':
        if (name) auditor.addTrustedAgent(name);
        break;
      case 'remove':
        if (name) auditor.removeTrustedAgent(name);
        break;
      default:
        console.log('Usage: sentinel network trusted <list|add|remove> [name]');
    }
  });

networkCmd
  .command('doctor')
  .description('Check network auditor health, coverage, and sensor drift')
  .option('--metrics', 'Show runtime metrics')
  .option('--coverage', 'Show detailed coverage report')
  .option('--drift', 'Run sensor confidence drift test')
  .action(async (options) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.doctor(options.metrics, options.coverage, options.drift);
  });

networkCmd
  .command('blindspots')
  .description('Manage the blind spot log (record detection failures)')
  .argument('<action>', 'list|add|show|update|delete|stats')
  .argument('[args...]', 'Additional arguments')
  .action(async (action, args) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.blindspots(action, ...(args || []));
  });

networkCmd
  .command('campaign')
  .description('Run validation campaigns against the detection pipeline')
  .argument('<action>', 'list|run|show|delete')
  .argument('[args...]', 'Additional arguments (tag filter, campaign id)')
  .action(async (action, args) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.campaign(action, ...(args || []));
  });

networkCmd
  .command('benchmark')
  .description('View benchmark history across engine versions')
  .argument('<action>', 'history')
  .action(async (action) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.benchmark(action);
  });

networkCmd
  .command('replay')
  .description('Replay recorded sessions through the detection pipeline')
  .argument('<action>', 'run|campaign|diff')
  .argument('[args...]', 'Session file, directory, or baseline/current dirs')
  .action(async (action, args) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.replay(action, ...(args || []));
  });

networkCmd
  .command('record')
  .description('Record a real OS session and replay through the pipeline')
  .argument('[duration_sec]', 'Recording duration in seconds (default: 30)')
  .argument('[output_dir]', 'Output directory (default: replay-corpus/recorded)')
  .argument('[tags...]', 'Optional tags')
  .option('--profile <id>', 'Canonical profile ID (e.g. git-clone)')
  .action(async (duration_sec, output_dir, tags, options) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    const args: string[] = [duration_sec || '30'];
    if (output_dir) args.push(output_dir);
    if (tags) args.push(...tags);
    if (options.profile) args.push('--profile', options.profile);
    await auditor.record('start', ...args);
  });

networkCmd
  .command('corpus')
  .description('Inspect corpus coverage against canonical profiles')
  .argument('<action>', 'coverage')
  .argument('[corpus_dir]', 'Corpus directory (default: replay-corpus)')
  .action(async (action, corpus_dir) => {
    const { NetworkAuditor } = await import('./network/auditor');
    const auditor = new NetworkAuditor();
    auditor.corpus(action, corpus_dir);
  });

// --- Replay System CLI ---

program
  .command('replay')
  .description('Replay datasets for regression testing')
  .argument('[action]', 'list|run|compare|create', 'list')
  .argument('[args...]', 'Dataset ID, platform, or command')
  .option('--platform <platform>', 'Filter by platform')
  .option('--campaign <campaign>', 'Filter by campaign')
  .option('--json', 'Output as JSON')
  .action(async (action, args, options) => {
    const { listReplayDatasets, loadReplayDataset, generateReplayReport, renderReplayReport, createReplayDatasetFromRecord } = await import('../core/network/replay-system');
    
    if (action === 'list') {
      const datasets = listReplayDatasets(options.platform, options.campaign);
      if (options.json) {
        console.log(JSON.stringify(datasets, null, 2));
      } else {
        console.log('');
        console.log('════════════════════════════════════════════════════════════');
        console.log('  REPLAY DATASETS');
        console.log('════════════════════════════════════════════════════════════');
        console.log('');
        console.log(`  Total: ${datasets.length}`);
        console.log('');
        for (const ds of datasets) {
          console.log(`  ${ds.id}`);
          console.log(`    Name:     ${ds.name}`);
          console.log(`    Attack:   ${ds.attackId || 'N/A'}`);
          console.log(`    Platform: ${ds.platform}`);
          console.log(`    Severity: ${ds.severity}`);
          console.log(`    Expected: ${ds.expectedVerdict}`);
          console.log('');
        }
        console.log('════════════════════════════════════════════════════════════');
      }
    } else if (action === 'run') {
      const datasetId = args[0];
      if (!datasetId) {
        console.error('Usage: sentinel replay run <dataset-id>');
        process.exit(1);
      }
      const dataset = loadReplayDataset(datasetId);
      if (!dataset) {
        console.error(`Dataset not found: ${datasetId}`);
        process.exit(1);
      }
      console.log(`Running replay for dataset: ${dataset.name}`);
      console.log(`Expected verdict: ${dataset.expectedVerdict}`);
      console.log('');
      console.log('Note: This requires running the actual build and analyzing it.');
      console.log('Use: sentinel build observe <command> --json');
      console.log('Then compare the output with the expected results.');
    }
  });

// --- Regression Suite CLI ---

program
  .command('regression')
  .description('Regression testing suite')
  .argument('[action]', 'list|run|create|coverage', 'list')
  .argument('[args...]', 'Suite ID or test name')
  .option('--json', 'Output as JSON')
  .action(async (action, args, options) => {
    const { listRegressionSuites, loadRegressionSuite, createDefaultRegressionSuite, createRegressionSuite, renderRegressionCoverage } = await import('../core/network/regression-suite');
    
    if (action === 'list') {
      let suites = listRegressionSuites();
      if (suites.length === 0) {
        console.log('No regression suites found. Creating default suite...');
        const defaultSuite = createDefaultRegressionSuite();
        createRegressionSuite(defaultSuite);
        suites = [defaultSuite];
      }
      if (options.json) {
        console.log(JSON.stringify(suites, null, 2));
      } else {
        console.log('');
        console.log('════════════════════════════════════════════════════════════');
        console.log('  REGRESSION SUITES');
        console.log('════════════════════════════════════════════════════════════');
        console.log('');
        for (const suite of suites) {
          console.log(`  ${suite.id}`);
          console.log(`    Name:   ${suite.name}`);
          console.log(`    Tests:  ${suite.tests.length}`);
          console.log(`    Version: ${suite.version}`);
          console.log('');
        }
        console.log('════════════════════════════════════════════════════════════');
      }
    } else if (action === 'coverage') {
      const suiteId = args[0] || 'sentinel-default';
      const suite = loadRegressionSuite(suiteId);
      if (!suite) {
        console.error(`Suite not found: ${suiteId}`);
        process.exit(1);
      }
      console.log(renderRegressionCoverage(suite));
    } else if (action === 'create') {
      const suite = createDefaultRegressionSuite();
      createRegressionSuite(suite);
      console.log(`Created default regression suite: ${suite.id}`);
      console.log(`Tests: ${suite.tests.length}`);
    }
  });

// --- ATT&CK Coverage CLI ---

program
  .command('coverage')
  .description('MITRE ATT&CK coverage matrix')
  .argument('[action]', 'show|generate|stats', 'show')
  .option('--json', 'Output as JSON')
  .option('--save', 'Save coverage matrix to file')
  .action(async (action, options) => {
    const { generateCoverageMatrix, saveCoverageMatrix, loadCoverageMatrix, renderCoverageMatrix } = await import('../core/network/attack-coverage');
    
    let matrix = loadCoverageMatrix();
    if (!matrix || action === 'generate') {
      matrix = generateCoverageMatrix();
      if (options.save) {
        saveCoverageMatrix(matrix);
        console.log('Coverage matrix saved to attack-coverage.json');
      }
    }
    
    if (options.json) {
      console.log(JSON.stringify(matrix, null, 2));
    } else {
      console.log(renderCoverageMatrix(matrix));
    }
  });

// --- Baseline Pro CLI ---

program
  .command('baseline-pro')
  .description('Advanced build baseline management with anomaly detection')
  .argument('[action]', 'list|create|show|add|diff', 'list')
  .argument('[args...]', 'Profile ID or command')
  .option('--json', 'Output as JSON')
  .action(async (action, args, options) => {
    const { listBaselineProfiles, loadBaselineProfile, createBaselineProfile, renderBaselineProfile, addBaselineEntry, detectBaselineDeviation } = await import('../core/network/baseline-system');
    
    if (action === 'list') {
      const profiles = listBaselineProfiles();
      if (options.json) {
        console.log(JSON.stringify(profiles, null, 2));
      } else {
        console.log('');
        console.log('════════════════════════════════════════════════════════════');
        console.log('  BASELINE PROFILES');
        console.log('════════════════════════════════════════════════════════════');
        console.log('');
        console.log(`  Total: ${profiles.length}`);
        console.log('');
        for (const profile of profiles) {
          console.log(`  ${profile.id}`);
          console.log(`    Name:      ${profile.name}`);
          console.log(`    Entries:   ${profile.entries.length}`);
          console.log(`    Trust:     ${profile.stats.meanTrustScore.toFixed(1)} ± ${profile.stats.stdTrustScore.toFixed(1)}`);
          console.log('');
        }
        console.log('════════════════════════════════════════════════════════════');
      }
    } else if (action === 'create') {
      const id = args[0] || `baseline-${Date.now()}`;
      const name = args[1] || 'New Baseline';
      const profile = createBaselineProfile(id, name, 'Created via CLI');
      console.log(`Created baseline profile: ${profile.id}`);
    } else if (action === 'show') {
      const profileId = args[0];
      if (!profileId) {
        console.error('Usage: sentinel baseline show <profile-id>');
        process.exit(1);
      }
      const profile = loadBaselineProfile(profileId);
      if (!profile) {
        console.error(`Profile not found: ${profileId}`);
        process.exit(1);
      }
      console.log(renderBaselineProfile(profile));
    }
  });

// --- Stress Testing CLI ---

program
  .command('stress')
  .description('Stress testing and performance benchmarks')
  .argument('[action]', 'run|config|results|compare', 'config')
  .argument('[args...]', 'Config ID or build command')
  .option('--builds <n>', 'Number of builds to process', '200')
  .option('--malicious <ratio>', 'Ratio of malicious builds (0-1)', '0.1')
  .option('--concurrency <n>', 'Concurrent analysis', '10')
  .option('--json', 'Output as JSON')
  .action(async (action, args, options) => {
    const { createDefaultStressConfig, saveStressConfig, loadStressConfig, listStressResults, renderStressResult, renderStressComparison } = await import('../core/network/stress-testing');
    
    if (action === 'config') {
      const config = createDefaultStressConfig();
      config.totalBuilds = parseInt(options.builds) || 200;
      config.maliciousRatio = parseFloat(options.malicious) || 0.1;
      config.concurrency = parseInt(options.concurrency) || 10;
      saveStressConfig(config);
      
      if (options.json) {
        console.log(JSON.stringify(config, null, 2));
      } else {
        console.log('');
        console.log('════════════════════════════════════════════════════════════');
        console.log('  STRESS TEST CONFIG');
        console.log('════════════════════════════════════════════════════════════');
        console.log('');
        console.log(`  Config:     ${config.id}`);
        console.log(`  Builds:     ${config.totalBuilds}`);
        console.log(`  Malicious:  ${(config.maliciousRatio * 100).toFixed(0)}%`);
        console.log(`  Concurrency: ${config.concurrency}`);
        console.log('');
        console.log('  Run: sentinel stress run');
        console.log('');
        console.log('════════════════════════════════════════════════════════════');
      }
    } else if (action === 'results') {
      const configId = args[0];
      if (!configId) {
        console.error('Usage: sentinel stress results <config-id>');
        process.exit(1);
      }
      const results = listStressResults(configId);
      if (results.length === 0) {
        console.log('No results found for this config.');
      } else {
        for (const result of results) {
          console.log(renderStressResult(result));
        }
      }
    } else if (action === 'compare') {
      const configId = args[0];
      if (!configId) {
        console.error('Usage: sentinel stress compare <config-id>');
        process.exit(1);
      }
      const results = listStressResults(configId);
      if (results.length < 2) {
        console.log('Need at least 2 results for comparison.');
      } else {
        console.log(renderStressComparison(results));
      }
    }
  });

// --- Token Inspector CLI (Fase 1C) ---

program
  .command('token-inspect')
  .description('Inspect and classify a token string (GitHub PAT, AWS, Stripe, Slack, etc.)')
  .argument('<token>', 'Token string to inspect')
  .option('--check', 'Verify GitHub token scopes and expiration via API (no data stored)')
  .action(async (token, options) => {
    const { inspectToken, formatInspectResult } = await import('./token_inspect');
    try {
      const result = await inspectToken(token, { check: options.check });
      console.log(formatInspectResult(result));
      if (result.riskLevel === 'critical' || result.riskLevel === 'high') {
        process.exitCode = 1;
      }
    } catch (err) {
      console.error(pc.red(`Token inspection failed: ${err instanceof Error ? err.message : err}`));
      process.exit(1);
    }
  });

// --- Sentinel Cloud: Login & Capabilities ---

const CLOUD_CAPABILITY_LABELS: Record<keyof CapabilityMap, string> = {
    content_intel_lookup: 'Content Intel Lookup',
    remote_scan: 'Remote Scan',
    oracle_integration: 'Oracle Integration',
    offline_sync: 'Offline Sync',
    sbom: 'SBOM',
    ai_review: 'AI Review',
};

function enabledCapabilityKeys(capabilities: CapabilityMap): Array<keyof CapabilityMap> {
    return (Object.keys(capabilities) as Array<keyof CapabilityMap>).filter((k) => capabilities[k]);
}

function enabledCapabilityLabels(capabilities: CapabilityMap): string[] {
    return enabledCapabilityKeys(capabilities).map((k) => CLOUD_CAPABILITY_LABELS[k]);
}

function printSession(session: Session, json: boolean): void {
    const enabled = enabledCapabilityKeys(session.capabilities);
    if (json) {
        console.log(JSON.stringify({
            user: session.user,
            subjectId: session.subjectId,
            plan: session.plan,
            planLabel: session.planLabel,
            capabilities: enabled,
            expiresAt: session.expiresAt,
            fetchedAt: session.fetchedAt,
            limits: session.limits,
        }, null, 2));
        return;
    }
    console.log(pc.green(`\n✔ Logged in as ${pc.bold(session.user || session.subjectId)} (${session.planLabel})`));
    console.log(pc.white(`  Plan:          ${session.plan} — ${session.planLabel}`));
    console.log(pc.white(`  Expires:       ${session.expiresAt}`));
    console.log(pc.white(`  Capabilities:  ${enabledCapabilityLabels(session.capabilities).join(', ') || '(none)'}`));
    console.log('');
}

program
    .command('login')
    .description('Log in to Sentinel Cloud with an API token.')
    .option('--token <token>', 'Sentinel Cloud API token (or set SENTINEL_CLOUD_API_TOKEN)')
    .option('--api <baseUrl>', 'Sentinel Cloud base URL (or set SENTINEL_CLOUD_URL)')
    .action(async (options) => {
        let baseUrl: string;
        try {
            baseUrl = getResolvedBaseUrl(options.api);
        } catch (err) {
            console.error(pc.red(`Error: ${err instanceof Error ? err.message : err}`));
            console.error(pc.yellow('Set SENTINEL_CLOUD_URL or pass --api <url>'));
            process.exit(1);
        }
        const token = resolveToken(options.token);
        if (!token) {
            console.error(pc.red('No token found. Pass --token <token> or set SENTINEL_CLOUD_API_TOKEN.'));
            process.exit(1);
        }
        const result = await loginWithToken(token, baseUrl);
        if (!result.ok) {
            console.error(pc.red(result.error));
            process.exit(1);
        }
        printSession(result.session, false);
    });

program
    .command('whoami')
    .description('Show the currently logged-in Sentinel Cloud account.')
    .option('--refresh', 'Re-fetch capabilities from Sentinel Cloud')
    .option('--api <baseUrl>', 'Sentinel Cloud base URL (or set SENTINEL_CLOUD_URL)')
    .option('--json', 'Emit output as JSON')
    .action(async (options) => {
        let session = loadSession();
        if (!session) {
            console.error(pc.red('Not logged in. Run "sentinel login".'));
            process.exit(1);
        }
        if (options.refresh) {
            let baseUrl: string;
            try {
                baseUrl = getResolvedBaseUrl(options.api);
            } catch {
                console.warn(pc.yellow('Warning: SENTINEL_CLOUD_URL not set; using cached session data.'));
                baseUrl = '';
            }
            if (baseUrl) {
                const result = await fetchCapabilities(session.token, baseUrl);
                if (result.ok) {
                    session = {
                        ...session,
                        user: result.data.user,
                        subjectId: result.data.subjectId,
                        plan: result.data.plan,
                        planLabel: result.data.planLabel,
                        expiresAt: result.data.expiresAt,
                        capabilities: result.data.capabilities,
                        limits: result.data.limits,
                        fetchedAt: new Date().toISOString(),
                    };
                    saveSession(session);
                } else if (result.status === 401) {
                    clearSession();
                    console.error(pc.red('Session expired. Run "sentinel login".'));
                    process.exit(1);
                } else {
                    console.warn(pc.yellow(`Warning: ${result.error} — using cached session data.`));
                }
            }
        }
        printSession(session, options.json);
    });

program
    .command('logout')
    .description('Log out of Sentinel Cloud.')
    .action(() => {
        clearSession();
        console.log(pc.green('Logged out.'));
    });

program
    .command('lookup')
    .description('Look up a content identity in Sentinel Cloud content intelligence.')
    .argument('<contentId>', 'sha512:<hex> identity or registry SRI')
    .option('--json', 'Emit the validated Cloud lookup result as JSON')
    .option('--api <baseUrl>', 'Sentinel Cloud base URL (or set SENTINEL_CLOUD_URL)')
    .option('--timeout <ms>', 'Request timeout in milliseconds', '5000')
    .action(async (contentId, options) => {
        const parsedTimeout = parseInt(options.timeout, 10);
        const timeoutMs = Number.isFinite(parsedTimeout) ? parsedTimeout : undefined;
        const result = await runLookup(
            {
                contentId,
                json: options.json,
                api: options.api,
                timeoutMs,
            },
            {}
        );
        for (const line of result.lines) {
            if (line.stream === 'stderr') {
                console.error(pc.red(line.text));
            } else {
                console.log(line.text);
            }
        }
        process.exitCode = result.exitCode;
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
  console.log(w(`${cmd('sentinel build observe <cmd>')}              — ${desc('Observe build: trust score, highlights, verdict')}`));
  console.log(w(`${cmd('sentinel build observe <cmd> --verbose')}    — ${desc('Build with technical details: graph, Bayesian, dominators')}`));
  console.log(w(`${cmd('sentinel build observe <cmd> --json')}       — ${desc('Build output as JSON for pipelines')}`));
  console.log(w(`${cmd('sentinel build explain')}                   — ${desc('Why is the trust score what it is?')}`));
  console.log(w(`${cmd('sentinel top')}                              — ${desc('Top findings from recent builds')}`));
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
  console.log(w(`${cmd('sentinel lookup <contentId>')}                    — ${desc('Cloud content intelligence lookup')}`));
  console.log(w(`${cmd('sentinel trust')}                            — ${desc('Trust calibration: corpus, features, labels')}`));
  console.log(w(`${cmd('sentinel trust --features')}                 — ${desc('Show last extracted feature vector')}`));
  console.log(w(`${cmd('sentinel inspect')}                          — ${desc('Investigate build: graph, dominators, Bayesian')}`));
  console.log(w(`${cmd('sentinel inspect --compare <id>')}           — ${desc('Diff two builds')}`));
  console.log(w(`${cmd('sentinel learning')}                         — ${desc('Continuous learning: feedback, models, retrain')}`));
  console.log(w(`${cmd('sentinel learning --feedback')}              — ${desc('Show feedback history')}`));
  console.log(w(`${cmd('sentinel top')}                              — ${desc('Top findings from recent builds')}`));
  console.log(w(`${cmd('sentinel top --limit 5')}                    — ${desc('Top 5 findings')}`));
  console.log(w(`${cmd('sentinel redteam')}                          — ${desc('Run Red Team attack scenarios')}`));
  console.log(w(`${cmd('sentinel redteam --list')}                    — ${desc('List all 26 attack scenarios')}`));
  console.log(w(`${cmd('sentinel redteam --coverage')}                — ${desc('Show coverage matrix')}`));
  console.log(w(`${cmd('sentinel atomic')}                            — ${desc('Run Atomic Red Team tests')}`));
  console.log(w(`${cmd('sentinel atomic --list')}                      — ${desc('List mapped Atomic RT tests')}`));
  console.log(w(`${cmd('sentinel atomic --dry-run')}                   — ${desc('Preview what would execute')}`));
  console.log(w(`${cmd('sentinel atomic --script')}                    — ${desc('Generate integration bash script')}`));
  console.log(w(`${cmd('sentinel replay')}                            — ${desc('Replay datasets for regression testing')}`));
  console.log(w(`${cmd('sentinel replay list')}                         — ${desc('List all replay datasets')}`));
  console.log(w(`${cmd('sentinel replay run <id>')}                     — ${desc('Run replay for specific dataset')}`));
  console.log(w(`${cmd('sentinel regression')}                         — ${desc('Regression testing suite')}`));
  console.log(w(`${cmd('sentinel regression list')}                      — ${desc('List regression suites')}`));
  console.log(w(`${cmd('sentinel regression coverage')}                 — ${desc('Show test coverage')}`));
  console.log(w(`${cmd('sentinel coverage')}                           — ${desc('MITRE ATT&CK coverage matrix')}`));
  console.log(w(`${cmd('sentinel coverage --save')}                     — ${desc('Save coverage matrix to file')}`));
  console.log(w(`${cmd('sentinel baseline-pro')}                        — ${desc('Advanced baseline management')}`));
  console.log(w(`${cmd('sentinel baseline-pro list')}                     — ${desc('List baseline profiles')}`));
  console.log(w(`${cmd('sentinel baseline-pro show <id>')}                 — ${desc('Show baseline profile details')}`));
  console.log(w(`${cmd('sentinel stress')}                             — ${desc('Stress testing and benchmarks')}`));
  console.log(w(`${cmd('sentinel stress config')}                        — ${desc('Configure stress test')}`));
  console.log(w(`${cmd('sentinel stress results <id>')}                   — ${desc('Show stress test results')}`));
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
} else {
  program.parse(process.argv);
}
