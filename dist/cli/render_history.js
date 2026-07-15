"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderTrend = renderTrend;
exports.renderSnapshotList = renderSnapshotList;
const picocolors_1 = __importDefault(require("picocolors"));
function fmtDelta(val, suffix = '') {
    if (val === 0)
        return picocolors_1.default.dim(`0${suffix}`);
    if (val > 0)
        return picocolors_1.default.green(`+${val}${suffix}`);
    return picocolors_1.default.red(`${val}${suffix}`);
}
function renderTrend(trend, opts) {
    var _a;
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   RISK HISTORY & TREND')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    if (trend.snapshots.length === 0) {
        lines.push(picocolors_1.default.dim('  No history available for this repository.'));
        lines.push(picocolors_1.default.dim('  Run scan with --save-history to start tracking.'));
        lines.push('');
        return lines.join('\n');
    }
    const latest = trend.snapshots[trend.snapshots.length - 1];
    const arrow = trend.direction === 'improving' ? picocolors_1.default.green('↑') :
        trend.direction === 'declining' ? picocolors_1.default.red('↓') : picocolors_1.default.dim('→');
    lines.push(`  ${picocolors_1.default.bold('Direction:')}  ${arrow} ${picocolors_1.default.bold(trend.direction.toUpperCase())}`);
    if (opts === null || opts === void 0 ? void 0 : opts.windowDays) {
        const windowLabel = `Last ${opts.windowDays} days`;
        lines.push(`  ${picocolors_1.default.bold('Window:')}    ${windowLabel}`);
    }
    if (opts === null || opts === void 0 ? void 0 : opts.branch) {
        lines.push(`  ${picocolors_1.default.bold('Branch:')}    ${opts.branch}`);
    }
    lines.push(`  ${picocolors_1.default.bold('Score Δ:')}    ${fmtDelta(trend.scoreDelta, ' pts')}`);
    lines.push(`  ${picocolors_1.default.bold('Findings Δ:')}  ${fmtDelta(trend.findingDelta)}`);
    lines.push(`  ${picocolors_1.default.bold('Critical Δ:')}  ${fmtDelta(trend.criticalDelta)}`);
    if ((opts === null || opts === void 0 ? void 0 : opts.baselineScore) !== undefined) {
        const scoreDiff = opts.baselineScore - latest.agencyScore;
        const criticalDiff = ((_a = opts.baselineCritical) !== null && _a !== void 0 ? _a : 0) - latest.criticalCount;
        lines.push(`  ${picocolors_1.default.bold('vs main:')}   ${fmtDelta(scoreDiff, ' pts')}, ${fmtDelta(criticalDiff, ' critical')}`);
    }
    lines.push('');
    lines.push(picocolors_1.default.dim('  ─── Recent Snapshots ─────────────────────────────'));
    lines.push('');
    const recent = trend.snapshots.slice(-5);
    for (const snap of recent) {
        const date = new Date(snap.timestamp).toLocaleDateString();
        const time = new Date(snap.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const scoreColor = snap.agencyScore >= 70 ? picocolors_1.default.red :
            snap.agencyScore >= 30 ? picocolors_1.default.yellow : picocolors_1.default.green;
        const verdictColor = snap.verdict === 'BLOCK' ? picocolors_1.default.red :
            snap.verdict === 'REVIEW' ? picocolors_1.default.yellow : picocolors_1.default.green;
        lines.push(`  ${picocolors_1.default.dim(`${date} ${time}`)}  ${scoreColor(`${snap.agencyScore}/100`)}  ${verdictColor(snap.verdict)}  ${picocolors_1.default.dim(`⬡ ${snap.totalFindings} findings, ${snap.criticalCount} critical, ${snap.scenarioCount} scenarios`)}`);
    }
    if (trend.snapshots.length > 5) {
        lines.push(picocolors_1.default.dim(`  ... and ${trend.snapshots.length - 5} older snapshot(s)`));
    }
    lines.push('');
    lines.push(picocolors_1.default.white('  ═══════════════════════════════════════════════'));
    lines.push('');
    return lines.join('\n');
}
function renderSnapshotList(repos) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   SENTINEL HISTORY')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    if (repos.size === 0) {
        lines.push(picocolors_1.default.dim('  No history found. Run scan --save-history to start tracking.'));
        lines.push('');
        return lines.join('\n');
    }
    for (const [repoPath, snapshots] of repos) {
        const latest = snapshots[0];
        const scoreColor = latest.agencyScore >= 70 ? picocolors_1.default.red :
            latest.agencyScore >= 30 ? picocolors_1.default.yellow : picocolors_1.default.green;
        const date = new Date(latest.timestamp).toLocaleDateString();
        lines.push(`  ${picocolors_1.default.bold(pathShort(repoPath))}`);
        lines.push(`    ${picocolors_1.default.dim(repoPath)}`);
        lines.push(`    Latest: ${scoreColor(`${latest.agencyScore}/100`)}  ${picocolors_1.default.dim(`${latest.totalFindings} findings, ${snapshots.length} snapshot(s) — ${date}`)}`);
        lines.push('');
    }
    return lines.join('\n');
}
function pathShort(p) {
    const parts = p.replace(/\\/g, '/').split('/');
    return parts.slice(-2).join('/');
}
