"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderBenchmark = renderBenchmark;
const picocolors_1 = __importDefault(require("picocolors"));
function pct(value) {
    const p = (value * 100).toFixed(1);
    if (value >= 0.9)
        return picocolors_1.default.green(`${p}%`);
    if (value >= 0.7)
        return picocolors_1.default.yellow(`${p}%`);
    return picocolors_1.default.red(`${p}%`);
}
function renderBenchmark(results, aggregated) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ══════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   SENTINEL BENCHMARK RESULTS')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ══════════════════════════════════════')));
    lines.push('');
    lines.push(`  ${picocolors_1.default.bold('Total Fixtures:')}   ${picocolors_1.default.cyan(String(aggregated.totalFixtures))}`);
    lines.push(`  ${picocolors_1.default.bold('Total Findings:')}   ${picocolors_1.default.cyan(String(aggregated.totalFindings))}`);
    lines.push(`  ${picocolors_1.default.bold('Avg Precision:')}    ${pct(aggregated.avgPrecision)}`);
    lines.push(`  ${picocolors_1.default.bold('Avg Recall:')}       ${pct(aggregated.avgRecall)}`);
    lines.push('');
    if (results.length === 0) {
        lines.push(picocolors_1.default.dim('  No fixtures found in corpus.'));
        lines.push('');
        return lines.join('\n');
    }
    lines.push(picocolors_1.default.dim('  ─── Per-fixture breakdown ───────────────'));
    lines.push('');
    for (const r of results) {
        const fpCount = r.falsePositives.length;
        const fnCount = r.falseNegatives.length;
        const label = fpCount > 0 || fnCount > 0 ? picocolors_1.default.red : picocolors_1.default.green;
        lines.push(`  ${picocolors_1.default.bold(r.repoPath)}`);
        lines.push(`    Findings: ${picocolors_1.default.cyan(String(r.findingsCount))}  `
            + `Precision: ${pct(r.precision)}  Recall: ${pct(r.recall)}  `
            + `Time: ${picocolors_1.default.dim(r.scanTimeMs + 'ms')}`);
        if (fpCount > 0) {
            lines.push(`    ${picocolors_1.default.red(`FP: ${fpCount}`)} ${picocolors_1.default.dim(r.falsePositives.join(', '))}`);
        }
        if (fnCount > 0) {
            lines.push(`    ${picocolors_1.default.yellow(`FN: ${fnCount}`)} ${picocolors_1.default.dim(r.falseNegatives.join(', '))}`);
        }
        lines.push('');
    }
    if (aggregated.worstFp.length > 0 && aggregated.worstFp[0].falsePositives.length > 0) {
        lines.push(picocolors_1.default.dim('  ─── Worst FP offenders ──────────────────'));
        lines.push('');
        for (const r of aggregated.worstFp) {
            if (r.falsePositives.length === 0)
                break;
            lines.push(`  ${picocolors_1.default.red(`${r.falsePositives.length} FP`)}  ${picocolors_1.default.bold(r.repoPath)}  ${picocolors_1.default.dim(r.falsePositives.join(', '))}`);
        }
        lines.push('');
    }
    if (aggregated.worstFn.length > 0 && aggregated.worstFn[0].falseNegatives.length > 0) {
        lines.push(picocolors_1.default.dim('  ─── Worst FN offenders ──────────────────'));
        lines.push('');
        for (const r of aggregated.worstFn) {
            if (r.falseNegatives.length === 0)
                break;
            lines.push(`  ${picocolors_1.default.yellow(`${r.falseNegatives.length} FN`)}  ${picocolors_1.default.bold(r.repoPath)}  ${picocolors_1.default.dim(r.falseNegatives.join(', '))}`);
        }
        lines.push('');
    }
    return lines.join('\n');
}
