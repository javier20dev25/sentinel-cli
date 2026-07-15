"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderDrift = renderDrift;
const picocolors_1 = __importDefault(require("picocolors"));
function renderDrift(result) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   BEHAVIORAL DRIFT REPORT')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    lines.push(`  ${picocolors_1.default.bold('Package')}: ${result.packageName}`);
    lines.push(`  ${picocolors_1.default.bold('Versions')}: ${result.previousVersion} → ${result.currentVersion}`);
    const riskColor = result.riskChange > 0 ? picocolors_1.default.red : result.riskChange < 0 ? picocolors_1.default.green : picocolors_1.default.dim;
    const riskSign = result.riskChange > 0 ? '+' : '';
    lines.push(`  ${picocolors_1.default.bold('Risk Δ')}:   ${riskColor(riskSign + String(result.riskChange))}`);
    lines.push('');
    if (result.newCapabilities.length > 0) {
        lines.push(picocolors_1.default.red(`  ● New Capabilities (${result.newCapabilities.length}):`));
        for (const cap of result.newCapabilities) {
            lines.push(`    ${picocolors_1.default.red('■')} ${cap}`);
        }
        lines.push('');
    }
    const increased = result.drifts.filter(d => d.severity === 'INCREASED');
    if (increased.length > 0) {
        lines.push(picocolors_1.default.yellow(`  ▲ Increased (${increased.length}):`));
        for (const d of increased) {
            lines.push(`    ${picocolors_1.default.yellow('▲')} ${d.capability}: ${d.previousCount} → ${d.currentCount}`);
        }
        lines.push('');
    }
    const decreased = result.drifts.filter(d => d.severity === 'DECREASED');
    const removed = result.drifts.filter(d => d.severity === 'REMOVED');
    if (decreased.length > 0 || removed.length > 0) {
        lines.push(picocolors_1.default.green('  ▼ Decreased/Removed:'));
        for (const d of removed) {
            lines.push(`    ${picocolors_1.default.green('✕')} ${d.capability} (removed)`);
        }
        for (const d of decreased) {
            lines.push(`    ${picocolors_1.default.green('▼')} ${d.capability}: ${d.previousCount} → ${d.currentCount}`);
        }
        lines.push('');
    }
    if (result.drifts.length === 0) {
        lines.push(picocolors_1.default.dim('  No capability drift detected.'));
        lines.push('');
    }
    const verdictStr = result.verdict === 'MALICIOUS'
        ? picocolors_1.default.bgRed(picocolors_1.default.white(` ${result.verdict} `))
        : result.verdict === 'SUSPICIOUS'
            ? picocolors_1.default.bgYellow(picocolors_1.default.black(` ${result.verdict} `))
            : picocolors_1.default.bgGreen(picocolors_1.default.black(` ${result.verdict} `));
    lines.push(`  Verdict: ${verdictStr}`);
    lines.push('');
    return lines.join('\n');
}
