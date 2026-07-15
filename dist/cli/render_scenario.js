"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderScenarios = renderScenarios;
const picocolors_1 = __importDefault(require("picocolors"));
function sevColor(sev) {
    switch (sev) {
        case 'CRITICAL': return picocolors_1.default.red;
        case 'HIGH': return picocolors_1.default.yellow;
        case 'MEDIUM': return picocolors_1.default.cyan;
        default: return picocolors_1.default.dim;
    }
}
function fmtPct(n) {
    return Math.round(n * 100) + '%';
}
function renderScenarios(scenarios) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   ATTACK SCENARIOS')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    if (scenarios.length === 0) {
        lines.push(picocolors_1.default.green('  ✔ No attack scenarios identified.'));
        lines.push('');
        return lines.join('\n');
    }
    lines.push(picocolors_1.default.dim(`  ${scenarios.length} scenario(s) detected`));
    lines.push('');
    for (let si = 0; si < scenarios.length; si++) {
        const s = scenarios[si];
        const color = sevColor(s.severity);
        const badge = color(`[${s.severity}]`);
        const confPct = fmtPct(s.confidence);
        lines.push(picocolors_1.default.dim(`  ─── Scenario ${si + 1} (${color(`${s.score}/100`)} • ${confPct} confidence) ──────`));
        lines.push('');
        lines.push(`    ${badge} ${picocolors_1.default.bold(s.name)}    ${picocolors_1.default.dim(s.id)}`);
        lines.push('');
        lines.push(`    ${picocolors_1.default.dim(s.description)}`);
        lines.push('');
        lines.push(`    ${picocolors_1.default.white('Impact:')} ${picocolors_1.default.dim(s.impact)}`);
        lines.push('');
        // Evidence
        lines.push(picocolors_1.default.dim('    Evidence:'));
        for (const ev of s.evidence) {
            lines.push(`      • ${picocolors_1.default.dim(ev)}`);
        }
        lines.push('');
    }
    lines.push(picocolors_1.default.white('  ═══════════════════════════════════════════════'));
    lines.push('');
    return lines.join('\n');
}
