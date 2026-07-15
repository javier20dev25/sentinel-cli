"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderDelta = renderDelta;
const picocolors_1 = __importDefault(require("picocolors"));
function renderDelta(delta) {
    const lines = [];
    const newCount = delta.newFindings.length;
    const fixedCount = delta.fixedFindings.length;
    const totalChange = delta.totalAfter - delta.totalBefore;
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   PR DELTA ANALYSIS')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    lines.push(`  ${picocolors_1.default.bold('Summary')}:  ${delta.totalBefore} → ${delta.totalAfter} findings (${totalChange > 0 ? picocolors_1.default.red(`+${totalChange}`) : totalChange < 0 ? picocolors_1.default.green(`${totalChange}`) : picocolors_1.default.dim('0')})`);
    lines.push('');
    if (newCount > 0) {
        lines.push(picocolors_1.default.red(`  ● ${newCount} new finding(s) introduced:`));
        lines.push('');
        for (const f of delta.newFindings.slice(0, 10)) {
            const color = f.severity === 'CRITICAL' ? picocolors_1.default.red :
                f.severity === 'HIGH' ? picocolors_1.default.yellow : picocolors_1.default.dim;
            lines.push(`    ${color('■')} [${f.severity}] ${picocolors_1.default.bold(f.subcode || f.type)}  ${picocolors_1.default.dim(f.file)}:${f.line}`);
            if (f.title)
                lines.push(`       ${picocolors_1.default.dim(f.title)}`);
        }
        if (newCount > 10) {
            lines.push(picocolors_1.default.dim(`    ... and ${newCount - 10} more new finding(s)`));
        }
        lines.push('');
    }
    if (fixedCount > 0) {
        lines.push(picocolors_1.default.green(`  ✔ ${fixedCount} finding(s) fixed since baseline:`));
        lines.push('');
        for (const f of delta.fixedFindings.slice(0, 10)) {
            lines.push(`    ${picocolors_1.default.green('✔')} ${picocolors_1.default.dim(`${f.subcode}  •  ${f.file}:${f.line}`)}`);
            if (f.title)
                lines.push(`       ${picocolors_1.default.dim(f.title)}`);
        }
        if (fixedCount > 10) {
            lines.push(picocolors_1.default.dim(`    ... and ${fixedCount - 10} more fixed finding(s)`));
        }
        lines.push('');
    }
    if (newCount === 0 && fixedCount === 0) {
        lines.push(picocolors_1.default.dim('  No change in findings since baseline.'));
        lines.push('');
    }
    lines.push(picocolors_1.default.white('  ═══════════════════════════════════════════════'));
    lines.push('');
    return lines.join('\n');
}
