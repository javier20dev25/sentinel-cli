"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderOwnership = renderOwnership;
const picocolors_1 = __importDefault(require("picocolors"));
function renderOwnership(ownership) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   OWNERSHIP GRAPH')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    if (ownership.totalAuthors === 0) {
        lines.push(picocolors_1.default.dim('  No git history available to determine ownership.'));
        lines.push('');
        return lines.join('\n');
    }
    lines.push(picocolors_1.default.dim(`  ${ownership.totalAuthors} author(s) identified`));
    lines.push('');
    for (const author of ownership.authors.slice(0, 10)) {
        const riskColor = author.riskScore >= 70 ? picocolors_1.default.red :
            author.riskScore >= 30 ? picocolors_1.default.yellow : picocolors_1.default.green;
        lines.push(`  ${picocolors_1.default.bold(author.name)}  ${picocolors_1.default.dim(`<${author.email}>`)}`);
        lines.push(`    Risk Contribution: ${riskColor(`${author.riskScore} pts`)}  ·  Files: ${author.files.length}  ·  Findings: ${author.findingCount}`);
        const topSubs = Array.from(author.topSubcodes.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 4);
        if (topSubs.length > 0) {
            const subStr = topSubs.map(([sub, count]) => `${sub} (${count})`).join(', ');
            lines.push(`    Top Subcodes: ${picocolors_1.default.dim(subStr)}`);
        }
        if (author.files.length <= 4) {
            for (const file of author.files) {
                lines.push(picocolors_1.default.dim(`    📄 ${file}`));
            }
        }
        else {
            for (const file of author.files.slice(0, 3)) {
                lines.push(picocolors_1.default.dim(`    📄 ${file}`));
            }
            lines.push(picocolors_1.default.dim(`    ... and ${author.files.length - 3} more file(s)`));
        }
        lines.push('');
    }
    if (ownership.totalAuthors > 10) {
        lines.push(picocolors_1.default.dim(`  ... and ${ownership.totalAuthors - 10} more author(s)`));
        lines.push('');
    }
    lines.push(picocolors_1.default.white('  ═══════════════════════════════════════════════'));
    lines.push('');
    return lines.join('\n');
}
