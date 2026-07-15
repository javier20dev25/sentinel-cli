"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderTeams = renderTeams;
const picocolors_1 = __importDefault(require("picocolors"));
function renderTeams(teams) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   CODEOWNERS TEAM GROUPING')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    if (teams.length === 0) {
        lines.push(picocolors_1.default.dim('  No teams found. Ensure a CODEOWNERS file exists (.github/CODEOWNERS, docs/CODEOWNERS, or CODEOWNERS).'));
        lines.push('');
        return lines.join('\n');
    }
    lines.push(picocolors_1.default.dim(`  ${teams.length} team(s) identified`));
    lines.push('');
    for (const team of teams) {
        const riskColor = team.riskScore >= 70 ? picocolors_1.default.red :
            team.riskScore >= 30 ? picocolors_1.default.yellow : picocolors_1.default.green;
        lines.push(`  ${picocolors_1.default.bold(team.name)}`);
        lines.push(`    Risk Score: ${riskColor(`${team.riskScore} pts`)}  ·  Files: ${team.files.length}  ·  Findings: ${team.findingCount}`);
        lines.push(`    Members: ${picocolors_1.default.dim(team.members.join(', '))}`);
        const fileList = team.files.slice(0, 5);
        for (const file of fileList) {
            lines.push(picocolors_1.default.dim(`    📄 ${file}`));
        }
        if (team.files.length > 5) {
            lines.push(picocolors_1.default.dim(`    ... and ${team.files.length - 5} more`));
        }
        lines.push('');
    }
    lines.push(picocolors_1.default.white('  ═══════════════════════════════════════════════'));
    lines.push('');
    return lines.join('\n');
}
