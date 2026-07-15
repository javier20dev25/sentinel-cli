"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderEvidenceCards = renderEvidenceCards;
const picocolors_1 = __importDefault(require("picocolors"));
function severityColor(sev) {
    switch (sev) {
        case 'CRITICAL': return picocolors_1.default.red;
        case 'HIGH': return picocolors_1.default.yellow;
        case 'MEDIUM': return picocolors_1.default.cyan;
        default: return (s) => s;
    }
}
function padRight(s, n) {
    return s + ' '.repeat(Math.max(0, n - s.length));
}
function renderEvidenceCards(cards, agency) {
    const lines = [];
    // Header
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   AGENCY SCORE REPORT')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    // Score summary
    const scoreColor = agency.agencyScore >= 70 ? picocolors_1.default.red :
        agency.agencyScore >= 30 ? picocolors_1.default.yellow : picocolors_1.default.green;
    lines.push(`    ${picocolors_1.default.bold('Agency Score')}:  ${scoreColor(`${agency.agencyScore}/100`)}`);
    lines.push(`    ${picocolors_1.default.bold('Blast Radius')}: ${severityColor(agency.blastRadius)(agency.blastRadius)}`);
    const verdictColor = agency.verdict === 'BLOCK' ? picocolors_1.default.red :
        agency.verdict === 'REVIEW' ? picocolors_1.default.yellow : picocolors_1.default.green;
    lines.push(`    ${picocolors_1.default.bold('Verdict')}:     ${verdictColor(agency.verdict)}`);
    lines.push(`    ${picocolors_1.default.bold('Findings')}:     ${agency.totalFindings} scored (${agency.criticalCount} critical, ${agency.highCount} high)`);
    lines.push('');
    // Top drivers
    if (agency.drivers.length > 0) {
        lines.push(picocolors_1.default.dim('  ─── Drivers ───────────────────────────────────'));
        lines.push('');
        for (const d of agency.drivers.slice(0, 5)) {
            const color = d.contribution >= 30 ? picocolors_1.default.red :
                d.contribution >= 15 ? picocolors_1.default.yellow : picocolors_1.default.dim;
            lines.push(`    ${color(`+${d.contribution}`)}  ${picocolors_1.default.dim(`[${d.subcode}]`)} ${d.title}`);
        }
        if (agency.drivers.length > 5) {
            lines.push(picocolors_1.default.dim(`    ... and ${agency.drivers.length - 5} more`));
        }
        lines.push('');
    }
    // Evidence Cards
    if (cards.length > 0) {
        lines.push(picocolors_1.default.dim('  ─── Evidence Cards ─────────────────────────────'));
        lines.push('');
        for (const card of cards) {
            const color = severityColor(card.severity);
            lines.push(picocolors_1.default.white(`  ┌──────────────────────────────────────────────────────┐`));
            // Title line
            const badge = color(`[${card.severity}]`);
            const contrib = card.contribution !== undefined ? picocolors_1.default.dim(` +${card.contribution}`) : '';
            const label = card.subcode ? `${card.subcode}` : '';
            lines.push(`  │ ${badge} ${picocolors_1.default.bold(card.title)}${contrib}`);
            // Subcode + file:line + category
            lines.push(`  │ ${picocolors_1.default.dim(`${label}  •  ${card.file}:${card.line}  •  ${card.category}  •  Score: ${card.riskScore}/100  •  Confidence: ${card.confidence.toUpperCase()}`)}`);
            // Description
            if (card.description) {
                lines.push(`  │ ${picocolors_1.default.dim(card.description.substring(0, 80))}`);
            }
            // Evidence
            if (card.evidence) {
                const ev = card.evidence.length > 70 ? card.evidence.substring(0, 67) + '...' : card.evidence;
                lines.push(`  │ ${picocolors_1.default.white('Evidence:')} ${picocolors_1.default.dim(ev)}`);
            }
            // Recommendation
            if (card.recommendation) {
                lines.push(`  │ ${picocolors_1.default.white('Fix:')} ${picocolors_1.default.dim(card.recommendation.substring(0, 75))}`);
            }
            lines.push(picocolors_1.default.white(`  └──────────────────────────────────────────────────────┘`));
            lines.push('');
        }
    }
    // Footer
    lines.push(picocolors_1.default.white('  ═══════════════════════════════════════════════'));
    lines.push('');
    return lines.join('\n');
}
