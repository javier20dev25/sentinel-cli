"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderEvidencePacks = renderEvidencePacks;
const picocolors_1 = __importDefault(require("picocolors"));
function sevColor(sev) {
    switch (sev) {
        case 'CRITICAL': return picocolors_1.default.red;
        case 'HIGH': return picocolors_1.default.yellow;
        case 'MEDIUM': return picocolors_1.default.cyan;
        default: return picocolors_1.default.dim;
    }
}
function renderEvidencePacks(packs) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   EXECUTIVE EVIDENCE REPORT')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════════════════')));
    lines.push('');
    if (packs.length === 0) {
        lines.push(picocolors_1.default.green('  ✔ No attack scenarios identified. No executive report needed.'));
        lines.push('');
        return lines.join('\n');
    }
    const critical = packs.filter(p => p.severity === 'CRITICAL').length;
    const high = packs.filter(p => p.severity === 'HIGH').length;
    lines.push(picocolors_1.default.dim(`  ${packs.length} scenario(s) detected  ·  ${picocolors_1.default.red(`${critical} critical`)}  ·  ${picocolors_1.default.yellow(`${high} high`)}`));
    lines.push('');
    for (let pi = 0; pi < packs.length; pi++) {
        const pack = packs[pi];
        const color = sevColor(pack.severity);
        const badge = color(`[${pack.severity}]`);
        const confPct = Math.round(pack.confidence * 100);
        lines.push(picocolors_1.default.dim(`  ${'─'.repeat(70)}`));
        lines.push('');
        lines.push(`  ${badge}  ${picocolors_1.default.bold(pack.title)}    ${picocolors_1.default.dim(`ID: ${pack.id}  ·  Score: ${color(`${pack.score}/100`)}  ·  Confidence: ${confPct}%`)}`);
        if (pack.chainLength > 0) {
            lines.push(picocolors_1.default.dim(`        ${pack.chainLength} step(s) in attack chain  ·  ${pack.affectedAssets.length} affected asset(s)`));
        }
        lines.push('');
        lines.push(`  ${picocolors_1.default.white('Narrative:')}`);
        lines.push(`    ${picocolors_1.default.dim(wrap(pack.narrative, 68))}`);
        lines.push('');
        lines.push(`  ${picocolors_1.default.white('Impact:')}`);
        lines.push(`    ${picocolors_1.default.dim(wrap(pack.impact, 68))}`);
        lines.push('');
        if (pack.evidenceItems.length > 0) {
            lines.push(`  ${picocolors_1.default.white('Evidence Chain:')}`);
            for (const item of pack.evidenceItems) {
                const itemColor = sevColor(item.severity);
                lines.push(`    ${itemColor('◆')} ${picocolors_1.default.bold(item.subcode)}  ${picocolors_1.default.dim(item.title)}`);
                lines.push(`       ${picocolors_1.default.dim(`${item.file}:${item.line}`)}  ·  Score: ${item.riskScore}/100  ·  ${itemColor(item.severity)}`);
                if (item.detail) {
                    lines.push(`       ${picocolors_1.default.dim(item.detail)}`);
                }
            }
            lines.push('');
        }
        if (pack.remediationSteps.length > 0) {
            lines.push(`  ${picocolors_1.default.white('Remediation:')}`);
            for (const step of pack.remediationSteps) {
                lines.push(`    ${picocolors_1.default.green('→')} ${picocolors_1.default.dim(step)}`);
            }
            lines.push('');
        }
        if (pack.affectedAssets.length > 0) {
            lines.push(`  ${picocolors_1.default.white('Affected Assets:')}`);
            for (const asset of pack.affectedAssets.slice(0, 5)) {
                lines.push(`    ${picocolors_1.default.dim('📄 ' + asset)}`);
            }
            if (pack.affectedAssets.length > 5) {
                lines.push(picocolors_1.default.dim(`    ... and ${pack.affectedAssets.length - 5} more`));
            }
            lines.push('');
        }
    }
    lines.push(picocolors_1.default.white('  ═══════════════════════════════════════════════════════════'));
    lines.push('');
    return lines.join('\n');
}
function wrap(text, maxWidth) {
    const words = text.split(' ');
    const lines = [];
    let current = '';
    for (const word of words) {
        if (current.length + word.length + 1 > maxWidth && current.length > 0) {
            lines.push(current);
            current = word;
        }
        else if (current.length === 0) {
            current = word;
        }
        else {
            current += ' ' + word;
        }
    }
    if (current)
        lines.push(current);
    return lines.join('\n       ');
}
