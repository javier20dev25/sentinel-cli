"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderGraph = renderGraph;
const picocolors_1 = __importDefault(require("picocolors"));
function severityColor(sev) {
    switch (sev) {
        case 'CRITICAL': return picocolors_1.default.red;
        case 'HIGH': return picocolors_1.default.yellow;
        case 'MEDIUM': return picocolors_1.default.cyan;
        default: return (s) => s;
    }
}
const EDGE_SYMBOLS = {
    causal: '⏩',
    correlated: '──→',
    same_file: '··→',
};
const EDGE_COLORS = {
    causal: picocolors_1.default.white,
    correlated: picocolors_1.default.dim,
    same_file: picocolors_1.default.dim,
};
function renderGraph(graph) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   AGENCY GRAPH')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    if (graph.chains.length === 0 && graph.nodes.length === 0) {
        lines.push(picocolors_1.default.dim('  No attack chains detected.'));
        lines.push('');
        return lines.join('\n');
    }
    lines.push(picocolors_1.default.dim(`  ${graph.chains.length} chain(s) • ${graph.nodes.length} node(s) • ${graph.edges.length} edge(s)`));
    // Legend
    lines.push('');
    lines.push(picocolors_1.default.dim('  Legend:  ') + picocolors_1.default.white('⏩ causal') + picocolors_1.default.dim('  ──→ correlated  ··→ same-file'));
    lines.push('');
    if (graph.chains.length === 0 && graph.nodes.length > 0) {
        lines.push(picocolors_1.default.dim('  Nodes found but no chains formed (isolated findings).'));
        lines.push('');
        return lines.join('\n');
    }
    for (let ci = 0; ci < graph.chains.length; ci++) {
        const chain = graph.chains[ci];
        const chainColor = chain.score >= 70 ? picocolors_1.default.red : chain.score >= 30 ? picocolors_1.default.yellow : picocolors_1.default.green;
        const confPct = Math.round(chain.confidence * 100);
        lines.push(picocolors_1.default.dim(`  ─── Chain ${ci + 1} (${chainColor(`${chain.score}/100`)} • confidence ${confPct}%) ────────`));
        lines.push('');
        for (let ni = 0; ni < chain.nodes.length; ni++) {
            const node = chain.nodes[ni];
            const badge = severityColor(node.severity)(`[${node.severity}]`);
            const contrib = node.contribution > 0
                ? picocolors_1.default.dim(` +${node.contribution}`)
                : '';
            lines.push(`    ${badge} ${picocolors_1.default.bold(node.subcode)} ${picocolors_1.default.dim(node.title)}${contrib}`);
            lines.push(`           ${picocolors_1.default.dim(node.file)}:${picocolors_1.default.dim(String(node.line))}  Score: ${node.riskScore}/100  ${picocolors_1.default.dim(node.category)}`);
            if (node.evidence) {
                const ev = node.evidence.length > 60 ? node.evidence.substring(0, 57) + '...' : node.evidence;
                lines.push(`           ${picocolors_1.default.dim(ev)}`);
            }
            if (ni < chain.nodes.length - 1) {
                const next = chain.nodes[ni + 1];
                const edge = graph.edges.find(e => e.sourceId === node.id && e.targetId === next.id);
                if (edge) {
                    const edgeType = edge.type;
                    const symbol = EDGE_SYMBOLS[edgeType] || '→';
                    const color = EDGE_COLORS[edgeType] || picocolors_1.default.dim;
                    const confPctEdge = Math.round(edge.confidence * 100);
                    lines.push(color(`           ${symbol}  ${edge.label}  (confidence ${confPctEdge}%)`));
                }
            }
        }
        lines.push('');
    }
    return lines.join('\n');
}
