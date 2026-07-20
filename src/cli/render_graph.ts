import pc from 'picocolors';
import { AgencyGraph, EdgeType, GraphNode, GraphEdge } from '../core/agency_graph';

function severityColor(sev: string): (s: string) => string {
  switch (sev) {
    case 'CRITICAL': return pc.red;
    case 'HIGH': return pc.yellow;
    case 'MEDIUM': return pc.cyan;
    default: return (s: string) => s;
  }
}

const EDGE_SYMBOLS: Record<string, string> = {
  causal: '⏩',
  correlated: '──→',
  same_file: '··→',
};

const EDGE_COLORS: Record<string, (s: string) => string> = {
  causal: pc.white,
  correlated: pc.dim,
  same_file: pc.dim,
};

export function renderGraph(graph: AgencyGraph): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   AGENCY GRAPH')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  if (graph.chains.length === 0 && graph.nodes.length === 0) {
    lines.push(pc.dim('  No attack chains detected.'));
    lines.push('');
    return lines.join('\n');
  }

  lines.push(pc.dim(`  ${graph.chains.length} chain(s) • ${graph.nodes.length} node(s) • ${graph.edges.length} edge(s)`));

  // Legend
  lines.push('');
  lines.push(pc.dim('  Legend:  ') + pc.white('⏩ causal') + pc.dim('  ──→ correlated  ··→ same-file'));
  lines.push('');

  if (graph.chains.length === 0 && graph.nodes.length > 0) {
    lines.push(pc.dim('  Nodes found but no chains formed (isolated findings).'));
    lines.push('');
    return lines.join('\n');
  }

  for (let ci = 0; ci < graph.chains.length; ci++) {
    const chain = graph.chains[ci];
    const chainColor = chain.score >= 70 ? pc.red : chain.score >= 30 ? pc.yellow : pc.green;
    const confPct = Math.round(chain.confidence * 100);

    lines.push(pc.dim(`  ─── Chain ${ci + 1} (${chainColor(`${chain.score}/100`)} • confidence ${confPct}%) ────────`));
    lines.push('');

    for (let ni = 0; ni < chain.nodes.length; ni++) {
      const node = chain.nodes[ni];
      const badge = severityColor(node.severity)(`[${node.severity}]`);
      const contrib = node.contribution > 0
        ? pc.dim(` +${node.contribution}`)
        : '';

      lines.push(`    ${badge} ${pc.bold(node.subcode)} ${pc.dim(node.title)}${contrib}`);
      lines.push(`           ${pc.dim(node.file)}:${pc.dim(String(node.line))}  Score: ${node.riskScore}/100  ${pc.dim(node.category)}`);
      if (node.evidence) {
        const ev = node.evidence.length > 60 ? node.evidence.substring(0, 57) + '...' : node.evidence;
        lines.push(`           ${pc.dim(ev)}`);
      }

      if (ni < chain.nodes.length - 1) {
        const next = chain.nodes[ni + 1];
        const edge = graph.edges.find(e => e.sourceId === node.id && e.targetId === next.id);
        if (edge) {
          const edgeType = edge.type as string;
          const symbol = EDGE_SYMBOLS[edgeType] || '→';
          const color = EDGE_COLORS[edgeType] || pc.dim;
          const confPctEdge = Math.round(edge.confidence * 100);
          lines.push(color(`           ${symbol}  ${edge.label}  (confidence ${confPctEdge}%)`));
        }
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}
