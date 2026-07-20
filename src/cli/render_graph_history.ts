import pc from 'picocolors';
import { GraphSnapshot } from '../core/graph_persistence';

function getTopScore(snapshot: GraphSnapshot): number {
  return snapshot.topChains[0]?.score ?? 0;
}

export function renderGraphHistory(snapshots: GraphSnapshot[]): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   GRAPH SNAPSHOT HISTORY')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  if (snapshots.length === 0) {
    lines.push(pc.dim('  No graph snapshots found. Run scan --save-graph to start tracking.'));
    lines.push('');
    return lines.join('\n');
  }

  lines.push(pc.dim(`  ${snapshots.length} snapshot(s)`));
  lines.push('');

  for (let i = 0; i < snapshots.length; i++) {
    const s = snapshots[i];
    const date = new Date(s.timestamp).toLocaleString();
    const topScore = getTopScore(s);
    const scoreColor = topScore >= 70 ? pc.red : topScore >= 30 ? pc.yellow : pc.green;

    lines.push(`  ${pc.bold(String(i + 1))}. ${pc.dim(date)}`);
    lines.push(`     Nodes: ${s.nodes}  Edges: ${s.edges}  Chains: ${pc.bold(String(s.chains))}  Top Score: ${scoreColor(String(topScore))}`);
    if (s.topChains.length > 0) {
      const top = s.topChains[0];
      lines.push(`     Best chain: score=${top.score}, confidence=${Math.round(top.confidence * 100)}%, nodes=${top.nodeCount}`);
    }
    lines.push('');
  }

  if (snapshots.length >= 2) {
    const sorted = [...snapshots].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const current = sorted[sorted.length - 1];
    const previous = sorted[sorted.length - 2];
    const chainDelta = current.chains - previous.chains;
    const scoreDelta = getTopScore(current) - getTopScore(previous);

    const chainDir = chainDelta > 0 ? pc.red(`+${chainDelta}`) : chainDelta < 0 ? pc.green(String(chainDelta)) : pc.dim('0');
    const scoreDir = scoreDelta > 0 ? pc.red(`+${scoreDelta}`) : scoreDelta < 0 ? pc.green(String(scoreDelta)) : pc.dim('0');

    lines.push(pc.dim('  Trend (vs previous):'));
    lines.push(`    Chain count: ${chainDir}   Top score: ${scoreDir}`);
    lines.push('');
  }

  return lines.join('\n');
}

export function renderGraphDiff(before: GraphSnapshot | null, after: GraphSnapshot): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   GRAPH DIFF')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  const beforeDate = before ? new Date(before.timestamp).toLocaleString() : '(none)';
  const afterDate = new Date(after.timestamp).toLocaleString();
  lines.push(pc.dim(`  Before: ${beforeDate}`));
  lines.push(pc.dim(`  After:  ${afterDate}`));
  lines.push('');

  if (!before) {
    lines.push(pc.dim('  No previous snapshot to compare. Showing current state.'));
    lines.push(pc.dim(`  Chains: ${after.chains}, Nodes: ${after.nodes}, Edges: ${after.edges}`));
    lines.push('');
    return lines.join('\n');
  }

  const chainDelta = after.chains - before.chains;
  const nodeDelta = after.nodes - before.nodes;
  const edgeDelta = after.edges - before.edges;

  lines.push(`  ${pc.bold('Chains:')}    ${before.chains} → ${after.chains}  ${deltaStr(chainDelta)}`);
  lines.push(`  ${pc.bold('Nodes:')}     ${before.nodes} → ${after.nodes}  ${deltaStr(nodeDelta)}`);
  lines.push(`  ${pc.bold('Edges:')}     ${before.edges} → ${after.edges}  ${deltaStr(edgeDelta)}`);
  lines.push('');

  const beforeChainSet = new Set<string>();
  const beforeChainMap = new Map<string, number>();
  for (const chain of before.fullGraph.chains) {
    const key = chain.nodes.map(n => `${n.subcode}:${n.file}:${n.line}`).join('|');
    beforeChainSet.add(key);
    beforeChainMap.set(key, chain.score);
  }

  const newChains: string[] = [];
  const stillPresent: string[] = [];
  for (const chain of after.fullGraph.chains) {
    const key = chain.nodes.map(n => `${n.subcode}:${n.file}:${n.line}`).join('|');
    if (!beforeChainSet.has(key)) {
      newChains.push(key);
    } else {
      stillPresent.push(key);
    }
  }

  const resolvedChains = Array.from(beforeChainMap.entries()).filter(([key]) => {
    return !after.fullGraph.chains.some(c => {
      const ck = c.nodes.map(n => `${n.subcode}:${n.file}:${n.line}`).join('|');
      return ck === key;
    });
  });

  if (newChains.length > 0) {
    lines.push(pc.red(`  🆕 New Chains (${newChains.length}):`));
    for (const key of newChains.slice(0, 5)) {
      lines.push(pc.dim(`     ${key.substring(0, 100)}`));
    }
    if (newChains.length > 5) {
      lines.push(pc.dim(`     ... and ${newChains.length - 5} more`));
    }
    lines.push('');
  }

  if (resolvedChains.length > 0) {
    lines.push(pc.green(`  ✅ Resolved Chains (${resolvedChains.length}):`));
    for (const [key] of resolvedChains.slice(0, 5)) {
      lines.push(pc.dim(`     ${key.substring(0, 100)}`));
    }
    if (resolvedChains.length > 5) {
      lines.push(pc.dim(`     ... and ${resolvedChains.length - 5} more`));
    }
    lines.push('');
  }

  if (newChains.length === 0 && resolvedChains.length === 0) {
    lines.push(pc.dim('  No change in attack chains between snapshots.'));
    lines.push('');
  }

  return lines.join('\n');
}

function deltaStr(delta: number): string {
  if (delta > 0) return pc.red(`+${delta}`);
  if (delta < 0) return pc.green(String(delta));
  return pc.dim('0');
}
