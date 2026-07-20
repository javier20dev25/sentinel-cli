import pc from 'picocolors';
import { RiskSnapshot, RiskTrend } from '../core/risk_history';

function fmtDelta(val: number, suffix = ''): string {
  if (val === 0) return pc.dim(`0${suffix}`);
  if (val > 0) return pc.green(`+${val}${suffix}`);
  return pc.red(`${val}${suffix}`);
}

export interface TrendDisplayOptions {
  windowDays?: number;
  branch?: string;
  baselineScore?: number;
  baselineCritical?: number;
}

export function renderTrend(trend: RiskTrend, opts?: TrendDisplayOptions): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   RISK HISTORY & TREND')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  if (trend.snapshots.length === 0) {
    lines.push(pc.dim('  No history available for this repository.'));
    lines.push(pc.dim('  Run scan with --save-history to start tracking.'));
    lines.push('');
    return lines.join('\n');
  }

  const latest = trend.snapshots[trend.snapshots.length - 1];
  const arrow = trend.direction === 'improving' ? pc.green('↑') :
    trend.direction === 'declining' ? pc.red('↓') : pc.dim('→');

  lines.push(`  ${pc.bold('Direction:')}  ${arrow} ${pc.bold(trend.direction.toUpperCase())}`);
  if (opts?.windowDays) {
    const windowLabel = `Last ${opts.windowDays} days`;
    lines.push(`  ${pc.bold('Window:')}    ${windowLabel}`);
  }
  if (opts?.branch) {
    lines.push(`  ${pc.bold('Branch:')}    ${opts.branch}`);
  }
  lines.push(`  ${pc.bold('Score Δ:')}    ${fmtDelta(trend.scoreDelta, ' pts')}`);
  lines.push(`  ${pc.bold('Findings Δ:')}  ${fmtDelta(trend.findingDelta)}`);
  lines.push(`  ${pc.bold('Critical Δ:')}  ${fmtDelta(trend.criticalDelta)}`);
  if (opts?.baselineScore !== undefined) {
    const scoreDiff = opts.baselineScore - latest.agencyScore;
    const criticalDiff = (opts.baselineCritical ?? 0) - latest.criticalCount;
    lines.push(`  ${pc.bold('vs main:')}   ${fmtDelta(scoreDiff, ' pts')}, ${fmtDelta(criticalDiff, ' critical')}`);
  }
  lines.push('');

  lines.push(pc.dim('  ─── Recent Snapshots ─────────────────────────────'));
  lines.push('');

  const recent = trend.snapshots.slice(-5);
  for (const snap of recent) {
    const date = new Date(snap.timestamp).toLocaleDateString();
    const time = new Date(snap.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const scoreColor = snap.agencyScore >= 70 ? pc.red :
      snap.agencyScore >= 30 ? pc.yellow : pc.green;
    const verdictColor = snap.verdict === 'BLOCK' ? pc.red :
      snap.verdict === 'REVIEW' ? pc.yellow : pc.green;

    lines.push(`  ${pc.dim(`${date} ${time}`)}  ${scoreColor(`${snap.agencyScore}/100`)}  ${verdictColor(snap.verdict)}  ${pc.dim(`⬡ ${snap.totalFindings} findings, ${snap.criticalCount} critical, ${snap.scenarioCount} scenarios`)}`);
  }

  if (trend.snapshots.length > 5) {
    lines.push(pc.dim(`  ... and ${trend.snapshots.length - 5} older snapshot(s)`));
  }

  lines.push('');
  lines.push(pc.white('  ═══════════════════════════════════════════════'));
  lines.push('');

  return lines.join('\n');
}

export function renderSnapshotList(repos: Map<string, RiskSnapshot[]>): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   SENTINEL HISTORY')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  if (repos.size === 0) {
    lines.push(pc.dim('  No history found. Run scan --save-history to start tracking.'));
    lines.push('');
    return lines.join('\n');
  }

  for (const [repoPath, snapshots] of repos) {
    const latest = snapshots[0];
    const scoreColor = latest.agencyScore >= 70 ? pc.red :
      latest.agencyScore >= 30 ? pc.yellow : pc.green;
    const date = new Date(latest.timestamp).toLocaleDateString();
    lines.push(`  ${pc.bold(pathShort(repoPath))}`);
    lines.push(`    ${pc.dim(repoPath)}`);
    lines.push(`    Latest: ${scoreColor(`${latest.agencyScore}/100`)}  ${pc.dim(`${latest.totalFindings} findings, ${snapshots.length} snapshot(s) — ${date}`)}`);
    lines.push('');
  }

  return lines.join('\n');
}

function pathShort(p: string): string {
  const parts = p.replace(/\\/g, '/').split('/');
  return parts.slice(-2).join('/');
}
