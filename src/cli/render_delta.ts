import pc from 'picocolors';
import { FindingDelta } from '../core/pr_delta';

export function renderDelta(delta: FindingDelta): string {
  const lines: string[] = [];

  const newCount = delta.newFindings.length;
  const fixedCount = delta.fixedFindings.length;
  const totalChange = delta.totalAfter - delta.totalBefore;

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   PR DELTA ANALYSIS')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  lines.push(`  ${pc.bold('Summary')}:  ${delta.totalBefore} → ${delta.totalAfter} findings (${totalChange > 0 ? pc.red(`+${totalChange}`) : totalChange < 0 ? pc.green(`${totalChange}`) : pc.dim('0')})`);
  lines.push('');

  if (newCount > 0) {
    lines.push(pc.red(`  ● ${newCount} new finding(s) introduced:`));
    lines.push('');
    for (const f of delta.newFindings.slice(0, 10)) {
      const color = f.severity === 'CRITICAL' ? pc.red :
        f.severity === 'HIGH' ? pc.yellow : pc.dim;
      lines.push(`    ${color('■')} [${f.severity}] ${pc.bold(f.subcode || f.type)}  ${pc.dim(f.file)}:${f.line}`);
      if (f.title) lines.push(`       ${pc.dim(f.title)}`);
    }
    if (newCount > 10) {
      lines.push(pc.dim(`    ... and ${newCount - 10} more new finding(s)`));
    }
    lines.push('');
  }

  if (fixedCount > 0) {
    lines.push(pc.green(`  ✔ ${fixedCount} finding(s) fixed since baseline:`));
    lines.push('');
    for (const f of delta.fixedFindings.slice(0, 10)) {
      lines.push(`    ${pc.green('✔')} ${pc.dim(`${f.subcode}  •  ${f.file}:${f.line}`)}`);
      if (f.title) lines.push(`       ${pc.dim(f.title)}`);
    }
    if (fixedCount > 10) {
      lines.push(pc.dim(`    ... and ${fixedCount - 10} more fixed finding(s)`));
    }
    lines.push('');
  }

  if (newCount === 0 && fixedCount === 0) {
    lines.push(pc.dim('  No change in findings since baseline.'));
    lines.push('');
  }

  lines.push(pc.white('  ═══════════════════════════════════════════════'));
  lines.push('');

  return lines.join('\n');
}
