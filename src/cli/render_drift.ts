import pc from 'picocolors';
import { DriftResult } from './intelligence/behavioral_drift';

export function renderDrift(result: DriftResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   BEHAVIORAL DRIFT REPORT')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');
  lines.push(`  ${pc.bold('Package')}: ${result.packageName}`);
  lines.push(`  ${pc.bold('Versions')}: ${result.previousVersion} → ${result.currentVersion}`);

  const riskColor = result.riskChange > 0 ? pc.red : result.riskChange < 0 ? pc.green : pc.dim;
  const riskSign = result.riskChange > 0 ? '+' : '';
  lines.push(`  ${pc.bold('Risk Δ')}:   ${riskColor(riskSign + String(result.riskChange))}`);
  lines.push('');

  if (result.newCapabilities.length > 0) {
    lines.push(pc.red(`  ● New Capabilities (${result.newCapabilities.length}):`));
    for (const cap of result.newCapabilities) {
      lines.push(`    ${pc.red('■')} ${cap}`);
    }
    lines.push('');
  }

  const increased = result.drifts.filter(d => d.severity === 'INCREASED');
  if (increased.length > 0) {
    lines.push(pc.yellow(`  ▲ Increased (${increased.length}):`));
    for (const d of increased) {
      lines.push(`    ${pc.yellow('▲')} ${d.capability}: ${d.previousCount} → ${d.currentCount}`);
    }
    lines.push('');
  }

  const decreased = result.drifts.filter(d => d.severity === 'DECREASED');
  const removed = result.drifts.filter(d => d.severity === 'REMOVED');
  if (decreased.length > 0 || removed.length > 0) {
    lines.push(pc.green('  ▼ Decreased/Removed:'));
    for (const d of removed) {
      lines.push(`    ${pc.green('✕')} ${d.capability} (removed)`);
    }
    for (const d of decreased) {
      lines.push(`    ${pc.green('▼')} ${d.capability}: ${d.previousCount} → ${d.currentCount}`);
    }
    lines.push('');
  }

  if (result.drifts.length === 0) {
    lines.push(pc.dim('  No capability drift detected.'));
    lines.push('');
  }

  const verdictStr = result.verdict === 'MALICIOUS'
    ? pc.bgRed(pc.white(` ${result.verdict} `))
    : result.verdict === 'SUSPICIOUS'
      ? pc.bgYellow(pc.black(` ${result.verdict} `))
      : pc.bgGreen(pc.black(` ${result.verdict} `));
  lines.push(`  Verdict: ${verdictStr}`);
  lines.push('');

  return lines.join('\n');
}
