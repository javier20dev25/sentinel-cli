import pc from 'picocolors';
import { AttackScenario } from '../core/attack_scenario';

function sevColor(sev: string): (s: string) => string {
  switch (sev) {
    case 'CRITICAL': return pc.red;
    case 'HIGH': return pc.yellow;
    case 'MEDIUM': return pc.cyan;
    default: return pc.dim;
  }
}

function fmtPct(n: number): string {
  return Math.round(n * 100) + '%';
}

export function renderScenarios(scenarios: AttackScenario[]): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   ATTACK SCENARIOS')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  if (scenarios.length === 0) {
    lines.push(pc.green('  ✔ No attack scenarios identified.'));
    lines.push('');
    return lines.join('\n');
  }

  lines.push(pc.dim(`  ${scenarios.length} scenario(s) detected`));
  lines.push('');

  for (let si = 0; si < scenarios.length; si++) {
    const s = scenarios[si];
    const color = sevColor(s.severity);
    const badge = color(`[${s.severity}]`);
    const confPct = fmtPct(s.confidence);

    lines.push(pc.dim(`  ─── Scenario ${si + 1} (${color(`${s.score}/100`)} • ${confPct} confidence) ──────`));
    lines.push('');
    lines.push(`    ${badge} ${pc.bold(s.name)}    ${pc.dim(s.id)}`);
    lines.push('');
    lines.push(`    ${pc.dim(s.description)}`);
    lines.push('');
    lines.push(`    ${pc.white('Impact:')} ${pc.dim(s.impact)}`);
    lines.push('');

    // Evidence
    lines.push(pc.dim('    Evidence:'));
    for (const ev of s.evidence) {
      lines.push(`      • ${pc.dim(ev)}`);
    }
    lines.push('');
  }

  lines.push(pc.white('  ═══════════════════════════════════════════════'));
  lines.push('');

  return lines.join('\n');
}
