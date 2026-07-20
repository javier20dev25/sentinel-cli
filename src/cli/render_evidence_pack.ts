import pc from 'picocolors';
import { EvidencePack, EvidenceItem } from '../core/evidence_pack';

function sevColor(sev: string): (s: string) => string {
  switch (sev) {
    case 'CRITICAL': return pc.red;
    case 'HIGH': return pc.yellow;
    case 'MEDIUM': return pc.cyan;
    default: return pc.dim;
  }
}

export function renderEvidencePacks(packs: EvidencePack[]): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   EXECUTIVE EVIDENCE REPORT')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════════════════')));
  lines.push('');

  if (packs.length === 0) {
    lines.push(pc.green('  ✔ No attack scenarios identified. No executive report needed.'));
    lines.push('');
    return lines.join('\n');
  }

  const critical = packs.filter(p => p.severity === 'CRITICAL').length;
  const high = packs.filter(p => p.severity === 'HIGH').length;
  lines.push(pc.dim(`  ${packs.length} scenario(s) detected  ·  ${pc.red(`${critical} critical`)}  ·  ${pc.yellow(`${high} high`)}`));
  lines.push('');

  for (let pi = 0; pi < packs.length; pi++) {
    const pack = packs[pi];
    const color = sevColor(pack.severity);
    const badge = color(`[${pack.severity}]`);
    const confPct = Math.round(pack.confidence * 100);

    lines.push(pc.dim(`  ${'─'.repeat(70)}`));
    lines.push('');
    lines.push(`  ${badge}  ${pc.bold(pack.title)}    ${pc.dim(`ID: ${pack.id}  ·  Score: ${color(`${pack.score}/100`)}  ·  Confidence: ${confPct}%`)}`);

    if (pack.chainLength > 0) {
      lines.push(pc.dim(`        ${pack.chainLength} step(s) in attack chain  ·  ${pack.affectedAssets.length} affected asset(s)`));
    }
    lines.push('');

    lines.push(`  ${pc.white('Narrative:')}`);
    lines.push(`    ${pc.dim(wrap(pack.narrative, 68))}`);
    lines.push('');

    lines.push(`  ${pc.white('Impact:')}`);
    lines.push(`    ${pc.dim(wrap(pack.impact, 68))}`);
    lines.push('');

    if (pack.evidenceItems.length > 0) {
      lines.push(`  ${pc.white('Evidence Chain:')}`);
      for (const item of pack.evidenceItems) {
        const itemColor = sevColor(item.severity);
        lines.push(`    ${itemColor('◆')} ${pc.bold(item.subcode)}  ${pc.dim(item.title)}`);
        lines.push(`       ${pc.dim(`${item.file}:${item.line}`)}  ·  Score: ${item.riskScore}/100  ·  ${itemColor(item.severity)}`);
        if (item.detail) {
          lines.push(`       ${pc.dim(item.detail)}`);
        }
      }
      lines.push('');
    }

    if (pack.remediationSteps.length > 0) {
      lines.push(`  ${pc.white('Remediation:')}`);
      for (const step of pack.remediationSteps) {
        lines.push(`    ${pc.green('→')} ${pc.dim(step)}`);
      }
      lines.push('');
    }

    if (pack.affectedAssets.length > 0) {
      lines.push(`  ${pc.white('Affected Assets:')}`);
      for (const asset of pack.affectedAssets.slice(0, 5)) {
        lines.push(`    ${pc.dim('📄 ' + asset)}`);
      }
      if (pack.affectedAssets.length > 5) {
        lines.push(pc.dim(`    ... and ${pack.affectedAssets.length - 5} more`));
      }
      lines.push('');
    }
  }

  lines.push(pc.white('  ═══════════════════════════════════════════════════════════'));
  lines.push('');

  return lines.join('\n');
}

function wrap(text: string, maxWidth: number): string {
  const words = text.split(' ');
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (current.length + word.length + 1 > maxWidth && current.length > 0) {
      lines.push(current);
      current = word;
    } else if (current.length === 0) {
      current = word;
    } else {
      current += ' ' + word;
    }
  }
  if (current) lines.push(current);
  return lines.join('\n       ');
}
