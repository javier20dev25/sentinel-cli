import pc from 'picocolors';
import { EvidenceCard } from '../core/evidence_card';
import { AgencyScoreResult } from '../core/agency_score';

function severityColor(sev: string): (s: string) => string {
  switch (sev) {
    case 'CRITICAL': return pc.red;
    case 'HIGH': return pc.yellow;
    case 'MEDIUM': return pc.cyan;
    default: return (s: string) => s;
  }
}

function padRight(s: string, n: number): string {
  return s + ' '.repeat(Math.max(0, n - s.length));
}

export function renderEvidenceCards(
  cards: EvidenceCard[],
  agency: AgencyScoreResult,
): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   AGENCY SCORE REPORT')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  // Score summary
  const scoreColor = agency.agencyScore >= 70 ? pc.red :
    agency.agencyScore >= 30 ? pc.yellow : pc.green;
  lines.push(`    ${pc.bold('Agency Score')}:  ${scoreColor(`${agency.agencyScore}/100`)}`);
  lines.push(`    ${pc.bold('Blast Radius')}: ${severityColor(agency.blastRadius)(agency.blastRadius)}`);
  const verdictColor = agency.verdict === 'BLOCK' ? pc.red :
    agency.verdict === 'REVIEW' ? pc.yellow : pc.green;
  lines.push(`    ${pc.bold('Verdict')}:     ${verdictColor(agency.verdict)}`);
  lines.push(`    ${pc.bold('Findings')}:     ${agency.totalFindings} scored (${agency.criticalCount} critical, ${agency.highCount} high)`);
  lines.push('');

  // Top drivers
  if (agency.drivers.length > 0) {
    lines.push(pc.dim('  ─── Drivers ───────────────────────────────────'));
    lines.push('');
    for (const d of agency.drivers.slice(0, 5)) {
      const color = d.contribution >= 30 ? pc.red :
        d.contribution >= 15 ? pc.yellow : pc.dim;
      lines.push(`    ${color(`+${d.contribution}`)}  ${pc.dim(`[${d.subcode}]`)} ${d.title}`);
    }
    if (agency.drivers.length > 5) {
      lines.push(pc.dim(`    ... and ${agency.drivers.length - 5} more`));
    }
    lines.push('');
  }

  // Evidence Cards
  if (cards.length > 0) {
    lines.push(pc.dim('  ─── Evidence Cards ─────────────────────────────'));
    lines.push('');

    for (const card of cards) {
      const color = severityColor(card.severity);
      lines.push(pc.white(`  ┌──────────────────────────────────────────────────────┐`));

      // Title line
      const badge = color(`[${card.severity}]`);
      const contrib = card.contribution !== undefined ? pc.dim(` +${card.contribution}`) : '';
      const label = card.subcode ? `${card.subcode}` : '';
      lines.push(`  │ ${badge} ${pc.bold(card.title)}${contrib}`);

      // Subcode + file:line + category
      lines.push(`  │ ${pc.dim(`${label}  •  ${card.file}:${card.line}  •  ${card.category}  •  Score: ${card.riskScore}/100  •  Confidence: ${card.confidence.toUpperCase()}`)}`);

      // Description
      if (card.description) {
        lines.push(`  │ ${pc.dim(card.description.substring(0, 80))}`);
      }

      // Evidence
      if (card.evidence) {
        const ev = card.evidence.length > 70 ? card.evidence.substring(0, 67) + '...' : card.evidence;
        lines.push(`  │ ${pc.white('Evidence:')} ${pc.dim(ev)}`);
      }

      // Recommendation
      if (card.recommendation) {
        lines.push(`  │ ${pc.white('Fix:')} ${pc.dim(card.recommendation.substring(0, 75))}`);
      }

      lines.push(pc.white(`  └──────────────────────────────────────────────────────┘`));
      lines.push('');
    }
  }

  // Footer
  lines.push(pc.white('  ═══════════════════════════════════════════════'));
  lines.push('');

  return lines.join('\n');
}
