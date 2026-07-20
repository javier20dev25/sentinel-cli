import pc from 'picocolors';
import { OwnershipResult, AuthorInfo } from '../core/ownership_graph';

export function renderOwnership(ownership: OwnershipResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   OWNERSHIP GRAPH')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  if (ownership.totalAuthors === 0) {
    lines.push(pc.dim('  No git history available to determine ownership.'));
    lines.push('');
    return lines.join('\n');
  }

  lines.push(pc.dim(`  ${ownership.totalAuthors} author(s) identified`));
  lines.push('');

  for (const author of ownership.authors.slice(0, 10)) {
    const riskColor = author.riskScore >= 70 ? pc.red :
      author.riskScore >= 30 ? pc.yellow : pc.green;

    lines.push(`  ${pc.bold(author.name)}  ${pc.dim(`<${author.email}>`)}`);
    lines.push(`    Risk Contribution: ${riskColor(`${author.riskScore} pts`)}  ·  Files: ${author.files.length}  ·  Findings: ${author.findingCount}`);

    const topSubs = Array.from(author.topSubcodes.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4);
    if (topSubs.length > 0) {
      const subStr = topSubs.map(([sub, count]) => `${sub} (${count})`).join(', ');
      lines.push(`    Top Subcodes: ${pc.dim(subStr)}`);
    }

    if (author.files.length <= 4) {
      for (const file of author.files) {
        lines.push(pc.dim(`    📄 ${file}`));
      }
    } else {
      for (const file of author.files.slice(0, 3)) {
        lines.push(pc.dim(`    📄 ${file}`));
      }
      lines.push(pc.dim(`    ... and ${author.files.length - 3} more file(s)`));
    }
    lines.push('');
  }

  if (ownership.totalAuthors > 10) {
    lines.push(pc.dim(`  ... and ${ownership.totalAuthors - 10} more author(s)`));
    lines.push('');
  }

  lines.push(pc.white('  ═══════════════════════════════════════════════'));
  lines.push('');

  return lines.join('\n');
}
