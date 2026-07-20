import pc from 'picocolors';
import { TeamInfo } from '../core/ownership_graph';

export function renderTeams(teams: TeamInfo[]): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   CODEOWNERS TEAM GROUPING')));
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')));
  lines.push('');

  if (teams.length === 0) {
    lines.push(pc.dim('  No teams found. Ensure a CODEOWNERS file exists (.github/CODEOWNERS, docs/CODEOWNERS, or CODEOWNERS).'));
    lines.push('');
    return lines.join('\n');
  }

  lines.push(pc.dim(`  ${teams.length} team(s) identified`));
  lines.push('');

  for (const team of teams) {
    const riskColor = team.riskScore >= 70 ? pc.red :
      team.riskScore >= 30 ? pc.yellow : pc.green;

    lines.push(`  ${pc.bold(team.name)}`);
    lines.push(`    Risk Score: ${riskColor(`${team.riskScore} pts`)}  ·  Files: ${team.files.length}  ·  Findings: ${team.findingCount}`);
    lines.push(`    Members: ${pc.dim(team.members.join(', '))}`);

    const fileList = team.files.slice(0, 5);
    for (const file of fileList) {
      lines.push(pc.dim(`    📄 ${file}`));
    }
    if (team.files.length > 5) {
      lines.push(pc.dim(`    ... and ${team.files.length - 5} more`));
    }
    lines.push('');
  }

  lines.push(pc.white('  ═══════════════════════════════════════════════'));
  lines.push('');

  return lines.join('\n');
}
