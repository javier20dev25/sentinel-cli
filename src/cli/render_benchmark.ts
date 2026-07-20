import pc from 'picocolors';
import { BenchmarkResult } from './benchmark';

function pct(value: number): string {
  const p = (value * 100).toFixed(1);
  if (value >= 0.9) return pc.green(`${p}%`);
  if (value >= 0.7) return pc.yellow(`${p}%`);
  return pc.red(`${p}%`);
}

export function renderBenchmark(results: BenchmarkResult[], aggregated: {
  totalFixtures: number;
  totalFindings: number;
  avgPrecision: number;
  avgRecall: number;
  worstFp: BenchmarkResult[];
  worstFn: BenchmarkResult[];
}): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.white(pc.bold('  ══════════════════════════════════════')));
  lines.push(pc.white(pc.bold('   SENTINEL BENCHMARK RESULTS')));
  lines.push(pc.white(pc.bold('  ══════════════════════════════════════')));
  lines.push('');

  lines.push(`  ${pc.bold('Total Fixtures:')}   ${pc.cyan(String(aggregated.totalFixtures))}`);
  lines.push(`  ${pc.bold('Total Findings:')}   ${pc.cyan(String(aggregated.totalFindings))}`);
  lines.push(`  ${pc.bold('Avg Precision:')}    ${pct(aggregated.avgPrecision)}`);
  lines.push(`  ${pc.bold('Avg Recall:')}       ${pct(aggregated.avgRecall)}`);
  lines.push('');

  if (results.length === 0) {
    lines.push(pc.dim('  No fixtures found in corpus.'));
    lines.push('');
    return lines.join('\n');
  }

  lines.push(pc.dim('  ─── Per-fixture breakdown ───────────────'));
  lines.push('');

  for (const r of results) {
    const fpCount = r.falsePositives.length;
    const fnCount = r.falseNegatives.length;
    const label = fpCount > 0 || fnCount > 0 ? pc.red : pc.green;
    lines.push(`  ${pc.bold(r.repoPath)}`);
    lines.push(`    Findings: ${pc.cyan(String(r.findingsCount))}  `
      + `Precision: ${pct(r.precision)}  Recall: ${pct(r.recall)}  `
      + `Time: ${pc.dim(r.scanTimeMs + 'ms')}`);
    if (fpCount > 0) {
      lines.push(`    ${pc.red(`FP: ${fpCount}`)} ${pc.dim(r.falsePositives.join(', '))}`);
    }
    if (fnCount > 0) {
      lines.push(`    ${pc.yellow(`FN: ${fnCount}`)} ${pc.dim(r.falseNegatives.join(', '))}`);
    }
    lines.push('');
  }

  if (aggregated.worstFp.length > 0 && aggregated.worstFp[0].falsePositives.length > 0) {
    lines.push(pc.dim('  ─── Worst FP offenders ──────────────────'));
    lines.push('');
    for (const r of aggregated.worstFp) {
      if (r.falsePositives.length === 0) break;
      lines.push(`  ${pc.red(`${r.falsePositives.length} FP`)}  ${pc.bold(r.repoPath)}  ${pc.dim(r.falsePositives.join(', '))}`);
    }
    lines.push('');
  }

  if (aggregated.worstFn.length > 0 && aggregated.worstFn[0].falseNegatives.length > 0) {
    lines.push(pc.dim('  ─── Worst FN offenders ──────────────────'));
    lines.push('');
    for (const r of aggregated.worstFn) {
      if (r.falseNegatives.length === 0) break;
      lines.push(`  ${pc.yellow(`${r.falseNegatives.length} FN`)}  ${pc.bold(r.repoPath)}  ${pc.dim(r.falseNegatives.join(', '))}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
