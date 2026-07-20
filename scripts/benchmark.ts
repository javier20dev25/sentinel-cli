import { runBenchmark, aggregateBenchmark, BenchmarkResult } from '../src/cli/benchmark';

const corpusRoot = process.argv[2] || './scripts/corpus';

const results = runBenchmark(corpusRoot);
const aggregated = aggregateBenchmark(results);

if (process.argv.includes('--json')) {
  console.log(JSON.stringify({ results, aggregated }, null, 2));
} else {
  console.log(`Benchmark complete: ${results.length} fixtures scanned`);
  console.log(`Total findings: ${aggregated.totalFindings}`);
  console.log(`Avg Precision: ${(aggregated.avgPrecision * 100).toFixed(1)}%`);
  console.log(`Avg Recall: ${(aggregated.avgRecall * 100).toFixed(1)}%`);

  for (const r of results) {
    console.log(`  ${r.repoPath}: ${r.findingsCount} findings, precision=${(r.precision * 100).toFixed(1)}%, recall=${(r.recall * 100).toFixed(1)}%`);
  }
}
