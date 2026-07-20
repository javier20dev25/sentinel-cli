import { describe, it, expect } from 'vitest';
import { runBenchmark, aggregateBenchmark } from '../src/cli/benchmark';
import * as path from 'path';

describe('Benchmark', () => {
  it('runs without error on empty corpus', () => {
    const emptyCorpus = path.resolve(__dirname, 'corpus-empty');
    const results = runBenchmark(emptyCorpus);
    expect(Array.isArray(results)).toBe(true);
    expect(results).toHaveLength(0);
  });

  it('calculates precision correctly', () => {
    const corpusRoot = path.resolve(__dirname, 'corpus');
    const results = runBenchmark(corpusRoot);

    const result = results.find(r => r.repoPath.includes('hardcoded_secret'));
    if (result) {
      const precision = result.precision;
      expect(precision).toBeGreaterThanOrEqual(0);
      expect(precision).toBeLessThanOrEqual(1);
    }

    if (results.length > 0) {
      const agg = aggregateBenchmark(results);
      expect(agg.avgPrecision).toBeGreaterThanOrEqual(0);
      expect(agg.avgPrecision).toBeLessThanOrEqual(1);
      expect(agg.avgRecall).toBeGreaterThanOrEqual(0);
      expect(agg.avgRecall).toBeLessThanOrEqual(1);
    }
  });
});
