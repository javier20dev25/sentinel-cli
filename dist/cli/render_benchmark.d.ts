import { BenchmarkResult } from './benchmark';
export declare function renderBenchmark(results: BenchmarkResult[], aggregated: {
    totalFixtures: number;
    totalFindings: number;
    avgPrecision: number;
    avgRecall: number;
    worstFp: BenchmarkResult[];
    worstFn: BenchmarkResult[];
}): string;
