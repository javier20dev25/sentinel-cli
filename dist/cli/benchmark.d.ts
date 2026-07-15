export interface BenchmarkResult {
    scanId: string;
    repoPath: string;
    findingsCount: number;
    criticalCount: number;
    highCount: number;
    agencyScore: number;
    scanTimeMs: number;
    falsePositives: string[];
    falseNegatives: string[];
    precision: number;
    recall: number;
}
export interface CorpusConfig {
    knownVulnerable: string[];
    knownBenign: string[];
    expectedFindings: Record<string, string[]>;
}
export declare function runBenchmark(corpusRoot: string): BenchmarkResult[];
export declare function aggregateBenchmark(results: BenchmarkResult[]): {
    totalFixtures: number;
    totalFindings: number;
    avgPrecision: number;
    avgRecall: number;
    worstFp: BenchmarkResult[];
    worstFn: BenchmarkResult[];
};
