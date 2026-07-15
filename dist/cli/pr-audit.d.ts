interface PrAuditOptions {
    repo: string;
    prNumber: number;
    diffFile?: string;
    diff?: string;
    author?: string;
    outputFile?: string;
    comment?: boolean;
    checkRun?: boolean;
}
interface FindingOutput {
    type: string;
    intent: string;
    file: string;
    line: number;
    severity: string;
    description: string;
    snippet: string;
    risk: string;
}
interface PrAuditResult {
    scanId: string;
    repo: string;
    prNumber: number;
    author: string;
    findings: FindingOutput[];
    filesAnalyzed: number;
    correlations: number;
    threatIntel: {
        knownAuthor: boolean;
        authorThreatCount: number;
        authorRiskLevel: string | null;
        patternMatches: number;
    };
    verdict: {
        band: string;
        decision: string;
        summary: string;
    };
    contentHash: string;
    error?: string;
}
declare function parseUnifiedDiff(raw: string): {
    filename: string;
    patch: string;
}[];
declare function buildMarkdown(result: PrAuditResult): string;
export declare function runPrAudit(options: PrAuditOptions): Promise<PrAuditResult>;
declare function main(): Promise<void>;
export { buildMarkdown, parseUnifiedDiff, main as runPrAuditMain };
