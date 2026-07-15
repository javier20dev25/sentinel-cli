import { Vault } from '../vault';
/** @public — frozen contract used by JSON/SARIF/MD exporters */
export interface LiteFinding {
    type: string;
    subcode?: string;
    category?: 'secret' | 'workflow' | 'agent' | 'token' | 'malware' | 'vulnerability' | 'generic' | 'supply-chain' | 'obfuscation' | 'injection' | 'misconfig' | 'ci-cd' | 'ci-supply-chain' | 'ci-evasion' | 'secrets';
    intent: string;
    file: string;
    line: number;
    severity: string;
    riskScore?: number;
    confidence?: 'low' | 'medium' | 'high';
    title?: string;
    description: string;
    evidence?: string;
    snippet: string;
}
export declare class LiteScanner {
    private vault;
    constructor(vault?: Vault);
    private static readonly RULES;
    private emit;
    /**
     * Performs a local scan of a file patch.
     * Uses the same deterministic SAST rules as the Pro version.
     */
    scanPatch(filename: string, patch: string): LiteFinding[];
    /**
     * Post-processing: enrich secret findings with token classification
     * and detect compound token risks from workflow permissions.
     */
    private enrichTokenFindings;
    /**
     * Full file content scan (not diff-based).
     * Scans all lines, calculates entropy, flags size anomalies.
     */
    scanFileContent(filename: string, content: string): {
        findings: LiteFinding[];
        entropyScore: number;
        sizeAnomaly: boolean;
    };
    /**
     * Shannon entropy calculation for a string.
     */
    private calculateEntropy;
    /**
     * Orchestrates the local scan, persists signals to the Vault,
     * and performs basic temporal correlation.
     */
    auditPR(repo: string, pr: number, author: string, files: {
        filename: string;
        patch: string;
    }[]): Promise<{
        scanId: string;
        findings: LiteFinding[];
        correlations: unknown[];
        verdict: {
            band: string;
            decision: string;
            correlationCount: number;
        };
        cta: string | null;
    }>;
}
