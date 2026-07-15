export interface SandboxResult {
    safe: boolean;
    risk: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    findings: {
        type: string;
        detail: string;
        riskScore: number;
    }[];
    executionTimeMs: number;
    error?: string;
}
export declare function runSandbox(code: string, timeoutMs?: number): SandboxResult;
