export interface MultiLangFinding {
    type: string;
    subcode: string;
    language: 'python' | 'go' | 'rust';
    file: string;
    line: number;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    riskScore: number;
    title: string;
    description: string;
    snippet: string;
    evidence?: string;
}
export interface MultiLangResult {
    findings: MultiLangFinding[];
    language: string;
    fileCount: number;
}
export declare function scanMultiLang(file: string, content: string): MultiLangFinding[];
