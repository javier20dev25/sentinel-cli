export interface NpmVulnerability {
    id: string;
    packageName: string;
    severity: string;
    title: string;
    cvssScore?: number;
    cveId?: string;
    fixAvailable?: string;
    path: string[];
}
export interface NpmAuditResult {
    auditDate: string;
    vulnerabilities: NpmVulnerability[];
    metadata: {
        totalDependencies: number;
        totalVulnerabilities: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}
export declare class NpmAuditParser {
    runAudit(): Promise<NpmAuditResult>;
    parseAuditJson(raw: any): NpmAuditResult;
    mockData(): NpmAuditResult;
}
