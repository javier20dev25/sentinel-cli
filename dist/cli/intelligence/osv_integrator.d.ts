export interface OSVVuln {
    id: string;
    summary: string;
    aliases: string[];
    severity: {
        type: string;
        score: string;
    }[];
    published: string;
    modified: string;
    database_specific?: Record<string, any>;
    affected?: Array<{
        ranges?: Array<{
            type?: string;
            events?: Array<Record<string, string>>;
        }>;
        versions?: string[];
    }>;
}
export interface OSVResponse {
    vulns: OSVVuln[];
}
export interface OSVResult {
    packageName: string;
    version: string;
    vulnerabilities: OSVVuln[];
    queryTimeMs: number;
}
export declare class OSVIntegrator {
    private static readonly API_URL;
    private static readonly BATCH_API_URL;
    /**
     * Query OSV.dev for known vulnerabilities affecting a package@version.
     * Uses the public API (no API key required).
     */
    queryPackage(name: string, version: string): Promise<OSVResult>;
    queryBatch(packages: {
        name: string;
        version: string;
    }[]): Promise<OSVResult[]>;
    /**
     * Get the highest CVSS score from a vulnerability's severity array.
     */
    static getMaxSeverity(vuln: OSVVuln): {
        type: string;
        score: number;
    } | null;
    /**
     * Map OSV severity to Sentinel severity
     */
    static toSentinelSeverity(cvssScore: number): string;
}
