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
    private static readonly VULN_API_URL;
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
     * OSV's /querybatch endpoint returns only minimal vuln stubs (id + modified)
     * — no severity, no affected ranges. This hydrates each unique advisory with
     * its full /v1/vulns/{id} document so source severity and fixed versions are
     * actually available. Hydration is deduplicated by advisory ID and bounded to
     * 8 concurrent requests. Advisories that fail to hydrate keep their stub
     * (later reported as UNKNOWN, never fabricated).
     */
    hydrateResults(results: OSVResult[]): Promise<OSVResult[]>;
    private fetchVuln;
    /**
     * Normalize a published severity label (OSV/GHSA `database_specific.severity`,
     * or CVSS scalar strings) to Sentinel's CRITICAL/HIGH/MEDIUM/LOW vocabulary.
     * Returns 'UNKNOWN' when the source value is not a recognized severity — it
     * must never be silently coerced into MEDIUM.
     */
    static normalizeSeverity(value: string): string;
    /**
     * Extract a numeric CVSS score from an OSV `severity[].score` value.
     * The value may be either a bare number ("7.5") or a CVSS **vector**
     * ("CVSS:3.1/AV:N/..."). CVSS v3.x vectors are scored; CVSS v4.0 vectors
     * return null because their base metric (MacroVector) is not implemented
     * here — callers must fall back to the published severity label.
     */
    static severityScoreOf(raw: string): number | null;
    /**
     * Compute the CVSS v3.0 / v3.1 base score from a vector string.
     * Implements the official base-score formula (FIRST spec). Returns null on
     * malformed vectors.
     */
    static parseCvssV3Vector(vector: string): number | null;
    /**
     * Resolve the **published** severity of an advisory plus its provenance,
     * without ever fabricating a level. Priority:
     *   1. database_specific.severity (OSV/GitHub published label)
     *   2. CVSS v3.x vector → numeric base score
     *   3. numeric CVSS score string
     *   4. CVSS v4.0 vector is recorded but left UNKNOWN (not scored here)
     *   5. otherwise UNKNOWN with source 'none'
     */
    static getSourceSeverity(vuln: OSVVuln): {
        level: string;
        source: string;
        cvssType?: string;
        cvssVector?: string;
        cvssScore?: number;
    };
    /**
     * Collect the first-fixed versions declared by an advisory's affected ranges.
     */
    static getFixedVersions(vuln: OSVVuln): string[];
    /**
     * Get the highest CVSS score from a vulnerability's severity array.
     * Accepts both numeric score strings and CVSS v3.x vectors.
     */
    static getMaxSeverity(vuln: OSVVuln): {
        type: string;
        score: number;
    } | null;
    /**
     * Map a numeric CVSS score to Sentinel severity.
     */
    static toSentinelSeverity(cvssScore: number): string;
}
