export interface OSVVuln {
    id: string;
    summary: string;
    aliases: string[];
    severity: { type: string; score: string }[];
    published: string;
    modified: string;
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

export class OSVIntegrator {
    private static readonly API_URL = 'https://api.osv.dev/v1/query';
    private static readonly BATCH_API_URL = 'https://api.osv.dev/v1/querybatch';

    /**
     * Query OSV.dev for known vulnerabilities affecting a package@version.
     * Uses the public API (no API key required).
     */
    public async queryPackage(name: string, version: string): Promise<OSVResult> {
        const startTime = Date.now();
        const vulnerabilities: OSVVuln[] = [];

        try {
            const body = JSON.stringify({
                package: { name, ecosystem: 'npm' },
                version: version || 'latest'
            });

            const response = await fetch(OSVIntegrator.API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body,
                signal: AbortSignal.timeout(10000)
            });

            if (!response.ok) {
                return { packageName: name, version, vulnerabilities: [], queryTimeMs: Date.now() - startTime };
            }

            const data = (await response.json()) as OSVResponse;
            if (data.vulns) {
                for (const v of data.vulns) {
                    vulnerabilities.push({
                        id: v.id,
                        summary: v.summary || '',
                        aliases: v.aliases || [],
                        severity: v.severity || [],
                        published: v.published || '',
                        modified: v.modified || ''
                    });
                }
            }
        } catch {
            // Network errors, timeouts — silently degrade
        }

        return {
            packageName: name,
            version,
            vulnerabilities,
            queryTimeMs: Date.now() - startTime
        };
    }

    public async queryBatch(packages: { name: string; version: string }[]): Promise<OSVResult[]> {
        if (packages.length === 0) return []

        const startTime = Date.now()

        try {
            const queries = packages.map(p => ({
                package: { name: p.name, ecosystem: 'npm' },
                version: p.version || 'latest'
            }))

            const response = await fetch(OSVIntegrator.BATCH_API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ queries }),
                signal: AbortSignal.timeout(10000)
            })

            if (!response.ok) throw new Error(`Batch query failed with status ${response.status}`)

            const data = (await response.json()) as { results: Record<string, { vulns: OSVVuln[] }> }

            return packages.map((pkg, index) => {
                const result = data.results ? data.results[String(index)] : undefined
                const vulnerabilities: OSVVuln[] = []
                if (result && result.vulns) {
                    for (const v of result.vulns) {
                        vulnerabilities.push({
                            id: v.id,
                            summary: v.summary || '',
                            aliases: v.aliases || [],
                            severity: v.severity || [],
                            published: v.published || '',
                            modified: v.modified || ''
                        })
                    }
                }
                return {
                    packageName: pkg.name,
                    version: pkg.version,
                    vulnerabilities,
                    queryTimeMs: Date.now() - startTime
                }
            })
        } catch {
            const results: OSVResult[] = []
            for (const pkg of packages) {
                const result = await this.queryPackage(pkg.name, pkg.version)
                results.push(result)
            }
            return results
        }
    }

    /**
     * Get the highest CVSS score from a vulnerability's severity array.
     */
    public static getMaxSeverity(vuln: OSVVuln): { type: string; score: number } | null {
        let max: { type: string; score: number } | null = null;
        for (const s of vuln.severity) {
            const score = parseFloat(s.score);
            if (!isNaN(score) && (!max || score > max.score)) {
                max = { type: s.type, score };
            }
        }
        return max;
    }

    /**
     * Map OSV severity to Sentinel severity
     */
    public static toSentinelSeverity(cvssScore: number): string {
        if (cvssScore >= 9.0) return 'CRITICAL';
        if (cvssScore >= 7.0) return 'HIGH';
        if (cvssScore >= 4.0) return 'MEDIUM';
        return 'LOW';
    }
}
