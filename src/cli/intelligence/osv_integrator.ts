export interface OSVVuln {
    id: string;
    summary: string;
    aliases: string[];
    severity: { type: string; score: string }[];
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

export class OSVIntegrator {
    private static readonly API_URL = 'https://api.osv.dev/v1/query';
    private static readonly BATCH_API_URL = 'https://api.osv.dev/v1/querybatch';
    private static readonly VULN_API_URL = 'https://api.osv.dev/v1/vulns';

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
                        modified: v.modified || '',
                        database_specific: (v as any).database_specific,
                        affected: (v as any).affected,
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
                            modified: v.modified || '',
                            database_specific: (v as any).database_specific,
                            affected: (v as any).affected,
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
     * OSV's /querybatch endpoint returns only minimal vuln stubs (id + modified)
     * — no severity, no affected ranges. This hydrates each unique advisory with
     * its full /v1/vulns/{id} document so source severity and fixed versions are
     * actually available. Hydration is deduplicated by advisory ID and bounded to
     * 8 concurrent requests. Advisories that fail to hydrate keep their stub
     * (later reported as UNKNOWN, never fabricated).
     */
    public async hydrateResults(results: OSVResult[]): Promise<OSVResult[]> {
        const ids = new Set<string>()
        for (const r of results) for (const v of r.vulnerabilities) if (v.id) ids.add(v.id)
        if (ids.size === 0) return results

        const list = Array.from(ids)
        const cache = new Map<string, OSVVuln>()
        const CONCURRENCY = 8
        for (let i = 0; i < list.length; i += CONCURRENCY) {
            const slice = list.slice(i, i + CONCURRENCY)
            const docs = await Promise.all(slice.map(id => this.fetchVuln(id)))
            docs.forEach((d, idx) => { if (d) cache.set(slice[idx], d) })
        }

        return results.map(r => ({
            ...r,
            vulnerabilities: r.vulnerabilities.map(v => cache.get(v.id) || v)
        }))
    }

    private async fetchVuln(id: string): Promise<OSVVuln | null> {
        try {
            const response = await fetch(`${OSVIntegrator.VULN_API_URL}/${encodeURIComponent(id)}`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
                signal: AbortSignal.timeout(10000)
            })
            if (!response.ok) return null
            const v = (await response.json()) as any
            return {
                id: v.id,
                summary: v.summary || '',
                aliases: v.aliases || [],
                severity: v.severity || [],
                published: v.published || '',
                modified: v.modified || '',
                database_specific: v.database_specific,
                affected: v.affected
            }
        } catch {
            return null
        }
    }

    /**
     * Normalize a published severity label (OSV/GHSA `database_specific.severity`,
     * or CVSS scalar strings) to Sentinel's CRITICAL/HIGH/MEDIUM/LOW vocabulary.
     * Returns 'UNKNOWN' when the source value is not a recognized severity — it
     * must never be silently coerced into MEDIUM.
     */
    public static normalizeSeverity(value: string): string {
        const u = String(value || '').trim().toUpperCase();
        if (u === 'MODERATE') return 'MEDIUM';
        if (u === 'CRITICAL' || u === 'HIGH' || u === 'MEDIUM' || u === 'LOW') return u;
        return 'UNKNOWN';
    }

    /**
     * Extract a numeric CVSS score from an OSV `severity[].score` value.
     * The value may be either a bare number ("7.5") or a CVSS **vector**
     * ("CVSS:3.1/AV:N/..."). CVSS v3.x vectors are scored; CVSS v4.0 vectors
     * return null because their base metric (MacroVector) is not implemented
     * here — callers must fall back to the published severity label.
     */
    public static severityScoreOf(raw: string): number | null {
        if (!raw) return null;
        const trimmed = raw.trim();
        if (/^[0-9]/.test(trimmed)) {
            const n = parseFloat(trimmed);
            return isNaN(n) ? null : n;
        }
        if (trimmed.startsWith('CVSS:3.0/') || trimmed.startsWith('CVSS:3.1/')) {
            return OSVIntegrator.parseCvssV3Vector(trimmed);
        }
        return null;
    }

    /**
     * Compute the CVSS v3.0 / v3.1 base score from a vector string.
     * Implements the official base-score formula (FIRST spec). Returns null on
     * malformed vectors.
     */
    public static parseCvssV3Vector(vector: string): number | null {
        try {
            if (!/^CVSS:3\.[01]\//.test(vector)) return null;
            const metric = (k: string): string => {
                const m = vector.match(new RegExp('(?:^|/)' + k + ':([A-Za-z])'));
                return m ? m[1] : '';
            };
            const AV = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as Record<string, number>)[metric('AV')];
            const AC = ({ L: 0.77, H: 0.44 } as Record<string, number>)[metric('AC')];
            const UI = ({ N: 0.85, R: 0.62 } as Record<string, number>)[metric('UI')];
            const S = metric('S');
            const CIA = ({ N: 0.0, L: 0.22, H: 0.56 } as Record<string, number>);
            const C = CIA[metric('C')];
            const I = CIA[metric('I')];
            const A = CIA[metric('A')];
            const prTable = S === 'C'
                ? ({ N: 0.85, L: 0.68, H: 0.5 } as Record<string, number>)
                : ({ N: 0.85, L: 0.62, H: 0.27 } as Record<string, number>);
            const PR = prTable[metric('PR')];

            if ([AV, AC, UI, C, I, A, PR].some(v => v === undefined) || (S !== 'U' && S !== 'C')) {
                return null;
            }

            const iss = 1 - ((1 - C) * (1 - I) * (1 - A));
            const impact = S === 'U'
                ? 6.42 * iss
                : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
            if (impact <= 0) return 0;

            const exploitability = 8.22 * AV * AC * PR * UI;
            const roundup = (x: number): number => Math.ceil(x * 10) / 10;
            const base = S === 'U'
                ? roundup(Math.min(impact + exploitability, 10))
                : roundup(Math.min(1.08 * (impact + exploitability), 10));
            return base;
        } catch {
            return null;
        }
    }

    /**
     * Resolve the **published** severity of an advisory plus its provenance,
     * without ever fabricating a level. Priority:
     *   1. database_specific.severity (OSV/GitHub published label)
     *   2. CVSS v3.x vector → numeric base score
     *   3. numeric CVSS score string
     *   4. CVSS v4.0 vector is recorded but left UNKNOWN (not scored here)
     *   5. otherwise UNKNOWN with source 'none'
     */
    public static getSourceSeverity(vuln: OSVVuln): {
        level: string;
        source: string;
        cvssType?: string;
        cvssVector?: string;
        cvssScore?: number;
    } {
        const db = vuln.database_specific && (vuln.database_specific as any).severity;
        if (typeof db === 'string' && db.trim()) {
            return { level: OSVIntegrator.normalizeSeverity(db), source: 'osv.database_specific.severity' };
        }

        let best: { type: string; score: number; vector: string } | null = null;
        for (const s of (vuln.severity || [])) {
            const num = OSVIntegrator.severityScoreOf(s.score);
            if (num !== null && (!best || num > best.score)) {
                best = { type: s.type, score: num, vector: s.score };
            }
        }
        if (best) {
            const fromVector = /^CVSS:/.test(best.vector);
            return {
                level: OSVIntegrator.toSentinelSeverity(best.score),
                source: fromVector ? 'osv.severity.cvss_vector' : 'osv.severity.cvss_score',
                cvssType: best.type,
                cvssVector: best.vector,
                cvssScore: best.score
            };
        }

        const v4 = (vuln.severity || []).find(s => s.type === 'CVSS_V4' || /^CVSS:4\.0\//.test(s.score || ''));
        if (v4) {
            return { level: 'UNKNOWN', source: 'osv.severity.cvss_v4_unmapped', cvssType: v4.type, cvssVector: v4.score };
        }

        return { level: 'UNKNOWN', source: 'none' };
    }

    /**
     * Collect the first-fixed versions declared by an advisory's affected ranges.
     */
    public static getFixedVersions(vuln: OSVVuln): string[] {
        const out = new Set<string>();
        for (const a of (vuln.affected || [])) {
            for (const r of (a.ranges || [])) {
                for (const e of (r.events || [])) {
                    if (e && typeof e.fixed === 'string' && e.fixed) out.add(e.fixed);
                }
            }
        }
        return Array.from(out).sort();
    }

    /**
     * Get the highest CVSS score from a vulnerability's severity array.
     * Accepts both numeric score strings and CVSS v3.x vectors.
     */
    public static getMaxSeverity(vuln: OSVVuln): { type: string; score: number } | null {
        let max: { type: string; score: number } | null = null;
        for (const s of vuln.severity) {
            const score = OSVIntegrator.severityScoreOf(s.score);
            if (score !== null && (!max || score > max.score)) {
                max = { type: s.type, score };
            }
        }
        return max;
    }

    /**
     * Map a numeric CVSS score to Sentinel severity.
     */
    public static toSentinelSeverity(cvssScore: number): string {
        if (cvssScore >= 9.0) return 'CRITICAL';
        if (cvssScore >= 7.0) return 'HIGH';
        if (cvssScore >= 4.0) return 'MEDIUM';
        return 'LOW';
    }
}
