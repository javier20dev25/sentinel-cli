import { OSVIntegrator, OSVResult } from './osv_integrator';

/**
 * Result of an audit-deps run. `INCOMPLETE` means the tool could NOT analyze
 * dependencies (unsupported lockfile format, missing lockfile, or a parser that
 * returned zero entries). It must never be conflated with "no findings".
 */
export type AuditStatus = 'COMPLETE' | 'INCOMPLETE';

export interface Finding {
    package: string;
    version: string;
    /** Advisory identifier (e.g. GHSA-xxxx). */
    ghsa: string;
    aliases: string[];
    /** Severity as published by the source (OSV/GHSA), never fabricated. */
    sourceSeverity: string;
    /** Where `sourceSeverity` came from (provenance). */
    sourceSeveritySource: string;
    cvssType?: string;
    cvssVector?: string;
    cvssScore?: number;
    /** Sentinel's own classification (derived from CVSS when available). */
    sentinelSeverity: string;
    /** First-fixed versions declared by the advisory. */
    fixedVersions: string[];
}

export interface AuditSummary {
    /** Raw advisory instances as returned by OSV (may repeat a GHSA). */
    instances: number;
    /** Unique package@version:GHSA combinations. */
    pkgVersionGhsa: number;
    /** Unique advisory IDs (GHSA/CVE), regardless of package/version. */
    uniqueGhsa: number;
    findings: Finding[];
    /** Distribution of unique advisories by published severity. */
    bySourceSeverity: Record<string, number>;
    /** Distribution of unique advisories by Sentinel severity. */
    bySentinelSeverity: Record<string, number>;
}

/**
 * Build the corrected audit summary from raw OSV results.
 *
 * Key guarantees:
 *  - `instances` counts every advisory occurrence (dedupe not applied).
 *  - `pkgVersionGhsa` and `uniqueGhsa` expose the deduplicated view so a single
 *    advisory repeated across versions is NOT counted as independent findings.
 *  - Severity distribution is computed over UNIQUE advisories and preserves the
 *    published (source) severity; Sentinel's own severity is reported separately.
 */
export function summarizeFindings(osvResults: OSVResult[]): AuditSummary {
    const findings: Finding[] = [];
    const seenPkgVerGhsa = new Set<string>();
    const seenGhsa = new Set<string>();
    const bySourceSeverity: Record<string, number> = {};
    const bySentinelSeverity: Record<string, number> = {};
    let instances = 0;
    let pkgVersionGhsa = 0;

    for (const r of osvResults) {
        for (const v of r.vulnerabilities) {
            instances++;

            const src = OSVIntegrator.getSourceSeverity(v);
            const sentinelSeverity = src.cvssScore !== undefined
                ? OSVIntegrator.toSentinelSeverity(src.cvssScore)
                : src.level;

            findings.push({
                package: r.packageName,
                version: r.version,
                ghsa: v.id,
                aliases: v.aliases || [],
                sourceSeverity: src.level,
                sourceSeveritySource: src.source,
                cvssType: src.cvssType,
                cvssVector: src.cvssVector,
                cvssScore: src.cvssScore,
                sentinelSeverity,
                fixedVersions: OSVIntegrator.getFixedVersions(v),
            });

            const pkgVerGhsaKey = `${r.packageName}@${r.version}:${v.id}`;
            if (!seenPkgVerGhsa.has(pkgVerGhsaKey)) {
                seenPkgVerGhsa.add(pkgVerGhsaKey);
                pkgVersionGhsa++;
            }
        }
    }

    for (const f of findings) {
        if (seenGhsa.has(f.ghsa)) continue;
        seenGhsa.add(f.ghsa);
        bySourceSeverity[f.sourceSeverity] = (bySourceSeverity[f.sourceSeverity] || 0) + 1;
        bySentinelSeverity[f.sentinelSeverity] = (bySentinelSeverity[f.sentinelSeverity] || 0) + 1;
    }

    return {
        instances,
        pkgVersionGhsa,
        uniqueGhsa: seenGhsa.size,
        findings,
        bySourceSeverity,
        bySentinelSeverity,
    };
}
