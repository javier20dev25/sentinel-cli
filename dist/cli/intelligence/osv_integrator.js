"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OSVIntegrator = void 0;
class OSVIntegrator {
    /**
     * Query OSV.dev for known vulnerabilities affecting a package@version.
     * Uses the public API (no API key required).
     */
    queryPackage(name, version) {
        return __awaiter(this, void 0, void 0, function* () {
            const startTime = Date.now();
            const vulnerabilities = [];
            try {
                const body = JSON.stringify({
                    package: { name, ecosystem: 'npm' },
                    version: version || 'latest'
                });
                const response = yield fetch(OSVIntegrator.API_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body,
                    signal: AbortSignal.timeout(10000)
                });
                if (!response.ok) {
                    return { packageName: name, version, vulnerabilities: [], queryTimeMs: Date.now() - startTime };
                }
                const data = (yield response.json());
                if (data.vulns) {
                    for (const v of data.vulns) {
                        vulnerabilities.push({
                            id: v.id,
                            summary: v.summary || '',
                            aliases: v.aliases || [],
                            severity: v.severity || [],
                            published: v.published || '',
                            modified: v.modified || '',
                            database_specific: v.database_specific,
                            affected: v.affected,
                        });
                    }
                }
            }
            catch (_a) {
                // Network errors, timeouts — silently degrade
            }
            return {
                packageName: name,
                version,
                vulnerabilities,
                queryTimeMs: Date.now() - startTime
            };
        });
    }
    queryBatch(packages) {
        return __awaiter(this, void 0, void 0, function* () {
            if (packages.length === 0)
                return [];
            const startTime = Date.now();
            try {
                const queries = packages.map(p => ({
                    package: { name: p.name, ecosystem: 'npm' },
                    version: p.version || 'latest'
                }));
                const response = yield fetch(OSVIntegrator.BATCH_API_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ queries }),
                    signal: AbortSignal.timeout(10000)
                });
                if (!response.ok)
                    throw new Error(`Batch query failed with status ${response.status}`);
                const data = (yield response.json());
                return packages.map((pkg, index) => {
                    const result = data.results ? data.results[String(index)] : undefined;
                    const vulnerabilities = [];
                    if (result && result.vulns) {
                        for (const v of result.vulns) {
                            vulnerabilities.push({
                                id: v.id,
                                summary: v.summary || '',
                                aliases: v.aliases || [],
                                severity: v.severity || [],
                                published: v.published || '',
                                modified: v.modified || '',
                                database_specific: v.database_specific,
                                affected: v.affected,
                            });
                        }
                    }
                    return {
                        packageName: pkg.name,
                        version: pkg.version,
                        vulnerabilities,
                        queryTimeMs: Date.now() - startTime
                    };
                });
            }
            catch (_a) {
                const results = [];
                for (const pkg of packages) {
                    const result = yield this.queryPackage(pkg.name, pkg.version);
                    results.push(result);
                }
                return results;
            }
        });
    }
    /**
     * OSV's /querybatch endpoint returns only minimal vuln stubs (id + modified)
     * — no severity, no affected ranges. This hydrates each unique advisory with
     * its full /v1/vulns/{id} document so source severity and fixed versions are
     * actually available. Hydration is deduplicated by advisory ID and bounded to
     * 8 concurrent requests. Advisories that fail to hydrate keep their stub
     * (later reported as UNKNOWN, never fabricated).
     */
    hydrateResults(results) {
        return __awaiter(this, void 0, void 0, function* () {
            const ids = new Set();
            for (const r of results)
                for (const v of r.vulnerabilities)
                    if (v.id)
                        ids.add(v.id);
            if (ids.size === 0)
                return results;
            const list = Array.from(ids);
            const cache = new Map();
            const CONCURRENCY = 8;
            for (let i = 0; i < list.length; i += CONCURRENCY) {
                const slice = list.slice(i, i + CONCURRENCY);
                const docs = yield Promise.all(slice.map(id => this.fetchVuln(id)));
                docs.forEach((d, idx) => { if (d)
                    cache.set(slice[idx], d); });
            }
            return results.map(r => (Object.assign(Object.assign({}, r), { vulnerabilities: r.vulnerabilities.map(v => cache.get(v.id) || v) })));
        });
    }
    fetchVuln(id) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const response = yield fetch(`${OSVIntegrator.VULN_API_URL}/${encodeURIComponent(id)}`, {
                    method: 'GET',
                    headers: { 'Content-Type': 'application/json' },
                    signal: AbortSignal.timeout(10000)
                });
                if (!response.ok)
                    return null;
                const v = (yield response.json());
                return {
                    id: v.id,
                    summary: v.summary || '',
                    aliases: v.aliases || [],
                    severity: v.severity || [],
                    published: v.published || '',
                    modified: v.modified || '',
                    database_specific: v.database_specific,
                    affected: v.affected
                };
            }
            catch (_a) {
                return null;
            }
        });
    }
    /**
     * Normalize a published severity label (OSV/GHSA `database_specific.severity`,
     * or CVSS scalar strings) to Sentinel's CRITICAL/HIGH/MEDIUM/LOW vocabulary.
     * Returns 'UNKNOWN' when the source value is not a recognized severity — it
     * must never be silently coerced into MEDIUM.
     */
    static normalizeSeverity(value) {
        const u = String(value || '').trim().toUpperCase();
        if (u === 'MODERATE')
            return 'MEDIUM';
        if (u === 'CRITICAL' || u === 'HIGH' || u === 'MEDIUM' || u === 'LOW')
            return u;
        return 'UNKNOWN';
    }
    /**
     * Extract a numeric CVSS score from an OSV `severity[].score` value.
     * The value may be either a bare number ("7.5") or a CVSS **vector**
     * ("CVSS:3.1/AV:N/..."). CVSS v3.x vectors are scored; CVSS v4.0 vectors
     * return null because their base metric (MacroVector) is not implemented
     * here — callers must fall back to the published severity label.
     */
    static severityScoreOf(raw) {
        if (!raw)
            return null;
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
    static parseCvssV3Vector(vector) {
        try {
            if (!/^CVSS:3\.[01]\//.test(vector))
                return null;
            const metric = (k) => {
                const m = vector.match(new RegExp('(?:^|/)' + k + ':([A-Za-z])'));
                return m ? m[1] : '';
            };
            const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metric('AV')];
            const AC = { L: 0.77, H: 0.44 }[metric('AC')];
            const UI = { N: 0.85, R: 0.62 }[metric('UI')];
            const S = metric('S');
            const CIA = { N: 0.0, L: 0.22, H: 0.56 };
            const C = CIA[metric('C')];
            const I = CIA[metric('I')];
            const A = CIA[metric('A')];
            const prTable = S === 'C'
                ? { N: 0.85, L: 0.68, H: 0.5 }
                : { N: 0.85, L: 0.62, H: 0.27 };
            const PR = prTable[metric('PR')];
            if ([AV, AC, UI, C, I, A, PR].some(v => v === undefined) || (S !== 'U' && S !== 'C')) {
                return null;
            }
            const iss = 1 - ((1 - C) * (1 - I) * (1 - A));
            const impact = S === 'U'
                ? 6.42 * iss
                : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
            if (impact <= 0)
                return 0;
            const exploitability = 8.22 * AV * AC * PR * UI;
            const roundup = (x) => Math.ceil(x * 10) / 10;
            const base = S === 'U'
                ? roundup(Math.min(impact + exploitability, 10))
                : roundup(Math.min(1.08 * (impact + exploitability), 10));
            return base;
        }
        catch (_a) {
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
    static getSourceSeverity(vuln) {
        const db = vuln.database_specific && vuln.database_specific.severity;
        if (typeof db === 'string' && db.trim()) {
            return { level: OSVIntegrator.normalizeSeverity(db), source: 'osv.database_specific.severity' };
        }
        let best = null;
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
    static getFixedVersions(vuln) {
        const out = new Set();
        for (const a of (vuln.affected || [])) {
            for (const r of (a.ranges || [])) {
                for (const e of (r.events || [])) {
                    if (e && typeof e.fixed === 'string' && e.fixed)
                        out.add(e.fixed);
                }
            }
        }
        return Array.from(out).sort();
    }
    /**
     * Get the highest CVSS score from a vulnerability's severity array.
     * Accepts both numeric score strings and CVSS v3.x vectors.
     */
    static getMaxSeverity(vuln) {
        let max = null;
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
    static toSentinelSeverity(cvssScore) {
        if (cvssScore >= 9.0)
            return 'CRITICAL';
        if (cvssScore >= 7.0)
            return 'HIGH';
        if (cvssScore >= 4.0)
            return 'MEDIUM';
        return 'LOW';
    }
}
exports.OSVIntegrator = OSVIntegrator;
OSVIntegrator.API_URL = 'https://api.osv.dev/v1/query';
OSVIntegrator.BATCH_API_URL = 'https://api.osv.dev/v1/querybatch';
OSVIntegrator.VULN_API_URL = 'https://api.osv.dev/v1/vulns';
