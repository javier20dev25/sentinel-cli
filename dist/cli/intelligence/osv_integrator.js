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
     * Get the highest CVSS score from a vulnerability's severity array.
     */
    static getMaxSeverity(vuln) {
        let max = null;
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
