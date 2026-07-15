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
exports.NpmAuditParser = void 0;
const child_process_1 = require("child_process");
const SEVERITY_MAP = {
    critical: 'CRITICAL',
    high: 'HIGH',
    moderate: 'MEDIUM',
    medium: 'MEDIUM',
    low: 'LOW',
    info: 'INFO',
};
function mapSeverity(severity) {
    return SEVERITY_MAP[severity.toLowerCase()] || severity.toUpperCase();
}
function extractCveId(advisory, via) {
    if ((advisory === null || advisory === void 0 ? void 0 : advisory.cve) && Array.isArray(advisory.cve) && advisory.cve.length > 0) {
        return advisory.cve[0];
    }
    for (const item of via) {
        if (typeof item === 'string' && item.startsWith('CVE-')) {
            return item;
        }
    }
    if (advisory === null || advisory === void 0 ? void 0 : advisory.url) {
        const match = advisory.url.match(/GHSA-[a-zA-Z0-9-]+$/);
        if (match)
            return match[0];
    }
    return undefined;
}
function extractId(advisory, vuln) {
    if (advisory === null || advisory === void 0 ? void 0 : advisory.url) {
        const match = advisory.url.match(/GHSA-[a-zA-Z0-9-]+$/);
        if (match)
            return match[0];
    }
    if (typeof vuln.id === 'number' || typeof vuln.id === 'string') {
        return String(vuln.id);
    }
    return 'unknown';
}
function formatFixAvailable(fix) {
    if (!fix)
        return undefined;
    if (typeof fix === 'object' && fix.name && fix.version) {
        return `${fix.name}@${fix.version}`;
    }
    return undefined;
}
function extractPath(via) {
    const path = [];
    for (const item of via) {
        if (typeof item === 'object' && item.name) {
            path.push(item.name);
        }
    }
    if (path.length === 0) {
        for (const item of via) {
            if (typeof item === 'string') {
                path.push(item);
            }
        }
    }
    return path;
}
class NpmAuditParser {
    runAudit() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const result = (0, child_process_1.execSync)('npm audit --json', { shell: true, encoding: 'utf8' });
                const raw = JSON.parse(result);
                return this.parseAuditJson(raw);
            }
            catch (e) {
                if (e.stdout) {
                    try {
                        const raw = JSON.parse(e.stdout.toString());
                        return this.parseAuditJson(raw);
                    }
                    catch (_a) {
                        // fall through to throw
                    }
                }
                throw e;
            }
        });
    }
    parseAuditJson(raw) {
        var _a, _b;
        const vulns = [];
        const metadata = {
            totalDependencies: 0,
            totalVulnerabilities: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };
        if (!raw || typeof raw !== 'object') {
            return { auditDate: '', vulnerabilities: vulns, metadata };
        }
        if (raw.metadata) {
            metadata.totalDependencies = raw.metadata.dependencies || 0;
            const vulnCounts = raw.metadata.vulnerabilities || {};
            metadata.critical = vulnCounts.critical || 0;
            metadata.high = vulnCounts.high || 0;
            metadata.medium = vulnCounts.moderate || vulnCounts.medium || 0;
            metadata.low = vulnCounts.low || 0;
        }
        const auditDate = raw.auditedAt || ((_a = raw.metadata) === null || _a === void 0 ? void 0 : _a.auditedAt) || '';
        if (raw.vulnerabilities && typeof raw.vulnerabilities === 'object') {
            for (const [pkgName, entries] of Object.entries(raw.vulnerabilities)) {
                if (!Array.isArray(entries))
                    continue;
                for (const entry of entries) {
                    if (!entry || typeof entry !== 'object')
                        continue;
                    const advisory = entry.advisory || {};
                    const via = entry.via || [];
                    vulns.push({
                        id: extractId(advisory, entry),
                        packageName: pkgName,
                        severity: mapSeverity(entry.severity || 'unknown'),
                        title: entry.title || 'No title',
                        cvssScore: ((_b = entry.cvss) === null || _b === void 0 ? void 0 : _b.score) !== undefined ? entry.cvss.score : undefined,
                        cveId: extractCveId(advisory, via),
                        fixAvailable: formatFixAvailable(entry.fixAvailable),
                        path: extractPath(via),
                    });
                }
            }
        }
        metadata.totalVulnerabilities = vulns.length;
        return { auditDate, vulnerabilities: vulns, metadata };
    }
    mockData() {
        return {
            auditDate: '2026-06-05T08:00:00.000Z',
            vulnerabilities: [
                {
                    id: 'GHSA-xxxx-xxxx-xxxx',
                    packageName: 'lodash',
                    severity: 'CRITICAL',
                    title: 'Prototype Pollution in lodash',
                    cvssScore: 9.1,
                    cveId: 'CVE-2024-1234',
                    fixAvailable: 'lodash@4.17.21',
                    path: ['lodash'],
                },
                {
                    id: 'GHSA-yyyy-yyyy-yyyy',
                    packageName: 'express',
                    severity: 'HIGH',
                    title: 'Directory Traversal in express',
                    cvssScore: 7.5,
                    cveId: 'CVE-2024-5678',
                    fixAvailable: undefined,
                    path: ['express'],
                },
                {
                    id: 'GHSA-zzzz-zzzz-zzzz',
                    packageName: 'minimatch',
                    severity: 'MEDIUM',
                    title: 'ReDoS in minimatch',
                    cvssScore: 5.3,
                    cveId: undefined,
                    fixAvailable: 'minimatch@5.1.6',
                    path: ['minimatch'],
                },
            ],
            metadata: {
                totalDependencies: 150,
                totalVulnerabilities: 3,
                critical: 1,
                high: 1,
                medium: 1,
                low: 0,
            },
        };
    }
}
exports.NpmAuditParser = NpmAuditParser;
