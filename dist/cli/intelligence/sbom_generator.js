"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SbomGenerator = void 0;
exports.enrichSbomWithCves = enrichSbomWithCves;
const lockfile_parser_1 = require("./lockfile_parser");
const osv_integrator_1 = require("./osv_integrator");
class SbomGenerator {
    constructor() {
        this.parser = new lockfile_parser_1.LockfileParser();
    }
    generate(lockfilePath) {
        const result = this.parser.parse(lockfilePath);
        return this.generateFromEntries(result.entries, result.format);
    }
    generateFromEntries(entries, format) {
        return this.toCycloneDx(entries);
    }
    toCycloneDx(entries) {
        const components = entries.map(entry => {
            const component = {
                type: 'library',
                name: entry.name,
                version: entry.version,
                purl: this.toPurl(entry.name, entry.version),
            };
            if (entry.integrity) {
                component.properties = [
                    { name: 'integrity', value: entry.integrity },
                ];
            }
            return component;
        });
        return {
            format: 'cyclonedx',
            bomFormat: 'CycloneDX',
            specVersion: '1.5',
            serialNumber: this.generateSerial(),
            version: 1,
            metadata: {
                timestamp: new Date().toISOString(),
                tools: [
                    { name: 'sentinel-cli', vendor: 'Sentinel' },
                ],
            },
            components,
        };
    }
    toPurl(name, version) {
        const encoded = name.replace(/^@/, '%40');
        return `pkg:npm/${encoded}@${version}`;
    }
    generateSerial() {
        const hex = (len) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');
        return `urn:uuid:${hex(8)}-${hex(4)}-4${hex(3)}-${hex(4)}-${hex(12)}`;
    }
}
exports.SbomGenerator = SbomGenerator;
function dbSeverityToSentinel(dbSev) {
    const upper = dbSev.toUpperCase();
    if (upper === 'CRITICAL')
        return 'CRITICAL';
    if (upper === 'HIGH')
        return 'HIGH';
    if (upper === 'MODERATE' || upper === 'MEDIUM')
        return 'MEDIUM';
    if (upper === 'LOW')
        return 'LOW';
    return 'MEDIUM';
}
function extractAffectedVersions(vuln, fallbackVersion) {
    if (!vuln.affected || vuln.affected.length === 0) {
        return { affectedVersions: fallbackVersion };
    }
    let fixedIn;
    const rangeStrs = [];
    for (const aff of vuln.affected) {
        if (!aff.ranges)
            continue;
        for (const range of aff.ranges) {
            if (range.type !== 'ECOSYSTEM' || !range.events)
                continue;
            const parts = [];
            for (const event of range.events) {
                if (event.introduced !== undefined)
                    parts.push(`>= ${event.introduced}`);
                if (event.fixed !== undefined) {
                    parts.push(`< ${event.fixed}`);
                    fixedIn = event.fixed;
                }
                if (event.last_affected !== undefined)
                    parts.push(`<= ${event.last_affected}`);
                if (event.limit !== undefined)
                    parts.push(`< ${event.limit}`);
            }
            if (parts.length > 0)
                rangeStrs.push(parts.join(', '));
        }
    }
    return {
        affectedVersions: rangeStrs.length > 0 ? rangeStrs.join(' || ') : fallbackVersion,
        fixedIn,
    };
}
function enrichSbomWithCves(sbom, osvResults) {
    if (!osvResults || osvResults.length === 0) {
        return JSON.parse(JSON.stringify(sbom));
    }
    const enriched = JSON.parse(JSON.stringify(sbom));
    enriched.components = enriched.components.map((component) => {
        const osvResult = osvResults.find((r) => r.packageName === component.name && r.version === component.version);
        if (osvResult && osvResult.vulnerabilities && osvResult.vulnerabilities.length > 0) {
            component.vulnerabilities = osvResult.vulnerabilities.map((v) => {
                var _a;
                const maxSeverity = osv_integrator_1.OSVIntegrator.getMaxSeverity(v);
                const score = maxSeverity ? maxSeverity.score : 0;
                const severity = maxSeverity
                    ? osv_integrator_1.OSVIntegrator.toSentinelSeverity(maxSeverity.score)
                    : (((_a = v.database_specific) === null || _a === void 0 ? void 0 : _a.severity)
                        ? dbSeverityToSentinel(v.database_specific.severity)
                        : 'MEDIUM');
                const { affectedVersions, fixedIn } = extractAffectedVersions(v, component.version);
                return Object.assign({ id: v.id, severity,
                    score, summary: v.summary || '', affectedVersions }, (fixedIn !== undefined ? { fixedIn } : {}));
            });
        }
        return component;
    });
    return enriched;
}
