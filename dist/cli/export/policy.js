"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluatePolicy = evaluatePolicy;
const VERDICT_ORDER = { PASS: 0, REVIEW: 1, BLOCK: 2 };
function evaluatePolicy(findings, agency, options) {
    var _a, _b;
    const failures = [];
    // fail-on-score
    if (options.failOnScore !== undefined && options.failOnScore >= 0 && options.failOnScore <= 100) {
        if (agency.agencyScore >= options.failOnScore) {
            failures.push(`Agency Score ${agency.agencyScore} >= threshold ${options.failOnScore}`);
        }
    }
    // fail-on-critical
    if (options.failOnCritical) {
        const critical = findings.filter(f => f.severity === 'CRITICAL');
        if (critical.length > 0) {
            const subcodes = [...new Set(critical.map(f => f.subcode).filter(Boolean))].join(', ');
            failures.push(`${critical.length} CRITICAL finding(s) detected: ${subcodes}`);
        }
    }
    // fail-on-high
    if (options.failOnHigh) {
        const high = findings.filter(f => f.severity === 'HIGH');
        if (high.length > 0) {
            const subcodes = [...new Set(high.map(f => f.subcode).filter(Boolean))].join(', ');
            failures.push(`${high.length} HIGH finding(s) detected: ${subcodes}`);
        }
    }
    // fail-on-verdict
    if (options.failOnVerdict) {
        const threshold = (_a = VERDICT_ORDER[options.failOnVerdict]) !== null && _a !== void 0 ? _a : 1;
        const actual = (_b = VERDICT_ORDER[agency.verdict]) !== null && _b !== void 0 ? _b : 0;
        if (actual >= threshold) {
            failures.push(`Verdict ${agency.verdict} meets or exceeds threshold ${options.failOnVerdict}`);
        }
    }
    if (failures.length > 0) {
        return { shouldFail: true, reason: failures.join('; ') };
    }
    return { shouldFail: false, reason: '' };
}
