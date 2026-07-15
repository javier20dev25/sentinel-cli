"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderEnrichedJson = renderEnrichedJson;
function renderEnrichedJson(findings, agency, cards, meta) {
    const output = {
        host: meta.host,
        scanTimeMs: meta.scanTimeMs,
        memoryMB: meta.memoryMB,
        totalFindings: agency.totalFindings,
        agencyScore: agency.agencyScore,
        verdict: agency.verdict,
        blastRadius: agency.blastRadius,
        drivers: agency.drivers,
        cards: cards.map(c => ({
            subcode: c.subcode,
            title: c.title,
            category: c.category,
            severity: c.severity,
            riskScore: c.riskScore,
            confidence: c.confidence,
            file: c.file,
            line: c.line,
            evidence: c.evidence,
            description: c.description,
            contribution: c.contribution,
            recommendation: c.recommendation,
        })),
        findings,
    };
    return JSON.stringify(output, null, 2);
}
