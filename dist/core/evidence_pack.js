"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildEvidencePacks = buildEvidencePacks;
function buildEvidencePacks(scenarios, graph, findings, cards, agency) {
    if (scenarios.length === 0)
        return [];
    const edgeLabels = new Map();
    for (const edge of graph.edges) {
        const key = `${edge.sourceId}|${edge.targetId}`;
        edgeLabels.set(key, edge.label);
    }
    const recBySubcode = new Map();
    for (const card of cards) {
        if (card.recommendation && !recBySubcode.has(card.subcode)) {
            recBySubcode.set(card.subcode, card.recommendation);
        }
    }
    const packs = [];
    for (const scenario of scenarios) {
        const evidenceItems = scenario.chain.nodes.map((n) => ({
            subcode: n.subcode,
            title: n.title,
            file: n.file,
            line: n.line,
            severity: n.severity,
            riskScore: n.riskScore,
            detail: buildNodeDetail(n, edgeLabels, scenario.chain.nodes),
        }));
        const uniqueFiles = new Set();
        for (const n of scenario.chain.nodes) {
            uniqueFiles.add(n.file);
        }
        const uniqueSubcodes = new Set();
        for (const n of scenario.chain.nodes) {
            uniqueSubcodes.add(n.subcode);
        }
        const remediationSteps = [];
        for (const subcode of uniqueSubcodes) {
            const rec = recBySubcode.get(subcode);
            if (rec)
                remediationSteps.push(`${subcode}: ${rec}`);
        }
        const affectedAssets = Array.from(uniqueFiles).sort();
        const narrative = buildNarrative(scenario, evidenceItems, edgeLabels);
        packs.push({
            id: scenario.id,
            title: scenario.name,
            severity: scenario.severity,
            score: scenario.score,
            confidence: scenario.confidence,
            narrative,
            impact: scenario.impact,
            evidenceItems,
            remediationSteps,
            affectedAssets,
            chainLength: scenario.chain.nodes.length,
        });
    }
    packs.sort((a, b) => b.score - a.score);
    return packs;
}
function buildNodeDetail(node, edgeLabels, chainNodes) {
    const idx = chainNodes.indexOf(node);
    if (idx < 0 || idx >= chainNodes.length - 1)
        return '';
    const next = chainNodes[idx + 1];
    const key = `${node.id}|${next.id}`;
    const label = edgeLabels.get(key);
    return label ? `${node.subcode} → ${next.subcode}: ${label}` : '';
}
function buildNarrative(scenario, evidenceItems, edgeLabels) {
    const parts = [];
    parts.push(scenario.description);
    if (evidenceItems.length > 0) {
        const steps = evidenceItems
            .filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH')
            .slice(0, 3)
            .map(e => `${e.subcode} in ${e.file}:${e.line}`);
        if (steps.length > 0) {
            parts.push(`Key evidence: ${steps.join(', ')}.`);
        }
    }
    return parts.join(' ');
}
