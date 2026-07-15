"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderGraphHistory = renderGraphHistory;
exports.renderGraphDiff = renderGraphDiff;
const picocolors_1 = __importDefault(require("picocolors"));
function getTopScore(snapshot) {
    var _a, _b;
    return (_b = (_a = snapshot.topChains[0]) === null || _a === void 0 ? void 0 : _a.score) !== null && _b !== void 0 ? _b : 0;
}
function renderGraphHistory(snapshots) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   GRAPH SNAPSHOT HISTORY')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    if (snapshots.length === 0) {
        lines.push(picocolors_1.default.dim('  No graph snapshots found. Run scan --save-graph to start tracking.'));
        lines.push('');
        return lines.join('\n');
    }
    lines.push(picocolors_1.default.dim(`  ${snapshots.length} snapshot(s)`));
    lines.push('');
    for (let i = 0; i < snapshots.length; i++) {
        const s = snapshots[i];
        const date = new Date(s.timestamp).toLocaleString();
        const topScore = getTopScore(s);
        const scoreColor = topScore >= 70 ? picocolors_1.default.red : topScore >= 30 ? picocolors_1.default.yellow : picocolors_1.default.green;
        lines.push(`  ${picocolors_1.default.bold(String(i + 1))}. ${picocolors_1.default.dim(date)}`);
        lines.push(`     Nodes: ${s.nodes}  Edges: ${s.edges}  Chains: ${picocolors_1.default.bold(String(s.chains))}  Top Score: ${scoreColor(String(topScore))}`);
        if (s.topChains.length > 0) {
            const top = s.topChains[0];
            lines.push(`     Best chain: score=${top.score}, confidence=${Math.round(top.confidence * 100)}%, nodes=${top.nodeCount}`);
        }
        lines.push('');
    }
    if (snapshots.length >= 2) {
        const sorted = [...snapshots].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
        const current = sorted[sorted.length - 1];
        const previous = sorted[sorted.length - 2];
        const chainDelta = current.chains - previous.chains;
        const scoreDelta = getTopScore(current) - getTopScore(previous);
        const chainDir = chainDelta > 0 ? picocolors_1.default.red(`+${chainDelta}`) : chainDelta < 0 ? picocolors_1.default.green(String(chainDelta)) : picocolors_1.default.dim('0');
        const scoreDir = scoreDelta > 0 ? picocolors_1.default.red(`+${scoreDelta}`) : scoreDelta < 0 ? picocolors_1.default.green(String(scoreDelta)) : picocolors_1.default.dim('0');
        lines.push(picocolors_1.default.dim('  Trend (vs previous):'));
        lines.push(`    Chain count: ${chainDir}   Top score: ${scoreDir}`);
        lines.push('');
    }
    return lines.join('\n');
}
function renderGraphDiff(before, after) {
    const lines = [];
    lines.push('');
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('   GRAPH DIFF')));
    lines.push(picocolors_1.default.white(picocolors_1.default.bold('  ═══════════════════════════════════════════════')));
    lines.push('');
    const beforeDate = before ? new Date(before.timestamp).toLocaleString() : '(none)';
    const afterDate = new Date(after.timestamp).toLocaleString();
    lines.push(picocolors_1.default.dim(`  Before: ${beforeDate}`));
    lines.push(picocolors_1.default.dim(`  After:  ${afterDate}`));
    lines.push('');
    if (!before) {
        lines.push(picocolors_1.default.dim('  No previous snapshot to compare. Showing current state.'));
        lines.push(picocolors_1.default.dim(`  Chains: ${after.chains}, Nodes: ${after.nodes}, Edges: ${after.edges}`));
        lines.push('');
        return lines.join('\n');
    }
    const chainDelta = after.chains - before.chains;
    const nodeDelta = after.nodes - before.nodes;
    const edgeDelta = after.edges - before.edges;
    lines.push(`  ${picocolors_1.default.bold('Chains:')}    ${before.chains} → ${after.chains}  ${deltaStr(chainDelta)}`);
    lines.push(`  ${picocolors_1.default.bold('Nodes:')}     ${before.nodes} → ${after.nodes}  ${deltaStr(nodeDelta)}`);
    lines.push(`  ${picocolors_1.default.bold('Edges:')}     ${before.edges} → ${after.edges}  ${deltaStr(edgeDelta)}`);
    lines.push('');
    const beforeChainSet = new Set();
    const beforeChainMap = new Map();
    for (const chain of before.fullGraph.chains) {
        const key = chain.nodes.map(n => `${n.subcode}:${n.file}:${n.line}`).join('|');
        beforeChainSet.add(key);
        beforeChainMap.set(key, chain.score);
    }
    const newChains = [];
    const stillPresent = [];
    for (const chain of after.fullGraph.chains) {
        const key = chain.nodes.map(n => `${n.subcode}:${n.file}:${n.line}`).join('|');
        if (!beforeChainSet.has(key)) {
            newChains.push(key);
        }
        else {
            stillPresent.push(key);
        }
    }
    const resolvedChains = Array.from(beforeChainMap.entries()).filter(([key]) => {
        return !after.fullGraph.chains.some(c => {
            const ck = c.nodes.map(n => `${n.subcode}:${n.file}:${n.line}`).join('|');
            return ck === key;
        });
    });
    if (newChains.length > 0) {
        lines.push(picocolors_1.default.red(`  🆕 New Chains (${newChains.length}):`));
        for (const key of newChains.slice(0, 5)) {
            lines.push(picocolors_1.default.dim(`     ${key.substring(0, 100)}`));
        }
        if (newChains.length > 5) {
            lines.push(picocolors_1.default.dim(`     ... and ${newChains.length - 5} more`));
        }
        lines.push('');
    }
    if (resolvedChains.length > 0) {
        lines.push(picocolors_1.default.green(`  ✅ Resolved Chains (${resolvedChains.length}):`));
        for (const [key] of resolvedChains.slice(0, 5)) {
            lines.push(picocolors_1.default.dim(`     ${key.substring(0, 100)}`));
        }
        if (resolvedChains.length > 5) {
            lines.push(picocolors_1.default.dim(`     ... and ${resolvedChains.length - 5} more`));
        }
        lines.push('');
    }
    if (newChains.length === 0 && resolvedChains.length === 0) {
        lines.push(picocolors_1.default.dim('  No change in attack chains between snapshots.'));
        lines.push('');
    }
    return lines.join('\n');
}
function deltaStr(delta) {
    if (delta > 0)
        return picocolors_1.default.red(`+${delta}`);
    if (delta < 0)
        return picocolors_1.default.green(String(delta));
    return picocolors_1.default.dim('0');
}
