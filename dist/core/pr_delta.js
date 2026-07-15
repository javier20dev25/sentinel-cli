"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeDelta = computeDelta;
exports.computeDeltaVsLatest = computeDeltaVsLatest;
exports.computeDeltaVsBaseline = computeDeltaVsBaseline;
const risk_history_1 = require("./risk_history");
function findingKey(f) {
    return `${f.subcode || f.type}|${f.file}|${f.line}`;
}
function computeDelta(currentFindings, snapshot, previousFindings) {
    const prevFindings = previousFindings || [];
    const currentKeys = new Set(currentFindings.map(f => findingKey(f)));
    const prevKeys = new Set(prevFindings.map(f => findingKey(f)));
    const fixedFindings = prevFindings
        .filter(f => !currentKeys.has(findingKey(f)))
        .map(f => ({
        subcode: f.subcode || f.type,
        file: f.file,
        line: f.line,
        title: f.title || f.type,
    }));
    const newFindings = currentFindings
        .filter(f => !prevKeys.has(findingKey(f)));
    const criticalBefore = snapshot.criticalCount;
    const highBefore = snapshot.highCount;
    const criticalNow = currentFindings.filter(f => f.severity === 'CRITICAL').length;
    const highNow = currentFindings.filter(f => f.severity === 'HIGH').length;
    return {
        newFindings,
        fixedFindings,
        scoreDelta: 0,
        criticalDelta: criticalNow - criticalBefore,
        highDelta: highNow - highBefore,
        totalBefore: prevFindings.length,
        totalAfter: currentFindings.length,
    };
}
function computeDeltaVsLatest(currentFindings, repoPath) {
    const history = (0, risk_history_1.loadHistory)(repoPath);
    const latest = history[0];
    if (!latest)
        return { delta: null, baseline: null };
    const delta = {
        newFindings: [],
        fixedFindings: [],
        scoreDelta: 0,
        criticalDelta: 0,
        highDelta: 0,
        totalBefore: latest.totalFindings,
        totalAfter: currentFindings.length,
    };
    const criticalBefore = latest.criticalCount;
    const criticalNow = currentFindings.filter(f => f.severity === 'CRITICAL').length;
    const highBefore = latest.highCount;
    const highNow = currentFindings.filter(f => f.severity === 'HIGH').length;
    delta.criticalDelta = criticalNow - criticalBefore;
    delta.highDelta = highNow - highBefore;
    return { delta, baseline: latest };
}
function computeDeltaVsBaseline(currentFindings, currentAgency, repoPath, baselineBranch) {
    let baseline = null;
    if (baselineBranch) {
        const history = (0, risk_history_1.loadHistory)(repoPath);
        baseline = history.find(s => s.branch === baselineBranch) || null;
    }
    else {
        baseline = (0, risk_history_1.loadBaseline)(repoPath);
        if (!baseline) {
            const history = (0, risk_history_1.loadHistory)(repoPath);
            baseline = history[0] || null;
        }
    }
    if (!baseline)
        return { delta: null, baseline: null };
    const criticalNow = currentFindings.filter(f => f.severity === 'CRITICAL').length;
    const highNow = currentFindings.filter(f => f.severity === 'HIGH').length;
    const delta = {
        newFindings: [],
        fixedFindings: [],
        scoreDelta: baseline.agencyScore - currentAgency.agencyScore,
        criticalDelta: criticalNow - baseline.criticalCount,
        highDelta: highNow - baseline.highCount,
        totalBefore: baseline.totalFindings,
        totalAfter: currentFindings.length,
    };
    return { delta, baseline };
}
