"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EdgeType = void 0;
exports.buildAgencyGraph = buildAgencyGraph;
var EdgeType;
(function (EdgeType) {
    EdgeType["CAUSAL"] = "causal";
    EdgeType["CORRELATED"] = "correlated";
    EdgeType["SAME_FILE"] = "same_file";
})(EdgeType || (exports.EdgeType = EdgeType = {}));
// Semantic pairs: ONLY applied when both findings share the same file (asset).
// This avoids connecting findings across unrelated files.
const SEMANTIC_PAIRS = {
    'SEC-GITHUB-TOKEN': [
        { target: 'TOK-001', label: 'enables contents:write' },
        { target: 'TOK-002', label: 'enables actions:write' },
        { target: 'TOK-003', label: 'enables pull-requests:write' },
        { target: 'TOK-004', label: 'enables pull_request_target' },
    ],
    'SEC-HARDCODED-TOKEN': [
        { target: 'TOK-001', label: 'enables contents:write' },
        { target: 'TOK-003', label: 'enables pull-requests:write' },
    ],
    'TOK-001': [
        { target: 'WF-001', label: 'enables pull_request_target with write' },
        { target: 'WF-003', label: 'feeds contents:write in workflow' },
        { target: 'WF-004', label: 'enables workflow self-modification' },
    ],
    'TOK-002': [
        { target: 'WF-002', label: 'enables write-all permissions' },
        { target: 'WF-004', label: 'enables workflow file writes' },
    ],
    'TOK-003': [
        { target: 'WF-001', label: 'feeds pull_request_target' },
        { target: 'WF-007', label: 'enables comment-triggered actions' },
    ],
    'TOK-004': [
        { target: 'WF-001', label: 'triggers pull_request_target' },
        { target: 'WF-007', label: 'enables comment-triggered workflows' },
    ],
    'WF-001': [{ target: 'AS-004', label: 'enables skip code review' }],
    'WF-002': [
        { target: 'AS-003', label: 'enables exec without validation' },
        { target: 'AS-005', label: 'enables root/privileged access' },
    ],
    'WF-003': [{ target: 'AS-002', label: 'enables unrestricted file write' }],
    'WF-004': [
        { target: 'AS-001', label: 'enables bypass Sentinel' },
        { target: 'AS-008', label: 'enables override security policies' },
    ],
    'WF-005': [{ target: 'AS-003', label: 'enables exec without validation' }],
    'WF-006': [{ target: 'AS-004', label: 'feeds credential misuse' }],
    'WF-007': [{ target: 'AS-004', label: 'enables skip code review' }],
};
const CATEGORY_ORDER = {
    secret: 0, token: 1, malware: 1, vulnerability: 2,
    workflow: 2, generic: 2, agent: 3,
};
function isWorkflowFile(file) {
    const normal = file.replace(/\\/g, '/');
    return normal.includes('.github/workflows/') &&
        (normal.endsWith('.yml') || normal.endsWith('.yaml'));
}
function isAgentFile(file) {
    const base = file.split(/[/\\]/).pop() || '';
    const agentFiles = ['agents.md', 'agents.txt', 'claude.md', 'claude.txt',
        'gemini.md', 'gemini.txt', 'codex.md', 'codex.txt',
        '.cursorrules', '.windsurfrules'];
    return agentFiles.includes(base) || base.endsWith('.mdc');
}
function buildAgencyGraph(findings, agency) {
    var _a;
    const scored = findings.filter(f => f.riskScore && f.riskScore > 0);
    const driverMap = new Map();
    for (const d of agency.drivers) {
        driverMap.set(d.subcode, d);
    }
    // Build nodes
    const nodes = [];
    const nodeMap = new Map();
    for (let i = 0; i < scored.length; i++) {
        const f = scored[i];
        const subcode = f.subcode || 'UNKNOWN';
        const id = `${subcode}-${f.file}-${f.line}-${i}`;
        const driver = driverMap.get(subcode);
        const node = {
            id,
            subcode,
            title: f.title || '',
            severity: f.severity,
            riskScore: f.riskScore || 0,
            contribution: (_a = driver === null || driver === void 0 ? void 0 : driver.contribution) !== null && _a !== void 0 ? _a : 0,
            file: f.file,
            line: f.line,
            category: f.category || 'generic',
            evidence: f.evidence || f.snippet.substring(0, 120),
        };
        nodes.push(node);
        nodeMap.set(id, node);
    }
    const edges = [];
    const edgeKey = (a, b) => `${a}|${b}`;
    const edgeSet = new Set();
    function addEdge(sourceId, targetId, type, confidence, label) {
        const key = edgeKey(sourceId, targetId);
        if (!edgeSet.has(key)) {
            edgeSet.add(key);
            edges.push({ sourceId, targetId, type, confidence, label });
        }
    }
    // 1) Semantic pairs: only within the same file
    for (const source of nodes) {
        const pairs = SEMANTIC_PAIRS[source.subcode];
        if (!pairs)
            continue;
        for (const pair of pairs) {
            const targets = nodes.filter(n => n.subcode === pair.target &&
                n.file === source.file &&
                n.id !== source.id);
            // Connect to the highest-contribution target in the same file
            const best = targets.sort((a, b) => b.contribution - a.contribution)[0];
            if (best) {
                addEdge(source.id, best.id, EdgeType.CAUSAL, 0.9, pair.label);
            }
        }
    }
    // 2) File-based category progression (CORRELATED)
    const fileGroups = new Map();
    for (const node of nodes) {
        const key = node.file;
        if (!fileGroups.has(key))
            fileGroups.set(key, []);
        fileGroups.get(key).push(node);
    }
    for (const [, group] of fileGroups) {
        if (group.length < 2)
            continue;
        group.sort((a, b) => { var _a, _b; return ((_a = CATEGORY_ORDER[a.category]) !== null && _a !== void 0 ? _a : 2) - ((_b = CATEGORY_ORDER[b.category]) !== null && _b !== void 0 ? _b : 2); });
        let lastCausal = false;
        for (let i = 0; i < group.length - 1; i++) {
            const a = group[i];
            const b = group[i + 1];
            const alreadyCausal = edges.some(e => e.sourceId === a.id && e.targetId === b.id && e.type === EdgeType.CAUSAL);
            if (!alreadyCausal) {
                addEdge(a.id, b.id, EdgeType.CORRELATED, 0.5, 'category progression');
                lastCausal = false;
            }
            else {
                lastCausal = true;
            }
        }
    }
    // 3) Same-workflow: connect workflow findings across different workflow files
    const workflowNodes = nodes.filter(n => isWorkflowFile(n.file));
    if (workflowNodes.length >= 2) {
        // Group by workflow file
        const wfGroups = new Map();
        for (const n of workflowNodes) {
            if (!wfGroups.has(n.file))
                wfGroups.set(n.file, []);
            wfGroups.get(n.file).push(n);
        }
        const wfFiles = Array.from(wfGroups.keys());
        // Connect findings across workflow files (they share the same workflow context)
        for (let i = 0; i < wfFiles.length; i++) {
            for (let j = i + 1; j < wfFiles.length; j++) {
                const groupA = wfGroups.get(wfFiles[i]);
                const groupB = wfGroups.get(wfFiles[j]);
                // Connect the highest-contribution finding from each file
                const sortedA = [...groupA].sort((a, b) => b.contribution - a.contribution);
                const sortedB = [...groupB].sort((a, b) => b.contribution - a.contribution);
                // Skip if same subcode (duplicate across files is correlation, not causation)
                for (const a of sortedA.slice(0, 2)) {
                    for (const b of sortedB.slice(0, 2)) {
                        if (a.subcode !== b.subcode) {
                            addEdge(a.id, b.id, EdgeType.SAME_FILE, 0.3, 'same workflow directory');
                        }
                    }
                }
            }
        }
    }
    // 4) Build chains via DFS — WITHOUT destructive global visited
    const chains = [];
    for (const start of nodes) {
        // Sources: nodes with no incoming CAUSAL edges
        const hasIncomingCausal = edges.some(e => e.targetId === start.id && e.type === EdgeType.CAUSAL);
        if (hasIncomingCausal)
            continue;
        // Per-path visited (allows shared nodes across chains, prevents cycles)
        const pathLocal = new Set();
        const currentPath = [];
        function dfs(node) {
            if (pathLocal.has(node.id))
                return;
            pathLocal.add(node.id);
            currentPath.push(node);
            const outgoing = edges.filter(e => e.sourceId === node.id);
            // Record chain at every intermediate step (not just leaves)
            if (currentPath.length >= 2) {
                const pathEdges = [];
                for (let k = 0; k < currentPath.length - 1; k++) {
                    const e = edges.find(ed => ed.sourceId === currentPath[k].id && ed.targetId === currentPath[k + 1].id);
                    if (e)
                        pathEdges.push(e);
                }
                const pathConfidence = pathEdges.length > 0
                    ? pathEdges.reduce((p, e) => p * e.confidence, 1)
                    : 0.5;
                const maxRiskScore = Math.max(...currentPath.map(n => n.riskScore));
                const lengthFactor = Math.min(currentPath.length / 3, 1);
                const score = Math.round(Math.min(100, maxRiskScore * pathConfidence * lengthFactor));
                chains.push({
                    nodes: [...currentPath],
                    score,
                    confidence: pathConfidence,
                });
            }
            for (const edge of outgoing) {
                const next = nodeMap.get(edge.targetId);
                if (next)
                    dfs(next);
            }
            currentPath.pop();
            pathLocal.delete(node.id);
        }
        dfs(start);
    }
    // Sort by score desc, then confidence desc
    chains.sort((a, b) => b.score - a.score || b.confidence - a.confidence);
    return { nodes, edges, chains };
}
