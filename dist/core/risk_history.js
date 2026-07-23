"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.repoHash = repoHash;
exports.saveSnapshot = saveSnapshot;
exports.loadHistory = loadHistory;
exports.loadBaseline = loadBaseline;
exports.loadHistoryInWindow = loadHistoryInWindow;
exports.computeTrendInWindow = computeTrendInWindow;
exports.loadAllHistory = loadAllHistory;
exports.computeTrend = computeTrend;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const crypto = __importStar(require("crypto"));
const child_process_1 = require("child_process");
let _snapshotSeq = 0;
function getHistoryDir() {
    return path.join(os.homedir(), '.sentinel', 'history');
}
function repoHash(repoPath) {
    return crypto.createHash('sha256').update(path.resolve(repoPath)).digest('hex').substring(0, 12);
}
function detectBranch(repoPath) {
    try {
        return (0, child_process_1.execSync)('git rev-parse --abbrev-ref HEAD', {
            cwd: repoPath,
            encoding: 'utf8',
            timeout: 5000,
        }).trim();
    }
    catch (_a) {
        return undefined;
    }
}
function saveSnapshot(repoPath, agency, scenarios, branch) {
    const dir = path.join(getHistoryDir(), repoHash(repoPath));
    if (!fs.existsSync(dir))
        fs.mkdirSync(dir, { recursive: true });
    const id = Date.now().toString(36) + '-' + (_snapshotSeq++).toString(36).padStart(4, '0');
    const effectiveBranch = branch !== null && branch !== void 0 ? branch : detectBranch(repoPath);
    const snapshot = {
        id,
        timestamp: new Date().toISOString(),
        agencyScore: agency.agencyScore,
        verdict: agency.verdict,
        blastRadius: agency.blastRadius,
        totalFindings: agency.totalFindings,
        criticalCount: agency.criticalCount,
        highCount: agency.highCount,
        scenarioCount: scenarios.length,
        topScenarios: scenarios.slice(0, 5).map(s => ({
            id: s.id,
            name: s.name,
            score: s.score,
            severity: s.severity,
        })),
        repoPath: path.resolve(repoPath),
        repoHash: repoHash(repoPath),
        branch: effectiveBranch,
    };
    const safeTs = snapshot.timestamp.replace(/:/g, '-');
    fs.writeFileSync(path.join(dir, `${safeTs}-${id}.json`), JSON.stringify(snapshot, null, 2));
    return snapshot;
}
function loadHistory(repoPath) {
    const dir = path.join(getHistoryDir(), repoHash(repoPath));
    if (!fs.existsSync(dir))
        return [];
    const entries = fs.readdirSync(dir)
        .filter(f => f.endsWith('.json'))
        .sort()
        .reverse();
    const snapshots = [];
    for (const entry of entries) {
        try {
            const data = JSON.parse(fs.readFileSync(path.join(dir, entry), 'utf8'));
            snapshots.push(data);
        }
        catch (_a) { }
    }
    return snapshots;
}
function loadBaseline(repoPath) {
    const history = loadHistory(repoPath).sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    return history.find(s => s.branch === 'main' || s.branch === 'master') || null;
}
function loadHistoryInWindow(repoPath, days) {
    const history = loadHistory(repoPath);
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    return history.filter(s => new Date(s.timestamp).getTime() >= cutoff);
}
function computeTrendInWindow(repoPath, days) {
    return computeTrend(loadHistoryInWindow(repoPath, days));
}
function loadAllHistory() {
    const base = getHistoryDir();
    if (!fs.existsSync(base))
        return new Map();
    const repos = new Map();
    const dirs = fs.readdirSync(base);
    for (const dir of dirs) {
        const dirPath = path.join(base, dir);
        if (!fs.statSync(dirPath).isDirectory())
            continue;
        try {
            const snapshots = fs.readdirSync(dirPath)
                .filter(f => f.endsWith('.json'))
                .sort()
                .reverse()
                .map(f => JSON.parse(fs.readFileSync(path.join(dirPath, f), 'utf8')));
            if (snapshots.length > 0) {
                repos.set(snapshots[0].repoPath, snapshots);
            }
        }
        catch (_a) { }
    }
    return repos;
}
function computeTrend(snapshots) {
    if (snapshots.length < 2) {
        return {
            snapshots,
            direction: 'stable',
            scoreDelta: 0,
            findingDelta: 0,
            criticalDelta: 0,
        };
    }
    const sorted = [...snapshots].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const current = sorted[sorted.length - 1];
    const previous = sorted[sorted.length - 2];
    const scoreDelta = previous.agencyScore - current.agencyScore;
    const findingDelta = previous.totalFindings - current.totalFindings;
    const criticalDelta = previous.criticalCount - current.criticalCount;
    let direction = 'stable';
    if (scoreDelta > 5 || criticalDelta > 0)
        direction = 'improving';
    else if (scoreDelta < -5 || criticalDelta < 0)
        direction = 'declining';
    return {
        snapshots: sorted,
        direction,
        scoreDelta,
        findingDelta,
        criticalDelta,
    };
}
