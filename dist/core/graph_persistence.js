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
exports.saveGraphSnapshot = saveGraphSnapshot;
exports.loadGraphHistory = loadGraphHistory;
exports.computeGraphTrend = computeGraphTrend;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const crypto = __importStar(require("crypto"));
function getGraphDir(repoPath) {
    const hash = crypto.createHash('sha256').update(path.resolve(repoPath)).digest('hex').substring(0, 12);
    return path.join(os.homedir(), '.sentinel', 'graphs', hash);
}
function saveGraphSnapshot(repoPath, graph) {
    const dir = getGraphDir(repoPath);
    if (!fs.existsSync(dir))
        fs.mkdirSync(dir, { recursive: true });
    const id = Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
    const hash = crypto.createHash('sha256').update(path.resolve(repoPath)).digest('hex').substring(0, 12);
    const snapshot = {
        id,
        timestamp: new Date().toISOString(),
        repoHash: hash,
        nodes: graph.nodes.length,
        edges: graph.edges.length,
        chains: graph.chains.length,
        topChains: graph.chains.slice(0, 5).map(c => ({
            score: c.score,
            confidence: c.confidence,
            nodeCount: c.nodes.length,
        })),
        fullGraph: graph,
    };
    const safeTimestamp = snapshot.timestamp.replace(/:/g, '-').replace(/\./g, '-');
    const filePath = path.join(dir, `${safeTimestamp}-${id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2));
    autoPrune(dir);
    return filePath;
}
function loadGraphHistory(repoPath) {
    const dir = getGraphDir(repoPath);
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
        catch (_a) {
            // skip corrupt entries
        }
    }
    return snapshots;
}
function computeGraphTrend(repoPath) {
    var _a, _b, _c, _d;
    const snapshots = loadGraphHistory(repoPath);
    if (snapshots.length < 2) {
        return { chainCountDelta: 0, scoreDelta: 0 };
    }
    const sorted = [...snapshots].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const current = sorted[sorted.length - 1];
    const previous = sorted[sorted.length - 2];
    const currentTopScore = (_b = (_a = current.topChains[0]) === null || _a === void 0 ? void 0 : _a.score) !== null && _b !== void 0 ? _b : 0;
    const previousTopScore = (_d = (_c = previous.topChains[0]) === null || _c === void 0 ? void 0 : _c.score) !== null && _d !== void 0 ? _d : 0;
    return {
        chainCountDelta: current.chains - previous.chains,
        scoreDelta: currentTopScore - previousTopScore,
    };
}
function autoPrune(dir) {
    const entries = fs.readdirSync(dir)
        .filter(f => f.endsWith('.json'))
        .sort()
        .reverse();
    if (entries.length <= 30)
        return;
    const toRemove = entries.slice(30);
    for (const entry of toRemove) {
        try {
            fs.unlinkSync(path.join(dir, entry));
        }
        catch (_a) {
            // ignore
        }
    }
}
