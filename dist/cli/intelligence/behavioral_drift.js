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
exports.analyzeCapabilities = analyzeCapabilities;
exports.computeDrift = computeDrift;
exports.saveSnapshot = saveSnapshot;
exports.loadPreviousSnapshot = loadPreviousSnapshot;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const lite_scanner_1 = require("../../core/lite/lite_scanner");
const capability_analyzer_1 = require("./capability_analyzer");
function toDriftCapName(capType) {
    const map = {
        'NETWORK': 'network',
        'FILESYSTEM': 'file_write',
        'PROCESS_EXEC': 'process_spawn',
        'ENV_ACCESS': 'env_access',
        'DYNAMIC_EXEC': 'eval',
        'DOM_MANIPULATION': 'dom_manipulation',
        'CREDENTIAL_LEAK': 'credential_leak',
    };
    return map[capType] || capType.toLowerCase();
}
const DANGEROUS_CAPABILITIES = new Set(['exec', 'eval', 'network', 'file_write', 'process_spawn']);
function walkDir(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    for (const file of list) {
        const lowerFile = file.toLowerCase();
        if (lowerFile === 'test' || lowerFile === 'tests' || lowerFile === 'example' ||
            lowerFile === 'examples' || lowerFile === 'benchmark' || lowerFile === 'docs' ||
            lowerFile === 'node_modules' || file.startsWith('.')) {
            continue;
        }
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            results = results.concat(walkDir(fullPath));
        }
        else {
            results.push(fullPath);
        }
    }
    return results;
}
function analyzeCapabilities(packageName, version, packagePath) {
    const scanner = new lite_scanner_1.LiteScanner();
    const allFindings = [];
    const files = walkDir(packagePath).filter(f => f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs'));
    for (const file of files) {
        try {
            const content = fs.readFileSync(file, 'utf8');
            const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
            const findings = scanner.scanPatch(path.relative(packagePath, file), patch);
            allFindings.push(...findings);
        }
        catch (_a) { }
    }
    const capabilities = capability_analyzer_1.CapabilityAnalyzer.analyze(allFindings);
    const capMap = new Map();
    let riskScore = 0;
    const riskWeights = { 'LOW': 1, 'MEDIUM': 5, 'HIGH': 15, 'CRITICAL': 25 };
    for (const cap of capabilities) {
        const key = toDriftCapName(cap.capability);
        capMap.set(key, (capMap.get(key) || 0) + 1);
        riskScore += riskWeights[cap.risk] || 0;
    }
    return {
        packageName,
        version,
        timestamp: new Date().toISOString(),
        capabilities: capMap,
        riskScore,
    };
}
function computeDrift(previous, current) {
    const drifts = [];
    const newCapabilities = [];
    const removedCapabilities = [];
    const allKeys = new Set([...previous.capabilities.keys(), ...current.capabilities.keys()]);
    for (const key of allKeys) {
        const prevVal = previous.capabilities.get(key) || 0;
        const currVal = current.capabilities.get(key) || 0;
        const change = currVal - prevVal;
        let severity;
        if (prevVal === 0 && currVal > 0) {
            severity = 'NEW';
            newCapabilities.push(key);
        }
        else if (prevVal > 0 && currVal === 0) {
            severity = 'REMOVED';
            removedCapabilities.push(key);
        }
        else if (change > 0) {
            severity = 'INCREASED';
        }
        else if (change < 0) {
            severity = 'DECREASED';
        }
        else {
            continue;
        }
        drifts.push({ capability: key, previousCount: prevVal, currentCount: currVal, change, severity });
    }
    const riskChange = current.riskScore - previous.riskScore;
    let verdict = 'SAFE';
    const hasNewDangerous = newCapabilities.some(c => DANGEROUS_CAPABILITIES.has(c));
    if (hasNewDangerous) {
        verdict = 'MALICIOUS';
    }
    const increasedCount = drifts.filter(d => d.severity === 'INCREASED').length;
    if (increasedCount > 2 && verdict !== 'MALICIOUS') {
        verdict = 'SUSPICIOUS';
    }
    if (riskChange > 30) {
        if (verdict === 'SAFE')
            verdict = 'SUSPICIOUS';
        else if (verdict === 'SUSPICIOUS')
            verdict = 'MALICIOUS';
    }
    return {
        packageName: current.packageName,
        previousVersion: previous.version,
        currentVersion: current.version,
        drifts,
        riskChange,
        verdict,
        newCapabilities,
        removedCapabilities,
    };
}
function saveSnapshot(snapshot) {
    const dir = path.join(os.homedir(), '.sentinel', 'drift', snapshot.packageName);
    fs.mkdirSync(dir, { recursive: true });
    const filePath = path.join(dir, `${snapshot.version}.json`);
    const data = Object.assign(Object.assign({}, snapshot), { capabilities: Object.fromEntries(snapshot.capabilities) });
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}
function loadPreviousSnapshot(packageName, currentVersion) {
    const dir = path.join(os.homedir(), '.sentinel', 'drift', packageName);
    if (!fs.existsSync(dir))
        return null;
    const files = fs.readdirSync(dir)
        .filter(f => f.endsWith('.json'))
        .sort()
        .reverse();
    for (const file of files) {
        const version = file.replace('.json', '');
        if (version !== currentVersion) {
            try {
                const raw = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
                return Object.assign(Object.assign({}, raw), { capabilities: new Map(Object.entries(raw.capabilities || {})) });
            }
            catch (_a) { }
        }
    }
    return null;
}
