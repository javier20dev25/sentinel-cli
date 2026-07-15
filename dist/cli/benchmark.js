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
exports.runBenchmark = runBenchmark;
exports.aggregateBenchmark = aggregateBenchmark;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const lite_scanner_1 = require("../core/lite/lite_scanner");
const agency_score_1 = require("../core/agency_score");
function* walkDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            yield* walkDir(fullPath);
        }
        else {
            yield fullPath;
        }
    }
}
function runBenchmark(corpusRoot) {
    const vulnerableDir = path.join(corpusRoot, 'known-vulnerable');
    const benignDir = path.join(corpusRoot, 'known-benign');
    const scanner = new lite_scanner_1.LiteScanner();
    const results = [];
    const vulnerableFiles = [];
    if (fs.existsSync(vulnerableDir)) {
        for (const f of walkDir(vulnerableDir)) {
            vulnerableFiles.push(f);
        }
    }
    const benignFiles = [];
    if (fs.existsSync(benignDir)) {
        for (const f of walkDir(benignDir)) {
            benignFiles.push(f);
        }
    }
    const allFixtures = new Map();
    for (const f of vulnerableFiles) {
        const relPath = path.relative(vulnerableDir, f);
        allFixtures.set(relPath, 'vulnerable');
    }
    for (const f of benignFiles) {
        const relPath = path.relative(benignDir, f);
        allFixtures.set(relPath, 'benign');
    }
    for (const [relPath, label] of allFixtures) {
        const fixturePath = label === 'vulnerable'
            ? path.join(vulnerableDir, relPath)
            : path.join(benignDir, relPath);
        const content = fs.readFileSync(fixturePath, 'utf8');
        const startTime = Date.now();
        const result = scanner.scanFileContent(relPath, content);
        const scanTimeMs = Date.now() - startTime;
        const agency = (0, agency_score_1.calculateAgencyScore)(result.findings);
        const expected = [];
        for (const [filePattern, entry] of Object.entries(existingExpectedFindings)) {
            const isTuple = entry.length === 2 && (entry[0] === 'vulnerable' || entry[0] === 'benign');
            const matchLabel = isTuple ? entry[0] : 'vulnerable';
            const expects = isTuple ? entry[1] : entry;
            if (!relPath.includes(filePattern) && relPath !== filePattern)
                continue;
            if (label !== matchLabel)
                continue;
            expected.push(...expects);
        }
        const actualSubcodes = new Set(result.findings.map(f => f.subcode).filter(Boolean));
        const falsePositives = [];
        const falseNegatives = [];
        let truePositives = 0;
        for (const subcode of actualSubcodes) {
            if (expected.includes(subcode)) {
                truePositives++;
            }
            else {
                falsePositives.push(subcode);
            }
        }
        for (const subcode of expected) {
            if (!actualSubcodes.has(subcode)) {
                falseNegatives.push(subcode);
            }
        }
        const tp = truePositives;
        const fp = falsePositives.length;
        const fn = falseNegatives.length;
        const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
        const recall = tp + fn > 0 ? tp / (tp + fn) : label === 'benign' ? 1 : 0;
        results.push({
            scanId: `${label}-${relPath.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
            repoPath: relPath,
            findingsCount: result.findings.length,
            criticalCount: result.findings.filter(f => f.severity === 'CRITICAL').length,
            highCount: result.findings.filter(f => f.severity === 'HIGH').length,
            agencyScore: agency.agencyScore,
            scanTimeMs,
            falsePositives,
            falseNegatives,
            precision,
            recall,
        });
    }
    return results;
}
function aggregateBenchmark(results) {
    if (results.length === 0) {
        return { totalFixtures: 0, totalFindings: 0, avgPrecision: 1, avgRecall: 1, worstFp: [], worstFn: [] };
    }
    const totalFixtures = results.length;
    const totalFindings = results.reduce((s, r) => s + r.findingsCount, 0);
    const avgPrecision = results.reduce((s, r) => s + r.precision, 0) / totalFixtures;
    const avgRecall = results.reduce((s, r) => s + r.recall, 0) / totalFixtures;
    const sortedByFp = [...results].sort((a, b) => b.falsePositives.length - a.falsePositives.length);
    const sortedByFn = [...results].sort((a, b) => b.falseNegatives.length - a.falseNegatives.length);
    return {
        totalFixtures,
        totalFindings,
        avgPrecision,
        avgRecall,
        worstFp: sortedByFp.slice(0, 5),
        worstFn: sortedByFn.slice(0, 5),
    };
}
const existingExpectedFindings = {
    '.env': ['SEC-ENV-FILE'],
    '.env.production': ['SEC-ENV-FILE'],
    'secrets.env': ['SEC-ENV-FILE', 'SEC-AWS-ID', 'SEC-AWS-ID-BARE', 'SEC-GITHUB-TOKEN', 'SEC-API-KEY', 'SEC-SSH-KEY', 'SEC-DB-PASSWORD'],
    'credentials.json': ['SEC-CREDS-FILE'],
    'secrets.json': ['SEC-CREDS-FILE'],
    'key.json': ['SEC-CREDS-FILE'],
    'id_rsa': ['SEC-SSH-FILE'],
    'binding.gyp': ['GYP-FILE'],
    'node-gyp-build.js': ['GYP-NODE'],
    'malware.js': ['SAST-EVAL', 'SAST-PROCESS', 'OBF-PAYLOAD'],
    'supply-chain.yml': ['WF-001', 'WF-002', 'WF-005'],
    'ast-threat.js': ['SAST-EVAL', 'SAST-PROCESS', 'SAST-NETWORK', 'SAST-ENV', 'SEC-HARDCODED-TOKEN'],
    'package.json': ['vulnerable', ['LIF-CURL-BASH', 'LIF-SHELL']],
    'package-lock.json': ['vulnerable', []],
    'rust-threat.rs': ['vulnerable', ['SAST-PROCESS']],
    'go-threat.go': ['vulnerable', ['SAST-PROCESS']],
};
