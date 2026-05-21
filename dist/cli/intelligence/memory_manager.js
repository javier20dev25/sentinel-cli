"use strict";
/**
 * Sentinel Memory Manager (v2.0)
 *
 * Handles local Signal Vault operations: cloud ingestion, status, threshold analysis, and cleanup.
 * v2.0: Real DB queries, cloud JSON format support, threshold-based drift detection.
 */
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
exports.MemoryManager = void 0;
const signal_vault_1 = require("./signal_vault");
const fs = __importStar(require("fs"));
const pc = __importStar(require("picocolors"));
class MemoryManager {
    constructor() {
        this.vault = new signal_vault_1.SignalVault();
    }
    getVault() {
        return this.vault;
    }
    /**
     * Ingests a pre-parsed JSON object (from --stdin or --paste).
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ingestReportFromJson(json) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j;
        if (((_a = json.metadata) === null || _a === void 0 ? void 0 : _a.topAlerts) || json.category === 'SECURITY_AUDIT') {
            return this.vault.ingestCloudReport(json);
        }
        const meta = json.metadata || {};
        const scanMeta = {
            id: json.id || json.event_hash || 'ingested_' + Date.now(),
            repo: meta.repoFullName || json.repo_hash || 'unknown',
            pr: meta.prNumber || 0,
            author: ((_b = meta.author) === null || _b === void 0 ? void 0 : _b.login) || meta.author || 'unknown',
            score: json.risk_score || ((_c = json.risk_assessment) === null || _c === void 0 ? void 0 : _c.score) || 0,
            band: ((_d = json.risk_assessment) === null || _d === void 0 ? void 0 : _d.band) || (json.risk_score >= 70 ? 'CRITICAL' : (json.risk_score >= 40 ? 'SUSPICIOUS' : 'SAFE'))
        };
        this.vault.recordScan(scanMeta);
        const alerts = ((_e = json.metadata) === null || _e === void 0 ? void 0 : _e.topAlerts) || json.findings || [];
        for (const f of alerts) {
            this.vault.recordSignal({
                repo: scanMeta.repo,
                author: scanMeta.author,
                signal_type: f.type || f.ruleName,
                weight: ((_g = (_f = f.riskLevel) !== null && _f !== void 0 ? _f : f.riskScore) !== null && _g !== void 0 ? _g : 5) / 10,
                file_path: (_j = (_h = f._file) !== null && _h !== void 0 ? _h : f.file) !== null && _j !== void 0 ? _j : '',
                source_scan: scanMeta.id
            });
        }
        return scanMeta.id;
    }
    /**
     * Ingests a Pro JSON report from the cloud into the local Signal Vault.
     * Supports both the new Sentinel SaaS format and legacy format.
     */
    ingestReport(reportPath) {
        const content = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        return this.ingestReportFromJson(content);
    }
    getStatus() {
        const stats = this.vault.getStats();
        return {
            signals: stats.totalSignals,
            scans: stats.totalScans,
            findings: stats.totalFindings,
            repos: stats.repos,
            authors: stats.authors,
            retention: 'Permanent (Manual Purge)'
        };
    }
    /**
     * Runs threshold-based drift detection.
     * Returns repos where accumulated signals cross the warning threshold.
     */
    getThresholdAnalysis(threshold = 5) {
        return this.vault.getThresholdAnalysis(threshold);
    }
    /**
     * Prints a formatted threshold status table.
     */
    printThresholdReport(threshold = 5) {
        const analysis = this.getThresholdAnalysis(threshold);
        console.log(pc.magenta('\n🧠 SENTINEL THRESHOLD DRIFT ANALYSIS'));
        console.log(pc.dim('   Repos with signals above threshold\n'));
        if (analysis.length === 0) {
            console.log(pc.green('   ✓ No repos have crossed the alert threshold.\n'));
            return;
        }
        for (const entry of analysis) {
            const trendColor = entry.riskTrend === 'ESCALATING' ? pc.bgRed :
                (entry.riskTrend === 'ELEVATED' ? pc.bgYellow : pc.bgCyan);
            const trendLabel = entry.riskTrend === 'ESCALATING' ? '⚠ ESCALATING' :
                (entry.riskTrend === 'ELEVATED' ? '⚡ ELEVATED' : '● MONITOR');
            console.log(` ${pc.cyan('▸')} ${pc.bold(entry.repo)}`);
            console.log(`   Signals: ${pc.white(String(entry.signalCount))} | Types: ${pc.dim(entry.uniqueTypes.slice(0, 5).join(', ') + (entry.uniqueTypes.length > 5 ? '...' : ''))}`);
            console.log(`   Trend: ${trendColor(pc.black(` ${trendLabel} `))}  ${pc.dim('Last: ' + entry.lastSignal)}`);
            console.log();
        }
    }
    /**
     * Prints multi-author correlations — detects when different attackers
     * contribute signals to the same repo (different pieces of a large attack).
     */
    printMultiAuthorCorrelation() {
        const repoAuthorMap = new Map();
        const signalMap = this.vault.getMultiAuthorSignals();
        for (const row of signalMap) {
            if (!repoAuthorMap.has(row.repo))
                repoAuthorMap.set(row.repo, new Set());
            repoAuthorMap.get(row.repo).add(row.author);
        }
        const multiAuthor = Array.from(repoAuthorMap.entries())
            .filter(([_, authors]) => authors.size >= 2)
            .sort((a, b) => b[1].size - a[1].size);
        if (multiAuthor.length === 0)
            return;
        console.log(pc.magenta('\n👥 MULTI-AUTHOR CORRELATION'));
        console.log(pc.dim('   Different authors contributing to the same repo\n'));
        for (const [repo, authors] of multiAuthor) {
            console.log(` ${pc.cyan('▸')} ${pc.bold(repo)}`);
            console.log(`   ${pc.dim('Authors:')} ${Array.from(authors).map(a => pc.white(a)).join(', ')}`);
            const typeCounts = new Map();
            for (const row of signalMap) {
                if (row.repo === repo) {
                    typeCounts.set(row.signal_type, (typeCounts.get(row.signal_type) || 0) + 1);
                }
            }
            const topTypes = Array.from(typeCounts.entries())
                .sort((a, b) => b[1] - a[1]).slice(0, 5)
                .map(([t, c]) => `${t}(${c})`);
            console.log(`   ${pc.dim('Top signals:')} ${topTypes.join(', ')}`);
            console.log();
        }
    }
    wipe() {
        this.vault.wipe();
    }
}
exports.MemoryManager = MemoryManager;
