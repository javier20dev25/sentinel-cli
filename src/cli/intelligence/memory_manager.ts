/**
 * Sentinel Memory Manager (v2.0)
 * 
 * Handles local Signal Vault operations: cloud ingestion, status, threshold analysis, and cleanup.
 * v2.0: Real DB queries, cloud JSON format support, threshold-based drift detection.
 */

import { SignalVault } from './signal_vault';
import * as fs from 'fs';
import * as pc from 'picocolors';

export class MemoryManager {
    private vault: SignalVault;

    constructor() {
        this.vault = new SignalVault();
    }

    public getVault(): SignalVault {
        return this.vault;
    }

    /**
     * Ingests a pre-parsed JSON object (from --stdin or --paste).
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    public ingestReportFromJson(json: any): string {
        if (json.metadata?.topAlerts || json.category === 'SECURITY_AUDIT') {
            return this.vault.ingestCloudReport(json);
        }
        const meta = json.metadata || {};
        const scanMeta = {
            id: json.id || json.event_hash || 'ingested_' + Date.now(),
            repo: meta.repoFullName || json.repo_hash || 'unknown',
            pr: meta.prNumber || 0,
            author: meta.author?.login || meta.author || 'unknown',
            score: json.risk_score || json.risk_assessment?.score || 0,
            band: json.risk_assessment?.band || (json.risk_score >= 70 ? 'CRITICAL' : (json.risk_score >= 40 ? 'SUSPICIOUS' : 'SAFE'))
        };
        this.vault.recordScan(scanMeta);
        const alerts = json.metadata?.topAlerts || json.findings || [];
        for (const f of alerts) {
            this.vault.recordSignal({
                repo: scanMeta.repo,
                author: scanMeta.author,
                signal_type: f.type || f.ruleName,
                weight: (f.riskLevel ?? f.riskScore ?? 5) / 10,
                file_path: f._file ?? f.file ?? '',
                source_scan: scanMeta.id
            });
        }
        return scanMeta.id;
    }

    /**
     * Ingests a Pro JSON report from the cloud into the local Signal Vault.
     * Supports both the new Sentinel SaaS format and legacy format.
     */
    public ingestReport(reportPath: string): string {
        const content = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        return this.ingestReportFromJson(content);
    }

    public getStatus(): {
        signals: number;
        scans: number;
        findings: number;
        repos: number;
        authors: number;
        retention: string;
    } {
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
    public getThresholdAnalysis(threshold = 5): Array<{
        repo: string;
        signalCount: number;
        uniqueTypes: string[];
        riskTrend: string;
        lastSignal: string;
    }> {
        return this.vault.getThresholdAnalysis(threshold);
    }

    /**
     * Prints a formatted threshold status table.
     */
    public printThresholdReport(threshold = 5): void {
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
    public printMultiAuthorCorrelation(): void {
        const repoAuthorMap = new Map<string, Set<string>>();
        const signalMap = this.vault.getMultiAuthorSignals();

        for (const row of signalMap) {
            if (!repoAuthorMap.has(row.repo)) repoAuthorMap.set(row.repo, new Set());
            repoAuthorMap.get(row.repo)!.add(row.author);
        }

        const multiAuthor = Array.from(repoAuthorMap.entries())
            .filter(([_, authors]) => authors.size >= 2)
            .sort((a, b) => b[1].size - a[1].size);

        if (multiAuthor.length === 0) return;

        console.log(pc.magenta('\n👥 MULTI-AUTHOR CORRELATION'));
        console.log(pc.dim('   Different authors contributing to the same repo\n'));

        for (const [repo, authors] of multiAuthor) {
            console.log(` ${pc.cyan('▸')} ${pc.bold(repo)}`);
            console.log(`   ${pc.dim('Authors:')} ${Array.from(authors).map(a => pc.white(a)).join(', ')}`);
            const typeCounts = new Map<string, number>();
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

    public wipe(): void {
        this.vault.wipe();
    }
}
