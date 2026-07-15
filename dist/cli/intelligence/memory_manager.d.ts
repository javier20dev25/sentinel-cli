/**
 * Sentinel Memory Manager (v2.0)
 *
 * Handles local Signal Vault operations: cloud ingestion, status, threshold analysis, and cleanup.
 * v2.0: Real DB queries, cloud JSON format support, threshold-based drift detection.
 */
import { SignalVault } from './signal_vault';
export declare class MemoryManager {
    private vault;
    constructor();
    getVault(): SignalVault;
    /**
     * Ingests a pre-parsed JSON object (from --stdin or --paste).
     */
    ingestReportFromJson(json: any): string;
    /**
     * Ingests a Pro JSON report from the cloud into the local Signal Vault.
     * Supports both the new Sentinel SaaS format and legacy format.
     */
    ingestReport(reportPath: string): string;
    getStatus(): {
        signals: number;
        scans: number;
        findings: number;
        repos: number;
        authors: number;
        retention: string;
    };
    /**
     * Runs threshold-based drift detection.
     * Returns repos where accumulated signals cross the warning threshold.
     */
    getThresholdAnalysis(threshold?: number): Array<{
        repo: string;
        signalCount: number;
        uniqueTypes: string[];
        riskTrend: string;
        lastSignal: string;
    }>;
    /**
     * Prints a formatted threshold status table.
     */
    printThresholdReport(threshold?: number): void;
    /**
     * Prints multi-author correlations — detects when different attackers
     * contribute signals to the same repo (different pieces of a large attack).
     */
    printMultiAuthorCorrelation(): void;
    wipe(): void;
}
