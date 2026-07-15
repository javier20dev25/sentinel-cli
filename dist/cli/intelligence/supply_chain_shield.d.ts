/**
 * Sentinel Supply Chain Shield (v5.0 — A2)
 *
 * Real package downloader + SAST scanner for supply chain threats.
 * Integrates OSV.dev CVE lookup, typosquatting detection, trust cache.
 * Downloads tarballs from npm registry, extracts to temp, and runs LiteScanner.
 */
import { LiteFinding } from '../../core/lite/lite_scanner';
import { OSVResult } from './osv_integrator';
import { TyposquatResult } from './typosquat_detector';
import { CacheResult } from './trust_cache';
export interface PackageAnalysis {
    pkg: string;
    findings: LiteFinding[];
    fileCount: number;
    scanTimeMs: number;
    memoryMB: number;
    sizeBytes: number;
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    osvResult?: OSVResult;
    typosquat?: TyposquatResult;
    cacheResult?: CacheResult;
}
export declare class SupplyChainShield {
    private scanner;
    private osv;
    private typosquat;
    private trustCache;
    constructor();
    /**
     * Download a package tarball (without installing) and run SAST.
     */
    analyzePackage(pkgSpec: string): Promise<PackageAnalysis>;
    /**
     * Scan multiple packages in batch and return a report.
     */
    analyzeBatch(pkgSpecs: string[]): Promise<PackageAnalysis[]>;
    /**
     * Scans a package installation intent (legacy interface).
     * Now delegates to analyzePackage but only warns, doesn't mock.
     */
    scanInstallation(manager: string, args: string[]): Promise<{
        success: boolean;
        results?: undefined;
    } | {
        success: boolean;
        results: PackageAnalysis[];
    }>;
    private walkDir;
}
