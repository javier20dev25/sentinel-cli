/**
 * Sentinel Trust Cache (v5.0)
 *
 * Caches package analysis results with timestamps for recency-based scoring.
 * Packages analyzed < 1 hour ago: BLOCK (stale cache not trusted)
 * Packages analyzed < 24 hours ago: REVIEW (somewhat trusted)
 * Packages analyzed >= 24 hours ago: PASS (trusted)
 */
export interface CacheEntry {
    packageName: string;
    version: string;
    verdict: string;
    findingCount: number;
    criticalCount: number;
    timestamp: number;
}
export interface CacheResult {
    found: boolean;
    entry?: CacheEntry;
    recencyBand: 'FRESH' | 'RECENT' | 'STALE' | 'UNKNOWN';
    ageHours: number;
}
export declare class TrustCache {
    private cachePath;
    private cache;
    constructor();
    private load;
    private save;
    private key;
    /**
     * Get a cached entry with recency scoring.
     */
    get(name: string, version: string): CacheResult;
    /**
     * Store a package analysis result.
     */
    set(name: string, version: string, verdict: string, findingCount: number, criticalCount: number): void;
    /**
     * Clear the entire cache.
     */
    clear(): void;
    /**
     * Remove expired entries (older than 7 days).
     */
    prune(maxAgeMs?: number): number;
    /**
     * Get cache stats.
     */
    stats(): {
        entries: number;
        oldest: number;
        newest: number;
    };
}
