/**
 * Sentinel Trust Cache (v5.0)
 *
 * Caches package analysis results with timestamps for recency-based scoring.
 * Packages analyzed < 1 hour ago: BLOCK (stale cache not trusted)
 * Packages analyzed < 24 hours ago: REVIEW (somewhat trusted)
 * Packages analyzed >= 24 hours ago: PASS (trusted)
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface CacheEntry {
    packageName: string;
    version: string;
    verdict: string;
    findingCount: number;
    criticalCount: number;
    timestamp: number;  // epoch ms
}

export interface CacheResult {
    found: boolean;
    entry?: CacheEntry;
    recencyBand: 'FRESH' | 'RECENT' | 'STALE' | 'UNKNOWN';
    ageHours: number;
}

export class TrustCache {
    private cachePath: string;
    private cache: Map<string, CacheEntry>;

    constructor() {
        this.cachePath = path.join(os.homedir(), '.sentinel', 'trust_cache.json');
        this.cache = new Map();
        this.load();
    }

    private load(): void {
        try {
            if (fs.existsSync(this.cachePath)) {
                const data = JSON.parse(fs.readFileSync(this.cachePath, 'utf8'));
                const entries: CacheEntry[] = data.packages || data.entries || [];
                for (const e of entries) {
                    this.cache.set(this.key(e.packageName, e.version), e);
                }
            }
        } catch {}
    }

    private save(): void {
        try {
            const dir = path.dirname(this.cachePath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            const entries = Array.from(this.cache.values());
            fs.writeFileSync(this.cachePath, JSON.stringify({ packages: entries, updated: Date.now() }, null, 2));
        } catch {}
    }

    private key(name: string, version: string): string {
        return `${name}@${version || 'latest'}`;
    }

    /**
     * Get a cached entry with recency scoring.
     */
    public get(name: string, version: string): CacheResult {
        const k = this.key(name, version);
        const entry = this.cache.get(k);

        if (!entry) {
            return { found: false, recencyBand: 'UNKNOWN', ageHours: 0 };
        }

        const ageHours = (Date.now() - entry.timestamp) / 3600000;

        let recencyBand: 'FRESH' | 'RECENT' | 'STALE';
        if (ageHours < 1) {
            recencyBand = 'FRESH';
        } else if (ageHours < 24) {
            recencyBand = 'RECENT';
        } else {
            recencyBand = 'STALE';
        }

        return { found: true, entry, recencyBand, ageHours };
    }

    /**
     * Store a package analysis result.
     */
    public set(name: string, version: string, verdict: string, findingCount: number, criticalCount: number): void {
        const entry: CacheEntry = {
            packageName: name,
            version,
            verdict,
            findingCount,
            criticalCount,
            timestamp: Date.now()
        };
        this.cache.set(this.key(name, version), entry);
        this.save();
    }

    /**
     * Clear the entire cache.
     */
    public clear(): void {
        this.cache.clear();
        this.save();
    }

    /**
     * Remove expired entries (older than 7 days).
     */
    public prune(maxAgeMs: number = 7 * 24 * 3600000): number {
        const now = Date.now();
        let removed = 0;
        for (const [k, v] of this.cache) {
            if (now - v.timestamp >= maxAgeMs) {
                this.cache.delete(k);
                removed++;
            }
        }
        if (removed > 0) this.save();
        return removed;
    }

    /**
     * Get cache stats.
     */
    public stats(): { entries: number; oldest: number; newest: number } {
        const entries = Array.from(this.cache.values());
        if (entries.length === 0) return { entries: 0, oldest: 0, newest: 0 };
        const times = entries.map(e => e.timestamp);
        return {
            entries: entries.length,
            oldest: Math.min(...times),
            newest: Math.max(...times)
        };
    }
}
