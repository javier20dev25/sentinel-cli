"use strict";
/**
 * Sentinel Trust Cache (v5.0)
 *
 * Caches package analysis results with timestamps for recency-based scoring.
 * Packages analyzed < 1 hour ago: BLOCK (stale cache not trusted)
 * Packages analyzed < 24 hours ago: REVIEW (somewhat trusted)
 * Packages analyzed >= 24 hours ago: PASS (trusted)
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
exports.TrustCache = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
class TrustCache {
    constructor() {
        this.cachePath = path.join(os.homedir(), '.sentinel', 'trust_cache.json');
        this.cache = new Map();
        this.load();
    }
    load() {
        try {
            if (fs.existsSync(this.cachePath)) {
                const data = JSON.parse(fs.readFileSync(this.cachePath, 'utf8'));
                const entries = data.packages || data.entries || [];
                for (const e of entries) {
                    this.cache.set(this.key(e.packageName, e.version), e);
                }
            }
        }
        catch (_a) { }
    }
    save() {
        try {
            const dir = path.dirname(this.cachePath);
            if (!fs.existsSync(dir))
                fs.mkdirSync(dir, { recursive: true });
            const entries = Array.from(this.cache.values());
            fs.writeFileSync(this.cachePath, JSON.stringify({ packages: entries, updated: Date.now() }, null, 2));
        }
        catch (_a) { }
    }
    key(name, version) {
        return `${name}@${version || 'latest'}`;
    }
    /**
     * Get a cached entry with recency scoring.
     */
    get(name, version) {
        const k = this.key(name, version);
        const entry = this.cache.get(k);
        if (!entry) {
            return { found: false, recencyBand: 'UNKNOWN', ageHours: 0 };
        }
        const ageHours = (Date.now() - entry.timestamp) / 3600000;
        let recencyBand;
        if (ageHours < 1) {
            recencyBand = 'FRESH';
        }
        else if (ageHours < 24) {
            recencyBand = 'RECENT';
        }
        else {
            recencyBand = 'STALE';
        }
        return { found: true, entry, recencyBand, ageHours };
    }
    /**
     * Store a package analysis result.
     */
    set(name, version, verdict, findingCount, criticalCount) {
        const entry = {
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
    clear() {
        this.cache.clear();
        this.save();
    }
    /**
     * Remove expired entries (older than 7 days).
     */
    prune(maxAgeMs = 7 * 24 * 3600000) {
        const now = Date.now();
        let removed = 0;
        for (const [k, v] of this.cache) {
            if (now - v.timestamp >= maxAgeMs) {
                this.cache.delete(k);
                removed++;
            }
        }
        if (removed > 0)
            this.save();
        return removed;
    }
    /**
     * Get cache stats.
     */
    stats() {
        const entries = Array.from(this.cache.values());
        if (entries.length === 0)
            return { entries: 0, oldest: 0, newest: 0 };
        const times = entries.map(e => e.timestamp);
        return {
            entries: entries.length,
            oldest: Math.min(...times),
            newest: Math.max(...times)
        };
    }
}
exports.TrustCache = TrustCache;
