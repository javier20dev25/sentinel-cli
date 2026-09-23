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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IntegrityChain = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const crypto = __importStar(require("crypto"));
const better_sqlite3_1 = __importDefault(require("better-sqlite3"));
/**
 * Cryptographic contract versions.
 *
 * The chain was written by two generations of hashing code:
 *
 *  V1 (legacy): payloads were stringified with JSON.stringify(...) WITHOUT
 *     sorting object keys. Links 1..5 were created this way (2026-06-05 and
 *     2026-06-10, rule hashes d166c870 / 661a936a).
 *  V2 (current): object keys are sorted before stringify. Links 6+ were
 *     created this way.
 *
 * The boundary is deterministic: a link is legacy (V1) when it lives in the
 * immutable id range below AND was persisted before the V2 migration date.
 * The date guard keeps freshly created chains (whose ids also start at 1)
 * on the current schema. The cutoffs match the real history of the persisted
 * chain (legacy links stop at 2026-06-10 08:33:38 UTC; V2 starts at
 * 2026-06-10 13:24:30 UTC) and must not be shifted or historic links will
 * stop verifying.
 */
const LEGACY_SCHEMA_MAX_LINK_ID = 5;
const LEGACY_SCHEMA_CUTOFF = '2026-06-10 12:00:00';
/** Fields covered by a link's own link_hash (identical set in V1 and V2). */
const LINK_HASH_FIELDS = [
    'session_id',
    'link_number',
    'code_hash',
    'previous_link_hash',
    'started_at',
    'accumulated_seconds',
];
/**
 * Full-row material bound by previous_link_hash (DB column order).
 * The next link's previous_link_hash covers the ENTIRE previous row,
 * including id, link_hash and created_at — this is how both generations
 * actually wrote the chain, and changing it would break the persisted 490
 * links without touching them.
 */
const CHAIN_HASH_FIELDS = [
    'id',
    'session_id',
    'link_number',
    'code_hash',
    'previous_link_hash',
    'link_hash',
    'started_at',
    'accumulated_seconds',
    'created_at',
];
class IntegrityChain {
    constructor(dbPath) {
        const resolvedPath = dbPath !== null && dbPath !== void 0 ? dbPath : path.join(os.homedir(), '.sentinel', 'vault.db');
        const dir = path.dirname(resolvedPath);
        if (!fs.existsSync(dir))
            fs.mkdirSync(dir, { recursive: true });
        this.db = new better_sqlite3_1.default(resolvedPath);
        this.cliRoot = path.join(__dirname, '..', '..', '..');
        this.sessionId = crypto.randomBytes(8).toString('hex');
        this.sessionStart = Date.now();
        this.initSchema();
    }
    initSchema() {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS integrity_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                link_number INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                previous_link_hash TEXT,
                link_hash TEXT NOT NULL,
                started_at TEXT NOT NULL,
                accumulated_seconds REAL NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
    }
    recordBoot(codeHash) {
        const lastLink = this.getLastLink();
        let accumulated = 0;
        let chainStatus = 'INTACT';
        let previousHash = null;
        if (lastLink) {
            if (!this.verifyLink(lastLink)) {
                chainStatus = 'BROKEN';
            }
            if (lastLink.code_hash !== codeHash) {
                chainStatus = 'BROKEN';
            }
            // New links are always written with the current (V2) schema, so the
            // chain binding covers the full previous row under V2.
            previousHash = this.hashForSchema('v2', this.pickFields(lastLink, CHAIN_HASH_FIELDS));
            const lastTime = new Date(lastLink.created_at).getTime();
            const elapsed = Math.max(0, (this.sessionStart - lastTime) / 1000);
            accumulated = lastLink.accumulated_seconds + elapsed;
        }
        const linkHash = this.hashForSchema('v2', {
            session_id: this.sessionId,
            link_number: lastLink ? lastLink.link_number + 1 : 1,
            code_hash: codeHash,
            previous_link_hash: previousHash,
            started_at: new Date(this.sessionStart).toISOString(),
            accumulated_seconds: accumulated,
        });
        const linkData = {
            session_id: this.sessionId,
            link_number: lastLink ? lastLink.link_number + 1 : 1,
            code_hash: codeHash,
            previous_link_hash: previousHash,
            link_hash: linkHash,
            started_at: new Date(this.sessionStart).toISOString(),
            accumulated_seconds: accumulated,
        };
        const stmt = this.db.prepare(`
            INSERT INTO integrity_chain (session_id, link_number, code_hash, previous_link_hash, link_hash, started_at, accumulated_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(linkData.session_id, linkData.link_number, linkData.code_hash, linkData.previous_link_hash, linkData.link_hash, linkData.started_at, linkData.accumulated_seconds);
        const inserted = this.getLastLink();
        const status = {
            status: chainStatus,
            totalLinks: this.getTotalLinks(),
            currentCodeHash: codeHash,
            lastLink: inserted,
            accumulatedSeconds: accumulated,
            sessionSeconds: 0,
            chainStart: lastLink ? lastLink.started_at : inserted.started_at,
            lastVerified: new Date().toISOString(),
        };
        return { chainStatus: status };
    }
    getStatus() {
        const lastLink = this.getLastLink();
        if (!lastLink) {
            return {
                status: 'EMPTY',
                totalLinks: 0,
                currentCodeHash: '',
                lastLink: null,
                accumulatedSeconds: 0,
                sessionSeconds: 0,
                chainStart: '',
                lastVerified: '',
            };
        }
        let chainStatus = 'INTACT';
        const allLinks = this.getAllLinks();
        for (const link of allLinks) {
            if (!this.verifyLink(link)) {
                chainStatus = 'BROKEN';
                break;
            }
        }
        if (chainStatus === 'INTACT') {
            for (let i = 1; i < allLinks.length; i++) {
                const link = allLinks[i];
                const prev = allLinks[i - 1];
                const expected = this.hashForSchema(this.schemaVersion(link), this.pickFields(prev, CHAIN_HASH_FIELDS));
                if (expected !== link.previous_link_hash) {
                    chainStatus = 'BROKEN';
                    break;
                }
            }
        }
        const elapsed = (Date.now() - new Date(lastLink.created_at).getTime()) / 1000;
        return {
            status: chainStatus,
            totalLinks: allLinks.length,
            currentCodeHash: lastLink.code_hash,
            lastLink,
            accumulatedSeconds: lastLink.accumulated_seconds + elapsed,
            sessionSeconds: elapsed,
            chainStart: allLinks[0].started_at,
            lastVerified: new Date().toISOString(),
        };
    }
    getLastLink() {
        const row = this.db.prepare('SELECT * FROM integrity_chain ORDER BY id DESC LIMIT 1').get();
        return row || null;
    }
    getAllLinks() {
        return this.db.prepare('SELECT * FROM integrity_chain ORDER BY id ASC').all();
    }
    getTotalLinks() {
        const r = this.db.prepare('SELECT COUNT(*) as c FROM integrity_chain').get();
        return r.c;
    }
    schemaVersion(link) {
        const legacy = link.id <= LEGACY_SCHEMA_MAX_LINK_ID
            && link.created_at < LEGACY_SCHEMA_CUTOFF;
        return legacy ? 'v1' : 'v2';
    }
    pickFields(source, fields) {
        const out = {};
        for (const key of fields)
            out[key] = source[key];
        return out;
    }
    hashForSchema(version, data) {
        if (version === 'v1') {
            return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
        }
        const sorted = {};
        Object.keys(data).sort().forEach(key => { sorted[key] = data[key]; });
        return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
    }
    /**
     * Verifies a single link's own link_hash using the schema that created it.
     * The link_hash covers exactly the 6 canonical fields; id and created_at
     * are not part of a link's own signed material.
     */
    verifyLink(link) {
        const expected = this.hashForSchema(this.schemaVersion(link), this.pickFields(link, LINK_HASH_FIELDS));
        return expected === link.link_hash;
    }
    formatDuration(totalSeconds) {
        const d = Math.floor(totalSeconds / 86400);
        const h = Math.floor((totalSeconds % 86400) / 3600);
        const m = Math.floor((totalSeconds % 3600) / 60);
        const s = Math.floor(totalSeconds % 60);
        const parts = [];
        if (d > 0)
            parts.push(`${d}d`);
        if (h > 0)
            parts.push(`${h}h`);
        if (m > 0)
            parts.push(`${m}m`);
        parts.push(`${s}s`);
        return parts.join(' ');
    }
}
exports.IntegrityChain = IntegrityChain;
