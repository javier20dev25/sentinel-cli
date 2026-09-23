import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import Database from 'better-sqlite3';

export interface ChainLink {
    id: number;
    session_id: string;
    link_number: number;
    code_hash: string;
    previous_link_hash: string | null;
    link_hash: string;
    started_at: string;
    accumulated_seconds: number;
    created_at: string;
    [key: string]: unknown;
}

interface ChainLinkInput {
    session_id: string;
    link_number: number;
    code_hash: string;
    previous_link_hash: string | null;
    started_at: string;
    accumulated_seconds: number;
    link_hash?: string;
    [key: string]: unknown;
}

export interface ChainStatus {
    status: 'INTACT' | 'BROKEN' | 'EMPTY';
    totalLinks: number;
    currentCodeHash: string;
    lastLink: ChainLink | null;
    accumulatedSeconds: number;
    sessionSeconds: number;
    chainStart: string;
    lastVerified: string;
}

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

type SchemaVersion = 'v1' | 'v2';

export class IntegrityChain {
    private db: Database.Database;
    private cliRoot: string;
    private sessionId: string;
    private sessionStart: number;

    constructor(dbPath?: string) {
        const resolvedPath = dbPath ?? path.join(os.homedir(), '.sentinel', 'vault.db');
        const dir = path.dirname(resolvedPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        this.db = new Database(resolvedPath);
        this.cliRoot = path.join(__dirname, '..', '..', '..');
        this.sessionId = crypto.randomBytes(8).toString('hex');
        this.sessionStart = Date.now();
        this.initSchema();
    }

    private initSchema(): void {
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

    public recordBoot(codeHash: string): { chainStatus: ChainStatus } {
        const lastLink = this.getLastLink();
        let accumulated = 0;
        let chainStatus: 'INTACT' | 'BROKEN' | 'EMPTY' = 'INTACT';
        let previousHash: string | null = null;

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
        stmt.run(
            linkData.session_id,
            linkData.link_number,
            linkData.code_hash,
            linkData.previous_link_hash,
            linkData.link_hash,
            linkData.started_at,
            linkData.accumulated_seconds
        );

        const inserted = this.getLastLink()!;
        const status: ChainStatus = {
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

    public getStatus(): ChainStatus {
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

        let chainStatus: 'INTACT' | 'BROKEN' | 'EMPTY' = 'INTACT';
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
                const expected = this.hashForSchema(
                    this.schemaVersion(link),
                    this.pickFields(prev, CHAIN_HASH_FIELDS)
                );
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

    private getLastLink(): ChainLink | null {
        const row = this.db.prepare(
            'SELECT * FROM integrity_chain ORDER BY id DESC LIMIT 1'
        ).get() as ChainLink | undefined;
        return row || null;
    }

    private getAllLinks(): ChainLink[] {
        return this.db.prepare(
            'SELECT * FROM integrity_chain ORDER BY id ASC'
        ).all() as ChainLink[];
    }

    private getTotalLinks(): number {
        const r = this.db.prepare('SELECT COUNT(*) as c FROM integrity_chain').get() as { c: number };
        return r.c;
    }

    private schemaVersion(link: ChainLink): SchemaVersion {
        const legacy = link.id <= LEGACY_SCHEMA_MAX_LINK_ID
            && link.created_at < LEGACY_SCHEMA_CUTOFF;
        return legacy ? 'v1' : 'v2';
    }

    private pickFields(source: Record<string, unknown>, fields: readonly string[]): Record<string, unknown> {
        const out: Record<string, unknown> = {};
        for (const key of fields) out[key] = source[key];
        return out;
    }

    private hashForSchema(version: SchemaVersion, data: Record<string, unknown>): string {
        if (version === 'v1') {
            return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
        }
        const sorted: Record<string, unknown> = {};
        Object.keys(data).sort().forEach(key => { sorted[key] = data[key]; });
        return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
    }

    /**
     * Verifies a single link's own link_hash using the schema that created it.
     * The link_hash covers exactly the 6 canonical fields; id and created_at
     * are not part of a link's own signed material.
     */
    public verifyLink(link: ChainLink): boolean {
        const expected = this.hashForSchema(
            this.schemaVersion(link),
            this.pickFields(link, LINK_HASH_FIELDS)
        );
        return expected === link.link_hash;
    }

    public formatDuration(totalSeconds: number): string {
        const d = Math.floor(totalSeconds / 86400);
        const h = Math.floor((totalSeconds % 86400) / 3600);
        const m = Math.floor((totalSeconds % 3600) / 60);
        const s = Math.floor(totalSeconds % 60);
        const parts: string[] = [];
        if (d > 0) parts.push(`${d}d`);
        if (h > 0) parts.push(`${h}h`);
        if (m > 0) parts.push(`${m}m`);
        parts.push(`${s}s`);
        return parts.join(' ');
    }
}
