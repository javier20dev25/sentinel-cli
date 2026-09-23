import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import * as crypto from 'crypto'
import Database from 'better-sqlite3'
import { IntegrityChain } from './integrity_chain'
import type { ChainLink } from './integrity_chain'

const LEGACY_MAX_ID = 5
const LEGACY_CUTOFF = '2026-06-10 12:00:00'

const LINK_HASH_FIELDS = ['session_id', 'link_number', 'code_hash', 'previous_link_hash', 'started_at', 'accumulated_seconds']
const CHAIN_HASH_FIELDS = ['id', 'session_id', 'link_number', 'code_hash', 'previous_link_hash', 'link_hash', 'started_at', 'accumulated_seconds', 'created_at']

function sha256(s: string): string {
  return crypto.createHash('sha256').update(s).digest('hex')
}

function pick(source: Record<string, unknown>, fields: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  fields.forEach(k => { out[k] = source[k] })
  return out
}

function hashV1(data: Record<string, unknown>): string {
  return sha256(JSON.stringify(data))
}

function hashV2(data: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {}
  Object.keys(data).sort().forEach(k => { sorted[k] = data[k] })
  return sha256(JSON.stringify(sorted))
}

function isLegacy(id: number, createdAt: string): boolean {
  return id <= LEGACY_MAX_ID && createdAt < LEGACY_CUTOFF
}

function linkHashFor(row: ChainLink): string {
  return isLegacy(row.id, row.created_at)
    ? hashV1(pick(row, LINK_HASH_FIELDS))
    : hashV2(pick(row, LINK_HASH_FIELDS))
}

function chainHashFor(prevRow: ChainLink, linkId: number, linkCreatedAt: string): string {
  return isLegacy(linkId, linkCreatedAt)
    ? hashV1(pick(prevRow, CHAIN_HASH_FIELDS))
    : hashV2(pick(prevRow, CHAIN_HASH_FIELDS))
}

function seedRows(codeHash: string, legacyCount = 5, currentCount = 3): ChainLink[] {
  const rows: ChainLink[] = []
  const legacyStart = Date.parse('2026-06-05T10:46:33Z')
  const currentStart = Date.parse('2026-08-01T12:00:00Z')
  const total = legacyCount + currentCount
  for (let i = 1; i <= total; i++) {
    const legacy = i <= legacyCount
    const createdAt = legacy
      ? new Date(legacyStart + i * 11000).toISOString().slice(0, 19).replace('T', ' ')
      : new Date(currentStart + i * 1000).toISOString().slice(0, 19).replace('T', ' ')
    const prev = rows[i - 2] ?? null
    const previousLinkHash = prev
      ? chainHashFor(prev, i, createdAt)
      : null
    const row: ChainLink = {
      id: i,
      session_id: `session-${i}`,
      link_number: i,
      code_hash: codeHash,
      previous_link_hash: previousLinkHash,
      link_hash: '',
      started_at: new Date(Date.parse('2026-01-01T00:00:00Z') + i * 1000).toISOString(),
      accumulated_seconds: i * 3600,
      created_at: createdAt,
    }
    row.link_hash = linkHashFor(row)
    rows.push(row)
  }
  return rows
}

function seedDatabase(dbPath: string, codeHash = 'codehash-a', legacyCount = 5, currentCount = 3): void {
  const db = new Database(dbPath)
  try {
    db.exec(`
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
    `)
    const stmt = db.prepare(`
      INSERT INTO integrity_chain (id, session_id, link_number, code_hash, previous_link_hash, link_hash, started_at, accumulated_seconds, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    for (const r of seedRows(codeHash, legacyCount, currentCount)) {
      stmt.run(r.id, r.session_id, r.link_number, r.code_hash, r.previous_link_hash, r.link_hash, r.started_at, r.accumulated_seconds, r.created_at)
    }
  } finally {
    db.close()
  }
}

function readRows(dbPath: string): ChainLink[] {
  const db = new Database(dbPath, { readonly: true })
  try {
    return db.prepare('SELECT * FROM integrity_chain ORDER BY id ASC').all() as ChainLink[]
  } finally {
    db.close()
  }
}

function mutate(dbPath: string, fn: (db: Database.Database) => void): void {
  const db = new Database(dbPath)
  try {
    fn(db)
  } finally {
    db.close()
  }
}

describe('IntegrityChain (versioned verifier V1 legacy / V2 current)', () => {
  let testDir: string
  let dbPath: string

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-int-'))
    dbPath = path.join(testDir, 'vault.db')
  })

  afterEach(() => {
    try { fs.rmSync(testDir, { recursive: true, force: true }) } catch {}
  })

  it('returns EMPTY on a fresh chain', () => {
    const chain = new IntegrityChain(dbPath)
    expect(chain.getStatus().status).toBe('EMPTY')
  })

  it('recordBoot on a fresh chain creates an INTACT V2 genesis link', () => {
    const chain = new IntegrityChain(dbPath)
    const { chainStatus } = chain.recordBoot('codehash-a')
    expect(chainStatus.status).toBe('INTACT')
    // A fresh chain gets id 1 but must be verified under the CURRENT (V2)
    // schema, never as legacy — that was the genesis edge case of the fix.
    const chain2 = new IntegrityChain(dbPath)
    expect(chain2.verifyLink(chainStatus.lastLink!)).toBe(true)
    expect(chain2.getStatus().status).toBe('INTACT')
  })

  it('verifies a legacy (V1) link', () => {
    seedDatabase(dbPath)
    const chain = new IntegrityChain(dbPath)
    const legacy = readRows(dbPath).find(r => r.id === 1)!
    expect(chain.verifyLink(legacy)).toBe(true)
  })

  it('verifies a current (V2) link', () => {
    seedDatabase(dbPath)
    const chain = new IntegrityChain(dbPath)
    const current = readRows(dbPath).find(r => r.id === 8)!
    expect(chain.verifyLink(current)).toBe(true)
  })

  it('reports INTACT for the mixed legacy + current chain', () => {
    seedDatabase(dbPath)
    const chain = new IntegrityChain(dbPath)
    const status = chain.getStatus()
    expect(status.status).toBe('INTACT')
    expect(status.totalLinks).toBe(8)
  })

  it('reports INTACT for a V1-only chain', () => {
    seedDatabase(dbPath, 'codehash-a', 5, 0)
    const chain = new IntegrityChain(dbPath)
    expect(chain.getStatus().status).toBe('INTACT')
  })

  it('reports INTACT for a V2-only chain', () => {
    seedDatabase(dbPath, 'codehash-a', 0, 3)
    const chain = new IntegrityChain(dbPath)
    expect(chain.getStatus().status).toBe('INTACT')
  })

  it('breaks when session_id is modified', () => {
    seedDatabase(dbPath)
    mutate(dbPath, db => db.prepare('UPDATE integrity_chain SET session_id = ? WHERE id = 7').run('tampered-session'))
    const chain = new IntegrityChain(dbPath)
    const row = readRows(dbPath).find(r => r.id === 7)!
    expect(chain.verifyLink(row)).toBe(false)
    expect(chain.getStatus().status).toBe('BROKEN')
  })

  it('breaks when code_hash is modified', () => {
    seedDatabase(dbPath)
    mutate(dbPath, db => db.prepare('UPDATE integrity_chain SET code_hash = ? WHERE id = 7').run('tampered-code'))
    const chain = new IntegrityChain(dbPath)
    const row = readRows(dbPath).find(r => r.id === 7)!
    expect(chain.verifyLink(row)).toBe(false)
    expect(chain.getStatus().status).toBe('BROKEN')
  })

  it('breaks when previous_link_hash is modified', () => {
    seedDatabase(dbPath)
    mutate(dbPath, db => db.prepare('UPDATE integrity_chain SET previous_link_hash = ? WHERE id = 7').run('tampered-prev'))
    const chain = new IntegrityChain(dbPath)
    const row = readRows(dbPath).find(r => r.id === 7)!
    expect(chain.verifyLink(row)).toBe(false)
    expect(chain.getStatus().status).toBe('BROKEN')
  })

  it('breaks when accumulated_seconds is modified', () => {
    seedDatabase(dbPath)
    mutate(dbPath, db => db.prepare('UPDATE integrity_chain SET accumulated_seconds = ? WHERE id = 7').run(99999))
    const chain = new IntegrityChain(dbPath)
    const row = readRows(dbPath).find(r => r.id === 7)!
    expect(chain.verifyLink(row)).toBe(false)
    expect(chain.getStatus().status).toBe('BROKEN')
  })

  it('breaks when link_hash is modified', () => {
    seedDatabase(dbPath)
    mutate(dbPath, db => db.prepare('UPDATE integrity_chain SET link_hash = ? WHERE id = 7').run('a'.repeat(64)))
    const chain = new IntegrityChain(dbPath)
    const row = readRows(dbPath).find(r => r.id === 7)!
    expect(chain.verifyLink(row)).toBe(false)
    expect(chain.getStatus().status).toBe('BROKEN')
  })

  it('created_at modification keeps the own link_hash INTACT but breaks the chain binding', () => {
    seedDatabase(dbPath)
    mutate(dbPath, db => db.prepare('UPDATE integrity_chain SET created_at = ? WHERE id = 6').run('2026-09-01 00:00:00'))
    const chain = new IntegrityChain(dbPath)
    const row = readRows(dbPath).find(r => r.id === 6)!
    expect(chain.verifyLink(row)).toBe(true)
    expect(chain.getStatus().status).toBe('BROKEN')
  })

  it('id modification of a V2 row keeps the own link_hash INTACT but breaks the chain binding', () => {
    seedDatabase(dbPath)
    mutate(dbPath, db => db.prepare('UPDATE integrity_chain SET id = 60 WHERE id = 6').run())
    const chain = new IntegrityChain(dbPath)
    const row = readRows(dbPath).find(r => r.id === 60)!
    expect(chain.verifyLink(row)).toBe(true)
    expect(chain.getStatus().status).toBe('BROKEN')
  })

  it('recordBoot on an intact chain returns INTACT and keeps appending consistent V2 links', () => {
    seedDatabase(dbPath)
    const chain = new IntegrityChain(dbPath)
    const first = chain.recordBoot('codehash-a')
    const second = chain.recordBoot('codehash-a')
    expect(first.chainStatus.status).toBe('INTACT')
    expect(second.chainStatus.status).toBe('INTACT')
    expect(chain.getStatus().status).toBe('INTACT')
    expect(chain.getStatus().totalLinks).toBe(10)
    for (const r of readRows(dbPath)) {
      expect(chain.verifyLink(r)).toBe(true)
    }
  })

  it('recordBoot detects a tampered last link', () => {
    seedDatabase(dbPath)
    mutate(dbPath, db => db.prepare('UPDATE integrity_chain SET accumulated_seconds = ? WHERE id = 8').run(424242))
    const chain = new IntegrityChain(dbPath)
    expect(chain.recordBoot('codehash-a').chainStatus.status).toBe('BROKEN')
  })

  it('recordBoot detects a rules hash mismatch on the last link', () => {
    seedDatabase(dbPath)
    const chain = new IntegrityChain(dbPath)
    expect(chain.recordBoot('different-rules-hash').chainStatus.status).toBe('BROKEN')
  })
})
